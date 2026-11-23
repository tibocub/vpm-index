-- Ed25519 (RFC 8032 section 5.1): pure EdDSA over edwards25519 with SHA-512, JWS "EdDSA".
--
--   ed25519.private_key(seed) -> key | nil, err        seed: the 32-byte private key
--   ed25519.public_key(bytes) -> key | nil, err        the 32-byte encoded point
--   ed25519.sign(key, message) -> 64-byte signature | nil, err
--   ed25519.verify(key, message, signature) -> boolean
--
-- Keys: key.public is the 32-byte public key. Coinbase CDP hands out base64 of
-- seed || public (64 bytes); pass the first 32 bytes as the seed.
--
-- Verification is the cofactorless check encode([S]B - [k]A) == R, with S < L required,
-- as OpenSSL (node:crypto) does. Extended coordinates (RFC 8032 section 5.1.4) over
-- distilled.crypto.bigint's Montgomery field, 4-bit windows. Not constant time.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local bigint = require("distilled.crypto.bigint")
local keys = require("distilled.crypto.key")

local ed25519 = {}

local H = bigint.from_hex
local floor = math.floor
local byte, char = string.byte, string.char

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "Ed25519: " .. message })
end

local C -- curve constants, built on first use

local function curve()
  if C then
    return C
  end
  local p = H("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
  local L = H("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
  local F = bigint.mont(p)
  local d = F:to(H("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"))
  C = {
    p = p,
    L = L,
    F = F,
    N = bigint.mont(L),
    d = d,
    d2 = F:add(d, d),
    sqrt_m1 = F:to(H("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0")),
    exp = bigint.shr(bigint.sub(p, { 5 }), 3), -- (p - 5) / 8
  }
  local bx = F:to(H("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"))
  local by = F:to(H("6666666666666666666666666666666666666666666666666666666666666658"))
  C.B = { bx, by, F.one, F:mul(bx, by) }
  return C
end

local function add(P, Q)
  local F = C.F
  local A = F:mul(F:sub(P[2], P[1]), F:sub(Q[2], Q[1]))
  local Bv = F:mul(F:add(P[2], P[1]), F:add(Q[2], Q[1]))
  local Cv = F:mul(F:mul(P[4], C.d2), Q[4])
  local D = F:mul(P[3], F:add(Q[3], Q[3]))
  local E, Fv, G, Hv = F:sub(Bv, A), F:sub(D, Cv), F:add(D, Cv), F:add(Bv, A)
  return { F:mul(E, Fv), F:mul(G, Hv), F:mul(Fv, G), F:mul(E, Hv) }
end

local function double(P)
  local F = C.F
  local A = F:sqr(P[1])
  local Bv = F:sqr(P[2])
  local z2 = F:sqr(P[3])
  local Cv = F:add(z2, z2)
  local Hv = F:add(A, Bv)
  local E = F:sub(Hv, F:sqr(F:add(P[1], P[2])))
  local G = F:sub(A, Bv)
  local Fv = F:add(Cv, G)
  return { F:mul(E, Fv), F:mul(G, Hv), F:mul(Fv, G), F:mul(E, Hv) }
end

local function table_of(P)
  local T = { P, double(P) }
  for i = 3, 15 do
    T[i] = add(T[i - 1], P)
  end
  return T
end

local function nibble(e, w)
  local b = w * 4
  return bigint.bit(e, b)
    + 2 * bigint.bit(e, b + 1)
    + 4 * bigint.bit(e, b + 2)
    + 8 * bigint.bit(e, b + 3)
end

local function multi_mul(scalars, tables)
  local F = C.F
  local nbits = 0
  for i = 1, #scalars do
    local b = bigint.bits(scalars[i])
    if b > nbits then
      nbits = b
    end
  end
  local R = { F.zero, F.one, F.one, F.zero }
  for w = floor((nbits + 3) / 4) - 1, 0, -1 do
    R = double(double(double(double(R))))
    for i = 1, #scalars do
      local v = nibble(scalars[i], w)
      if v ~= 0 then
        R = add(R, tables[i][v])
      end
    end
  end
  return R
end

local function b_table()
  if not C.B_table then
    C.B_table = table_of(C.B)
  end
  return C.B_table
end

local function reverse(s)
  return s:reverse()
end

local function le_int(s)
  return bigint.from_bytes(reverse(s))
end

local function le_bytes(x, n)
  return reverse(bigint.to_bytes(x, n))
end

local function encode(P)
  local F = C.F
  local zi = F:inv(P[3])
  local x = F:from(F:mul(P[1], zi))
  local y = F:from(F:mul(P[2], zi))
  local s = le_bytes(y, 32)
  if bigint.is_odd(x) then
    s = s:sub(1, 31) .. char(byte(s, 32) + 128)
  end
  return s
end

-- RFC 8032 section 5.1.3
local function decode(s)
  if #s ~= 32 then
    return nil
  end
  local F = C.F
  local last = byte(s, 32)
  local sign = last >= 128
  local y = le_int(s:sub(1, 31) .. char(last % 128))
  if bigint.cmp(y, C.p) >= 0 then
    return nil
  end
  local ym = F:to(y)
  local yy = F:sqr(ym)
  local u = F:sub(yy, F.one)
  local v = F:add(F:mul(C.d, yy), F.one)
  local v3 = F:mul(F:sqr(v), v)
  local v7 = F:mul(F:sqr(v3), v)
  local x = F:mul(F:mul(u, v3), F:pow(F:mul(u, v7), C.exp))
  local vxx = F:mul(v, F:sqr(x))
  if not F:eq(vxx, u) then
    if F:eq(vxx, F:neg(u)) then
      x = F:mul(x, C.sqrt_m1)
    else
      return nil
    end
  end
  local xp = F:from(x)
  if bigint.is_zero(xp) and sign then
    return nil
  end
  if bigint.is_odd(xp) ~= sign then
    x = F:neg(x)
  end
  return { x, ym, F.one, F:mul(x, ym) }
end

local function sha512(s)
  return require("distilled.crypto").sha512(s)
end

function ed25519.private_key(seed)
  if type(seed) ~= "string" then
    compat.raise("ed25519.private_key: seed must be a string", 2)
  end
  if #seed ~= 32 then
    return invalid("the private key must be 32 bytes, got " .. #seed)
  end
  curve()
  local h = sha512(seed)
  -- clamp: clear the low 3 bits and bit 255, set bit 254
  local a0 = byte(h, 1)
  local a31 = byte(h, 32)
  local scalar = le_int(char(a0 - a0 % 8) .. h:sub(2, 31) .. char(a31 % 64 + 64))
  local A = multi_mul({ scalar }, { b_table() })
  local public = encode(A)
  local k = keys.new("ed25519", { public = public }, {
    seed = seed,
    scalar = scalar,
    prefix = h:sub(33, 64),
  })
  keys.cache(k).point = A
  return k
end

function ed25519.public_key(bytes)
  if type(bytes) ~= "string" then
    compat.raise("ed25519.public_key: expected a string", 2)
  end
  curve()
  local A = decode(bytes)
  if not A then
    return invalid("not an encoded point")
  end
  local k = keys.new("ed25519", { public = bytes })
  keys.cache(k).point = A
  return k
end

local function check_key(k, fname)
  if not keys.is(k) or k.kind ~= "ed25519" then
    compat.raise(fname .. ": expected an Ed25519 key", 3)
  end
end

function ed25519.sign(k, message)
  check_key(k, "ed25519.sign")
  if type(message) ~= "string" then
    compat.raise("ed25519.sign: message must be a string", 2)
  end
  local private = keys.private(k)
  if not private then
    return invalid("signing needs a private key")
  end
  curve()
  local N = C.N
  local r = N:mod(le_int(sha512(private.prefix .. message)))
  local R = encode(multi_mul({ r }, { b_table() }))
  local kk = N:to(le_int(sha512(R .. k.public .. message)))
  local S = N:from(N:add(N:to(r), N:mul(kk, N:to(private.scalar))))
  return R .. le_bytes(S, 32)
end

function ed25519.verify(k, message, signature)
  check_key(k, "ed25519.verify")
  if type(message) ~= "string" or type(signature) ~= "string" then
    compat.raise("ed25519.verify: message and signature must be strings", 2)
  end
  if #signature ~= 64 then
    return false
  end
  curve()
  local cache = keys.cache(k)
  if not cache.point then
    cache.point = decode(k.public)
  end
  local A = cache.point
  if not A then
    return false
  end
  local Rb = signature:sub(1, 32)
  if not decode(Rb) then
    return false
  end
  local S = le_int(signature:sub(33))
  if bigint.cmp(S, C.L) >= 0 then
    return false
  end
  local N = C.N
  local kk = N:mod(le_int(sha512(Rb .. k.public .. message)))
  local neg_k = bigint.is_zero(kk) and kk or bigint.sub(C.L, kk)
  if not cache.table then
    cache.table = table_of(A)
  end
  local P = multi_mul({ S, neg_k }, { b_table(), cache.table })
  return encode(P) == Rb
end

return ed25519
