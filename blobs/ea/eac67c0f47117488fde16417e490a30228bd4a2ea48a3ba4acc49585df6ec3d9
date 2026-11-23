-- ECDSA over P-256 (ES256) and secp256k1 (ES256K, Ethereum), with RFC 6979
-- deterministic nonces, so a signature is a function of the key and the message.
--
--   ecdsa.private_key(curve, d [, public_point]) -> key | nil, err
--       curve: "P-256" | "secp256k1"; d: 32-byte big-endian string or a bigint;
--       public_point: SEC1 bytes (04 x y, or 02/03 x); when given it must match d
--   ecdsa.public_key(curve, point) -> key | nil, err          SEC1 point bytes
--   ecdsa.sign(key, message [, opts]) -> signature, recovery_id | nil, err
--   ecdsa.sign_digest(key, digest [, opts]) -> signature, recovery_id | nil, err
--       opts.hash   "sha256" (default) | "sha224" | "sha384" | "sha512" | "sha1" | "keccak256":
--                   the message hash (sign) and the RFC 6979 HMAC hash (SHA-256 for
--                   keccak256 and for sign_digest, as libsecp256k1 and noble do)
--       opts.format "raw" (default: r || s, 32 bytes each, as JWS wants) | "der"
--       opts.low_s  true: return s <= n/2 (Ethereum, Bitcoin); default false, which is
--                   what RFC 6979's vectors and node:crypto produce
--   ecdsa.verify(key, message, signature [, opts]) -> boolean  (opts.hash, opts.format)
--   ecdsa.verify_digest(key, digest, signature [, opts]) -> boolean
--   ecdsa.recover(curve, digest, signature, recovery_id) -> public key | nil, err
--   ecdsa.point_bytes(key [, compressed]) -> SEC1 bytes of the public point
--   ecdsa.der_to_raw(der) -> raw | nil, err;  ecdsa.raw_to_der(raw) -> der
--
-- recovery_id: bit 0 is the parity of R.y, bit 1 is set when R.x >= n (Ethereum's v is
-- 27 + recovery_id). With low_s the id is adjusted to the returned s.
--
-- Arithmetic: Jacobian coordinates over distilled.crypto.bigint's Montgomery fields,
-- 4-bit fixed windows. Not constant time (see bigint).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local bigint = require("distilled.crypto.bigint")
local keys = require("distilled.crypto.key")
local asn1 = require("distilled.crypto.asn1")

local ecdsa = {}

local H = bigint.from_hex
local floor = math.floor

local CURVE_PARAMS = {
  ["P-256"] = {
    p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    a = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    b = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    n = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    a_minus3 = true,
  },
  secp256k1 = {
    p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    a = "0",
    b = "7",
    gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    a_zero = true,
  },
}

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "ECDSA: " .. message })
end

---------------------------------------------------------------------------------------
-- curve arithmetic
---------------------------------------------------------------------------------------

local curves = {}

local function curve_of(name)
  local C = curves[name]
  if C then
    return C
  end
  local params = CURVE_PARAMS[name]
  if not params then
    return nil
  end
  local p, n = H(params.p), H(params.n)
  local F = bigint.mont(p)
  C = {
    name = name,
    p = p,
    n = n,
    F = F,
    N = bigint.mont(n),
    a = F:to(H(params.a)),
    b = F:to(H(params.b)),
    a_minus3 = params.a_minus3,
    a_zero = params.a_zero,
    half_n = bigint.shr(n, 1),
    sqrt_exp = bigint.shr(bigint.add(p, { 1 }), 2), -- (p + 1) / 4: both p are 3 mod 4
    size = 32,
  }
  C.G = { F:to(H(params.gx)), F:to(H(params.gy)), F.one }
  curves[name] = C
  return C
end
ecdsa.curve = curve_of

local function is_infinity(C, P)
  return C.F:is_zero(P[3])
end

local function double(C, P)
  local F = C.F
  if F:is_zero(P[3]) then
    return P
  end
  local X, Y, Z = P[1], P[2], P[3]
  -- dbl-2001-b (a = -3) and its general form: alpha = 3 X^2 + a Z^4
  local delta = F:sqr(Z)
  local gamma = F:sqr(Y)
  local beta = F:mul(X, gamma)
  local alpha
  if C.a_minus3 then
    local t = F:mul(F:sub(X, delta), F:add(X, delta))
    alpha = F:add(F:add(t, t), t)
  else
    local xx = F:sqr(X)
    alpha = F:add(F:add(xx, xx), xx)
    if not C.a_zero then
      alpha = F:add(alpha, F:mul(C.a, F:sqr(delta)))
    end
  end
  local beta2 = F:add(beta, beta)
  local beta4 = F:add(beta2, beta2)
  local beta8 = F:add(beta4, beta4)
  local X3 = F:sub(F:sqr(alpha), beta8)
  local Z3 = F:sub(F:sub(F:sqr(F:add(Y, Z)), gamma), delta)
  local g1 = F:sqr(gamma)
  local g2 = F:add(g1, g1)
  local g4 = F:add(g2, g2)
  local g8 = F:add(g4, g4)
  -- Y3 = alpha (4 beta - X3) - 8 gamma^2
  local Y3 = F:sub(F:mul(alpha, F:sub(beta4, X3)), g8)
  return { X3, Y3, Z3 }
end

-- add-2007-bl, with the doubling and infinity cases
local function add(C, P, Q)
  local F = C.F
  if F:is_zero(P[3]) then
    return Q
  end
  if F:is_zero(Q[3]) then
    return P
  end
  local Z1Z1 = F:sqr(P[3])
  local Z2Z2 = F:sqr(Q[3])
  local U1 = F:mul(P[1], Z2Z2)
  local U2 = F:mul(Q[1], Z1Z1)
  local S1 = F:mul(F:mul(P[2], Q[3]), Z2Z2)
  local S2 = F:mul(F:mul(Q[2], P[3]), Z1Z1)
  local Hh = F:sub(U2, U1)
  local rr = F:sub(S2, S1)
  if F:is_zero(Hh) then
    if F:is_zero(rr) then
      return double(C, P)
    end
    return { F.zero, F.one, F.zero }
  end
  rr = F:add(rr, rr)
  local H2 = F:add(Hh, Hh)
  local I = F:sqr(H2)
  local J = F:mul(Hh, I)
  local V = F:mul(U1, I)
  local X3 = F:sub(F:sub(F:sqr(rr), J), F:add(V, V))
  local S1J = F:mul(S1, J)
  local Y3 = F:sub(F:mul(rr, F:sub(V, X3)), F:add(S1J, S1J))
  local Z3 = F:mul(F:sub(F:sub(F:sqr(F:add(P[3], Q[3])), Z1Z1), Z2Z2), Hh)
  return { X3, Y3, Z3 }
end

-- P, 2P, ..., 15P
local function table_of(C, P)
  local T = { P }
  T[2] = double(C, P)
  for i = 3, 15 do
    T[i] = add(C, T[i - 1], P)
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

-- sum of k_i * P_i (tables from table_of), one shared run of doublings (Shamir's trick)
local function multi_mul(C, scalars, tables)
  local F = C.F
  local nbits = 0
  for i = 1, #scalars do
    local b = bigint.bits(scalars[i])
    if b > nbits then
      nbits = b
    end
  end
  local R = { F.zero, F.one, F.zero }
  for w = floor((nbits + 3) / 4) - 1, 0, -1 do
    R = double(C, double(C, double(C, double(C, R))))
    for i = 1, #scalars do
      local v = nibble(scalars[i], w)
      if v ~= 0 then
        R = add(C, R, tables[i][v])
      end
    end
  end
  return R
end

local function g_table(C)
  if not C.G_table then
    C.G_table = table_of(C, C.G)
  end
  return C.G_table
end

-- madd-2007-bl: P (Jacobian) + Q (affine { x, y }, Montgomery form)
local function add_affine(C, P, Q)
  local F = C.F
  if F:is_zero(P[3]) then
    return { Q[1], Q[2], F.one }
  end
  local Z1Z1 = F:sqr(P[3])
  local U2 = F:mul(Q[1], Z1Z1)
  local S2 = F:mul(F:mul(Q[2], P[3]), Z1Z1)
  local Hh = F:sub(U2, P[1])
  local rr = F:sub(S2, P[2])
  if F:is_zero(Hh) then
    if F:is_zero(rr) then
      return double(C, P)
    end
    return { F.zero, F.one, F.zero }
  end
  rr = F:add(rr, rr)
  local HH = F:sqr(Hh)
  local I = F:add(HH, HH)
  I = F:add(I, I)
  local J = F:mul(Hh, I)
  local V = F:mul(P[1], I)
  local X3 = F:sub(F:sub(F:sqr(rr), J), F:add(V, V))
  local YJ = F:mul(P[2], J)
  local Y3 = F:sub(F:mul(rr, F:sub(V, X3)), F:add(YJ, YJ))
  local Z3 = F:sub(F:sub(F:sqr(F:add(P[3], Hh)), Z1Z1), HH)
  return { X3, Y3, Z3 }
end

-- Fixed-base comb: comb[w][v] = v * 16^(w-1) * G in affine form, so k*G is one mixed
-- addition per 4-bit window and no doublings (about 4x faster). Building it costs about
-- as much as six scalar multiplications, so it is built on the COMB_AFTER-th use of G in
-- the process, not the first: a script that signs once does not pay for it.
local COMB_AFTER = 4
ecdsa.COMB_AFTER = COMB_AFTER

local function build_comb(C)
  local F = C.F
  local points = {}
  local base = C.G
  local windows = floor((bigint.bits(C.n) + 3) / 4)
  for w = 1, windows do
    local row = table_of(C, base)
    for v = 1, 15 do
      points[#points + 1] = row[v]
    end
    base = double(C, double(C, double(C, double(C, row[1]))))
  end
  -- batch inversion of every Z (Montgomery's trick): one field inversion in total
  local n = #points
  local prefix = {}
  local acc = F.one
  for i = 1, n do
    prefix[i] = acc
    acc = F:mul(acc, points[i][3])
  end
  local inv = F:inv(acc)
  local affine_points = {}
  for i = n, 1, -1 do
    local P = points[i]
    local zi = F:mul(inv, prefix[i])
    inv = F:mul(inv, P[3])
    local zi2 = F:sqr(zi)
    affine_points[i] = { F:mul(P[1], zi2), F:mul(F:mul(P[2], zi2), zi) }
  end
  local comb = {}
  for w = 1, windows do
    local row = {}
    for v = 1, 15 do
      row[v] = affine_points[(w - 1) * 15 + v]
    end
    comb[w] = row
  end
  return comb
end

-- k * G
local function base_mul(C, k)
  if not C.comb then
    C.g_uses = (C.g_uses or 0) + 1
    if C.g_uses < COMB_AFTER then
      return multi_mul(C, { k }, { g_table(C) })
    end
    C.comb = build_comb(C)
  end
  local F = C.F
  local R = { F.zero, F.one, F.zero }
  for w = 0, floor((bigint.bits(k) + 3) / 4) - 1 do
    local v = nibble(k, w)
    if v ~= 0 then
      R = add_affine(C, R, C.comb[w + 1][v])
    end
  end
  return R
end

-- u1 * G + u2 * P (P's window table given)
local function double_mul(C, u1, u2, ptable)
  if C.comb then
    return add(C, base_mul(C, u1), multi_mul(C, { u2 }, { ptable }))
  end
  C.g_uses = (C.g_uses or 0) + 1
  return multi_mul(C, { u1, u2 }, { g_table(C), ptable })
end

-- affine plain coordinates (bigints) of a Jacobian point, or nil at infinity
local function affine(C, P)
  local F = C.F
  if F:is_zero(P[3]) then
    return nil
  end
  local zi = F:inv(P[3])
  local zi2 = F:sqr(zi)
  local x = F:from(F:mul(P[1], zi2))
  local y = F:from(F:mul(F:mul(P[2], zi2), zi))
  return x, y
end

-- y^2 = x^3 + a x + b, in Montgomery form
local function rhs(C, xm)
  local F = C.F
  local v = F:add(F:mul(F:sqr(xm), xm), C.b)
  if not C.a_zero then
    v = F:add(v, F:mul(C.a, xm))
  end
  return v
end

-- the point for x (plain bigint) with y of the given parity, or nil
local function lift_x(C, x, odd)
  local F = C.F
  if bigint.cmp(x, C.p) >= 0 then
    return nil
  end
  local xm = F:to(x)
  local v = rhs(C, xm)
  local ym = F:pow(v, C.sqrt_exp)
  if not F:eq(F:sqr(ym), v) then
    return nil
  end
  local y = F:from(ym)
  if bigint.is_odd(y) ~= odd then
    ym = F:neg(ym)
  end
  return { xm, ym, F.one }
end

local function decode_point(C, bytes)
  local size = C.size
  local first = bytes:byte(1)
  if #bytes == 2 * size + 1 and first == 4 then
    local x = bigint.from_bytes(bytes:sub(2, size + 1))
    local y = bigint.from_bytes(bytes:sub(size + 2))
    if bigint.cmp(x, C.p) >= 0 or bigint.cmp(y, C.p) >= 0 then
      return nil
    end
    local F = C.F
    local P = { F:to(x), F:to(y), F.one }
    if not F:eq(F:sqr(P[2]), rhs(C, P[1])) then
      return nil
    end
    return P
  elseif #bytes == size + 1 and (first == 2 or first == 3) then
    return lift_x(C, bigint.from_bytes(bytes:sub(2)), first == 3)
  end
  return nil
end

---------------------------------------------------------------------------------------
-- keys
---------------------------------------------------------------------------------------

local function make_public(C, P)
  local x, y = affine(C, P)
  local k = keys.new("ec", {
    curve = C.name,
    x = bigint.to_bytes(x, C.size),
    y = bigint.to_bytes(y, C.size),
  })
  keys.cache(k).point = P
  return k
end

local function point_of(C, k)
  local cache = keys.cache(k)
  if not cache.point then
    local F = C.F
    cache.point = { F:to(bigint.from_bytes(k.x)), F:to(bigint.from_bytes(k.y)), F.one }
  end
  return cache.point
end

local function curve_arg(curve, fname)
  local C = type(curve) == "string" and curve_of(curve)
  if not C then
    compat.raise(fname .. ": unsupported curve " .. tostring(curve) .. " (P-256, secp256k1)", 3)
  end
  return C
end

function ecdsa.public_key(curve, point)
  local C = curve_arg(curve, "ecdsa.public_key")
  if type(point) ~= "string" then
    compat.raise("ecdsa.public_key: the point must be a string", 2)
  end
  local P = decode_point(C, point)
  if not P then
    return invalid("not a point on " .. C.name)
  end
  return make_public(C, P)
end

function ecdsa.private_key(curve, d, point)
  local C = curve_arg(curve, "ecdsa.private_key")
  if type(d) == "string" then
    if #d > C.size then
      return invalid("the private scalar is longer than " .. C.size .. " bytes")
    end
    d = bigint.from_bytes(d)
  elseif type(d) ~= "table" then
    compat.raise("ecdsa.private_key: d must be a string or a bigint", 2)
  end
  if bigint.is_zero(d) or bigint.cmp(d, C.n) >= 0 then
    return invalid("the private scalar is out of range")
  end
  local pub = make_public(C, base_mul(C, d))
  -- a public point stored with the scalar (SEC1, JWK) must be the one it derives
  if point ~= nil then
    local P = decode_point(C, point)
    if not P then
      return invalid("the public key is not a point on " .. C.name)
    end
    local x, y = affine(C, P)
    if bigint.to_bytes(x, C.size) ~= pub.x or bigint.to_bytes(y, C.size) ~= pub.y then
      return invalid("the public key does not match the private key")
    end
  end
  local k = keys.new("ec", { curve = C.name, x = pub.x, y = pub.y }, { d = d })
  keys.cache(k).point = keys.cache(pub).point
  return k
end

function ecdsa.point_bytes(k, compressed)
  if compressed then
    local odd = k.y:byte(#k.y) % 2 == 1
    return (odd and "\3" or "\2") .. k.x
  end
  return "\4" .. k.x .. k.y
end

---------------------------------------------------------------------------------------
-- signatures
---------------------------------------------------------------------------------------

local HASH_BITS =
  { sha1 = 160, sha224 = 224, sha256 = 256, sha384 = 384, sha512 = 512, keccak256 = 256 }

-- bits2int (RFC 6979 2.3.2): the leftmost qlen bits of the digest
local function bits2int(C, digest)
  local x = bigint.from_bytes(digest)
  local extra = #digest * 8 - bigint.bits(C.n)
  if extra > 0 then
    x = bigint.shr(x, extra)
  end
  return x
end

local function reduce_n(C, x)
  if bigint.cmp(x, C.n) >= 0 then
    return bigint.sub(x, C.n)
  end
  return x
end

-- RFC 6979 section 3.2: the nonces for (d, digest), one per call of the returned iterator
local function nonces(C, d, digest, hmac_hash)
  local crypto = require("distilled.crypto")
  local function mac(key, data)
    return crypto.hmac(hmac_hash, key, data)
  end
  local hlen = #crypto.digest(hmac_hash, "")
  local size = C.size
  local x = bigint.to_bytes(d, size)
  local h = bigint.to_bytes(reduce_n(C, bits2int(C, digest)), size)
  local V = string.rep("\1", hlen)
  local K = string.rep("\0", hlen)
  K = mac(K, V .. "\0" .. x .. h)
  V = mac(K, V)
  K = mac(K, V .. "\1" .. x .. h)
  V = mac(K, V)
  local first = true
  return function()
    while true do
      if not first then
        K = mac(K, V .. "\0")
        V = mac(K, V)
      end
      first = false
      local T = ""
      while #T < size do
        V = mac(K, V)
        T = T .. V
      end
      local k = bits2int(C, T)
      if not bigint.is_zero(k) and bigint.cmp(k, C.n) < 0 then
        return k
      end
    end
  end
end

local function encode_signature(C, r, s, format)
  if format == "der" then
    return asn1.sequence(asn1.encode_integer(r), asn1.encode_integer(s))
  end
  return bigint.to_bytes(r, C.size) .. bigint.to_bytes(s, C.size)
end

local function options(opts, fname)
  if opts ~= nil and type(opts) ~= "table" then
    compat.raise(fname .. ": opts must be a table", 3)
  end
  opts = opts or {}
  local hash = opts.hash or "sha256"
  if not HASH_BITS[hash] then
    compat.raise(fname .. ": unsupported hash " .. tostring(hash), 3)
  end
  local format = opts.format or "raw"
  if format ~= "raw" and format ~= "der" then
    compat.raise(fname .. ': format must be "raw" or "der"', 3)
  end
  return hash, format, opts.low_s == true
end

local function check_key(k, fname)
  if not keys.is(k) or k.kind ~= "ec" then
    compat.raise(fname .. ": expected an EC key", 3)
  end
  return curve_of(k.curve)
end

local function sign_digest(k, digest, hmac_hash, format, low_s)
  local C = curve_of(k.curve)
  local private = keys.private(k)
  if not private then
    return invalid("signing needs a private key")
  end
  local N = C.N
  local d = private.d
  local e = reduce_n(C, bits2int(C, digest))
  local next_k = nonces(C, d, digest, hmac_hash)
  local dm = keys.cache(k).dm
  if not dm then
    dm = N:to(d)
    keys.cache(k).dm = dm
  end
  for _ = 1, 64 do
    local kk = next_k()
    local R = base_mul(C, kk)
    local x, y = affine(C, R)
    local r = reduce_n(C, x)
    if not bigint.is_zero(r) then
      -- s = k^-1 (e + r d) mod n
      local km = N:to(kk)
      local sm = N:mul(N:inv(km), N:add(N:to(e), N:mul(N:to(r), dm)))
      local s = N:from(sm)
      if not bigint.is_zero(s) then
        local recid = (bigint.is_odd(y) and 1 or 0) + (bigint.cmp(x, C.n) >= 0 and 2 or 0)
        if low_s and bigint.cmp(s, C.half_n) > 0 then
          s = bigint.sub(C.n, s)
          recid = recid % 2 == 1 and recid - 1 or recid + 1
        end
        return encode_signature(C, r, s, format), recid
      end
    end
  end
  return invalid("no valid nonce") -- probability ~ 2^-8000
end

function ecdsa.sign(k, message, opts)
  check_key(k, "ecdsa.sign")
  if type(message) ~= "string" then
    compat.raise("ecdsa.sign: message must be a string", 2)
  end
  local hash, format, low_s = options(opts, "ecdsa.sign")
  local digest = require("distilled.crypto").digest(hash, message)
  return sign_digest(k, digest, hash == "keccak256" and "sha256" or hash, format, low_s)
end

function ecdsa.sign_digest(k, digest, opts)
  check_key(k, "ecdsa.sign_digest")
  if type(digest) ~= "string" or #digest == 0 then
    compat.raise("ecdsa.sign_digest: digest must be a non-empty string", 2)
  end
  local _, format, low_s = options(opts, "ecdsa.sign_digest")
  return sign_digest(k, digest, "sha256", format, low_s)
end

-- r, s (bigints) from either encoding, or nil
local function decode_signature(C, signature, format)
  if format == "der" then
    local raw = ecdsa.der_to_raw(signature, C.size)
    if not raw then
      return nil
    end
    signature = raw
  end
  if #signature ~= 2 * C.size then
    return nil
  end
  return bigint.from_bytes(signature:sub(1, C.size)), bigint.from_bytes(signature:sub(C.size + 1))
end

local function in_range(C, v)
  return not bigint.is_zero(v) and bigint.cmp(v, C.n) < 0
end

local function verify_digest(k, digest, signature, format)
  local C = curve_of(k.curve)
  local r, s = decode_signature(C, signature, format)
  if not r or not in_range(C, r) or not in_range(C, s) then
    return false
  end
  local N = C.N
  local e = reduce_n(C, bits2int(C, digest))
  local w = N:inv(N:to(s))
  local u1 = N:from(N:mul(N:to(e), w))
  local u2 = N:from(N:mul(N:to(r), w))
  local cache = keys.cache(k)
  if not cache.table then
    cache.table = table_of(C, point_of(C, k))
  end
  local X = double_mul(C, u1, u2, cache.table)
  local x = affine(C, X)
  if not x then
    return false
  end
  return bigint.cmp(reduce_n(C, x), r) == 0
end

function ecdsa.verify(k, message, signature, opts)
  check_key(k, "ecdsa.verify")
  if type(message) ~= "string" or type(signature) ~= "string" then
    compat.raise("ecdsa.verify: message and signature must be strings", 2)
  end
  local hash, format = options(opts, "ecdsa.verify")
  return verify_digest(k, require("distilled.crypto").digest(hash, message), signature, format)
end

function ecdsa.verify_digest(k, digest, signature, opts)
  check_key(k, "ecdsa.verify_digest")
  if type(digest) ~= "string" or type(signature) ~= "string" then
    compat.raise("ecdsa.verify_digest: digest and signature must be strings", 2)
  end
  local _, format = options(opts, "ecdsa.verify_digest")
  return verify_digest(k, digest, signature, format)
end

-- Q = r^-1 (s R - e G), R the point with x = r (+ n) and the recorded parity
function ecdsa.recover(curve, digest, signature, recovery_id)
  local C = curve_arg(curve, "ecdsa.recover")
  if type(digest) ~= "string" or type(signature) ~= "string" then
    compat.raise("ecdsa.recover: digest and signature must be strings", 2)
  end
  if recovery_id ~= 0 and recovery_id ~= 1 and recovery_id ~= 2 and recovery_id ~= 3 then
    compat.raise("ecdsa.recover: recovery_id must be 0, 1, 2 or 3", 2)
  end
  local r, s = decode_signature(C, signature, "raw")
  if not r or not in_range(C, r) or not in_range(C, s) then
    return invalid("malformed signature")
  end
  local x = r
  if recovery_id >= 2 then
    x = bigint.add(r, C.n)
  end
  local R = lift_x(C, x, recovery_id % 2 == 1)
  if not R then
    return invalid("the signature does not recover a point")
  end
  local N = C.N
  local e = reduce_n(C, bits2int(C, digest))
  local ri = N:inv(N:to(r))
  local u1 = N:from(N:mul(N:neg(N:to(e)), ri))
  local u2 = N:from(N:mul(N:to(s), ri))
  local Q = double_mul(C, u1, u2, table_of(C, R))
  if is_infinity(C, Q) then
    return invalid("the signature recovers the point at infinity")
  end
  return make_public(C, Q)
end

---------------------------------------------------------------------------------------
-- signature encodings
---------------------------------------------------------------------------------------

-- DER SEQUENCE { r INTEGER, s INTEGER } -> r || s with each padded to size bytes
function ecdsa.der_to_raw(der, size)
  size = size or 32
  local seq = asn1.read_all(der)
  local items = seq and seq.tag == asn1.SEQUENCE and asn1.items(seq.value)
  if not items or #items ~= 2 then
    return invalid("malformed DER signature")
  end
  local r, s = asn1.integer(items[1]), asn1.integer(items[2])
  local rb = r and bigint.to_bytes(r, size)
  local sb = s and bigint.to_bytes(s, size)
  if not rb or not sb then
    return invalid("malformed DER signature")
  end
  return rb .. sb
end

function ecdsa.raw_to_der(raw)
  if type(raw) ~= "string" or #raw == 0 or #raw % 2 == 1 then
    compat.raise("ecdsa.raw_to_der: expected r || s", 2)
  end
  local half = #raw / 2
  return asn1.sequence(
    asn1.encode_integer(bigint.from_bytes(raw:sub(1, half))),
    asn1.encode_integer(bigint.from_bytes(raw:sub(half + 1)))
  )
end

return ecdsa
