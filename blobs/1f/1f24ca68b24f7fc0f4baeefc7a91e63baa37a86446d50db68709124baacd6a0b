-- RSA signatures, PKCS #1 v1.5 (RFC 8017 section 8.2): RS256 / RS384 / RS512.
--
--   rsa.public_key{ n = bigint, e = bigint } -> key | nil, err
--   rsa.private_key{ n, e, d [, p, q, dp, dq, qi] } -> key | nil, err
--   rsa.sign(key, message [, hash]) -> signature | nil, err      hash: "sha256" (default),
--                                                                 "sha384", "sha512", "sha1"
--   rsa.verify(key, message, signature [, hash]) -> boolean
--
-- Keys usually come from distilled.crypto.pem or a JWK (distilled.crypto.jws). A private
-- key with its CRT parameters (every PKCS #1 file has them) signs with two half-size
-- exponentiations; without them it uses d directly (about 3x slower). Every signature is
-- checked with the public exponent before it is returned, so a wrong key or an
-- arithmetic fault cannot leak (the Bellcore attack) or produce a bad token.
--
-- Modulus size: 1024 to 4400 bits (bigint.MAX_LIMBS). Not constant time; see bigint.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local bigint = require("distilled.crypto.bigint")
local keys = require("distilled.crypto.key")

local rsa = {}

local function hexbytes(h)
  return (h:gsub("..", function(p)
    return string.char(tonumber(p, 16))
  end))
end

-- DER DigestInfo prefixes (RFC 8017 section 9.2, note 1)
local DIGEST_INFO = {
  sha1 = hexbytes("3021300906052b0e03021a05000414"),
  sha256 = hexbytes("3031300d060960864801650304020105000420"),
  sha384 = hexbytes("3041300d060960864801650304020205000430"),
  sha512 = hexbytes("3051300d060960864801650304020305000440"),
}

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "RSA: " .. message })
end

local function check_public(n, e)
  if type(n) ~= "table" or type(e) ~= "table" then
    compat.raise("rsa: n and e must be bigints", 3)
  end
  local bits = bigint.bits(n)
  if bits < 1024 then
    return nil, "the modulus is shorter than 1024 bits"
  end
  if bits > bigint.MAX_LIMBS * bigint.LIMB_BITS then
    return nil, "the modulus is longer than " .. bigint.MAX_LIMBS * bigint.LIMB_BITS .. " bits"
  end
  if not bigint.is_odd(n) then
    return nil, "the modulus is even"
  end
  if bigint.cmp(e, { 3 }) < 0 or not bigint.is_odd(e) or bigint.cmp(e, n) >= 0 then
    return nil, "bad public exponent"
  end
  return bits
end

function rsa.public_key(fields)
  if type(fields) ~= "table" then
    compat.raise("rsa.public_key: expected a table", 2)
  end
  local bits, problem = check_public(fields.n, fields.e)
  if not bits then
    return invalid(problem)
  end
  return keys.new("rsa", { n = fields.n, e = fields.e, bits = bits })
end

function rsa.private_key(fields)
  if type(fields) ~= "table" then
    compat.raise("rsa.private_key: expected a table", 2)
  end
  local n, e, d = fields.n, fields.e, fields.d
  local bits, problem = check_public(n, e)
  if not bits then
    return invalid(problem)
  end
  if type(d) ~= "table" or bigint.is_zero(d) or bigint.cmp(d, n) >= 0 then
    return invalid("bad private exponent")
  end
  local private = { d = d }
  local p, q = fields.p, fields.q
  if p and q and fields.dp and fields.dq and fields.qi then
    if bigint.cmp(bigint.mul(p, q), n) ~= 0 or not bigint.is_odd(p) or not bigint.is_odd(q) then
      return invalid("the primes do not multiply to the modulus")
    end
    if bigint.cmp(fields.dp, p) >= 0 or bigint.cmp(fields.dq, q) >= 0 then
      return invalid("bad CRT exponent")
    end
    if bigint.cmp(fields.qi, p) >= 0 then
      return invalid("bad CRT coefficient")
    end
    private.p, private.q = p, q
    private.dp, private.dq, private.qi = fields.dp, fields.dq, fields.qi
  end
  return keys.new("rsa", { n = n, e = e, bits = bits }, private)
end

-- Montgomery contexts are cached on the key (keys are long-lived)
local function ctx_of(holder, field, modulus)
  local ctx = holder[field]
  if not ctx then
    ctx = bigint.mont(modulus)
    holder[field] = ctx
  end
  return ctx
end

local function public_op(key, s)
  local ctx = ctx_of(keys.cache(key), "ctx_n", key.n)
  return ctx:from(ctx:pow(ctx:to(s), key.e))
end

-- EMSA-PKCS1-v1_5: 00 01 FF..FF 00 DigestInfo H
local function encode(digest, hash, k)
  local t = DIGEST_INFO[hash] .. digest
  if k < #t + 11 then
    return nil
  end
  return "\0\1" .. string.rep("\255", k - #t - 3) .. "\0" .. t
end

local function hash_of(name, fname)
  name = name or "sha256"
  if not DIGEST_INFO[name] then
    compat.raise(fname .. ": unsupported hash " .. tostring(name), 3)
  end
  return name
end

function rsa.sign(key, message, hash)
  if not keys.is(key) or key.kind ~= "rsa" then
    compat.raise("rsa.sign: expected an RSA key", 2)
  end
  if type(message) ~= "string" then
    compat.raise("rsa.sign: message must be a string", 2)
  end
  hash = hash_of(hash, "rsa.sign")
  local private = keys.private(key)
  if not private then
    return invalid("signing needs a private key")
  end
  local k = math.floor((key.bits + 7) / 8)
  local em = encode(require("distilled.crypto").digest(hash, message), hash, k)
  if not em then
    return invalid("the modulus is too short for " .. hash)
  end
  local m = bigint.from_bytes(em)
  local s
  if private.p then
    -- CRT (RFC 8017 section 5.1.2, 2.b): two exponentiations modulo p and q
    local cp = ctx_of(private, "ctx_p", private.p)
    local cq = ctx_of(private, "ctx_q", private.q)
    local m1 = cp:from(cp:pow(cp:to(m), private.dp))
    local m2 = cq:from(cq:pow(cq:to(m), private.dq))
    -- h = qi * (m1 - m2) mod p
    local diff = cp:sub(m1, cp:mod(m2))
    local h = cp:from(cp:mul(cp:to(diff), cp:to(private.qi)))
    s = bigint.add(m2, bigint.mul(h, private.q))
  else
    local cn = ctx_of(private, "ctx_n", key.n)
    s = cn:from(cn:pow(cn:to(m), private.d))
  end
  if bigint.cmp(public_op(key, s), m) ~= 0 then
    return invalid("the private key does not match its public key")
  end
  return bigint.to_bytes(s, k)
end

function rsa.verify(key, message, signature, hash)
  if not keys.is(key) or key.kind ~= "rsa" then
    compat.raise("rsa.verify: expected an RSA key", 2)
  end
  if type(message) ~= "string" or type(signature) ~= "string" then
    compat.raise("rsa.verify: message and signature must be strings", 2)
  end
  hash = hash_of(hash, "rsa.verify")
  local k = math.floor((key.bits + 7) / 8)
  if #signature ~= k then
    return false
  end
  local s = bigint.from_bytes(signature)
  if bigint.cmp(s, key.n) >= 0 then
    return false
  end
  local em = encode(require("distilled.crypto").digest(hash, message), hash, k)
  if not em then
    return false
  end
  return bigint.to_bytes(public_op(key, s), k) == em
end

return rsa
