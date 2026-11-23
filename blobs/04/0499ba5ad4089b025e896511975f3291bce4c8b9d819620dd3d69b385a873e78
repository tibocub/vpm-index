-- JSON Web Signatures (RFC 7515) and keys (RFC 7517/7638/8037): what JWT bearer tokens,
-- ACME requests and DPoP proofs are made of.
--
--   jws.object(k1, v1, k2, v2, ...) -> ordered JSON object (nil values are left out,
--       like JSON.stringify drops undefined); jws.json(value) -> text | nil, err
--   jws.compact{ key, alg?, header?, payload } -> "h.p.s" | nil, err
--   jws.flattened{ key, alg?, header?, payload? } -> { protected, payload, signature }
--       header: extra header fields, an ordered object (or a plain table, sorted);
--       the encoded header is alg followed by them, as every Distilled package writes
--       it. payload: bytes (a string) or a table encoded as JSON; flattened with no
--       payload is ACME's POST-as-GET (empty payload).
--   jws.decode(token) -> { header, payload, signing_input, signature } | nil, err
--   jws.verify(token, key [, algorithms]) -> header, payload | nil, err
--   jws.sign_bytes(alg, key, input) / jws.verify_bytes(alg, key, input, signature)
--   jws.algorithm(key) -> "RS256" | "ES256" | "ES256K" | "EdDSA"
--   jws.public_jwk(key) -> ordered object in RFC 7638 member order
--   jws.jwk(key [, { private = true }]) -> ordered object
--   jws.thumbprint(key) -> base64url SHA-256 of the canonical public JWK (RFC 7638)
--   jws.key_from_jwk(jwk) -> key | nil, err     (a table, JSON text, or a secret of either)
--   jws.b64(bytes) / jws.b64_decode(text)       base64url without padding
--
-- Algorithms: RS256/RS384/RS512 (RSA PKCS #1 v1.5), ES256 (P-256), ES256K (secp256k1),
-- EdDSA (Ed25519), HS256/HS384/HS512 (the key is the raw secret: a string or a
-- distilled.secret). `key` may also be PEM text or a secret holding it; it is parsed with
-- distilled.crypto.pem on every call, so parse once and pass the key object instead.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")
local keys = require("distilled.crypto.key")
local bigint = require("distilled.crypto.bigint")
local base64 = require("distilled.crypto.base64")

local jws = {}

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "JWS: " .. message })
end

function jws.b64(bytes)
  return base64.url_encode(bytes, false)
end

function jws.b64_decode(text)
  return base64.url_decode(text)
end

---------------------------------------------------------------------------------------
-- ordered JSON
---------------------------------------------------------------------------------------

local ORDERED_MT = { __jsontype = "object" }

function jws.object(...)
  local names, values = {}, {}
  local n = select("#", ...)
  if n % 2 == 1 then
    compat.raise("jws.object: expected name, value pairs", 2)
  end
  local args = { ... }
  for i = 1, n, 2 do
    local name, value = args[i], args[i + 1]
    if type(name) ~= "string" then
      compat.raise("jws.object: member names must be strings", 2)
    end
    if value ~= nil then
      names[#names + 1] = name
      values[#values + 1] = value
    end
  end
  return setmetatable({ names = names, values = values }, ORDERED_MT)
end

function jws.is_object(v)
  return type(v) == "table" and getmetatable(v) == ORDERED_MT
end

-- value of member `name` of an ordered object
function jws.get(obj, name)
  for i, n in ipairs(obj.names) do
    if n == name then
      return obj.values[i]
    end
  end
  return nil
end

local MAX_DEPTH = 32

local function is_sequence(t)
  if json.is_array(t) then
    return true
  end
  if json.is_object(t) then
    return false
  end
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" then
      return false
    end
    n = n + 1
  end
  return n > 0 and n == #t
end

-- bounded recursion: JOSE headers and claims are a few levels deep at most
local function encode(value, depth, out)
  if depth > MAX_DEPTH then
    return nil, "nesting deeper than " .. MAX_DEPTH
  end
  if type(value) ~= "table" or value == json.null then
    local s, err = json.encode(value)
    if not s then
      return nil, err.message
    end
    out[#out + 1] = s
    return true
  end
  if secret.is(value) then
    return nil, "a secret; unwrap it first"
  end
  if jws.is_object(value) then
    out[#out + 1] = "{"
    for i, name in ipairs(value.names) do
      if i > 1 then
        out[#out + 1] = ","
      end
      out[#out + 1] = json.encode(name) .. ":"
      local ok, err = encode(value.values[i], depth + 1, out)
      if not ok then
        return nil, err
      end
    end
    out[#out + 1] = "}"
    return true
  end
  if is_sequence(value) then
    out[#out + 1] = "["
    for i = 1, #value do
      if i > 1 then
        out[#out + 1] = ","
      end
      local ok, err = encode(value[i], depth + 1, out)
      if not ok then
        return nil, err
      end
    end
    out[#out + 1] = "]"
    return true
  end
  local names = {}
  for k in pairs(value) do
    if type(k) ~= "string" then
      return nil, "a table key of type " .. type(k)
    end
    names[#names + 1] = k
  end
  table.sort(names)
  out[#out + 1] = "{"
  for i, name in ipairs(names) do
    if i > 1 then
      out[#out + 1] = ","
    end
    out[#out + 1] = json.encode(name) .. ":"
    local ok, err = encode(value[name], depth + 1, out)
    if not ok then
      return nil, err
    end
  end
  out[#out + 1] = "}"
  return true
end

function jws.json(value)
  local out = {}
  local ok, err = encode(value, 1, out)
  if not ok then
    return invalid("cannot encode " .. err)
  end
  return compat.concat(out)
end

---------------------------------------------------------------------------------------
-- algorithms
---------------------------------------------------------------------------------------

local HMAC_HASH = { HS256 = "sha256", HS384 = "sha384", HS512 = "sha512" }
local RSA_HASH = { RS256 = "sha256", RS384 = "sha384", RS512 = "sha512" }
local EC_CURVE = { ES256 = "P-256", ES256K = "secp256k1" }

function jws.algorithm(key)
  if key.kind == "rsa" then
    return "RS256"
  elseif key.kind == "ec" then
    return key.curve == "P-256" and "ES256" or "ES256K"
  elseif key.kind == "ed25519" then
    return "EdDSA"
  end
  return nil
end

local function key_arg(alg, key, private)
  if HMAC_HASH[alg] then
    local raw = secret.unwrap(key)
    if type(raw) ~= "string" then
      compat.raise("jws: " .. alg .. " needs the secret as a string or a distilled.secret", 4)
    end
    return raw
  end
  if keys.is(key) then
    return key
  end
  local raw = secret.unwrap(key)
  if type(raw) ~= "string" then
    compat.raise("jws: key must be a key object, PEM text or a secret", 4)
  end
  local pem = require("distilled.crypto.pem")
  if private then
    return pem.private_key(key)
  end
  local k, err = pem.public_key(key)
  if not k then
    local pk = pem.private_key(key)
    if pk then
      return keys.public(pk)
    end
  end
  return k, err
end

local function check_alg(alg, key)
  if RSA_HASH[alg] then
    return key.kind == "rsa"
  elseif EC_CURVE[alg] then
    return key.kind == "ec" and key.curve == EC_CURVE[alg]
  elseif alg == "EdDSA" then
    return key.kind == "ed25519"
  end
  return false
end

local function known(alg)
  return HMAC_HASH[alg] or RSA_HASH[alg] or EC_CURVE[alg] or alg == "EdDSA"
end

-- jws.sign_bytes(alg, key, input) -> signature | nil, err
function jws.sign_bytes(alg, key, input)
  if not known(alg) then
    compat.raise("jws.sign_bytes: unsupported algorithm " .. tostring(alg), 2)
  end
  if type(input) ~= "string" then
    compat.raise("jws.sign_bytes: input must be a string", 2)
  end
  local k, err = key_arg(alg, key, true)
  if not k then
    return nil, err
  end
  if HMAC_HASH[alg] then
    return require("distilled.crypto").hmac(HMAC_HASH[alg], k, input)
  end
  if not check_alg(alg, k) then
    return invalid(alg .. " needs a different key type than " .. tostring(k))
  end
  if RSA_HASH[alg] then
    return require("distilled.crypto.rsa").sign(k, input, RSA_HASH[alg])
  elseif EC_CURVE[alg] then
    local sig, serr = require("distilled.crypto.ecdsa").sign(k, input)
    return sig, sig == nil and serr or nil
  end
  return require("distilled.crypto.ed25519").sign(k, input)
end

-- jws.verify_bytes(alg, key, input, signature) -> boolean
function jws.verify_bytes(alg, key, input, signature)
  if not known(alg) then
    return false
  end
  local k = key_arg(alg, key, false)
  if not k then
    return false
  end
  if HMAC_HASH[alg] then
    local expected = require("distilled.crypto").hmac(HMAC_HASH[alg], k, input)
    return require("distilled.crypto").equal(expected, signature)
  end
  if not check_alg(alg, k) then
    return false
  end
  if RSA_HASH[alg] then
    return require("distilled.crypto.rsa").verify(k, input, signature, RSA_HASH[alg])
  elseif EC_CURVE[alg] then
    return require("distilled.crypto.ecdsa").verify(k, input, signature)
  end
  return require("distilled.crypto.ed25519").verify(k, input, signature)
end

---------------------------------------------------------------------------------------
-- serialisations
---------------------------------------------------------------------------------------

-- the protected header: alg, then the caller's fields in their order
local function header_of(alg, header, default_typ)
  local h = jws.object("alg", alg)
  if header == nil then
    if default_typ then
      h.names[2], h.values[2] = "typ", default_typ
    end
    return h
  end
  if type(header) ~= "table" then
    compat.raise("jws: header must be a table or a jws.object", 4)
  end
  if jws.is_object(header) then
    for i, name in ipairs(header.names) do
      if name == "alg" then
        compat.raise("jws: alg is set from the key or the alg argument, not the header", 4)
      end
      h.names[#h.names + 1] = name
      h.values[#h.values + 1] = header.values[i]
    end
    return h
  end
  local names = {}
  for name in pairs(header) do
    if name == "alg" then
      compat.raise("jws: alg is set from the key or the alg argument, not the header", 4)
    end
    names[#names + 1] = name
  end
  table.sort(names)
  for _, name in ipairs(names) do
    h.names[#h.names + 1] = name
    h.values[#h.values + 1] = header[name]
  end
  return h
end

local function payload_of(payload)
  if payload == nil then
    return ""
  end
  if type(payload) == "string" then
    return jws.b64(payload)
  end
  local text, err = jws.json(payload)
  if not text then
    return nil, err
  end
  return jws.b64(text)
end

local function resolve_alg(args, fname)
  if type(args) ~= "table" then
    compat.raise(fname .. ": expected a table of arguments", 3)
  end
  local alg = args.alg
  local key = args.key
  if key == nil then
    compat.raise(fname .. ": key is required", 3)
  end
  if alg == nil then
    if keys.is(key) then
      alg = jws.algorithm(key)
    else
      local pk, err = key_arg("RS256", key, true)
      if not pk then
        return nil, err
      end
      key = pk
      alg = jws.algorithm(pk)
    end
  elseif not known(alg) then
    compat.raise(fname .. ": unsupported algorithm " .. tostring(alg), 3)
  end
  return alg, key
end

-- shared by compact and flattened; returns protected, payload, signature
function jws.sign_parts(args, default_typ, require_payload)
  local alg, key = resolve_alg(args, "jws.sign")
  if not alg then
    return nil, key
  end
  if require_payload and args.payload == nil then
    compat.raise("jws.compact: payload is required", 3)
  end
  local header_text, herr = jws.json(header_of(alg, args.header, default_typ))
  if not header_text then
    return nil, herr
  end
  local protected = jws.b64(header_text)
  local payload, perr = payload_of(args.payload)
  if not payload then
    return nil, perr
  end
  local signature, serr = jws.sign_bytes(alg, key, protected .. "." .. payload)
  if not signature then
    return nil, serr
  end
  return protected, payload, jws.b64(signature)
end

function jws.compact(args)
  local protected, payload, signature = jws.sign_parts(args, nil, true)
  if not protected then
    return nil, payload
  end
  return protected .. "." .. payload .. "." .. signature
end

function jws.flattened(args)
  local protected, payload, signature = jws.sign_parts(args, nil, false)
  if not protected then
    return nil, payload
  end
  return { protected = protected, payload = payload, signature = signature }
end

function jws.decode(token)
  if type(token) ~= "string" then
    compat.raise("jws.decode: token must be a string", 2)
  end
  local h, p, s = token:match("^([%w_%-]*)%.([%w_%-]*)%.([%w_%-]*)$")
  if not h then
    return invalid("not a compact serialization (three base64url parts)")
  end
  local header_text = jws.b64_decode(h)
  local payload = jws.b64_decode(p)
  local signature = jws.b64_decode(s)
  if not header_text or not payload or not signature then
    return invalid("a part is not base64url")
  end
  local header = json.decode(header_text)
  if type(header) ~= "table" or json.is_array(header) or type(header.alg) ~= "string" then
    return invalid("the header is not a JSON object with alg")
  end
  return { header = header, payload = payload, signing_input = h .. "." .. p, signature = signature }
end

-- jws.verify(token, key [, algorithms]) -> header, payload | nil, err
-- algorithms: the list of acceptable alg values. Default: what the key object can verify;
-- for PEM text, the asymmetric algorithms. HS256/384/512 must always be listed.
function jws.verify(token, key, algorithms)
  local parts, err = jws.decode(token)
  if not parts then
    return nil, err
  end
  local alg = parts.header.alg
  local allowed
  if algorithms then
    for _, a in ipairs(algorithms) do
      if a == alg then
        allowed = true
      end
    end
  elseif keys.is(key) then
    allowed = check_alg(alg, key)
  else
    -- PEM text or a secret: never HMAC unless asked for, or a public key's PEM would
    -- verify an HS256 token keyed with that (public) text (algorithm confusion)
    allowed = known(alg) and not HMAC_HASH[alg]
  end
  if not allowed then
    return invalid("algorithm " .. tostring(alg) .. " is not accepted")
  end
  if not jws.verify_bytes(alg, key, parts.signing_input, parts.signature) then
    return invalid("signature verification failed")
  end
  return parts.header, parts.payload
end

---------------------------------------------------------------------------------------
-- JWK
---------------------------------------------------------------------------------------

local function b64int(x)
  return jws.b64(bigint.to_bytes(x))
end

local OKP_CURVE = "Ed25519"

function jws.public_jwk(key)
  if not keys.is(key) then
    compat.raise("jws.public_jwk: expected a key", 2)
  end
  if key.kind == "rsa" then
    return jws.object("e", b64int(key.e), "kty", "RSA", "n", b64int(key.n))
  elseif key.kind == "ec" then
    return jws.object("crv", key.curve, "kty", "EC", "x", jws.b64(key.x), "y", jws.b64(key.y))
  end
  return jws.object("crv", OKP_CURVE, "kty", "OKP", "x", jws.b64(key.public))
end

-- the order node:crypto's KeyObject.export({ format = "jwk" }) uses
function jws.jwk(key, opts)
  if not keys.is(key) then
    compat.raise("jws.jwk: expected a key", 2)
  end
  local private = opts and opts.private and keys.private(key)
  if opts and opts.private and not private then
    compat.raise("jws.jwk: a private JWK needs a private key", 2)
  end
  if key.kind == "rsa" then
    local obj = jws.object("kty", "RSA", "n", b64int(key.n), "e", b64int(key.e))
    if private then
      local names = { "d", "p", "q", "dp", "dq", "qi" }
      for _, name in ipairs(names) do
        if private[name] then
          obj.names[#obj.names + 1] = name
          obj.values[#obj.values + 1] = b64int(private[name])
        end
      end
    end
    return obj
  elseif key.kind == "ec" then
    return jws.object(
      "kty",
      "EC",
      "x",
      jws.b64(key.x),
      "y",
      jws.b64(key.y),
      "crv",
      key.curve,
      "d",
      private and jws.b64(bigint.to_bytes(private.d, 32)) or nil
    )
  end
  return jws.object(
    "crv",
    OKP_CURVE,
    "d",
    private and jws.b64(private.seed) or nil,
    "x",
    jws.b64(key.public),
    "kty",
    "OKP"
  )
end

function jws.thumbprint(key)
  local text = assert(jws.json(jws.public_jwk(key)))
  return jws.b64(require("distilled.crypto").sha256(text))
end

local function field(jwk, name, required)
  local v = jwk[name]
  if v == nil then
    if required then
      return nil, "missing " .. name
    end
    return false
  end
  if type(v) ~= "string" then
    return nil, name .. " is not a string"
  end
  local bytes = jws.b64_decode(v)
  if not bytes then
    return nil, name .. " is not base64url"
  end
  return bytes
end

function jws.key_from_jwk(jwk)
  jwk = secret.unwrap(jwk)
  if type(jwk) == "string" then
    local decoded = json.decode(jwk)
    if type(decoded) ~= "table" then
      return invalid("the key is not a JSON Web Key")
    end
    jwk = decoded
  end
  if type(jwk) ~= "table" then
    compat.raise("jws.key_from_jwk: expected a table, JSON text or a secret", 2)
  end
  local problem
  -- the decoded member, false when absent and optional, nil (and problem set) when bad
  local function get(name, required)
    local v, err = field(jwk, name, required)
    if v == nil then
      problem = problem or err
    end
    return v
  end
  if jwk.kty == "RSA" then
    local n, e, d = get("n", true), get("e", true), get("d")
    if problem then
      return invalid("bad JWK: " .. problem)
    end
    local f = { n = bigint.from_bytes(n), e = bigint.from_bytes(e) }
    if not d then
      return require("distilled.crypto.rsa").public_key(f)
    end
    f.d = bigint.from_bytes(d)
    for _, name in ipairs({ "p", "q", "dp", "dq", "qi" }) do
      local v = get(name)
      f[name] = v and bigint.from_bytes(v) or nil
    end
    if problem then
      return invalid("bad JWK: " .. problem)
    end
    return require("distilled.crypto.rsa").private_key(f)
  elseif jwk.kty == "EC" then
    local curve = jwk.crv
    if curve ~= "P-256" and curve ~= "secp256k1" then
      return invalid("unsupported EC curve " .. tostring(curve))
    end
    local x, y, d = get("x", true), get("y", true), get("d")
    if problem then
      return invalid("bad JWK: " .. problem)
    end
    if #x ~= 32 or #y ~= 32 then
      return invalid("EC coordinates must be 32 bytes")
    end
    local ecdsa = require("distilled.crypto.ecdsa")
    if d then
      return ecdsa.private_key(curve, d, "\4" .. x .. y)
    end
    return ecdsa.public_key(curve, "\4" .. x .. y)
  elseif jwk.kty == "OKP" then
    if jwk.crv ~= OKP_CURVE then
      return invalid("unsupported OKP curve " .. tostring(jwk.crv))
    end
    local x, d = get("x", true), get("d")
    if problem then
      return invalid("bad JWK: " .. problem)
    end
    local ed = require("distilled.crypto.ed25519")
    if d then
      local k, err = ed.private_key(d)
      if k and k.public ~= x then
        return invalid("the Ed25519 public key does not match the private key")
      end
      return k, err
    end
    return ed.public_key(x)
  end
  return invalid("unsupported key type " .. tostring(jwk.kty))
end

return jws
