-- JSON Web Tokens (RFC 7519) in the compact JWS serialisation.
--
--   jwt.encode{ key, alg?, header?, claims } -> token | nil, err
--       header: extra header fields after alg (a jws.object keeps their order); with no
--       header the header is {"alg":...,"typ":"JWT"} (GitHub Apps). claims: a
--       jws.object (order kept, as JSON.stringify of an object literal) or a table
--       (keys sorted).
--   jwt.decode(token) -> claims, header | nil, err          no signature check
--   jwt.verify(token, key [, opts]) -> claims, header | nil, err
--       checks the signature, then exp and nbf against opts.now (default os.time())
--       with opts.leeway seconds (default 0); opts.algorithms limits the alg values.
--
-- The tokens Distilled's packages mint, reproduced byte for byte (see
-- verify/features/crypto.md for each):
--
--   jwt.encode{ key = app_key, claims = jws.object("iss", app_id, "iat", iat,
--     "exp", iat + 600) }                                                GitHub App
--   jwt.encode{ key = sa_key, header = jws.object("typ", "JWT", "kid", key_id),
--     claims = jws.object("iss", email, "scope", scope, "aud", token_url,
--     "iat", now, "exp", now + 3600) }                                   GCP
--   jwt.encode{ key = cdp_key, header = jws.object("kid", id, "typ", "JWT",
--     "nonce", nonce), claims = jws.object("sub", id, "iss", "cdp",
--     "aud", { "cdp_service" }, "nbf", now, "exp", now + 120, "uri", uri) }  Coinbase
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local jws = require("distilled.crypto.jws")

local jwt = {}

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "JWT: " .. message })
end

function jwt.encode(args)
  if type(args) ~= "table" then
    compat.raise("jwt.encode: expected a table of arguments", 2)
  end
  if type(args.claims) ~= "table" then
    compat.raise("jwt.encode: claims must be a table or a jws.object", 2)
  end
  local protected, payload, signature = jws.sign_parts({
    key = args.key,
    alg = args.alg,
    header = args.header,
    payload = args.claims,
  }, "JWT", true)
  if not protected then
    return nil, payload
  end
  return protected .. "." .. payload .. "." .. signature
end

local function claims_of(parts)
  local claims = json.decode(parts.payload)
  if type(claims) ~= "table" or json.is_array(claims) then
    return invalid("the payload is not a JSON object")
  end
  return claims
end

function jwt.decode(token)
  local parts, err = jws.decode(token)
  if not parts then
    return nil, err
  end
  local claims, cerr = claims_of(parts)
  if not claims then
    return nil, cerr
  end
  return claims, parts.header
end

function jwt.verify(token, key, opts)
  if opts ~= nil and type(opts) ~= "table" then
    compat.raise("jwt.verify: opts must be a table", 2)
  end
  opts = opts or {}
  local header, payload = jws.verify(token, key, opts.algorithms)
  if not header then
    return nil, payload
  end
  local claims, cerr = claims_of({ payload = payload })
  if not claims then
    return nil, cerr
  end
  local now = opts.now or os.time()
  local leeway = opts.leeway or 0
  if type(claims.exp) == "number" and now > claims.exp + leeway then
    return invalid("the token has expired")
  end
  if type(claims.nbf) == "number" and now + leeway < claims.nbf then
    return invalid("the token is not valid yet")
  end
  return claims, header
end

return jwt
