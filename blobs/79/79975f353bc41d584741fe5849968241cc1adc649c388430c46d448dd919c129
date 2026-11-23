-- Polymarket CLOB and Combos RFQ: the credential groups and the request signing
-- (packages/polymarket/src/credentials.ts, protocol.ts, signing.ts).
--
-- L2 (Distilled's l2Signed / withL2Headers): with the CLOB group set, every request
-- carries
--   POLY_ADDRESS     the configured address, as given
--   POLY_SIGNATURE   base64url, WITH padding, of HMAC-SHA256(key, timestamp .. METHOD ..
--                    path .. body); key = the secret read as base64 (decodeSecret:
--                    -_ -> +/, other characters dropped, padding restored); path = the
--                    URL below the base URL without query or fragment, with a leading /;
--                    body = the exact body text, nothing when empty
--   POLY_TIMESTAMP   floor(host.epoch()) in seconds
--   POLY_API_KEY, POLY_PASSPHRASE
-- Without the CLOB group the request goes out unsigned (public endpoints accept it).
--
-- L1 (not in Distilled; Polymarket's clob-client createL1Headers): with l1_private_key
-- set, CreateApiKey and DeriveApiKey carry instead
--   POLY_ADDRESS     the EIP-55 address of the key
--   POLY_SIGNATURE   0x .. r .. s .. v (v = 27 + recovery id, low s) of the EIP-712
--                    digest of ClobAuth{ address, timestamp (string), nonce (uint256),
--                    message } in the domain { name "ClobAuthDomain", version "1",
--                    chainId } (ethers' _signTypedData; RFC 6979, so byte-exact)
--   POLY_TIMESTAMP, POLY_NONCE (l1_nonce, default 0)
--
-- Parsed L1 keys are cached by the SHA-256 of the key text (at most 16 entries).
local crypto = require("distilled.crypto")
local errors = require("distilled.errors")
local secret = require("distilled.secret")

local glue = {}
-- helpers that are not hooks (the generator accepts only hook names as fields):
-- reachable as glue.sign_l2 / glue.l1_headers through the metatable, for callers and specs
local helpers = {}
setmetatable(glue, { __index = helpers })

---------------------------------------------------------------------------------------
-- credential groups (the same as glue/polymarket.lua)
---------------------------------------------------------------------------------------

local GROUPS = {
  {
    label = "CLOB",
    { "clob_address", "POLY_ADDRESS" },
    { "clob_api_key", "CLOB_API_KEY" },
    { "clob_secret", "CLOB_SECRET" },
    { "clob_passphrase", "CLOB_PASS_PHRASE" },
  },
  {
    label = "relayer",
    { "relayer_address", "RELAYER_API_KEY_ADDRESS" },
    { "relayer_api_key", "RELAYER_API_KEY" },
  },
  {
    label = "Perps",
    { "perps_proxy", "POLYMARKET_PROXY" },
    { "perps_secret", "POLYMARKET_SECRET" },
  },
}

local function present(v)
  if v == nil then
    return false
  end
  local plain = secret.unwrap(v)
  return plain ~= nil and plain ~= ""
end

local function plain(v)
  return tostring(secret.unwrap(v))
end

function glue.settings(s)
  for _, group in ipairs(GROUPS) do
    local missing = {}
    for _, entry in ipairs(group) do
      if not present(s[entry[1]]) then
        missing[#missing + 1] = entry[2]
      end
    end
    if #missing > 0 and #missing < #group then
      return nil,
        errors.new("ConfigError", {
          message = "Polymarket "
            .. group.label
            .. " credentials are incomplete: set "
            .. table.concat(missing, ", "),
          key = missing[1],
        })
    end
  end
  return s
end

---------------------------------------------------------------------------------------
-- L2: HMAC-SHA256
---------------------------------------------------------------------------------------

-- decodeSecret: base64url read as base64, characters outside the alphabet dropped,
-- missing padding restored
local function decode_secret(text)
  local stripped = string.gsub(string.gsub(string.gsub(text, "%-", "+"), "_", "/"), "[^%w+/]", "")
  local padded = stripped .. string.rep("=", (4 - #stripped % 4) % 4)
  local key = crypto.base64.decode(padded)
  if key == nil then
    return nil,
      errors.new("ConfigError", {
        message = "The Polymarket CLOB secret is not base64",
        key = "clob_secret",
      })
  end
  return key
end

--- glue.sign_l2{ secret, timestamp, method, request_path, body? } -> POLY_SIGNATURE | nil, err
-- (Distilled's signL2)
function helpers.sign_l2(args)
  local key, err = decode_secret(plain(args.secret))
  if not key then
    return nil, err
  end
  local message = tostring(args.timestamp) .. args.method .. args.request_path .. (args.body or "")
  return crypto.base64.url_encode(crypto.hmac_sha256(key, message), true)
end

-- routePath: the URL below the base URL, no query or fragment, with a leading "/"
local function route_path(target, base)
  base = string.gsub(base or "", "/+$", "")
  local below = target
  if string.sub(target, 1, #base) == base then
    below = string.sub(target, #base + 1)
  end
  local path = string.match(below, "^[^?#]*")
  if string.sub(path, 1, 1) ~= "/" then
    path = "/" .. path
  end
  return path
end

---------------------------------------------------------------------------------------
-- L1: EIP-712 ClobAuth, secp256k1
---------------------------------------------------------------------------------------

local MSG_TO_SIGN = "This message attests that I control the given wallet"
local L1_OPERATIONS = { CreateApiKey = true, DeriveApiKey = true }

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

-- a non-negative decimal integer (number or digit string) as 32 big-endian bytes
local function uint256(v, what)
  local digits
  if type(v) == "number" then
    if v < 0 or v ~= math.floor(v) or v >= 2 ^ 53 then
      return nil
    end
    digits = string.format("%.0f", v)
  else
    digits = tostring(v)
  end
  if not string.find(digits, "^%d+$") then
    return nil, config_error("Polymarket " .. what .. " must be a non-negative integer", nil)
  end
  local bytes = {}
  -- long division by 256 of the decimal digit string
  while digits ~= "0" and digits ~= "" do
    local q, r = {}, 0
    for i = 1, #digits do
      local cur = r * 10 + (string.byte(digits, i) - 48)
      local d = math.floor(cur / 256)
      r = cur - d * 256
      if #q > 0 or d > 0 then
        q[#q + 1] = string.char(48 + d % 10)
        -- d < 10 always: cur < 2560
      end
    end
    bytes[#bytes + 1] = string.char(r)
    digits = #q > 0 and table.concat(q) or "0"
  end
  if #bytes > 32 then
    return nil, config_error("Polymarket " .. what .. " is larger than 2^256", nil)
  end
  local out = {}
  for i = #bytes, 1, -1 do
    out[#out + 1] = bytes[i]
  end
  return string.rep("\0", 32 - #bytes) .. table.concat(out)
end

local keccak = crypto.keccak256

local function hex(bytes)
  return crypto.hex.encode(bytes)
end

-- EIP-55: the address's hex digits, upper case where keccak(lower hex) has a nibble >= 8
local function checksum_address(raw20)
  local lower = hex(raw20)
  local h = hex(keccak(lower))
  local out = {}
  for i = 1, #lower do
    local c = string.sub(lower, i, i)
    if tonumber(string.sub(h, i, i), 16) >= 8 then
      c = string.upper(c)
    end
    out[i] = c
  end
  return "0x" .. table.concat(out)
end

local DOMAIN_TYPE = keccak("EIP712Domain(string name,string version,uint256 chainId)")
local CLOB_AUTH_TYPE =
  keccak("ClobAuth(address address,string timestamp,uint256 nonce,string message)")

-- the EIP-712 digest of ClobAuth (hashStruct per EIP-712; strings hash as keccak256)
local function clob_auth_digest(address20, timestamp, nonce32, chain32)
  local domain = keccak(DOMAIN_TYPE .. keccak("ClobAuthDomain") .. keccak("1") .. chain32)
  local struct = keccak(
    CLOB_AUTH_TYPE
      .. string.rep("\0", 12)
      .. address20
      .. keccak(timestamp)
      .. nonce32
      .. keccak(MSG_TO_SIGN)
  )
  return keccak("\25\1" .. domain .. struct)
end

local l1_cache, l1_cache_size = {}, 0

-- the wallet key: 32 bytes of hex, with or without 0x -> { key, address20, address }
local function wallet(text)
  local id = crypto.sha256(text)
  local hit = l1_cache[id]
  if hit then
    return hit
  end
  local h = string.gsub(text, "^0[xX]", "")
  local raw = #h == 64 and crypto.hex.decode(h) or nil
  if raw == nil then
    return nil,
      config_error("The Polymarket L1 private key must be 32 bytes of hex", "l1_private_key")
  end
  local key = require("distilled.crypto.ecdsa").private_key("secp256k1", raw)
  if not key then
    return nil, config_error("The Polymarket L1 private key is out of range", "l1_private_key")
  end
  local address20 = string.sub(keccak(key.x .. key.y), 13)
  local w = { key = key, address20 = address20, address = checksum_address(address20) }
  if l1_cache_size >= 16 then
    l1_cache, l1_cache_size = {}, 0
  end
  l1_cache[id] = w
  l1_cache_size = l1_cache_size + 1
  return w
end

--- glue.l1_headers{ private_key, chain_id, nonce, timestamp } -> headers | nil, err
-- (clob-client createL1Headers)
function helpers.l1_headers(args)
  local w, err = wallet(plain(args.private_key))
  if not w then
    return nil, err
  end
  local chain, cerr = uint256(args.chain_id, "chain_id")
  if not chain then
    return nil, cerr or config_error("Polymarket chain_id must be a non-negative integer")
  end
  local nonce, nerr = uint256(args.nonce, "l1_nonce")
  if not nonce then
    return nil, nerr or config_error("Polymarket l1_nonce must be a non-negative integer")
  end
  local ts = tostring(args.timestamp)
  local digest = clob_auth_digest(w.address20, ts, nonce, chain)
  local ecdsa = require("distilled.crypto.ecdsa")
  local sig, recid = ecdsa.sign_digest(w.key, digest, { low_s = true })
  if not sig then
    return nil, recid
  end
  return {
    poly_address = w.address,
    poly_signature = "0x" .. hex(sig) .. string.format("%02x", 27 + recid),
    poly_timestamp = ts,
    poly_nonce = tostring(args.nonce),
  }
end

---------------------------------------------------------------------------------------
-- the hook
---------------------------------------------------------------------------------------

function glue.sign(req, s, info)
  local host = info.host or {}
  local timestamp = math.floor((host.epoch or os.time)())
  local headers = req.headers
  if L1_OPERATIONS[info.op and info.op.name] and present(s.l1_private_key) then
    local l1, err = helpers.l1_headers({
      private_key = s.l1_private_key,
      chain_id = s.chain_id or "137",
      nonce = s.l1_nonce or "0",
      timestamp = timestamp,
    })
    if not l1 then
      return nil, err
    end
    for k, v in pairs(l1) do
      headers[k] = v
    end
    return req
  end
  if not present(s.clob_api_key) then
    return req -- no CLOB credentials: unsigned (the groups are all or nothing)
  end
  local body = req.body
  if body == "" then
    body = nil
  end
  local signature, err = helpers.sign_l2({
    secret = s.clob_secret,
    timestamp = timestamp,
    method = req.method,
    request_path = route_path(req.url, info.base_url),
    body = body,
  })
  if not signature then
    return nil, err
  end
  headers["poly_address"] = plain(s.clob_address)
  headers["poly_signature"] = signature
  headers["poly_timestamp"] = tostring(timestamp)
  headers["poly_api_key"] = plain(s.clob_api_key)
  headers["poly_passphrase"] = plain(s.clob_passphrase)
  return req
end

return glue
