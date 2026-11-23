-- TC3-HMAC-SHA256, the Tencent Cloud API 3.0 request signature. Port of Distilled's
-- packages/tencentcloud/src/signer.ts (https://www.tencentcloud.com/document/api/213/33224):
--
--   CanonicalRequest = POST \n / \n "" \n CanonicalHeaders \n SignedHeaders \n hex(sha256(payload))
--   StringToSign     = TC3-HMAC-SHA256 \n <timestamp> \n <date>/<service>/tc3_request \n
--                      hex(sha256(CanonicalRequest))
--   SecretSigning    = HMAC(HMAC(HMAC("TC3" .. SecretKey, date), service), "tc3_request")
--   Signature        = hex(HMAC(SecretSigning, StringToSign))
--
--   local signer = require("distilled.tencentcloud.signer")
--   local s = signer.sign{ secret_id = "AKID...", secret_key = <string or secret>,
--                          service = "cvm", host = "cvm.tencentcloudapi.com",
--                          action = "DescribeInstances", timestamp = 1551113065,
--                          content_type = "application/json; charset=utf-8",
--                          payload = '{"Limit":1}',
--                          signed_headers = { "content-type", "host" } }  -- optional
--   -- s = { authorization, signature, canonical_request, string_to_sign, credential_scope }
--
-- `<date>` is the UTC date of the timestamp (never the local one: the documented pitfall
-- is 00:44 in UTC+8 being the previous day). Canonical headers are `name:value`, value
-- trimmed and lower-cased, sorted by name. Only ASCII is lower-cased (string.lower);
-- every signed value (the constant content type, the host, the action) is ASCII, where
-- JavaScript's toLowerCase agrees.
local compat = require("distilled.compat")
local crypto = require("distilled.crypto")
local secret = require("distilled.secret")

local floor = math.floor
local format = string.format

local signer = {}

signer.ALGORITHM = "TC3-HMAC-SHA256"

--- What the SDK signs, like Tencent's own SDKs (Distilled's DEFAULT_SIGNED_HEADERS).
signer.DEFAULT_SIGNED_HEADERS = { "content-type", "host", "x-tc-action" }

local SIGNABLE = { ["content-type"] = "content_type", host = "host", ["x-tc-action"] = "action" }

--- signer.utc_date(timestamp) -> "YYYY-MM-DD", the UTC date of a Unix time in seconds.
-- Without os.date (its "!" form is not portable to every runtime): H. Hinnant's
-- days-from-civil inverse, exact for any date after 1970.
function signer.utc_date(timestamp)
  local days = floor(floor(timestamp) / 86400)
  local z = days + 719468
  local era = floor(z / 146097)
  local doe = z - era * 146097
  local yoe = floor((doe - floor(doe / 1460) + floor(doe / 36524) - floor(doe / 146096)) / 365)
  local doy = doe - (365 * yoe + floor(yoe / 4) - floor(yoe / 100))
  local mp = floor((5 * doy + 2) / 153)
  local d = doy - floor((153 * mp + 2) / 5) + 1
  local m = mp < 10 and mp + 3 or mp - 9
  local y = yoe + era * 400 + (m <= 2 and 1 or 0)
  return format("%04d-%02d-%02d", y, m, d)
end

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

local function sha256_hex(data)
  return crypto.hex.encode(crypto.sha256(data))
end

local function need_string(args, key)
  if type(args[key]) ~= "string" then
    compat.raise("tencentcloud.signer.sign: " .. key .. " must be a string", 3)
  end
end

--- signer.sign(args) -> { authorization, signature, canonical_request, string_to_sign,
--   credential_scope }. Raises only on misuse (a missing or mistyped argument).
function signer.sign(args)
  if type(args) ~= "table" then
    compat.raise("tencentcloud.signer.sign: expected a table", 2)
  end
  for _, key in ipairs({ "secret_id", "service", "host", "action", "content_type", "payload" }) do
    need_string(args, key)
  end
  if type(args.secret_key) ~= "string" and not secret.is(args.secret_key) then
    compat.raise("tencentcloud.signer.sign: secret_key must be a string or a secret", 2)
  end
  local timestamp = args.timestamp
  if type(timestamp) ~= "number" or timestamp ~= timestamp or timestamp < 0 then
    compat.raise("tencentcloud.signer.sign: timestamp must be Unix seconds", 2)
  end
  timestamp = floor(timestamp)

  -- the signed header names: deduplicated, sorted (Distilled: [...new Set(names)].sort())
  local seen, names = {}, {}
  for _, name in ipairs(args.signed_headers or signer.DEFAULT_SIGNED_HEADERS) do
    if SIGNABLE[name] == nil then
      compat.raise("tencentcloud.signer.sign: cannot sign header " .. tostring(name), 2)
    end
    if not seen[name] then
      seen[name] = true
      names[#names + 1] = name
    end
  end
  table.sort(names)
  local canonical_headers = {}
  for i, name in ipairs(names) do
    canonical_headers[i] = name .. ":" .. string.lower(trim(args[SIGNABLE[name]])) .. "\n"
  end
  local signed_headers = table.concat(names, ";")

  local canonical_request = table.concat({
    "POST",
    "/",
    "",
    table.concat(canonical_headers),
    signed_headers,
    sha256_hex(args.payload),
  }, "\n")

  local ts = format("%d", timestamp)
  local date = signer.utc_date(timestamp)
  local credential_scope = date .. "/" .. args.service .. "/tc3_request"
  local string_to_sign = table.concat({
    signer.ALGORITHM,
    ts,
    credential_scope,
    sha256_hex(canonical_request),
  }, "\n")

  -- the key is unwrapped only here, into locals that never leave this function
  local secret_date = crypto.hmac_sha256("TC3" .. secret.unwrap(args.secret_key), date)
  local secret_service = crypto.hmac_sha256(secret_date, args.service)
  local secret_signing = crypto.hmac_sha256(secret_service, "tc3_request")
  local signature = crypto.hex.encode(crypto.hmac_sha256(secret_signing, string_to_sign))

  return {
    authorization = signer.ALGORITHM
      .. " Credential="
      .. args.secret_id
      .. "/"
      .. credential_scope
      .. ", SignedHeaders="
      .. signed_headers
      .. ", Signature="
      .. signature,
    signature = signature,
    canonical_request = canonical_request,
    string_to_sign = string_to_sign,
    credential_scope = credential_scope,
  }
end

return signer
