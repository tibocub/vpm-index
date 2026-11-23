-- AWS Signature Version 2 (SimpleDB), a port of Distilled's packages/aws/src/sigv2.ts.
--
-- The signature goes into the form body, not a header: the body's pairs plus
-- AWSAccessKeyId, SignatureVersion=2, SignatureMethod=HmacSHA256, Timestamp (ISO 8601,
-- no fraction) and SecurityToken are RFC 3986 encoded and sorted, and
--   "<METHOD>\n<host>\n<path>\n<canonical pairs>"
-- is signed with HMAC-SHA256 under the secret key; `&Signature=<base64>` ends the body.
--
--   sigv2.sign{ request = { method, url, headers, body }, credentials, now_epoch }
--     -> { method, url, headers, body }
local crypto = require("distilled.crypto")
local secret = require("distilled.secret")
local compat = require("distilled.compat")

local sigv2 = {}

-- encodeURIComponent plus !'()*: everything but A-Z a-z 0-9 - _ . ~
local function rfc3986(s)
  return (
    string.gsub(s, "[^A-Za-z0-9%-_%.~]", function(c)
      return string.format("%%%02X", string.byte(c))
    end)
  )
end
sigv2.rfc3986 = rfc3986

local function decode(s)
  s = string.gsub(s, "+", " ")
  return (string.gsub(s, "%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

--- sigv2.timestamp(epoch) -> "2023-11-14T22:13:20Z"
function sigv2.timestamp(epoch)
  return os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(epoch))
end

function sigv2.sign(args)
  local req, creds = args.request, args.credentials
  local pairs_list = {}
  for part in string.gmatch(type(req.body) == "string" and req.body or "", "[^&]+") do
    local eq = string.find(part, "=", 1, true)
    if eq then
      pairs_list[#pairs_list + 1] =
        { decode(string.sub(part, 1, eq - 1)), decode(string.sub(part, eq + 1)) }
    else
      pairs_list[#pairs_list + 1] = { decode(part), "" }
    end
  end
  pairs_list[#pairs_list + 1] = { "AWSAccessKeyId", secret.unwrap(creds.access_key_id) }
  pairs_list[#pairs_list + 1] = { "SignatureVersion", "2" }
  pairs_list[#pairs_list + 1] = { "SignatureMethod", "HmacSHA256" }
  pairs_list[#pairs_list + 1] = { "Timestamp", sigv2.timestamp(args.now_epoch or os.time()) }
  local token = creds.session_token and secret.unwrap(creds.session_token)
  if token and token ~= "" then
    pairs_list[#pairs_list + 1] = { "SecurityToken", token }
  end
  local encoded = {}
  for i, kv in ipairs(pairs_list) do
    encoded[i] = { rfc3986(kv[1]), rfc3986(kv[2]) }
  end
  table.sort(encoded, function(a, b)
    if a[1] ~= b[1] then
      return a[1] < b[1]
    end
    return a[2] < b[2]
  end)
  local parts = {}
  for i, kv in ipairs(encoded) do
    parts[i] = kv[1] .. "=" .. kv[2]
  end
  local canonical = compat.concat(parts, "&")
  local host, path = string.match(req.url, "^%a+://([^/?#]*)([^?#]*)")
  if path == nil or path == "" then
    path = "/"
  end
  local to_sign = req.method .. "\n" .. tostring(host) .. "\n" .. path .. "\n" .. canonical
  local signature = crypto.base64.encode(crypto.hmac_sha256(creds.secret_access_key, to_sign))
  local headers = {}
  local has_type = false
  for k, v in pairs(req.headers or {}) do
    headers[k] = v
    if string.lower(k) == "content-type" then
      has_type = true
    end
  end
  if not has_type then
    headers["Content-Type"] = "application/x-www-form-urlencoded"
  end
  return {
    method = req.method,
    url = req.url,
    headers = headers,
    body = canonical .. "&Signature=" .. rfc3986(signature),
  }
end

return sigv2
