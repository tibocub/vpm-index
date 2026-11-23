-- AWS Signature Version 4 (SigV4): sign a request in headers or in the query string.
--
-- A port of Distilled's `@distilled.cloud/aws4signer` (packages/aws4signer/src/index.ts),
-- itself an Effect port of aws4fetch's AwsV4Signer (MIT, Michael Hart). It keeps
-- aws4fetch's canonicalisation byte for byte: header, path and query encoding, the
-- unsignable-header set, S3's UNSIGNED-PAYLOAD defaults, duplicate query keys on S3,
-- service and region guessed from the host. spec/sigv4_spec.lua checks every case
-- against requests signed by Distilled and aws4fetch (spec/golden/sigv4/vectors.lua).
--
--   sigv4.sign{ request, credentials, region?, service?, now_epoch | datetime,
--               sign_query?, all_headers?, hash_payload?, append_session_token?,
--               single_encode?, key_cache? } -> signed request | nil, err
--   sigv4.presign{ url, method?, headers?, credentials, region?, service?, expires_in?,
--                  now_epoch | datetime, ... } -> url | nil, err
--   sigv4.canonical_request{ same arguments as sign } -> string | nil, err
--   sigv4.signing_key(secret_access_key, date, region, service) -> binary key
--   sigv4.guess_service_region(url [, headers]) -> service, region   ("" when unknown)
--
-- docs/interfaces.md ("distilled.sigv4") has the full contract. The URL handling below
-- implements the part of the WHATWG URL parser and URLSearchParams that aws4fetch's
-- results depend on, for http and https URLs.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local secret = require("distilled.secret")
local url_codec = require("distilled.url")
local crypto = require("distilled.crypto")
local hex = require("distilled.crypto.hex")

local sigv4 = {}

local byte, char, find, format, gsub, lower, sub, upper =
  string.byte,
  string.char,
  string.find,
  string.format,
  string.gsub,
  string.lower,
  string.sub,
  string.upper
local floor = math.floor

local ALGORITHM = "AWS4-HMAC-SHA256"

-- Headers left out of the signature unless all_headers (aws4fetch's list).
local UNSIGNABLE = {
  ["authorization"] = true,
  ["content-type"] = true,
  ["content-length"] = true,
  ["user-agent"] = true,
  ["presigned-expires"] = true,
  ["expect"] = true,
  ["x-amzn-trace-id"] = true,
  ["range"] = true,
  ["connection"] = true,
}
sigv4.UNSIGNABLE_HEADERS = UNSIGNABLE

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "sigv4: " .. message })
end

---------------------------------------------------------------------------------------
-- percent-encoding sets (WHATWG URL) and UTF-8 repair
---------------------------------------------------------------------------------------

-- escape table for bytes in `set` (plus every C0 control and byte above 0x7E)
local function escape_set(chars)
  local t = {}
  for b = 0, 255 do
    local c = char(b)
    if b < 0x20 or b > 0x7e or find(chars, c, 1, true) then
      t[c] = format("%%%02X", b)
    else
      t[c] = c
    end
  end
  return t
end

local PATH_SET = escape_set(' "#<>?^`{}')
local QUERY_SET = escape_set(" \"#<>'") -- the special-query set (http and https)
local FRAGMENT_SET = escape_set(' "<>`')
local USERINFO_SET = escape_set(' "#<>?^`{}/:;=@[\\]|')

local REPLACEMENT = "\239\191\189" -- U+FFFD

-- The bytes of s with every ill-formed UTF-8 sequence replaced by U+FFFD, one per
-- maximal subpart, as the WHATWG UTF-8 decoder does (TextDecoder, URLSearchParams).
local function utf8_repair(s)
  if not find(s, "[\128-\255]") then
    return s
  end
  local out, n = {}, 0
  local i, len = 1, #s
  while i <= len do
    local b = byte(s, i)
    local need, lo, hi = 0, 0x80, 0xbf
    if b < 0x80 then
      need = -1
    elseif b >= 0xc2 and b <= 0xdf then
      need = 1
    elseif b >= 0xe0 and b <= 0xef then
      need = 2
      lo = b == 0xe0 and 0xa0 or 0x80
      hi = b == 0xed and 0x9f or 0xbf
    elseif b >= 0xf0 and b <= 0xf4 then
      need = 3
      lo = b == 0xf0 and 0x90 or 0x80
      hi = b == 0xf4 and 0x8f or 0xbf
    end
    if need == -1 then
      n = n + 1
      out[n] = char(b)
      i = i + 1
    elseif need == 0 then
      n = n + 1
      out[n] = REPLACEMENT
      i = i + 1
    else
      local j, ok = i + 1, true
      for k = 1, need do
        local c = byte(s, j)
        if not c or c < lo or c > hi then
          ok = false
          break
        end
        lo, hi = 0x80, 0xbf
        j = j + 1
        if k == need then
          break
        end
      end
      n = n + 1
      if ok then
        out[n] = sub(s, i, j - 1)
      else
        out[n] = REPLACEMENT -- the bytes consumed so far; the offending byte is re-read
      end
      i = j
    end
  end
  return compat.concat(out)
end

local function is_hex(c)
  return c and find(c, "^%x$") ~= nil
end

-- percent-decode; a "%" not followed by two hex digits stays as it is (URLSearchParams)
local function percent_decode_lenient(s)
  return (gsub(s, "%%(%x%x)", function(h)
    return char(tonumber(h, 16))
  end))
end

-- decodeURIComponent: nil when an escape is malformed or the bytes are not UTF-8
local function decode_uri_component(s)
  local i = 1
  while true do
    local at = find(s, "%", i, true)
    if not at then
      break
    end
    if not (is_hex(sub(s, at + 1, at + 1)) and is_hex(sub(s, at + 2, at + 2))) then
      return nil
    end
    i = at + 3
  end
  local decoded = percent_decode_lenient(s)
  if utf8_repair(decoded) ~= decoded then
    return nil
  end
  return decoded
end

-- encodeURIComponent, then the characters it leaves but RFC 3986 reserves: ! ' ( ) *
local RFC3986_EXTRA = { ["!"] = "%21", ["'"] = "%27", ["("] = "%28", [")"] = "%29", ["*"] = "%2A" }
local function encode_rfc3986(s)
  return (gsub(s, "[!'()*]", RFC3986_EXTRA))
end

---------------------------------------------------------------------------------------
-- URL parsing and serialisation (http and https only)
---------------------------------------------------------------------------------------

local DEFAULT_PORT = { http = "80", https = "443" }

-- The path of a special URL: "\" is "/", dot segments resolved, bytes escaped.
local function parse_path(raw)
  local segments = {}
  local function is_single_dot(seg)
    return seg == "." or lower(seg) == "%2e"
  end
  local function is_double_dot(seg)
    local l = lower(seg)
    return l == ".." or l == ".%2e" or l == "%2e." or l == "%2e%2e"
  end
  raw = gsub(raw, "\\", "/")
  -- the path always starts with "/", which is consumed before the first segment
  if sub(raw, 1, 1) == "/" then
    raw = sub(raw, 2)
  end
  local start = 1
  while true do
    local at = find(raw, "/", start, true)
    local seg = sub(raw, start, (at or 0) - 1)
    if not at then
      seg = sub(raw, start)
    end
    seg = gsub(seg, ".", PATH_SET)
    local last = at == nil
    if is_double_dot(seg) then
      segments[#segments] = nil
      if last then
        segments[#segments + 1] = ""
      end
    elseif is_single_dot(seg) then
      if last then
        segments[#segments + 1] = ""
      end
    else
      segments[#segments + 1] = seg
    end
    if last then
      break
    end
    start = at + 1
  end
  return "/" .. compat.concat(segments, "/")
end

-- parse_url(s) -> { scheme, userinfo, hostname, port, host, path, query, fragment } | nil
-- host is hostname[:port] with the default port left out; query and fragment are nil
-- when absent (a "?" with nothing after it is query "").
local function parse_url(s)
  if type(s) ~= "string" then
    return nil
  end
  s = gsub(s, "^[%z\1- ]+", "")
  s = gsub(s, "[%z\1- ]+$", "")
  s = gsub(s, "[\t\n\r]", "")
  local scheme, rest = string.match(s, "^([A-Za-z][A-Za-z0-9+.%-]*):(.*)$")
  if not scheme then
    return nil
  end
  scheme = lower(scheme)
  if not DEFAULT_PORT[scheme] then
    return nil
  end
  rest = gsub(rest, "^[/\\]*", "")
  local auth_end = find(rest, "[/\\?#]") or (#rest + 1)
  local authority, tail = sub(rest, 1, auth_end - 1), sub(rest, auth_end)
  local userinfo
  local at = string.match(authority, "^.*()@")
  if at then
    -- username and password are escaped separately; the first ":" separates them
    local raw = sub(authority, 1, at - 1)
    local colon_at = find(raw, ":", 1, true)
    if colon_at then
      userinfo = gsub(sub(raw, 1, colon_at - 1), ".", USERINFO_SET)
        .. ":"
        .. gsub(sub(raw, colon_at + 1), ".", USERINFO_SET)
    else
      userinfo = gsub(raw, ".", USERINFO_SET)
    end
    authority = sub(authority, at + 1)
  end
  local hostname, port = authority, nil
  local colon = string.match(authority, "^.*():")
  if colon and not find(authority, "]", colon, true) then
    hostname, port = sub(authority, 1, colon - 1), sub(authority, colon + 1)
    if not find(port, "^%d*$") then
      return nil
    end
    if port == "" then
      port = nil
    else
      local n = tonumber(port)
      if n > 65535 then
        return nil
      end
      port = tostring(floor(n))
      if port == DEFAULT_PORT[scheme] then
        port = nil
      end
    end
  end
  hostname = lower(hostname)
  if
    hostname == ""
    or find(hostname, "[%z\1- #%%/:<>%?@%[\\%]%^|]") and not find(hostname, "^%[[%x:.]+%]$")
  then
    return nil
  end
  local fragment
  local hash = find(tail, "#", 1, true)
  if hash then
    fragment = gsub(sub(tail, hash + 1), ".", FRAGMENT_SET)
    tail = sub(tail, 1, hash - 1)
  end
  local query
  local q = find(tail, "?", 1, true)
  if q then
    query = gsub(sub(tail, q + 1), ".", QUERY_SET)
    tail = sub(tail, 1, q - 1)
  end
  return {
    scheme = scheme,
    userinfo = userinfo,
    hostname = hostname,
    port = port,
    host = port and (hostname .. ":" .. port) or hostname,
    path = parse_path(tail),
    query = query,
    fragment = fragment,
  }
end

-- URLSearchParams: the query as an ordered list of { name, value } (decoded, UTF-8
-- repaired), and its serialisation (application/x-www-form-urlencoded).
local function parse_params(query)
  local params = {}
  if not query or query == "" then
    return params
  end
  for piece in string.gmatch(query, "[^&]+") do
    local eq = find(piece, "=", 1, true)
    local name, value = piece, ""
    if eq then
      name, value = sub(piece, 1, eq - 1), sub(piece, eq + 1)
    end
    name = utf8_repair(percent_decode_lenient((gsub(name, "+", " "))))
    value = utf8_repair(percent_decode_lenient((gsub(value, "+", " "))))
    params[#params + 1] = { name, value }
  end
  return params
end

local function serialize_params(params)
  local parts = {}
  for i, p in ipairs(params) do
    parts[i] = url_codec.encode_form(p[1]) .. "=" .. url_codec.encode_form(p[2])
  end
  return compat.concat(parts, "&")
end

-- URLSearchParams.set: replace the first pair named `name`, drop the others, or append
local function params_set(params, name, value)
  local found = false
  local i = 1
  while i <= #params do
    if params[i][1] == name then
      if found then
        table.remove(params, i)
      else
        params[i][2] = value
        found = true
        i = i + 1
      end
    else
      i = i + 1
    end
  end
  if not found then
    params[#params + 1] = { name, value }
  end
end

local function params_has(params, name)
  for _, p in ipairs(params) do
    if p[1] == name then
      return true
    end
  end
  return false
end

local function serialize_url(u, query)
  return u.scheme
    .. "://"
    .. (u.userinfo and (u.userinfo .. "@") or "")
    .. u.host
    .. u.path
    .. (query and ("?" .. query) or "")
    .. (u.fragment and ("#" .. u.fragment) or "")
end

---------------------------------------------------------------------------------------
-- headers
---------------------------------------------------------------------------------------

-- The request headers as `Headers` normalises them: lower-case names, values trimmed of
-- spaces and tabs, names that differ only in case joined with ", " (in sorted order of
-- the original names, since a Lua table has no insertion order).
local function header_record(input)
  local out = {}
  if input == nil then
    return out
  end
  if type(input) ~= "table" then
    return invalid("request.headers must be a table")
  end
  local names = {}
  for name in pairs(input) do
    if type(name) ~= "string" or not find(name, "^[!#$%%&'*+%-.%^_`|~0-9A-Za-z]+$") then
      return invalid("a header name is not an HTTP token")
    end
    names[#names + 1] = name
  end
  table.sort(names)
  for _, name in ipairs(names) do
    local value = input[name]
    if type(value) ~= "string" then
      return invalid("header " .. name .. " is not a string")
    end
    if find(value, "[%z\r\n]") then
      return invalid("header " .. name .. " has a NUL, CR or LF in its value")
    end
    value = gsub(gsub(value, "^[ \t]+", ""), "[ \t]+$", "")
    local key = lower(name)
    out[key] = out[key] and (out[key] .. ", " .. value) or value
  end
  return out
end

local function sorted_keys(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  return keys
end

---------------------------------------------------------------------------------------
-- time
---------------------------------------------------------------------------------------

-- "YYYYMMDDTHHMMSSZ" for a Unix time, without os.date (days-from-civil inverse,
-- H. Hinnant's algorithm; exact for any date after 1970).
local function amz_datetime(epoch)
  local secs = floor(epoch)
  local days = floor(secs / 86400)
  local rem = secs - days * 86400
  local z = days + 719468
  local era = floor(z / 146097)
  local doe = z - era * 146097
  local yoe = floor((doe - floor(doe / 1460) + floor(doe / 36524) - floor(doe / 146096)) / 365)
  local doy = doe - (365 * yoe + floor(yoe / 4) - floor(yoe / 100))
  local mp = floor((5 * doy + 2) / 153)
  local d = doy - floor((153 * mp + 2) / 5) + 1
  local m = mp < 10 and mp + 3 or mp - 9
  local y = yoe + era * 400 + (m <= 2 and 1 or 0)
  return format(
    "%04d%02d%02dT%02d%02d%02dZ",
    y,
    m,
    d,
    floor(rem / 3600),
    floor(rem % 3600 / 60),
    rem % 60
  )
end
sigv4.amz_datetime = amz_datetime

---------------------------------------------------------------------------------------
-- service and region from the host (aws4fetch's guess)
---------------------------------------------------------------------------------------

-- Hosts whose first label differs from the signing name.
local HOST_SERVICES = {
  appstream2 = "appstream",
  cloudhsmv2 = "cloudhsm",
  email = "ses",
  marketplace = "aws-marketplace",
  mobile = "AWSMobileHubService",
  pinpoint = "mobiletargeting",
  queue = "sqs",
  ["git-codecommit"] = "codecommit",
  ["mturk-requester-sandbox"] = "mturk-requester",
  ["personalize-runtime"] = "personalize",
}

local function ends_with(s, suffix)
  return #s >= #suffix and sub(s, -#suffix) == suffix
end

local function label_ok(l)
  return l ~= nil and #l >= 1 and #l <= 63
end

local function header_value(headers, name)
  if headers == nil then
    return nil
  end
  for k, v in pairs(headers) do
    if type(k) == "string" and lower(k) == name then
      return v
    end
  end
  return nil
end

-- guess(hostname, pathname, headers) -> service, region ("" when the host does not say)
local function guess(hostname, pathname, headers)
  if ends_with(hostname, ".on.aws") then
    local fn, region = string.match(hostname, "^([^.]+)%.lambda%-url%.([^.]+)%.on%.aws$")
    if label_ok(fn) and label_ok(region) then
      return "lambda", region
    end
    return "", ""
  end
  if ends_with(hostname, ".r2.cloudflarestorage.com") then
    return "s3", "auto"
  end
  if ends_with(hostname, ".backblazeb2.com") then
    local region = string.match(hostname, "^s3%.([^.]+)%.backblazeb2%.com$")
    local first, r2 = string.match(hostname, "^([^.]+)%.s3%.([^.]+)%.backblazeb2%.com$")
    if label_ok(region) then
      return "s3", region
    elseif label_ok(first) and label_ok(r2) then
      return "s3", r2
    end
    return "", ""
  end
  -- /([^.]{1,63})\.(?:([^.]{0,63})\.)?amazonaws\.com(?:\.cn)?$/ on the host without its
  -- first "dualstack.": the leftmost match takes the two labels before "amazonaws"
  local h = hostname
  local ds = find(h, "dualstack.", 1, true)
  if ds then
    h = sub(h, 1, ds - 1) .. sub(h, ds + 10)
  end
  local labels = {}
  for l in string.gmatch(h .. ".", "([^.]*)%.") do
    labels[#labels + 1] = l
  end
  local n = #labels
  local a
  if n >= 3 and labels[n - 1] == "amazonaws" and labels[n] == "com" then
    a = n - 1
  elseif
    n >= 4
    and labels[n - 2] == "amazonaws"
    and labels[n - 1] == "com"
    and labels[n] == "cn"
  then
    a = n - 2
  end
  local service, region = "", nil
  if a then
    if a >= 3 and label_ok(labels[a - 2]) and #labels[a - 1] <= 63 then
      service, region = labels[a - 2], labels[a - 1]
    elseif label_ok(labels[a - 1]) then
      service = labels[a - 1]
    end
  end
  if region == "us-gov" then
    region = "us-gov-west-1"
  elseif region == "s3" or region == "s3-accelerate" then
    region, service = "us-east-1", "s3"
  elseif service == "iot" then
    if sub(hostname, 1, 4) == "iot." then
      service = "execute-api"
    elseif sub(hostname, 1, 14) == "data.jobs.iot." then
      service = "iot-jobs-data"
    else
      service = pathname == "/mqtt" and "iotdevicegateway" or "iotdata"
    end
  elseif service == "autoscaling" then
    local target = header_value(headers, "x-amz-target") or ""
    local prefix = string.match(target, "^[^.]*")
    if prefix == "AnyScaleFrontendService" then
      service = "application-autoscaling"
    elseif prefix == "AnyScaleScalingPlannerFrontendService" then
      service = "autoscaling-plans"
    end
  elseif region == nil and sub(service, 1, 3) == "s3-" then
    region = sub(service, 4)
    if sub(region, 1, 5) == "fips-" then
      region = sub(region, 6)
    elseif sub(region, 1, 10) == "external-1" then
      region = sub(region, 11)
    end
    service = "s3"
  elseif ends_with(service, "-fips") then
    service = sub(service, 1, -6)
  elseif region and region ~= "" and find(service, "%-%d$") and not find(region, "%-%d$") then
    -- not `service, region = region, service`: gopher-lua assigns a multiple assignment
    -- to locals one by one, so a swap reads the value it just wrote (STATUS.md, task 14)
    local swapped = service
    service = region
    region = swapped
  end
  return HOST_SERVICES[service] or service, region or ""
end

function sigv4.guess_service_region(url, headers)
  if type(url) ~= "string" then
    compat.raise("sigv4.guess_service_region: url must be a string", 2)
  end
  local u = parse_url(url)
  if not u then
    return "", ""
  end
  return guess(u.hostname, u.path, headers)
end

---------------------------------------------------------------------------------------
-- signing
---------------------------------------------------------------------------------------

local SIGN_ARGS = {
  request = "table",
  credentials = "table",
  region = "string",
  service = "string",
  now_epoch = "number",
  datetime = "string",
  sign_query = "boolean",
  all_headers = "boolean",
  hash_payload = "boolean",
  append_session_token = "boolean",
  single_encode = "boolean",
  key_cache = "table",
}

local function check_args(args, allowed, fname)
  if type(args) ~= "table" then
    compat.raise(fname .. ": expected a table of named arguments", 3)
  end
  for k, v in pairs(args) do
    local want = allowed[k]
    if not want then
      local names = sorted_keys(allowed)
      compat.raise(
        fname
          .. ": unknown argument "
          .. tostring(k)
          .. " (expected "
          .. table.concat(names, ", ")
          .. ")",
        3
      )
    end
    if type(v) ~= want then
      compat.raise(fname .. ": " .. k .. " must be a " .. want .. ", got " .. type(v), 3)
    end
  end
  if args.now_epoch == nil and args.datetime == nil then
    compat.raise(fname .. ": now_epoch (or datetime) is required", 3)
  end
  if args.datetime ~= nil and not find(args.datetime, "^%d%d%d%d%d%d%d%dT%d%d%d%d%d%dZ$") then
    compat.raise(fname .. ": datetime must look like 20240115T120000Z", 3)
  end
  if args.now_epoch ~= nil and not (args.now_epoch >= 0 and args.now_epoch < 253402300800) then
    compat.raise(fname .. ": now_epoch must be a Unix time in seconds", 3)
  end
end

local function sha256_hex(s)
  return hex.encode(crypto.sha256(s))
end

--- sigv4.signing_key(secret_access_key, date, region, service) -> binary key
-- The HMAC chain over "AWS4" .. secret, the date (YYYYMMDD), region, service and
-- "aws4_request". Use it to sign something other than a request (an S3 POST policy:
-- hex(hmac_sha256(key, policy))). The secret may be a distilled.secret.
function sigv4.signing_key(secret_access_key, date, region, service)
  local key = secret.unwrap(secret_access_key)
  if type(key) ~= "string" then
    compat.raise("sigv4.signing_key: secret_access_key must be a string or a secret", 2)
  end
  local k = crypto.hmac_sha256("AWS4" .. key, date)
  k = crypto.hmac_sha256(k, region)
  k = crypto.hmac_sha256(k, service)
  return crypto.hmac_sha256(k, "aws4_request")
end

-- The derived key, from args.key_cache when the caller keeps one (a table it owns, one
-- per client, as Distilled keeps a cache per secret). Entries are keyed by a hash of the
-- secret, never the secret itself, plus the scope; at most 16 are kept, so rotating
-- temporary credentials do not pile up secret-derived keys.
local KEY_CACHE_MAX = 16
local function cached_signing_key(cache, state)
  if not cache then
    return sigv4.signing_key(state.secret_key, state.date, state.region, state.service)
  end
  local id = crypto.sha256(state.secret_key)
    .. "/"
    .. state.date
    .. "/"
    .. state.region
    .. "/"
    .. state.service
  local key = cache[id]
  if not key then
    key = sigv4.signing_key(state.secret_key, state.date, state.region, state.service)
    local n = 0
    for _ in pairs(cache) do
      n = n + 1
    end
    if n >= KEY_CACHE_MAX then
      for k in pairs(cache) do
        cache[k] = nil
      end
    end
    cache[id] = key
  end
  return key
end

-- prepare(args) -> state | nil, err: everything up to the canonical request
local function prepare(args)
  local request, creds = args.request, args.credentials
  local access_key_id = creds.access_key_id
  local secret_key = secret.unwrap(creds.secret_access_key)
  local session_token = secret.unwrap(creds.session_token)
  if type(access_key_id) ~= "string" or access_key_id == "" then
    return nil,
      errors.new(
        "ConfigError",
        { message = "sigv4: credentials.access_key_id is missing", key = "access_key_id" }
      )
  end
  if type(secret_key) ~= "string" or secret_key == "" then
    return nil,
      errors.new(
        "ConfigError",
        { message = "sigv4: credentials.secret_access_key is missing", key = "secret_access_key" }
      )
  end
  if session_token ~= nil and type(session_token) ~= "string" then
    return nil,
      errors.new(
        "ConfigError",
        { message = "sigv4: credentials.session_token must be a string", key = "session_token" }
      )
  end
  if session_token == "" then
    session_token = nil
  end
  local body = request.body
  if body ~= nil and type(body) ~= "string" then
    compat.raise("sigv4.sign: request.body must be a string or nil", 3)
  end
  local u = parse_url(request.url)
  if not u then
    return invalid("request.url is not an absolute http(s) URL")
  end
  local service, region = args.service, args.region
  if not (service and service ~= "" and region and region ~= "") then
    local gs, gr = guess(u.hostname, u.path, request.headers)
    service = (service and service ~= "") and service or gs
    region = (region and region ~= "") and region or (gr ~= "" and gr or "us-east-1")
  end
  local headers, herr = header_record(request.headers)
  if not headers then
    return nil, herr
  end
  if args.hash_payload then
    headers["x-amz-content-sha256"] = sha256_hex(body or "")
  end
  headers.host = nil
  local method = request.method or ((body ~= nil and body ~= "") and "POST" or "GET")
  local datetime = args.datetime or amz_datetime(args.now_epoch)
  local append_token = args.append_session_token or service == "iotdevicegateway"
  local sign_query = args.sign_query

  if service == "s3" and not sign_query and headers["x-amz-content-sha256"] == nil then
    headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
  end

  local params = parse_params(u.query)
  local query_changed = false
  if sign_query then
    params_set(params, "X-Amz-Date", datetime)
    if session_token and not append_token then
      params_set(params, "X-Amz-Security-Token", session_token)
    end
    query_changed = true
  else
    headers["x-amz-date"] = datetime
    if session_token and not append_token then
      headers["x-amz-security-token"] = session_token
    end
  end

  local signable = { "host" }
  for name in pairs(headers) do
    signable[#signable + 1] = name
  end
  local kept = {}
  for _, name in ipairs(signable) do
    if args.all_headers or not UNSIGNABLE[name] then
      kept[#kept + 1] = name
    end
  end
  table.sort(kept)
  local signed_headers = table.concat(kept, ";")
  local canonical_headers = {}
  for i, name in ipairs(kept) do
    local value = name == "host" and u.host or gsub(headers[name], "[ \t\n\v\f\r]+", " ")
    canonical_headers[i] = name .. ":" .. value
  end
  local date = sub(datetime, 1, 8)
  local credential_scope = date .. "/" .. region .. "/" .. service .. "/aws4_request"

  if sign_query then
    if service == "s3" and not params_has(params, "X-Amz-Expires") then
      params_set(params, "X-Amz-Expires", "86400")
    end
    params_set(params, "X-Amz-Algorithm", ALGORITHM)
    params_set(params, "X-Amz-Credential", access_key_id .. "/" .. credential_scope)
    params_set(params, "X-Amz-SignedHeaders", signed_headers)
  end

  -- path: S3 signs the decoded path encoded once; other services the path with runs of
  -- "/" collapsed, encoded again (so "%20" is signed as "%2520"), unless single_encode
  local path
  if service == "s3" then
    path = decode_uri_component((gsub(u.path, "+", " "))) or u.path
  else
    path = gsub(u.path, "/+", "/")
  end
  if not args.single_encode then
    path = gsub(url_codec.encode_component(path), "%%2F", "/")
  end
  path = encode_rfc3986(path)

  -- query: every pair with a name (S3: the first of each name), encoded, sorted
  local pairs_list, seen = {}, {}
  local has_query = query_changed or (u.query ~= nil and u.query ~= "")
  if has_query then
    for _, p in ipairs(params) do
      local name = p[1]
      if name ~= "" and not (service == "s3" and seen[name]) then
        seen[name] = true
        pairs_list[#pairs_list + 1] = {
          encode_rfc3986(url_codec.encode_component(name)),
          encode_rfc3986(url_codec.encode_component(p[2])),
        }
      end
    end
  end
  table.sort(pairs_list, function(x, y)
    if x[1] ~= y[1] then
      return x[1] < y[1]
    end
    return x[2] < y[2]
  end)
  local encoded = {}
  for i, p in ipairs(pairs_list) do
    encoded[i] = p[1] .. "=" .. p[2]
  end

  local payload_hash = headers["x-amz-content-sha256"]
  if payload_hash == nil and service == "s3" and sign_query then
    payload_hash = "UNSIGNED-PAYLOAD"
  end
  if payload_hash == nil then
    payload_hash = sha256_hex(body or "")
  end

  local canonical = table.concat({
    upper(method),
    path,
    compat.concat(encoded, "&"),
    compat.concat(canonical_headers, "\n") .. "\n",
    signed_headers,
    payload_hash,
  }, "\n")

  return {
    request = request,
    url = u,
    params = params,
    query_changed = query_changed,
    headers = headers,
    method = method,
    datetime = datetime,
    date = date,
    region = region,
    service = service,
    access_key_id = access_key_id,
    secret_key = secret_key,
    session_token = session_token,
    append_token = append_token,
    sign_query = sign_query,
    signed_headers = signed_headers,
    credential_scope = credential_scope,
    canonical = canonical,
  }
end

function sigv4.canonical_request(args)
  check_args(args, SIGN_ARGS, "sigv4.canonical_request")
  if not args.request or not args.credentials then
    compat.raise("sigv4.canonical_request: request and credentials are required", 2)
  end
  local state, err = prepare(args)
  if not state then
    return nil, err
  end
  return state.canonical
end

--- sigv4.sign(args) -> signed | nil, err
-- `signed` is a copy of args.request with method, url and headers replaced: header
-- names lower-case, values normalised, Host left to the transport, and x-amz-date,
-- x-amz-security-token, x-amz-content-sha256 and authorization added (or, with
-- sign_query, the X-Amz-* parameters in the URL instead).
function sigv4.sign(args)
  check_args(args, SIGN_ARGS, "sigv4.sign")
  if not args.request or not args.credentials then
    compat.raise("sigv4.sign: request and credentials are required", 2)
  end
  local state, err = prepare(args)
  if not state then
    return nil, err
  end
  local string_to_sign = table.concat({
    ALGORITHM,
    state.datetime,
    state.credential_scope,
    sha256_hex(state.canonical),
  }, "\n")
  local key = cached_signing_key(args.key_cache, state)
  local signature = hex.encode(crypto.hmac_sha256(key, string_to_sign))

  local headers = state.headers
  local query = state.url.query
  if state.sign_query then
    params_set(state.params, "X-Amz-Signature", signature)
    if state.session_token and state.append_token then
      params_set(state.params, "X-Amz-Security-Token", state.session_token)
    end
  else
    headers.authorization = ALGORITHM
      .. " Credential="
      .. state.access_key_id
      .. "/"
      .. state.credential_scope
      .. ", SignedHeaders="
      .. state.signed_headers
      .. ", Signature="
      .. signature
  end
  if state.query_changed then
    query = serialize_params(state.params)
    if query == "" then
      query = nil
    end
  end
  local signed = {}
  for k, v in pairs(state.request) do
    signed[k] = v
  end
  signed.method = state.method
  signed.url = serialize_url(state.url, query)
  signed.headers = headers
  return signed
end

local PRESIGN_ARGS = {
  url = "string",
  method = "string",
  headers = "table",
  credentials = "table",
  region = "string",
  service = "string",
  expires_in = "number",
  now_epoch = "number",
  datetime = "string",
  all_headers = "boolean",
  append_session_token = "boolean",
  single_encode = "boolean",
}

--- sigv4.presign(args) -> url | nil, err
-- A URL carrying its signature in the query: anyone holding it can send the request
-- until it expires. expires_in (seconds, floored) becomes X-Amz-Expires; S3 defaults to
-- 86400 and AWS allows at most 604800.
function sigv4.presign(args)
  check_args(args, PRESIGN_ARGS, "sigv4.presign")
  if not args.credentials then
    compat.raise("sigv4.presign: credentials are required", 2)
  end
  local target = args.url
  if args.expires_in ~= nil then
    local u = parse_url(target)
    if not u then
      return invalid("url is not an absolute http(s) URL")
    end
    local params = parse_params(u.query)
    params_set(params, "X-Amz-Expires", tostring(floor(args.expires_in)))
    target = serialize_url(u, serialize_params(params))
  end
  local signed, err = sigv4.sign({
    request = { method = args.method, url = target, headers = args.headers },
    credentials = args.credentials,
    region = args.region,
    service = args.service,
    now_epoch = args.now_epoch,
    datetime = args.datetime,
    sign_query = true,
    all_headers = args.all_headers,
    append_session_token = args.append_session_token,
    single_encode = args.single_encode,
  })
  if not signed then
    return nil, err
  end
  return signed.url
end

-- exposed for the spec
sigv4._parse_url = parse_url
sigv4._utf8_repair = utf8_repair

return sigv4
