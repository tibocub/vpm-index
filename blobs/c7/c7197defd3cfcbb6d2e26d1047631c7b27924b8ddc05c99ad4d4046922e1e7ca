-- SigV4 presigning: URLs and POST policies anyone holding them can use until they expire.
--
-- Port of Distilled's packages/s3/src/presign.ts (presignUrl, presignS3Url, presignPost;
-- presignRequest is `s3.presign_request`, built on the client's protocol). Pure client-side
-- computation: nothing is sent.
--
--   local presign = require("distilled.s3.presign")
--   presign.url{ url, service, method?, region?, expires_in?, headers?, ... } -> url | nil, err
--   presign.s3_url{ bucket, key, method?, version_id?, region?, expires_in?, content_type?,
--                   response_content_type?, endpoint?, ... } -> url | nil, err
--   presign.post{ bucket, key, region?, expires_in?, conditions?, fields?, endpoint?, ... }
--     -> { url, fields = { [name] = value }, field_list = { { name, value }, ... } } | nil, err
--
-- Every function also takes:
--   credentials   a creds table { access_key_id, secret_access_key, session_token?, region? }
--                 (values may be secrets) or a source fn(host) -> creds | nil, err
--                 (distilled.aws.credentials.chain(), .static{...}, ...)
--   host          for the credential source and the clock (host.epoch); optional
--   datetime      "YYYYMMDDTHHMMSSZ" (fixed signing time, for tests) or now_epoch (seconds);
--                 default: host.epoch() or os.time()
--   key_cache     sigv4's derived-key cache (one table per client)
--
-- The region is `region`, else the credentials' `region`; with neither the call fails
-- with ConfigError (Distilled reads its Region layer). `expires_in` defaults to 900
-- seconds. `endpoint` (MinIO, R2, LocalStack, ...) gives a path-style URL under it;
-- without one the URL is virtual-hosted, `https://<bucket>.s3.<region>.<dnsSuffix>/<key>`,
-- with the DNS suffix of the region's partition.
--
-- A bucket or key that would address another resource fails with InvalidInput before
-- anything is signed: "", a "." or ".." bucket or key segment, and (without an endpoint)
-- a bucket that is not plain host-name text.
local aws_endpoint = require("distilled.aws.endpoint")
local compat = require("distilled.compat")
local crypto = require("distilled.crypto")
local errors = require("distilled.errors")
local http = require("distilled.aws.http")
local json = require("distilled.json")
local secret = require("distilled.secret")
local sigv4 = require("distilled.sigv4")
local url_codec = require("distilled.url")

local presign = {}

local floor, format, sub = math.floor, string.format, string.sub

presign.DEFAULT_EXPIRES_IN = 900

---------------------------------------------------------------------------------------
-- credentials, region, time
---------------------------------------------------------------------------------------

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

-- the creds table: given, or what a source returns
local function resolve_credentials(args)
  local c = args.credentials
  if
    type(c) == "function" or (type(c) == "table" and getmetatable(c) and getmetatable(c).__call)
  then
    local ok, creds, err = compat.pcall(c, args.host)
    if not ok then
      return nil,
        errors.new("SdkError", { message = "credential source raised: " .. tostring(creds) })
    end
    if not creds then
      return nil,
        err or config_error("presign: the credential source returned nothing", "credentials")
    end
    return creds
  end
  if type(c) ~= "table" then
    return nil, config_error("presign: credentials are required", "credentials")
  end
  return c
end

local function region_of(args, creds)
  local region = args.region or (creds and secret.unwrap(creds.region))
  if type(region) ~= "string" or region == "" then
    return nil,
      config_error("presign: no region (pass region, or credentials that carry one)", "region")
  end
  return region
end

local function datetime_of(args)
  if args.datetime then
    return args.datetime
  end
  local now = args.now_epoch
  if now == nil then
    local host = args.host
    now = (host and host.epoch) and host.epoch() or os.time()
  end
  return sigv4.amz_datetime(now)
end

-- the creds sigv4 takes (secrets stay secrets)
local function signing_credentials(creds)
  return {
    access_key_id = secret.unwrap(creds.access_key_id),
    secret_access_key = creds.secret_access_key,
    session_token = creds.session_token,
  }
end

---------------------------------------------------------------------------------------
-- URLs
---------------------------------------------------------------------------------------

-- URLSearchParams.set on a URL we built (no query yet, or one we built): append
local function with_params(base, params)
  local parts = {}
  for _, p in ipairs(params) do
    parts[#parts + 1] = url_codec.encode_form(p[1]) .. "=" .. url_codec.encode_form(p[2])
  end
  if #parts == 0 then
    return base
  end
  return base .. "?" .. table.concat(parts, "&")
end

--- presign.object_url(bucket, key, region, path, endpoint) -> url | nil, InvalidInput
-- `path` under the bucket's URL (Distilled's objectUrl).
function presign.object_url(bucket, key, region, path, endpoint)
  local invalid = http.invalid_label("bucket", bucket, false)
    or http.invalid_label("key", key, true)
    or (
      (not endpoint and http.encode_label(bucket) ~= bucket)
      and http.invalid_host_label("bucket", bucket)
    )
  if invalid then
    return nil, invalid
  end
  if endpoint then
    return (string.gsub(endpoint, "/+$", "")) .. "/" .. http.encode_label(bucket) .. "/" .. path
  end
  return "https://"
    .. bucket
    .. ".s3."
    .. region
    .. "."
    .. aws_endpoint.dns_suffix(region)
    .. "/"
    .. path
end

-- `new URL(u).toString()`: what the signer's WHATWG parser makes of it
local function normalize_url(u)
  local p = sigv4._parse_url(u)
  if not p then
    return nil,
      errors.new(
        "InvalidInput",
        { message = "presign: the endpoint URL is not an absolute http(s) URL" }
      )
  end
  return p.scheme
    .. "://"
    .. (p.userinfo and (p.userinfo .. "@") or "")
    .. p.host
    .. p.path
    .. (p.query and ("?" .. p.query) or "")
    .. (p.fragment and ("#" .. p.fragment) or "")
end

local function check(args, allowed, what)
  if type(args) ~= "table" then
    compat.raise(what .. ": expected a table of options", 3)
  end
  for k in pairs(args) do
    if not allowed[k] then
      compat.raise(what .. ": unknown option " .. tostring(k), 3)
    end
  end
end

local COMMON = {
  credentials = true,
  host = true,
  datetime = true,
  now_epoch = true,
  key_cache = true,
  region = true,
  expires_in = true,
}

local function options(extra)
  local t = {}
  for k in pairs(COMMON) do
    t[k] = true
  end
  for _, k in ipairs(extra) do
    t[k] = true
  end
  return t
end

local URL_OPTIONS = options({ "url", "service", "method", "headers" })

--- presign.url{ url, service, method?, region?, expires_in?, headers?, ... } -> url | nil, err
-- Distilled's presignUrl: X-Amz-Expires set on the URL, the signature in its query.
-- `headers` are signed into the URL (X-Amz-SignedHeaders), content-type and the other
-- normally unsigned headers included: whoever uses the URL must send them verbatim.
function presign.url(args)
  check(args, URL_OPTIONS, "presign.url")
  if type(args.url) ~= "string" or type(args.service) ~= "string" then
    compat.raise("presign.url: url and service are required strings", 2)
  end
  local creds, err = resolve_credentials(args)
  if not creds then
    return nil, err
  end
  local region
  region, err = region_of(args, creds)
  if not region then
    return nil, err
  end
  return sigv4.presign({
    url = args.url,
    method = args.method or "GET",
    headers = args.headers,
    credentials = signing_credentials(creds),
    service = args.service,
    region = region,
    expires_in = args.expires_in or presign.DEFAULT_EXPIRES_IN,
    datetime = datetime_of(args),
    -- the signer leaves content-type (and others) out unless told: headers given here
    -- are meant to be pinned, as the AWS SDK's getSignedUrl pins ContentType
    all_headers = args.headers ~= nil,
  })
end

local S3_URL_OPTIONS = options({
  "bucket",
  "key",
  "method",
  "version_id",
  "content_type",
  "response_content_type",
  "endpoint",
})

--- presign.s3_url{ bucket, key, ... } -> url | nil, err (Distilled's presignS3Url)
function presign.s3_url(args)
  check(args, S3_URL_OPTIONS, "presign.s3_url")
  if type(args.bucket) ~= "string" or type(args.key) ~= "string" then
    compat.raise("presign.s3_url: bucket and key are required strings", 2)
  end
  local creds, err = resolve_credentials(args)
  if not creds then
    return nil, err
  end
  local region
  region, err = region_of(args, creds)
  if not region then
    return nil, err
  end
  local base
  base, err = presign.object_url(
    args.bucket,
    args.key,
    region,
    http.encode_greedy_label(args.key),
    args.endpoint
  )
  if not base then
    return nil, err
  end
  local params = {}
  if args.version_id ~= nil then
    params[#params + 1] = { "versionId", args.version_id }
  end
  if args.response_content_type ~= nil then
    params[#params + 1] = { "response-content-type", args.response_content_type }
  end
  return presign.url({
    method = args.method or "GET",
    url = with_params(base, params),
    service = "s3",
    region = region,
    expires_in = args.expires_in,
    headers = args.content_type ~= nil and { ["content-type"] = args.content_type } or nil,
    datetime = datetime_of(args),
    credentials = creds,
  })
end

---------------------------------------------------------------------------------------
-- POST policies
---------------------------------------------------------------------------------------

-- days since 1970-01-01 (Howard Hinnant's days_from_civil)
local function days_from_civil(y, m, d)
  if m <= 2 then
    y = y - 1
  end
  local era = floor(y / 400)
  local yoe = y - era * 400
  local mp = (m + 9) % 12
  local doy = floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + floor(yoe / 4) - floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

-- "YYYYMMDDTHHMMSSZ" -> epoch seconds (Date.UTC of its fields)
local function datetime_epoch(dt)
  local y, mo, d = tonumber(sub(dt, 1, 4)), tonumber(sub(dt, 5, 6)), tonumber(sub(dt, 7, 8))
  local h, mi, s = tonumber(sub(dt, 10, 11)), tonumber(sub(dt, 12, 13)), tonumber(sub(dt, 14, 15))
  if not (y and mo and d and h and mi and s) then
    return nil
  end
  return ((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + s
end

-- Date.prototype.toISOString of epoch milliseconds: "2026-01-02T03:04:05.000Z"
local function iso_string(ms)
  ms = floor(ms)
  local secs = floor(ms / 1000)
  local frac = ms - secs * 1000
  local dt = sigv4.amz_datetime(secs)
  return format(
    "%s-%s-%sT%s:%s:%s.%03dZ",
    sub(dt, 1, 4),
    sub(dt, 5, 6),
    sub(dt, 7, 8),
    sub(dt, 10, 11),
    sub(dt, 12, 13),
    sub(dt, 14, 15),
    frac
  )
end
presign._iso_string = iso_string

-- one policy condition as JSON: { name = value } (one pair) or a list
local function condition_json(c)
  if type(c) ~= "table" then
    compat.raise("presign.post: a condition must be a table", 4)
  end
  if c[1] ~= nil then
    local parts = {}
    for i = 1, #c do
      parts[i] = json.encode(c[i])
    end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  local name, value = next(c)
  if name == nil or next(c, name) ~= nil then
    compat.raise("presign.post: an exact-match condition has exactly one field", 4)
  end
  return "{" .. json.encode(name) .. ":" .. json.encode(value) .. "}"
end

local POST_OPTIONS = options({ "bucket", "key", "conditions", "fields", "endpoint" })

local FILENAME = "${filename}"

--- presign.post{ bucket, key, ... } -> { url, fields, field_list } | nil, err
-- Distilled's presignPost (the AWS SDK's createPresignedPost): a browser form uploads to
-- `url` with `field_list` (in that order) and then the `file` field. `fields` are sent
-- with exactly these values and also added to the policy as exact matches, in order:
-- give them as a list of pairs `{ { name, value }, ... }` to fix the order, a map is taken
-- sorted by name (a Lua table has no insertion order). `conditions` are policy conditions:
-- `{ acl = "private" }`, `{ "starts-with", "$key", "uploads/" }`,
-- `{ "content-length-range", 0, 10485760 }`. A key ending in `${filename}` allows any key
-- that starts with the text before it.
function presign.post(args)
  check(args, POST_OPTIONS, "presign.post")
  if type(args.bucket) ~= "string" or type(args.key) ~= "string" then
    compat.raise("presign.post: bucket and key are required strings", 2)
  end
  local creds, err = resolve_credentials(args)
  if not creds then
    return nil, err
  end
  local region
  region, err = region_of(args, creds)
  if not region then
    return nil, err
  end
  local url
  url, err = presign.object_url(args.bucket, args.key, region, "", args.endpoint)
  if not url then
    return nil, err
  end
  url, err = normalize_url(url)
  if not url then
    return nil, err
  end
  local datetime = datetime_of(args)
  local signed_at = datetime_epoch(datetime)
  if not signed_at then
    compat.raise("presign.post: datetime must be YYYYMMDDTHHMMSSZ", 2)
  end
  local date = sub(datetime, 1, 8)
  local expires_in = args.expires_in or presign.DEFAULT_EXPIRES_IN
  local expiration = iso_string(signed_at * 1000 + expires_in * 1000)

  local access_key_id = secret.unwrap(creds.access_key_id)
  if type(access_key_id) ~= "string" or access_key_id == "" then
    return nil, config_error("presign: credentials.access_key_id is missing", "access_key_id")
  end
  local secret_key = creds.secret_access_key
  local unwrapped_secret = secret.unwrap(secret_key)
  if type(unwrapped_secret) ~= "string" or unwrapped_secret == "" then
    return nil,
      config_error("presign: credentials.secret_access_key is missing", "secret_access_key")
  end

  local list = {}
  local given = args.fields or {}
  if given[1] ~= nil then
    for _, p in ipairs(given) do
      list[#list + 1] = { p[1], p[2] }
    end
  else
    local user = {}
    for name in pairs(given) do
      user[#user + 1] = name
    end
    table.sort(user)
    for _, name in ipairs(user) do
      list[#list + 1] = { name, given[name] }
    end
  end
  -- fields the policy and form carry after the caller's (an object spread: a caller's
  -- field of the same name keeps its place and takes the new value)
  local function set(name, value)
    for _, p in ipairs(list) do
      if p[1] == name then
        p[2] = value
        return
      end
    end
    list[#list + 1] = { name, value }
  end
  set("bucket", args.bucket)
  set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
  set("X-Amz-Credential", access_key_id .. "/" .. date .. "/" .. region .. "/s3/aws4_request")
  set("X-Amz-Date", datetime)
  local token = secret.unwrap(creds.session_token)
  if token ~= nil then
    set("X-Amz-Security-Token", token)
  end

  local conditions = {}
  for _, c in ipairs(args.conditions or {}) do
    conditions[#conditions + 1] = condition_json(c)
  end
  for _, p in ipairs(list) do
    conditions[#conditions + 1] = "{" .. json.encode(p[1]) .. ":" .. json.encode(p[2]) .. "}"
  end
  local key = args.key
  if #key >= #FILENAME and sub(key, -#FILENAME) == FILENAME then
    conditions[#conditions + 1] =
      json.encode({ "starts-with", "$key", sub(key, 1, #key - #FILENAME) })
  else
    conditions[#conditions + 1] = "{" .. json.encode("key") .. ":" .. json.encode(key) .. "}"
  end
  local policy = '{"expiration":'
    .. json.encode(expiration)
    .. ',"conditions":['
    .. table.concat(conditions, ",")
    .. "]}"
  local encoded_policy = crypto.base64.encode(policy)
  local signing_key = sigv4.signing_key(secret_key, date, region, "s3")
  local signature = crypto.hex.encode(crypto.hmac_sha256(signing_key, encoded_policy))

  set("key", key)
  set("Policy", encoded_policy)
  set("X-Amz-Signature", signature)
  local fields = {}
  for _, p in ipairs(list) do
    fields[p[1]] = p[2]
  end
  return { url = url, fields = fields, field_list = list }
end

return presign
