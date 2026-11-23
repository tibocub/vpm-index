-- S3 helpers that work with a generated S3 client (clients/s3, `require("s3")`).
--
--   local s3 = require("distilled.s3")
--   s3.presign_request(client, "put_object", { Bucket = "b", Key = "k", ContentType = "image/png" },
--                      { expires_in = 300 }) -> { method, url, headers } | nil, err
--   s3.presign_s3_url(client, { bucket, key, ... })  -> url | nil, err
--   s3.presign_post(client, { bucket, key, ... })    -> { url, fields, field_list } | nil, err
--   s3.presign_url(client, { url, service, ... })    -> url | nil, err
--
-- The last three are distilled.s3.presign's functions with the client's credentials,
-- region, endpoint and host filled in (an option given in the call wins). The modules
-- themselves: s3.presign, s3.checksum (httpChecksum middleware), s3.payload (the
-- x-amz-content-sha256 rules).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local secret = require("distilled.secret")
local sigv4 = require("distilled.sigv4")
local url_codec = require("distilled.url")

local s3 = {}

s3.presign = require("distilled.s3.presign")
s3.checksum = require("distilled.s3.checksum")
s3.payload = require("distilled.s3.payload")

local find, gsub, lower, sub = string.find, string.gsub, string.lower, string.sub

local function state_of(client, what)
  local st = type(client) == "table" and rawget(client, "_state")
  if type(st) ~= "table" or type(st.protocol) ~= "table" then
    compat.raise(what .. ": expected a client built by a generated S3 client class", 3)
  end
  return st
end

-- the client's resolved options: { credentials = <secret creds>, region, endpoint, ... }
local function resolved_options(st)
  if not st.ctx or not st.ctx.credentials then
    return {}
  end
  return st.ctx.credentials()
end

-- the client's credentials table (plain or secrets inside), or a ConfigError
local function client_credentials(opts)
  local creds = secret.unwrap(opts.credentials)
  if type(creds) ~= "table" then
    return nil,
      errors.new("ConfigError", {
        message = "the client's credentials option gave no { access_key_id, secret_access_key }",
        key = "credentials",
      })
  end
  return creds
end

-- fill a presign call's options from the client
local function with_client(client, args, what)
  local st = state_of(client, what)
  if type(args) ~= "table" then
    compat.raise(what .. ": expected a table of options", 3)
  end
  local out = {}
  for k, v in pairs(args) do
    out[k] = v
  end
  if out.credentials == nil or out.region == nil or out.endpoint == nil then
    local opts, err = resolved_options(st)
    if not opts then
      return nil, err
    end
    if out.credentials == nil then
      local creds, cerr = client_credentials(opts)
      if not creds then
        return nil, cerr
      end
      out.credentials = creds
    end
    if out.region == nil and opts.region ~= nil then
      out.region = opts.region
    end
    if out.endpoint == nil and opts.endpoint ~= nil and opts.endpoint ~= "" then
      out.endpoint = opts.endpoint
    end
  end
  if out.host == nil then
    out.host = st.host
  end
  return out
end

function s3.presign_s3_url(client, args)
  local a, err = with_client(client, args, "s3.presign_s3_url")
  if not a then
    return nil, err
  end
  return s3.presign.s3_url(a)
end

function s3.presign_post(client, args)
  local a, err = with_client(client, args, "s3.presign_post")
  if not a then
    return nil, err
  end
  return s3.presign.post(a)
end

function s3.presign_url(client, args)
  local a, err = with_client(client, args, "s3.presign_url")
  if not a then
    return nil, err
  end
  a.endpoint = nil -- presign.url signs the URL it is given
  return s3.presign.url(a)
end

---------------------------------------------------------------------------------------
-- presign_request
---------------------------------------------------------------------------------------

-- `x-amz-*` headers S3 reads only as headers: a presigned request keeps them as signed
-- headers (presign.ts UNHOISTABLE; the AWS SDK's S3 presigner does the same for SSE)
local function unhoistable(name)
  return find(name, "^x%-amz%-server%-side%-encryption") ~= nil
    or find(name, "^x%-amz%-checksum%-") ~= nil
    or name == "x-amz-sdk-checksum-algorithm"
end
s3._unhoistable = unhoistable

-- headers the signer added to the request the protocol signed: taken off again
local SIGNER_HEADERS = {
  ["authorization"] = true,
  ["x-amz-date"] = true,
  ["x-amz-security-token"] = true,
  ["x-amz-content-sha256"] = true,
  ["user-agent"] = true,
}

local function percent_decode(s)
  s = gsub(s, "+", " ")
  return (gsub(s, "%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

-- URLSearchParams.set on the URL's query
local function query_set(params, name, value)
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

local function split_url(u)
  local q = find(u, "?", 1, true)
  if not q then
    return u, {}
  end
  local base, query = sub(u, 1, q - 1), sub(u, q + 1)
  local params = {}
  for piece in string.gmatch(query, "[^&]+") do
    local eq = find(piece, "=", 1, true)
    if eq then
      params[#params + 1] =
        { percent_decode(sub(piece, 1, eq - 1)), percent_decode(sub(piece, eq + 1)) }
    else
      params[#params + 1] = { percent_decode(piece), "" }
    end
  end
  return base, params
end

local function join_url(base, params)
  if #params == 0 then
    return base
  end
  local parts = {}
  for i, p in ipairs(params) do
    parts[i] = url_codec.encode_form(p[1]) .. "=" .. url_codec.encode_form(p[2])
  end
  return base .. "?" .. table.concat(parts, "&")
end

local PRESIGN_REQUEST_OPTIONS = { expires_in = true, datetime = true, now_epoch = true }

--- s3.presign_request(client, operation, input, opts?) -> { method, url, headers } | nil, err
-- Distilled's Presign.presignRequest (the AWS SDK's getSignedUrl): the request a call to
-- `operation` would send (same serializer, checksum middleware and endpoint rules),
-- signed into its query string instead of its headers, so every member the input sets
-- is pinned:
-- - query members (versionId, partNumber, response-*) are signed into the URL;
-- - `x-amz-*` header members (x-amz-meta-*, x-amz-tagging, x-amz-storage-class, ...)
--   move into the query, except the server-side encryption and checksum headers, which
--   S3 reads only as headers;
-- - every other header member (Content-Type, Content-Length, Content-MD5, If-None-Match,
--   Range, ...) and those exceptions come back in `headers` (lower-case names): the
--   request must send exactly these.
-- The body is not signed (UNSIGNED-PAYLOAD); pin it with ContentLength, ContentMD5 or a
-- Checksum* member. An input that serializes into a body (PutObjectTagging's tag set, a
-- Body member) fails with InvalidInput: a URL cannot carry it. opts: expires_in (900),
-- datetime "YYYYMMDDTHHMMSSZ" or now_epoch (default: the client's host clock).
function s3.presign_request(client, operation, input, opts)
  local st = state_of(client, "s3.presign_request")
  opts = opts or {}
  for k in pairs(opts) do
    if not PRESIGN_REQUEST_OPTIONS[k] then
      compat.raise("s3.presign_request: unknown option " .. tostring(k), 2)
    end
  end
  local op = st.service.ops[operation]
  if op == nil then
    compat.raise("s3.presign_request: unknown operation " .. tostring(operation), 2)
  end
  if type(st.protocol.encode) ~= "function" then
    return nil,
      errors.new(
        "SdkError",
        { message = "s3.presign_request: the client's protocol cannot encode requests" }
      )
  end
  local resolved, err = resolved_options(st)
  if not resolved then
    return nil, err
  end
  local ctx =
    { service = st.service, op_name = operation, host = st.host, validation = st.ctx.validation }
  local req
  req, err = st.protocol.encode(ctx, op, input or {}, resolved)
  if not req then
    return nil, err
  end
  -- the signing scope the protocol used: region and name of the endpoint's auth scheme
  local auth = req.headers and req.headers.authorization
  local region, service
  if type(auth) == "string" then
    region, service = string.match(auth, "Credential=[^/]+/%d+/([^/]+)/([^/]+)/aws4_request")
  end
  -- Distilled names the operation by its model name (PutObject)
  local member = op.name or operation
  if not region then
    return nil,
      errors.new("InvalidInput", {
        member = member,
        message = "The request does not sign with SigV4, which presigning needs.",
      })
  end
  if req.body ~= nil and req.body ~= "" then
    return nil,
      errors.new("InvalidInput", {
        member = member,
        message = "The input serializes into a request body, which a presigned URL cannot carry.",
      })
  end
  local creds
  creds, err = client_credentials(resolved)
  if not creds then
    return nil, err
  end
  local base, params = split_url(req.url)
  local headers = {}
  local names = {}
  for name in pairs(req.headers) do
    names[#names + 1] = name
  end
  table.sort(names)
  for _, name in ipairs(names) do
    local l = lower(name)
    if not SIGNER_HEADERS[l] then
      local value = req.headers[name]
      if sub(l, 1, 6) == "x-amz-" and not unhoistable(l) then
        query_set(params, l, value)
      else
        headers[l] = value
      end
    end
  end
  -- the signer assumes UNSIGNED-PAYLOAD only for the signing name "s3"; access points
  -- sign S3 operations under other names
  if service ~= "s3" then
    headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
  end
  query_set(params, "X-Amz-Expires", tostring(opts.expires_in or s3.presign.DEFAULT_EXPIRES_IN))
  local now = opts.now_epoch
  if opts.datetime == nil and now == nil then
    now = (st.host and st.host.epoch) and st.host.epoch() or os.time()
  end
  local signed
  signed, err = sigv4.sign({
    request = { method = req.method, url = join_url(base, params), headers = headers },
    credentials = {
      access_key_id = secret.unwrap(creds.access_key_id),
      secret_access_key = creds.secret_access_key,
      session_token = creds.session_token,
    },
    region = region,
    service = service,
    datetime = opts.datetime,
    now_epoch = opts.datetime == nil and now or nil,
    sign_query = true,
    -- pin every header the input set, content-type and content-length included
    all_headers = true,
  })
  if not signed then
    return nil, err
  end
  return { method = signed.method, url = signed.url, headers = signed.headers }
end

return s3
