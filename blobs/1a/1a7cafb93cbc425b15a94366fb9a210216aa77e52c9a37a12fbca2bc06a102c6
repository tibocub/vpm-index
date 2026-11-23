-- The Tencent Cloud API 3.0 protocol. Port of Distilled's packages/tencentcloud/src/
-- protocol.ts, credentials.ts and region.ts (https://www.tencentcloud.com/document/api/213/33224):
--
--   request:  POST https://<service>.<root_domain>/ with the input as the JSON body,
--             X-TC-Action / X-TC-Version from the operation's `rpc` field (the model's
--             com.tencentcloud#action trait), X-TC-Timestamp, X-TC-Region, X-TC-Token for
--             temporary credentials, and a TC3-HMAC-SHA256 Authorization
--             (distilled.tencentcloud.signer).
--   response: { "Response": { ...output, "RequestId": "..." } }, HTTP 200 even for
--             failures. The Response object is the output. Response.Error fails the call:
--             a typed error of the operation first, then the common code's class
--             (distilled.tencentcloud.errors), else the unknown class. A response without
--             the envelope fails by HTTP status (core status map), or with the parse
--             error on a 2xx.
--
--   local tencentcloud = require("distilled.protocol.tencentcloud")
--   local protocol = tencentcloud.new(service, { unknown_tag, parse_tag, user_agent })
--   -- or tencentcloud(service, args); tencentcloud.options are the client options
--   protocol.call(ctx, op, input) -> value, nil, meta | nil, err, meta
--   protocol.encode(ctx, op, input [, creds]) -> request | nil, err   (no send)
--   protocol.decode(ctx, op, response) -> value | nil, err
--
-- The region of a call (X-TC-Region), in Distilled's order: the input's `region` member
-- (bound to the X-TC-Region header in every model), else the client's `region` option
-- (Distilled's Region layer and the credentials' region are both that one option here:
-- `client:with{ region = ... }` scopes it), else TENCENTCLOUD_REGION, else no header
-- (what products that are not regional expect).
--
-- Operations are never paginated (Distilled generates none: Offset/Limit and TotalCount
-- are plain members the caller drives).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local keys = require("distilled.keys")
local noop = require("distilled.trace.noop")
local redact = require("distilled.redact")
local request = require("distilled.request")
local retry = require("distilled.retry")
local schema = require("distilled.schema")
local secret = require("distilled.secret")
local signer = require("distilled.tencentcloud.signer")
local tc_errors = require("distilled.tencentcloud.errors")
local validate = require("distilled.validate")

local tencentcloud = {}

tencentcloud.VERSION = "0.1.0"
tencentcloud.USER_AGENT = "distilled-lua/" .. tencentcloud.VERSION

--- The Content-Type every request sends, and signs (Distilled's CONTENT_TYPE).
tencentcloud.CONTENT_TYPE = "application/json; charset=utf-8"

--- API hosts are <service>.<root_domain>, e.g. cvm.tencentcloudapi.com.
tencentcloud.DEFAULT_ROOT_DOMAIN = "tencentcloudapi.com"

--- The client options (Client.define's `options`): Distilled's CredentialsFromEnv
-- variables, and its `credentials({ ... rootDomain })` fields. secret_id identifies the
-- key and is not a secret (Distilled keeps it a plain string; it is in every
-- Authorization header).
tencentcloud.options = {
  secret_id = { env = "TENCENTCLOUD_SECRET_ID", required = true, type = "string" },
  secret_key = { secret = true, env = "TENCENTCLOUD_SECRET_KEY", required = true },
  session_token = { secret = true, env = "TENCENTCLOUD_SESSION_TOKEN" },
  region = { env = "TENCENTCLOUD_REGION", type = "string" },
  root_domain = { default = tencentcloud.DEFAULT_ROOT_DOMAIN, type = "string" },
  endpoint = { type = "string" },
}

--- README rows for the options, in this order (gen/rpc.lua writes them).
tencentcloud.option_docs = {
  { "secret_id", "required: the SecretId of the API key; default from `TENCENTCLOUD_SECRET_ID`" },
  {
    "secret_key",
    "required secret: a string, a secret, or `fn(host) -> value, err`; default from "
      .. "`TENCENTCLOUD_SECRET_KEY`",
  },
  {
    "session_token",
    "secret: the session token of temporary (STS) credentials, sent as `X-TC-Token`; default "
      .. "from `TENCENTCLOUD_SESSION_TOKEN`",
  },
  {
    "region",
    "default region (`X-TC-Region`) for calls whose input sets no `region`; default from "
      .. "`TENCENTCLOUD_REGION`; none: no header (products that are not regional)",
  },
  { "root_domain", "the domain API hosts live under, default `tencentcloudapi.com`" },
  {
    "endpoint",
    "a URL that replaces `https://<service>.<root_domain>` (a proxy, a test server); "
      .. "`{service}` in it is the product's service name. The signed host is its host",
  },
}

local null = json.null

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

local function is_record(v)
  return type(v) == "table" and v ~= null and not json.is_array(v) and not secret.is(v)
end

local function lower_headers(h)
  if type(h) ~= "table" then
    return {}
  end
  local out = {}
  for k, v in pairs(h) do
    out[type(k) == "string" and string.lower(k) or k] = v
  end
  return out
end

local TRANSPORT_HINT = require("distilled.host").TRANSPORT_HINT
local function contract_error(res)
  local what
  if res == nil then
    what = "returned nothing (neither a response table nor nil, err)"
  elseif type(res) == "function" then
    what = "returned a function, so it is probably a transport constructor, not a transport"
  else
    what = "returned a " .. type(res) .. " instead of a response table or nil, err"
  end
  return errors.new("ConfigError", {
    message = "the transport " .. what .. "; " .. TRANSPORT_HINT,
    key = "transport",
  })
end

-- the host part of a URL with its port, as sent in the Host header
local function authority_of(url)
  local a = string.match(url, "^%a[%w+.-]*://([^/?#]*)") or ""
  return (string.gsub(a, "^.*@", ""))
end

local function host_and_port(url)
  local authority = authority_of(url)
  local host, port = string.match(authority, "^(.*):(%d+)$")
  if host then
    return host, tonumber(port)
  end
  return authority, string.find(url, "^https") and 443 or 80
end

-- a host label from configuration: letters, digits, '.', '-' only
local function host_text(v)
  return type(v) == "string" and v ~= "" and string.find(v, "^[%w.-]+$") ~= nil
end

--- tencentcloud.new(service, args) -> protocol
function tencentcloud.new(service, args)
  args = args or {}
  if type(args) ~= "table" then
    compat.raise("tencentcloud.new: args must be a table", 2)
  end
  local unknown_class = tc_errors.unknown_class(args.unknown_tag)
  local parse_class = tc_errors.parse_class(args.parse_tag)
  local user_agent = args.user_agent or tencentcloud.USER_AGENT

  local protocol = {
    service = service,
    unknown_class = unknown_class,
    parse_class = parse_class,
  }

  local class_cache = {}
  local function classes_of(svc, op)
    local list = class_cache[op]
    if list then
      return list
    end
    list = {}
    local declared = (svc and svc.errors) or {}
    for _, name in ipairs(op.errors or {}) do
      local class = declared[name] or errors.classes[name]
      if errors.is_class(class) and class.tag ~= unknown_class.tag then
        list[#list + 1] = class
      end
    end
    class_cache[op] = list
    return list
  end

  local function parse_error(op, body, cause)
    local why = type(cause) == "table" and cause.message or tostring(cause)
    return errors.new(parse_class, {
      message = "cannot decode the response of " .. tostring(op.name) .. ": " .. tostring(why),
      body = body,
      cause = cause,
    })
  end

  -----------------------------------------------------------------------------------
  -- request
  -----------------------------------------------------------------------------------

  --- protocol.encode(ctx, op, input [, creds]) -> request | nil, err
  -- The signed request: { method = "POST", url, headers, body }.
  function protocol.encode(ctx, op, input, creds)
    ctx = ctx or {}
    local action = op.rpc
    if type(action) ~= "table" or type(action.action) ~= "string" then
      return nil,
        errors.new("SdkError", {
          message = "operation " .. tostring(op.name) .. " has no Tencent Cloud action (op.rpc)",
        })
    end
    if creds == nil then
      if ctx.credentials then
        local c, err = ctx.credentials()
        if c == nil then
          return nil, err
        end
        creds = c
      else
        creds = {}
      end
    end
    if creds.secret_id == nil or creds.secret_key == nil then
      return nil,
        errors.new("ConfigError", {
          message = "Tencent Cloud needs secret_id and secret_key (TENCENTCLOUD_SECRET_ID and "
            .. "TENCENTCLOUD_SECRET_KEY)",
          key = creds.secret_id == nil and "secret_id" or "secret_key",
        })
    end
    local root_domain = creds.root_domain or tencentcloud.DEFAULT_ROOT_DOMAIN
    if not host_text(root_domain) then
      return nil,
        errors.new("ConfigError", {
          message = "root_domain must be a host name like tencentcloudapi.com",
          key = "root_domain",
        })
    end
    local base = "https://" .. action.service .. "." .. root_domain
    if creds.endpoint ~= nil then
      local e = string.gsub(creds.endpoint, "{service}", action.service)
      e = string.gsub(e, "/+$", "")
      if not string.find(e, "^https?://[^/]") then
        return nil,
          errors.new(
            "ConfigError",
            { message = "endpoint must be an http(s) URL", key = "endpoint" }
          )
      end
      base = e
    end

    local svc = ctx.service or {}
    -- the body and the region header (the input's X-TC-Region member): request.build
    -- unwraps secrets, maps members and always sends a JSON object, `{}` when empty
    local req, berr = request.build({
      op = op,
      input = input,
      registry = svc.shapes,
      base_url = base,
      empty_json_body = true,
    })
    if req == nil then
      return nil, berr
    end
    local headers = req.headers
    local payload = req.body or "{}"
    if headers["x-tc-region"] == nil then
      local region = creds.region
      if type(region) == "string" and region ~= "" then
        headers["x-tc-region"] = region
      end
    end

    local now = ctx.host and ctx.host.epoch and ctx.host.epoch() or os.time()
    local timestamp = math.floor(now)
    local signed = signer.sign({
      secret_id = tostring(secret.unwrap(creds.secret_id)),
      secret_key = creds.secret_key,
      service = action.service,
      host = authority_of(req.url),
      action = action.action,
      timestamp = timestamp,
      content_type = tencentcloud.CONTENT_TYPE,
      payload = payload,
    })
    headers["content-type"] = tencentcloud.CONTENT_TYPE
    headers["authorization"] = signed.authorization
    headers["x-tc-action"] = action.action
    headers["x-tc-version"] = action.version
    headers["x-tc-timestamp"] = string.format("%d", timestamp)
    if creds.session_token ~= nil then
      headers["x-tc-token"] = tostring(secret.unwrap(creds.session_token))
    end
    return { method = "POST", url = req.url, headers = headers, body = payload }
  end

  -----------------------------------------------------------------------------------
  -- response
  -----------------------------------------------------------------------------------

  local function decode_success(ctx, op, envelope, value)
    local svc = ctx.service or {}
    local registry = svc.shapes
    local output = op.output
    if output == nil then
      return envelope
    end
    local mapped = keys.decode(output, envelope, registry)
    local sensitive = redact.holds_sensitive(output, registry)
    local mode = ctx.validation or "lenient"
    if mode ~= "lenient" then
      local ok, mismatch = validate.check(output, mapped, registry, { exact = mode == "strict" })
      if not ok then
        if sensitive then
          return nil, parse_error(op, "[REDACTED]", validate.withhold(mismatch))
        end
        return nil, parse_error(op, value, mismatch)
      end
    end
    if sensitive then
      return redact.wrap(output, mapped, registry)
    end
    return mapped
  end

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    ctx = ctx or {}
    local status = res.status
    local headers = lower_headers(res.headers)
    local text = res.body or ""
    if type(text) ~= "string" then
      text = tostring(text)
    end
    local value, non_json = nil, false
    if trim(text) ~= "" then
      local v = json.decode(text)
      if v == nil then
        -- not JSON: a proxy or gateway page, handled as a body without the envelope
        non_json = true
      else
        value = v
      end
    end
    local envelope = is_record(value)
        and is_record(rawget(value, "Response"))
        and rawget(value, "Response")
      or nil
    local e = envelope and rawget(envelope, "Error")
    if is_record(e) then
      local code = rawget(e, "Code")
      code = type(code) == "string" and code or ""
      local message = rawget(e, "Message")
      message = type(message) == "string" and message or code
      local request_id = rawget(envelope, "RequestId")
      request_id = type(request_id) == "string" and request_id or nil
      local typed = errors.match(classes_of(ctx.service, op), {
        status = status,
        message = message,
        body = value,
        headers = headers,
      })
      if typed then
        typed.code = typed.code or code
        typed.request_id = request_id
        return nil, typed
      end
      return nil,
        tc_errors.envelope_error(
          { code = code, message = message, request_id = request_id },
          status,
          value,
          unknown_class,
          headers
        )
    end

    if status < 200 or status >= 300 then
      local message = non_json and string.sub(trim(text), 1, 500) or ("HTTP " .. tostring(status))
      local now = ctx.host and ctx.host.epoch and ctx.host.epoch() or os.time()
      local class = errors.STATUS_MAP[status]
      if class == nil and status >= 500 then
        class = errors.InternalServerError
      end
      if class ~= nil then
        return nil,
          errors.new(class, {
            message = message,
            status = status,
            retry_after = retry.parse_for_status(status, headers, now),
          })
      end
      local body = value
      if body == nil then
        body = string.sub(text, 1, 2000)
      end
      return nil,
        errors.new(unknown_class, {
          message = message,
          status = status,
          body = body,
          headers = headers,
        })
    end

    if envelope == nil then
      local body = value
      if body == nil then
        body = string.sub(text, 1, 2000)
      end
      return nil, parse_error(op, body, "The response has no `Response` envelope")
    end
    -- the envelope's members are the output's, RequestId included
    return decode_success(ctx, op, envelope, value)
  end

  -----------------------------------------------------------------------------------
  -- the whole call
  -----------------------------------------------------------------------------------

  --- protocol.call(ctx, op, input) -> value, nil, meta | nil, err, meta
  function protocol.call(ctx, op, input)
    local tracer = ctx.tracer or noop
    local span = ctx.span or noop.NOOP_SPAN
    local host = ctx.host or {}
    local attempt = ctx.attempt or {}

    local creds, cerr
    if ctx.credentials then
      creds, cerr = tracer:with("distilled.credentials", { debug = true }, function()
        return ctx.credentials()
      end)
      if creds == nil then
        return nil, cerr
      end
    else
      creds = {}
    end

    local req, berr = tracer:with("distilled.request.build", { debug = true }, function()
      return protocol.encode(ctx, op, input, creds)
    end)
    if req == nil then
      return nil, berr
    end
    local h = req.headers
    local traceparent = tracer:traceparent()
    if
      traceparent
      and not (ctx.service and ctx.service.telemetry and ctx.service.telemetry.propagate == false)
    then
      h["traceparent"] = traceparent
    end
    if h["user-agent"] == nil then
      h["user-agent"] = ctx.user_agent or user_agent
    end
    req.timeout = ctx.timeout

    local server, port = host_and_port(req.url)
    span:set("http.request.method", req.method)
    span:set("server.address", server)
    span:set("server.port", port)
    attempt.host = server

    local transport = host.transport
    if transport == nil then
      return nil,
        errors.new(
          "ConfigError",
          { message = "no transport; " .. TRANSPORT_HINT, key = "transport" }
        )
    end
    local res, terr = tracer:with("distilled.transport", {
      debug = true,
      attributes = { ["http.request.method"] = req.method, ["server.address"] = server },
    }, function(s)
      local r, e = transport(req)
      if type(r) == "table" then
        s:set("http.response.status_code", r.status)
      end
      return r, e
    end)
    if type(res) ~= "table" and (res ~= nil or terr == nil) then
      return nil, contract_error(res)
    end
    if type(res) ~= "table" then
      if not errors.is(terr) then
        terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
      end
      return nil, terr
    end
    if type(res.status) ~= "number" then
      return nil, errors.new("TransportError", { message = "the transport returned no status" })
    end
    local headers = lower_headers(res.headers)
    res = { status = res.status, headers = headers, body = res.body or "" }
    local meta = { status = res.status, headers = headers }
    attempt.status = res.status
    if res.status >= 300 then
      attempt.hint_ms = retry.bounded_hint_ms(headers)
    end
    span:set("http.response.status_code", res.status)
    local current = tracer:current()
    if current and current ~= span then
      current:set("http.response.status_code", res.status)
    end

    local value, derr = tracer:with("distilled.decode", { debug = true }, function()
      return protocol.decode(ctx, op, res)
    end)
    if value == nil and derr ~= nil then
      return nil, derr, meta
    end
    return value, nil, meta
  end

  return protocol
end

return setmetatable(tencentcloud, {
  __call = function(_, service, args)
    return tencentcloud.new(service, args)
  end,
})
