-- The GCP protocol: Google's JSON REST protocol for discovery-based APIs. Port of
-- Distilled's packages/gcp/src/protocol.ts (GcpProtocol), with endpoint.ts, region.ts
-- and the default credentials of credentials-service.ts. Generated GCP clients call it:
--
--   local protocol = require("distilled.gcp.protocol")(service, {
--     unknown_tag = "UnknownGCPError", parse_tag = "GCPParseError",
--     base_url = "https://storage.googleapis.com/storage/v1",   -- the service's own
--   })
--
-- (google-workspace uses distilled.gcp.workspace: the same protocol without the quota
-- project header, the endpoint override and regional endpoints.)
--
-- Request (encode), per attempt:
-- - Credentials are resolved on every attempt, so a refreshing provider rotates tokens:
--   the client's `credentials` provider, else its `access_token`, else
--   GOOGLE_ACCESS_TOKEN, else Application Default Credentials (one provider per client
--   host, so its token cache lives as long as the client). `authorization: Bearer
--   <token>`; `x-goog-user-project` with the quota project (the `quota_project` option,
--   else the credentials' own).
-- - Labels: a greedy label (discovery `{+name}`, `{name+}` after gen/discovery.lua)
--   with RFC 6570 reserved expansion (`/` and the other reserved characters stay), a
--   plain one like encodeURIComponent. Query members: lists repeat the key, values are
--   String(v). Header members: lower-cased names. The payload member is the whole JSON
--   body; other members are JSON body fields. A body is sent only when a member has a
--   value, and never on GET or HEAD. Input keys the schema does not declare are not
--   sent (GcpProtocol reads only declared props).
-- - The URL is the service base URL (or the regional host the location in the path
--   calls for, region.lua), with the `endpoint` override (GOOGLE_API_ENDPOINT) replacing
--   its origin.
-- Response (decode): a 2xx body is the output as is (empty: {}), checked in strict mode
-- like any REST client (protocol/rest.lua). A failure reads the envelope
-- `{ error = { code, message, status, details } }`: the operation's typed errors first
-- (matchers on status and message; fields under /error), then errors.STATUS_MAP, then
-- InternalServerError for an unmapped 5xx, else UnknownGCPError (code = the envelope's
-- status text, as Distilled). Every HTTP error carries `rpc_status` (error.status,
-- e.g. "FAILED_PRECONDITION": `status` is the HTTP status in Lua) and `details`.
--
-- Differences from Distilled, on purpose: a missing label, or a label segment "." or
-- "..", fails with InvalidInput (Distilled sends `{name}` or lets the URL parser resolve
-- the dots); a CR or LF in a header value fails with InvalidInput.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local keys = require("distilled.keys")
local rest = require("distilled.protocol.rest")
local retry = require("distilled.retry")
local schema = require("distilled.schema")
local secret = require("distilled.secret")
local url = require("distilled.url")
local gcp_credentials = require("distilled.gcp.credentials")
local endpoint = require("distilled.gcp.endpoint")
local region = require("distilled.gcp.region")

local protocol_mod = {}

local null = json.null
local BODYLESS = { GET = true, HEAD = true }
local EMPTY_INPUT = schema.struct({ name = "Empty", members = {} })

--- RFC 6570 reserved expansion: everything outside unreserved and reserved is encoded.
local KEEP = {}
for c in
  string.gmatch(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=",
    "."
  )
do
  KEEP[c] = true
end
local RESERVED = {}
for b = 0, 255 do
  local c = string.char(b)
  RESERVED[c] = KEEP[c] and c or string.format("%%%02X", b)
end

function protocol_mod.encode_reserved(s)
  return (string.gsub(s, ".", RESERVED))
end

local function invalid(member, message)
  return errors.new("InvalidInput", { member = member, message = message })
end

-- a label segment "." or ".." would address another resource (Distilled's core
-- invalidLabel; GcpProtocol lacks the check, see the header)
local function bad_label(name, text, greedy)
  local segments = greedy and {} or { text }
  if greedy then
    for seg in string.gmatch(text .. "/", "([^/]*)/") do
      segments[#segments + 1] = seg
    end
  end
  for _, seg in ipairs(segments) do
    if seg == "." or seg == ".." then
      return invalid(
        name,
        "Input member "
          .. name
          .. " is "
          .. (greedy and ("a path with the segment " .. seg) or seg)
          .. ": as a path label it would address another resource"
      )
    end
  end
  return nil
end

-- appendQuery: lists as repeated k=v, null and absent skipped, scalars String(v)
local function append_query(q, name, value)
  if type(value) == "table" and value ~= null and json.is_array(value) then
    for i = 1, #value do
      append_query(q, name, value[i])
    end
  elseif type(value) == "table" and value ~= null and value[1] ~= nil then
    for i = 1, #value do
      append_query(q, name, value[i])
    end
  elseif value ~= nil and value ~= null then
    q:add(name, url.text(value))
  end
end

--- protocol_mod.envelope(body) -> { code, message, status, details } (each may be nil)
-- extractGCPErrorEnvelope: the standard envelope of https://cloud.google.com/apis/design/errors
function protocol_mod.envelope(body)
  local out = {}
  if type(body) ~= "table" or body == null or json.is_array(body) then
    return out
  end
  local e = rawget(body, "error")
  if type(e) ~= "table" or e == null then
    return out
  end
  local code, message = rawget(e, "code"), rawget(e, "message")
  local status, details = rawget(e, "status"), rawget(e, "details")
  out.code = type(code) == "number" and code or nil
  out.message = type(message) == "string" and message or nil
  out.status = type(status) == "string" and status or nil
  out.details = (type(details) == "table" and details ~= null and json.is_array(details))
      and details
    or nil
  return out
end

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

--- protocol_mod.new(service, opts) -> protocol
-- opts = { unknown_tag, parse_tag, base_url, workspace = bool, title }
function protocol_mod.new(service, opts)
  opts = opts or {}
  if type(opts.base_url) ~= "string" then
    compat.raise("distilled.gcp.protocol: base_url must be the service's base URL", 2)
  end
  local workspace = opts.workspace == true
  -- Distilled's forms: the base URL ends with "/", the uri does not start with one
  local base = string.gsub(opts.base_url, "/+$", "") .. "/"
  local inner = rest.new({
    base_url = opts.base_url,
    unknown_tag = opts.unknown_tag,
    parse_tag = opts.parse_tag,
  })
  local protocol = inner
  local unknown_class = inner.unknown_class
  -- Application Default Credentials per client host (the client's lifetime)
  local default_providers = setmetatable({}, { __mode = "k" })

  -- the GCP credentials config of one attempt: { access_token, quota_project, ... }
  local function config_for(creds, host)
    local provider = creds.credentials
    if provider ~= nil then
      if not gcp_credentials.is_provider(provider) then
        return nil,
          config_error(
            "the credentials option must be a provider from distilled.gcp.credentials (a table"
              .. " with resolve(host)) or a function(host) -> config",
            "credentials"
          )
      end
      return gcp_credentials.resolve(provider, host)
    end
    if creds.access_token ~= nil then
      return { access_token = creds.access_token }
    end
    local getenv = host.getenv or os.getenv
    local env_token = getenv("GOOGLE_ACCESS_TOKEN")
    if env_token ~= nil and env_token ~= "" then
      local project = getenv("GOOGLE_PROJECT_ID")
      return { access_token = secret.wrap(env_token), project = project ~= "" and project or nil }
    end
    if workspace then
      -- google-workspace's CredentialsFromEnv: no ADC
      return nil,
        config_error("GOOGLE_ACCESS_TOKEN environment variable is required", "access_token")
    end
    local p = default_providers[host]
    if p == nil then
      p = gcp_credentials.from_application_default()
      default_providers[host] = p
    end
    return gcp_credentials.resolve(p, host)
  end
  protocol.config_for = config_for

  -- the base URL of one request: the endpoint override, else the regional host
  local function base_for(creds, host, uri)
    if workspace then
      return base
    end
    local override = creds.endpoint
    if override == nil then
      local getenv = host.getenv or os.getenv
      local e = getenv(endpoint.ENV)
      if e ~= nil and e ~= "" then
        override = e
      end
    end
    if override ~= nil then
      local with = endpoint.with_endpoint(base, override)
      if with == nil then
        return nil,
          config_error(
            "GCP endpoint override must be an absolute URL (e.g. http://localhost:8085), got "
              .. json.encode(override),
            "endpoint"
          )
      end
      return with
    end
    local mode = creds.regional_endpoints or "required"
    if not region.MODES[mode] then
      return nil,
        config_error(
          'the regional_endpoints option must be "required", "prefer" or "never", got '
            .. tostring(mode),
          "regional_endpoints"
        )
    end
    return region.endpoint_for(base, uri, mode)
  end

  --- protocol.encode(ctx, op, input [, creds]) -> request | nil, err
  function protocol.encode(ctx, op, input, creds)
    ctx = ctx or {}
    local host = ctx.host or {}
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
    if op.unsupported ~= nil then
      return nil,
        errors.new("SdkError", {
          message = "operation "
            .. tostring(op.name)
            .. ": distilled-lua cannot perform "
            .. tostring(op.unsupported)
            .. " operations yet",
        })
    end
    local config, cerr = config_for(creds, host)
    if not config then
      return nil, cerr
    end

    local registry = (ctx.service or service or {}).shapes
    local node = EMPTY_INPUT
    if op.input ~= nil then
      local resolved, rerr = schema.resolve(op.input, registry)
      if not resolved then
        return nil, errors.new("SdkError", { message = rerr.message })
      end
      node = resolved
    end
    if input == nil then
      input = {}
    elseif type(input) ~= "table" or input == null or json.is_array(input) then
      return nil, invalid(nil, "the input of " .. tostring(op.name) .. " must be a table")
    end
    input = secret.unwrap_deep(input)
    local plan = schema.plan(node)

    local headers = {
      authorization = "Bearer " .. tostring(secret.unwrap(config.access_token)),
    }
    -- bill quota to this project; user credentials need it for many APIs
    local quota = creds.quota_project or config.quota_project
    if not workspace and quota ~= nil and quota ~= "" then
      headers["x-goog-user-project"] = quota
    end

    local uri = op.uri
    local query = url.query()
    local raw_body, has_raw = nil, false
    local body, has_bag = {}, false
    for _, m in ipairs(plan.members) do
      local value = rawget(input, m.name)
      local bind = m.bind or "body"
      local wire = m.wire or m.name
      if value == nil then
        if bind == "label" then
          return nil,
            invalid(
              m.name,
              "Input member " .. m.name .. " is required: it fills the path " .. op.uri
            )
        end
      elseif bind == "label" then
        local text = url.text(value)
        local greedy = string.find(uri, "{" .. wire .. "+}", 1, true) ~= nil
        local refused = bad_label(m.name, text, greedy)
        if refused then
          return nil, refused
        end
        if greedy then
          uri = url.fill(uri, wire, protocol_mod.encode_reserved(text), true)
        else
          uri = url.fill(uri, wire, url.encode_component(text), false)
        end
      elseif bind == "query" then
        append_query(query, wire, value)
      elseif bind == "header" then
        local text = url.text(value)
        if string.find(text, "[\r\n]") then
          return nil, invalid(m.name, "Input member " .. m.name .. " holds a line break")
        end
        headers[string.lower(wire)] = text
      elseif bind == "payload" then
        raw_body, has_raw = keys.encode(m.schema, value, registry), true
      elseif bind ~= "status" then
        if m.string_encoded then
          body[wire] = keys.string_encode(value)
        else
          body[wire] = keys.encode(m.schema, value, registry)
        end
        has_bag = true
      end
    end

    -- A placeholder no member fills (recaptchaenterprise `{+key}`: discovery's global
    -- `key` parameter was filtered out): filled from the input key of that name, as
    -- request.build does (rule 14); Distilled would send the placeholder as is.
    for _, p in ipairs(url.placeholders(string.match(uri, "^[^?]*"))) do
      local value = rawget(input, p.name)
      if value == nil then
        return nil,
          invalid(
            p.name,
            "the path "
              .. op.uri
              .. " has a {"
              .. p.name
              .. "} that no input member fills; pass it as input."
              .. p.name
          )
      end
      local text = url.text(value)
      local refused = bad_label(p.name, text, p.greedy)
      if refused then
        return nil, refused
      end
      local encoded = p.greedy and protocol_mod.encode_reserved(text) or url.encode_component(text)
      uri = url.fill(uri, p.name, encoded, p.greedy)
    end

    -- Distilled's forms for the regional rule: the path without its leading "/"
    local path = string.gsub(uri, "^/", "")
    local base_url, berr = base_for(creds, host, path)
    if not base_url then
      return nil, berr
    end
    local target = base_url .. path
    if not query:empty() then
      target = target .. "?" .. query:encode()
    end
    local method = string.upper(op.method)
    local out = { method = method, url = target, headers = headers }
    local payload
    if has_raw then
      payload = raw_body
    elseif has_bag then
      payload = json.object(body)
    end
    if payload ~= nil and not BODYLESS[method] then
      local text, jerr = json.encode(payload)
      if not text then
        return nil,
          invalid(
            nil,
            "cannot encode the request body of "
              .. tostring(op.name)
              .. ": "
              .. tostring(jerr.message)
          )
      end
      out.body = text
      headers["content-type"] = "application/json"
    end
    return out
  end

  -- the operation's declared error classes, resolved once per op table (long-lived)
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
      if errors.is_class(class) then
        list[#list + 1] = class
      end
    end
    class_cache[op] = list
    return list
  end

  local success_decode = inner.decode

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    ctx = ctx or {}
    local status = res.status
    if status < 400 then
      return success_decode(ctx, op, res)
    end
    local headers = res.headers or {}
    local text = res.body or ""
    if type(text) ~= "string" then
      text = tostring(text)
    end
    -- read as text and parse tolerantly: proxies and HTML error pages are not JSON
    local value, non_json = nil, false
    if string.find(text, "%S") then
      value = json.decode(text)
      non_json = value == nil
    end
    local env = protocol_mod.envelope(value)
    local message = env.message
    if message == nil then
      message = (non_json and text ~= "") and text or tostring(status)
    end
    local body = non_json and text or value
    local now = (ctx.host and ctx.host.epoch or os.time)()
    local extra = { rpc_status = env.status, details = env.details }

    -- 1. the operation's typed errors (matchers on status and message; a quota message
    -- matcher must win over the status map); their fields sit under `error`
    local typed = errors.match(classes_of(ctx.service or service, op), {
      status = status,
      code = env.code,
      message = message,
      body = body,
      headers = headers,
      fields_at = "/error",
      retry_after = retry.parse_server_hint(headers, now),
    })
    local err = typed
    if err == nil then
      -- 2. the status map, 3. an unmapped 5xx is a retryable server error
      local class = errors.STATUS_MAP[status]
      if class == nil and status >= 500 then
        class = errors.InternalServerError
      end
      if class then
        err = errors.new(class, {
          message = message,
          status = status,
          code = env.code,
          body = body,
          headers = headers,
          retry_after = retry.parse_for_status(status, headers, now),
        })
      else
        -- 4. UnknownGCPError: code is the envelope's status text (Distilled's field)
        err = errors.new(unknown_class, {
          status = status,
          code = env.status,
          message = message,
          body = value ~= nil and value or text,
          headers = headers,
        })
      end
    end
    for k, v in pairs(extra) do
      if err[k] == nil then
        err[k] = v
      end
    end
    return nil, err
  end

  return protocol
end

return setmetatable(protocol_mod, {
  __call = function(_, service, opts)
    return protocol_mod.new(service, opts)
  end,
})
