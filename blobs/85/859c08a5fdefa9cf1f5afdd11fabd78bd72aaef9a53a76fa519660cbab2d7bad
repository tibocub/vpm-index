-- Cloudflare's client-v4 JSON protocol. Port of Distilled's packages/cloudflare/src/
-- protocol.ts (request building and the `{ success, errors, messages, result,
-- result_info }` envelope), credentials.ts (API token, or API key + email, from options
-- or the environment), errors.ts (UnknownCloudflareError, CloudflareParseError,
-- InvalidRoute) and jurisdiction.ts (the cf-r2-jurisdiction header).
--
--   local cloudflare = require("distilled.protocol.cloudflare")
--   local protocol = cloudflare.new{ unknown_tag = "UnknownCloudflareError",
--                                    parse_tag = "CloudflareParseError",
--                                    base_url_option = "base_url" }
--
-- It is the REST protocol (protocol/rest.lua: credentials, transport, spans, meta) with
-- its own `encode` and `decode`. Generated Cloudflare clients (gen/cloudflare.lua) use it.
--
-- Credentials (credentials.ts resolveFromEnv + formatHeaders). Client options first:
-- `api_token` -> authorization: Bearer <token>; else `api_key` and `email` -> x-auth-key
-- and x-auth-email (one without the other is a ConfigError). With none of the three set,
-- the same from CLOUDFLARE_API_TOKEN, CLOUDFLARE_API_KEY and CLOUDFLARE_EMAIL (read
-- through host.getenv on every request; an empty variable counts as unset). An OAuth
-- access token is an api_token (a function source re-resolves it on refresh).
--
-- Errors, in protocol.ts's order: a failure is status >= 400 or `success: false` in any
-- status; 1. the operation's typed errors (errors.match on the first envelope error,
-- its code 0 when it has none), 2. the global codes (971, 6003, 9103, 9106, 9109, 10000,
-- 10001, 7003, 1000), 3. throttling (429 or a rate-limit message), 4. the status class
-- (4xx in errors.STATUS_MAP; any 5xx), 5. UnknownCloudflareError. Transient
-- authentication blips ("Authentication error", "Unable to authenticate request", code
-- 10001 "internal error") are marked retryable on every path.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local keys = require("distilled.keys")
local redact = require("distilled.redact")
local regex = require("distilled.regex")
local request = require("distilled.request")
local rest = require("distilled.protocol.rest")
local retry = require("distilled.retry")
local schema = require("distilled.schema")
local secret = require("distilled.secret")
local url = require("distilled.url")
local validate = require("distilled.validate")

local cloudflare = {}

local null = json.null

cloudflare.DEFAULT_BASE_URL = "https://api.cloudflare.com/client/v4"
cloudflare.JURISDICTION_HEADER = "cf-r2-jurisdiction"
cloudflare.RESULT_INFO = "result_info"
-- Longest slice of a response body carried into an error message.
cloudflare.MAX_ERROR_BODY_LENGTH = 1000

--- InvalidRoute (errors.ts): code 7003, "invalid request: invalid route" -- a path
-- component (account or zone id) that is not a real resource. A model's own InvalidRoute
-- class has the same tag.
cloudflare.InvalidRoute = errors.define({ tag = "InvalidRoute" })

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

local function is_record(v)
  return type(v) == "table" and v ~= null and not json.is_array(v) and not secret.is(v)
end

-- Validation sees every union as `unknown`. Distilled's Cloudflare generator emits
-- unions with unionStyle "opaque-cases" (scripts/generate.ts): the schema is
-- `S.Unknown.pipe(T.UnionCases(...))`, so a validating mode accepts any value there --
-- Cloudflare returns every case's keys, null for the inactive ones, which no single
-- arm would accept. Decoding still picks an arm (keys.decode, schema.pick_arm).
-- The view is a lazy copy of the registry, built once per registry and node; registries
-- and nodes live as long as the generated service, so the caches stay bounded.
local OPAQUE = { t = "unknown" }
local opaque_nodes = {} -- original node -> node with unions replaced
local opaque_views = {} -- registry -> view registry
local MAX_INLINE_DEPTH = 32

local function opaque_node(node, depth)
  if type(node) ~= "table" or node.t == "ref" then
    return node
  end
  if node.t == "union" then
    return OPAQUE
  end
  local done = opaque_nodes[node]
  if done then
    return done
  end
  local t = node.t
  if depth > MAX_INLINE_DEPTH or (t ~= "struct" and t ~= "list" and t ~= "map") then
    return node
  end
  -- inline nesting only (named shapes are refs): bounded by the schema, not the data
  local copy = {}
  for k, v in pairs(node) do
    copy[k] = v
  end
  if t == "list" then
    copy.item = opaque_node(node.item, depth + 1)
  elseif t == "map" then
    copy.value = opaque_node(node.value, depth + 1)
  else
    local members = {}
    for i, m in ipairs(node.members or {}) do
      local mc = {}
      for k, v in pairs(m) do
        mc[k] = v
      end
      mc.schema = opaque_node(m.schema, depth + 1)
      members[i] = mc
    end
    copy.members = members
  end
  opaque_nodes[node] = copy
  return copy
end

local function opaque_view(registry)
  local view = opaque_views[registry]
  if view == nil then
    view = setmetatable({}, {
      __index = function(t, name)
        local n = registry[name]
        if n == nil then
          return nil
        end
        local c = opaque_node(n, 0)
        rawset(t, name, c)
        return c
      end,
    })
    opaque_views[registry] = view
  end
  return view
end
cloudflare.opaque_view = opaque_view

-- JavaScript /.../i: the patterns below are written in lower case and tested against the
-- lower-cased message (ASCII case folding; Cloudflare's messages are English).
local PATTERNS = {
  rate_limit = "\\b(rate ?limit(ed|ing)?|throttl(ed|ing) your request)\\b",
  blip = "authentication error|unable to authenticate request",
  internal_error = "internal error",
  auth_error = "authentication error",
  forbidden_retry = "internal error|unable to authenticate request",
  timeout = "\\btimeout\\b",
  internal_server = "internal (server )?error",
}
local compiled = {}
local function test(name, message)
  local re = compiled[name]
  if re == nil then
    local err
    re, err = regex.compile(PATTERNS[name])
    if not re then
      compat.raise("cloudflare: pattern " .. name .. ": " .. tostring(err and err.message), 2)
    end
    compiled[name] = re
  end
  return re:test(string.lower(message))
end
cloudflare._test_pattern = test

---------------------------------------------------------------------------------------
-- credentials (credentials.ts)
---------------------------------------------------------------------------------------

local function present(v)
  if v == nil then
    return nil
  end
  local raw = secret.unwrap(v)
  if raw == nil or raw == "" then
    return nil
  end
  return raw
end

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

--- cloudflare.auth_headers(creds, getenv) -> headers | nil, ConfigError
function cloudflare.auth_headers(creds, getenv)
  creds = creds or {}
  local token, key, email = present(creds.api_token), present(creds.api_key), present(creds.email)
  local from_env = token == nil and key == nil and email == nil
  if from_env then
    getenv = getenv or os.getenv
    token = present(getenv("CLOUDFLARE_API_TOKEN"))
    key = present(getenv("CLOUDFLARE_API_KEY"))
    email = present(getenv("CLOUDFLARE_EMAIL"))
  end
  if token ~= nil then
    return { authorization = "Bearer " .. tostring(token) }
  end
  if key ~= nil and email ~= nil then
    return { ["x-auth-key"] = tostring(key), ["x-auth-email"] = tostring(email) }
  end
  if key ~= nil then
    if from_env then
      return nil,
        config_error(
          "CLOUDFLARE_EMAIL environment variable is required when using CLOUDFLARE_API_KEY",
          "email"
        )
    end
    return nil, config_error("option email is required with api_key", "email")
  end
  if email ~= nil then
    if from_env then
      return nil,
        config_error(
          "CLOUDFLARE_API_KEY environment variable is required when using CLOUDFLARE_EMAIL",
          "api_key"
        )
    end
    return nil, config_error("option api_key is required with email", "api_key")
  end
  return nil,
    config_error(
      "Either CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY+CLOUDFLARE_EMAIL environment variables"
        .. " are required (or pass api_token, or api_key and email)",
      "api_token"
    )
end

---------------------------------------------------------------------------------------
-- request helpers
---------------------------------------------------------------------------------------

--- cloudflare.camel_to_snake(key): Distilled's unknownKeyToWire for Cloudflare
function cloudflare.camel_to_snake(key)
  return string.lower((string.gsub(key, "([a-z0-9])([A-Z])", "%1_%2")))
end

--- cloudflare.bearer_prefix(name, value): a member-supplied Authorization header is a raw
-- token (the asset-upload session JWT): Bearer-prefix it unless it already is
function cloudflare.bearer_prefix(name, value)
  if name == "authorization" and not string.find(string.lower(value), "^bearer%s") then
    return "Bearer " .. value
  end
  return value
end

-- hostFor: an op.host template with its {labels} filled from the input's label members
local function host_for(op, input, registry)
  local template = op.host
  local node = schema.resolve(op.input, registry)
  local host = template
  if node and node.t == "struct" then
    for _, m in ipairs(schema.plan(node).by_bind.label) do
      local value = type(input) == "table" and rawget(input, m.name) or nil
      if value ~= nil then
        local wire = m.wire or m.name
        host = url.fill(host, wire, url.encode_component(url.text(secret.unwrap(value))), false)
      end
    end
  end
  local unset = string.match(host, "{([^}]+)}")
  if unset then
    return nil,
      errors.new("InvalidInput", {
        member = unset,
        message = "the host label " .. unset .. " is required (host " .. template .. ")",
      })
  end
  return host
end

-- FormDataFile members: each file is its own part named after its filename ("file" when
-- it has none), after the other parts. The values move to input keys of those names,
-- which request.build sends as parts as they are (see `file_keys` below).
local function lift_form_files(op, input, registry)
  local node = schema.resolve(op.input, registry)
  if not (node and node.t == "struct") or type(input) ~= "table" then
    return input, nil
  end
  local out, names
  for _, m in ipairs(node.members or {}) do
    if m.form_file and rawget(input, m.name) ~= nil then
      if out == nil then
        out = {}
        for k, v in pairs(input) do
          out[k] = v
        end
        names = {}
      end
      local value = rawget(input, m.name)
      out[m.name] = nil
      local list = (type(value) == "table" and (json.is_array(value) or value[1] ~= nil)) and value
        or { value }
      for i = 1, #list do
        local f = list[i]
        local filename = type(f) == "table" and rawget(f, "filename") or nil
        if type(filename) ~= "string" or filename == "" then
          filename = "file"
        end
        if out[filename] ~= nil and not names[filename] then
          return nil,
            errors.new("InvalidInput", {
              member = m.name,
              message = "the file name " .. filename .. " is also an input member",
            })
        end
        out[filename] = f
        names[filename] = true
      end
    end
  end
  return out or input, names
end

---------------------------------------------------------------------------------------
-- response helpers
---------------------------------------------------------------------------------------

-- envelopeErrorMessage: errors[1].message, a top-level message, the errors entries as
-- JSON, the raw text of an unfamiliar shape (1000 characters at most), or HTTP <status>
local function envelope_error_message(body, raw_errors, text, status)
  local first = raw_errors[1]
  if type(first) == "table" and type(rawget(first, "message")) == "string" then
    return first.message
  end
  local top = is_record(body) and rawget(body, "message") or nil
  if type(top) == "string" and top ~= "" then
    return top
  end
  local detail
  if #raw_errors > 0 then
    detail = json.encode(json.array(raw_errors)) or ""
  elseif (is_record(body) and json.is_array(rawget(body, "errors"))) or trim(text) == "" then
    detail = ""
  else
    detail = text
  end
  if detail ~= "" then
    return string.sub(detail, 1, cloudflare.MAX_ERROR_BODY_LENGTH)
  end
  return "HTTP " .. tostring(status)
end

-- numbers in response headers: Number(raw) unless blank (withResponseHeaders)
local function header_value(member, raw, registry)
  local node = schema.resolve(member.schema, registry)
  if node and node.t == "number" and trim(raw) ~= "" then
    local n = retry._js_number(raw)
    if n ~= nil then
      return n
    end
  end
  return raw
end

local function with_response_headers(plan, result, headers, registry)
  for _, m in ipairs(plan.by_bind.header or {}) do
    local raw = headers[string.lower(m.wire or m.name)]
    if raw ~= nil then
      result[m.name] = header_value(m, raw, registry)
    end
  end
  return result
end

---------------------------------------------------------------------------------------
-- the protocol
---------------------------------------------------------------------------------------

--- cloudflare.new(opts) -> protocol
-- opts = { unknown_tag, parse_tag, base_url_option = "base_url", user_agent }
function cloudflare.new(opts)
  opts = opts or {}
  if type(opts) ~= "table" then
    compat.raise("cloudflare.new: expected an options table", 2)
  end
  local base_option = opts.base_url_option or "base_url"
  local protocol = rest.new({
    base_url = cloudflare.DEFAULT_BASE_URL,
    unknown_tag = opts.unknown_tag or "UnknownCloudflareError",
    parse_tag = opts.parse_tag or "CloudflareParseError",
    user_agent = opts.user_agent,
  })
  local unknown_class = protocol.unknown_class
  local parse_class = protocol.parse_class

  local class_cache = {}
  local function classes_of(service, op)
    local list = class_cache[op]
    if list then
      return list
    end
    list = {}
    local declared = (service and service.errors) or {}
    for _, name in ipairs(op.errors or {}) do
      local class = declared[name] or errors.classes[name]
      if errors.is_class(class) then
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

  --- protocol.encode(ctx, op, input [, creds]) -> request | nil, err
  function protocol.encode(ctx, op, input, creds)
    ctx = ctx or {}
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
    local host = ctx.host or {}
    local headers, herr = cloudflare.auth_headers(creds, host.getenv)
    if not headers then
      return nil, herr
    end
    -- the client's jurisdiction, for operations that take one; a `jurisdiction` member
    -- on the call is a header too, and wins (request.build sets member headers last)
    local jurisdiction = present(creds.jurisdiction)
    if op.jurisdiction and jurisdiction ~= nil then
      headers[cloudflare.JURISDICTION_HEADER] = tostring(jurisdiction)
    end
    local service = ctx.service or {}
    local registry = service.shapes
    local base = creds[base_option]
    if base == nil or base == "" then
      base = cloudflare.DEFAULT_BASE_URL
    end
    if op.host then
      local h, err = host_for(op, input, registry)
      if not h then
        return nil, err
      end
      base = h
    end
    local file_keys
    input, file_keys = lift_form_files(op, input, registry)
    if input == nil then
      return nil, file_keys
    end
    return request.build({
      op = op,
      input = input,
      registry = registry,
      base_url = base,
      headers = headers,
      map_member_header = cloudflare.bearer_prefix,
      unknown_key_to_wire = function(key)
        if file_keys and file_keys[key] then
          return key
        end
        return cloudflare.camel_to_snake(key)
      end,
      host = ctx.host,
    })
  end

  -- a failed response -> the error (protocol.ts decodeResponse, `failed` branch)
  local function decode_failure(ctx, op, status, headers, text, body, non_json)
    local raw_errors = {}
    if not non_json and is_record(body) then
      local list = rawget(body, "errors")
      local single = rawget(body, "error")
      if json.is_array(list) then
        raw_errors = list
      elseif is_record(single) then
        -- K2's produce endpoint answers with a single `error: { code, message }`
        raw_errors = { single }
      end
    end
    local first = raw_errors[1]
    -- Cloudflare sometimes omits the code (webhook errors): 0, so { code = 0 } matches
    local code
    if first ~= nil then
      code = (type(first) == "table" and type(rawget(first, "code")) == "number") and first.code
        or 0
    end
    local message = non_json and text or envelope_error_message(body, raw_errors, text, status)
    local wire_body = non_json and text or body
    local now = ctx.host and ctx.host.epoch and ctx.host.epoch() or os.time()

    local blip = test("blip", message) or (code == 10001 and test("internal_error", message))
    local function tag_blip(err)
      if blip then
        err.retryable = true
      end
      return err
    end

    -- 1. the operation's typed errors
    local typed = errors.match(classes_of(ctx.service, op), {
      status = status,
      errors = { { code = code, message = message } },
      body = wire_body,
      headers = headers,
    })
    if typed then
      -- matchTypedError builds the class with `code: best.code ?? 0` (an envelope-less
      -- 404 matched by a status matcher still has code 0)
      if typed.code == nil then
        typed.code = 0
      end
      return tag_blip(typed)
    end

    -- 2. global codes, on any endpoint and under any status (GLOBAL_ERROR_CODE_MAP)
    if code == 971 then
      return tag_blip(errors.new("TooManyRequests", {
        message = message,
        status = status,
        retry_after = retry.parse_server_hint(headers, now),
      }))
    elseif code == 6003 or code == 9103 or code == 9106 or code == 9109 then
      return tag_blip(errors.new("Unauthorized", { message = message, status = status }))
    elseif code == 10000 then
      -- valid tokens are rejected with "Authentication error" under high concurrency
      local err = errors.new("Unauthorized", { message = message, status = status })
      if test("auth_error", message) then
        err.retryable = true
      end
      return tag_blip(err)
    elseif code == 10001 then
      -- "Method not allowed for token" is a real denial; the other two are hiccups
      local err = errors.new("Forbidden", { message = message, status = status })
      if test("forbidden_retry", message) then
        err.retryable = true
      end
      return tag_blip(err)
    elseif code == 7003 then
      return tag_blip(
        errors.new(cloudflare.InvalidRoute, { code = 7003, message = message, status = status })
      )
    elseif code == 1000 then
      if test("timeout", message) then
        return tag_blip(errors.new("GatewayTimeout", { message = message, status = status }))
      elseif test("internal_server", message) then
        return tag_blip(errors.new("InternalServerError", { message = message, status = status }))
      end
      return tag_blip(errors.new(unknown_class, {
        status = status,
        code = 1000,
        message = message,
        body = wire_body,
        headers = headers,
      }))
    end

    -- 3. throttling: 429, or the rate-limit message under any status (often 200)
    if status == 429 or test("rate_limit", message) then
      return errors.new("TooManyRequests", {
        message = message,
        status = status,
        retry_after = retry.parse_server_hint(headers, now),
      })
    end

    -- 4. the status classes: mapped 4xx; any 5xx (unmapped ones, Cloudflare's 520-530,
    -- are InternalServerError)
    if status >= 400 and status < 500 and errors.STATUS_MAP[status] then
      return tag_blip(errors.new(errors.STATUS_MAP[status], {
        message = message,
        status = status,
        headers = headers,
        retry_after = retry.parse_for_status(status, headers, now),
      }))
    end
    if status >= 500 then
      local class = errors.STATUS_MAP[status] or errors.InternalServerError
      return errors.new(class, {
        message = message,
        status = status,
        headers = headers,
        retry_after = retry.parse_for_status(status, headers, now),
      })
    end

    -- 5. an unknown envelope error
    return errors.new(unknown_class, {
      status = status,
      code = code,
      message = message,
      body = wire_body,
      headers = headers,
    })
  end

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    ctx = ctx or {}
    local status = res.status
    local headers = res.headers or {}
    local text = res.body or ""
    if type(text) ~= "string" then
      text = tostring(text)
    end
    local service = ctx.service or {}
    local registry = service.shapes
    local output = op.output
    local node = output and schema.resolve(output, registry) or nil
    local plan = (node and node.t == "struct") and schema.plan(node) or nil

    -- a raw binary response (BinaryResponseBody: a Blob payload member): the body bytes
    -- and the header members; error statuses take the envelope path below
    if status < 400 and plan then
      local binary
      for _, m in ipairs(plan.by_bind.payload) do
        local mn = schema.resolve(m.schema, registry)
        if mn and mn.t == "blob" then
          binary = binary or m
        end
      end
      if binary then
        local result = json.object({ [binary.name] = text })
        for _, m in ipairs(plan.by_bind.status) do
          result[m.name] = status
        end
        return with_response_headers(plan, result, headers, registry)
      end
    end

    -- read as text and parse tolerantly: HTML 5xx pages and plain-text 4xx exist
    local body = json.object({})
    local non_json = false
    if trim(text) ~= "" then
      local v = json.decode(text)
      if type(v) == "table" and v ~= null then
        body = v
      else
        non_json = true
      end
    end

    local failed = status >= 400
      or (not non_json and is_record(body) and rawget(body, "success") == false)
    if failed then
      return nil, decode_failure(ctx, op, status, headers, text, body, non_json)
    end
    if output == nil then
      return json.object({})
    end

    local mode = ctx.validation or "lenient"
    local wire_body = non_json and text or body
    local sensitive = redact.holds_sensitive(output, registry)
    local function finish(value)
      if non_json and sensitive then
        return nil, parse_error(op, "[REDACTED]", "Invalid JSON response")
      end
      if mode ~= "lenient" then
        local ok, mismatch = validate.check(
          opaque_node(output, 0),
          value,
          opaque_view(registry),
          { exact = mode == "strict" }
        )
        if not ok then
          if sensitive then
            return nil, parse_error(op, "[REDACTED]", validate.withhold(mismatch))
          end
          return nil, parse_error(op, wire_body, mismatch)
        end
      end
      if sensitive then
        return redact.wrap(output, value, registry)
      end
      return value
    end

    -- the payload is `result`; a body without one is the payload itself; a non-JSON
    -- success body is the payload verbatim (security.txt's bare sentinel)
    local payload
    if non_json then
      payload = text
    elseif is_record(body) and rawget(body, "result") ~= nil then
      payload = rawget(body, "result")
    else
      payload = body
    end

    -- a bare-payload output (EnvelopePayloadRoot): the value is `result` itself
    if op.output_raw or not plan then
      return finish(keys.decode(output, payload, registry))
    end
    -- a non-JSON body for a struct output: lenient returns the text, strict fails it
    if non_json then
      return finish(text)
    end

    local result = json.object({})
    local consumed = {}
    local whole = false
    local fallback = op.fallback_wire or {}
    for _, m in ipairs(plan.members) do
      local bind = m.bind or "body"
      if op.pagination and m.name == cloudflare.RESULT_INFO then
        local info = is_record(body) and rawget(body, "result_info") or nil
        if info ~= nil then
          result[m.name] = keys.decode(m.schema, info, registry)
        end
      elseif bind == "payload" then
        whole = true
        result[m.name] = keys.decode(m.schema, payload, registry)
      elseif bind == "header" then
        -- filled from the response headers below
      elseif bind == "status" then
        result[m.name] = status
      elseif is_record(payload) then
        -- the schema's wire name, then the key dictionary's (gen/cloudflare.lua)
        local wire = m.wire or m.name
        local src
        if rawget(payload, wire) ~= nil then
          src = wire
        elseif fallback[m.name] ~= nil and rawget(payload, fallback[m.name]) ~= nil then
          src = fallback[m.name]
        end
        if src ~= nil then
          consumed[src] = true
          result[m.name] = keys.decode(m.schema, rawget(payload, src), registry)
        end
      end
    end
    if not whole and #plan.members > 0 and is_record(payload) and mode == "strict" then
      local extra = {}
      for k in pairs(payload) do
        if not consumed[k] then
          extra[#extra + 1] = tostring(k)
        end
      end
      table.sort(extra)
      if extra[1] ~= nil then
        return nil,
          parse_error(op, wire_body, {
            path = { extra[1] },
            expected = "no value (the schema does not model this key)",
            actual = rawget(payload, extra[1]),
            message = "no value (the schema does not model this key)",
          })
      end
    end
    return finish(with_response_headers(plan, result, headers, registry))
  end

  return protocol
end

-- The provider spec's protocol module contract: require(module)(service, spec) -> protocol.
return setmetatable(cloudflare, {
  __call = function(_, _, spec)
    return cloudflare.new(spec)
  end,
})
