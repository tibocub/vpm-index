-- GraphQL clients: the configuration a run needs (credentials, host, retry, tracing) and
-- the transport that posts one compiled document. Replaces each Distilled GraphQL
-- package's hand-written graphql-transport.ts (GqlTransport) and credentials.ts, and the
-- `execute` step of core graphql.ts (retries, the document span).
--
--   local Class = GraphQLClient.define{
--     name = "Linear",                       -- class name, messages
--     transport = { ... },                   -- the provider's transport facts (below)
--     telemetry = { system, prefix, response_headers, fields, propagate } | nil,
--     options = { api_key = { secret = true }, base_url = { type = "string" } },
--   }
--   local client = Class.new{ api_key = key, host = host }
--   local value, err = client:run(plan)              -- plan: a Query, a table of them,
--                                                    -- or a function returning one
--   for team in client:items(Linear.teams({ first = 50 })) do ... end
--   local pages = client:pages(query)                -- a list of items per page
--
-- Built on distilled.client (Client.define with no operations), so `new`, `with`,
-- `close`, the common options (host, retry, deadline_s, tracing, tracer, user_agent, ...)
-- and the credential cells are the REST clients' own.
--
-- transport = {
--   name = "Linear",                         -- in error messages ("Linear HTTP 500 ...")
--   url = "https://api.fly.io/graphql"       -- a fixed endpoint, or
--     or { option = "base_url", env = "LINEAR_API_URL", default = "https://api.linear.app",
--          path = "/graphql", strip = "/v3" },   -- base (one trailing / and `strip` removed)
--                                                -- .. path
--   accept = "application/json",
--   auth = { { option = "api_key", env = { "LINEAR_API_KEY" }, header = "authorization",
--              prefix = "Bearer ", trim = true, skip_empty = true }, ... },
--             -- the first option (or env variable) with a value wins
--   missing = "LINEAR_API_KEY ... is required",  -- ConfigError message when none has one
--   user_agent = { env = "GITHUB_USER_AGENT", default = "distilled.cloud-github" } | nil,
--   error_type_code = true | nil,            -- GitHub: a top-level `type` is the code
--   http_detail = { "message", "error" } | nil,  -- body fields an HTTP failure names
-- }
local Client = require("distilled.client")
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local graphql = require("distilled.graphql")
local json = require("distilled.json")
local noop = require("distilled.trace.noop")
local retry = require("distilled.retry")
local secret = require("distilled.secret")

local M = {}

local null = json.null
local EMPTY = {}

M.USER_AGENT = "distilled-lua/0.1.0"

-- Query retries (graphql.ts execute): Schedule.exponential("200 millis"), at most 5
M.RETRY = {
  base_ms = 200,
  factor = 2,
  cap_ms = 2 ^ 40,
  max_retries = 5,
}

---------------------------------------------------------------------------------------
-- small helpers
---------------------------------------------------------------------------------------

local function lower_headers(h)
  local out = {}
  if type(h) ~= "table" then
    return out
  end
  for k, v in pairs(h) do
    out[type(k) == "string" and string.lower(k) or k] = v
  end
  return out
end

local function host_and_port(target)
  local host = retry.host_of(target)
  local authority = string.match(target, "^%a[%w+.-]*://([^/?#]*)") or ""
  authority = string.gsub(authority, "^.*@", "")
  local port = string.match(authority, ":(%d+)$")
  if port then
    return host, tonumber(port)
  end
  return host, string.find(target, "^https") and 443 or 80
end

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

local function is_record(v)
  return type(v) == "table" and v ~= null and not json.is_array(v) and not secret.is(v)
end

local function transport_error(fields)
  return errors.new(graphql.GraphQLTransportError, fields)
end

local function contract_error(res)
  local what
  if res == nil then
    what = "returned nothing (neither a response table nor nil, err)"
  elseif type(res) == "function" then
    what = "returned a function, so it is probably a transport constructor, not a transport"
  else
    what = "returned a " .. type(res) .. " instead of a response table"
  end
  return errors.new("ConfigError", {
    message = "the transport " .. what .. "; " .. require("distilled.host").TRANSPORT_HINT,
    key = "transport",
  })
end

---------------------------------------------------------------------------------------
-- the request (graphql-transport.ts)
---------------------------------------------------------------------------------------

-- the value of an option, else the first non-empty environment variable
local function option_or_env(creds, host, option, envs)
  local v = creds[option]
  if v ~= nil then
    return v
  end
  for _, name in ipairs(envs or EMPTY) do
    local e = host.getenv and host.getenv(name)
    if type(e) == "string" and e ~= "" then
      return e
    end
  end
  return nil
end

local function endpoint(spec, creds, host)
  local u = spec.url
  if type(u) == "string" then
    return u
  end
  local base = option_or_env(creds, host, u.option, { u.env }) or u.default
  base = string.gsub(tostring(secret.unwrap(base)), "/$", "")
  if u.strip and string.sub(base, -#u.strip) == u.strip then
    base = string.sub(base, 1, #base - #u.strip)
  end
  return base .. (u.path or "")
end

-- the auth header: the first credential with a value (credentials.ts precedence)
local function auth_header(spec, creds, host)
  local list = spec.auth or EMPTY
  if #list == 0 then
    return nil
  end
  for _, a in ipairs(list) do
    local v = option_or_env(creds, host, a.option, a.env)
    if v ~= nil then
      local token = secret.unwrap(v)
      if type(token) ~= "string" then
        return nil,
          errors.new("ConfigError", {
            message = "option " .. a.option .. " must be a string",
            key = a.option,
          })
      end
      if a.trim then
        token = trim(token)
      end
      if a.skip_empty and token == "" then
        return false
      end
      return { a.header, (a.prefix or "") .. token }
    end
  end
  return nil,
    errors.new("ConfigError", {
      message = spec.missing or (list[1].option .. " is required"),
      key = list[1].option,
    })
end

-- GitHub puts an error's code in a top-level `type` (graphql-transport.ts normalizeError)
local function normalize_type_code(entry)
  if not is_record(entry) or type(entry.type) ~= "string" then
    return entry
  end
  local ext = entry.extensions
  if is_record(ext) and type(ext.code) == "string" then
    return entry
  end
  local copy = {}
  for k, v in pairs(entry) do
    copy[k] = v
  end
  local ext_copy = {}
  if is_record(ext) then
    for k, v in pairs(ext) do
      ext_copy[k] = v
    end
  end
  ext_copy.code = entry.type
  copy.extensions = ext_copy
  return copy
end

--- M.send(spec, ctx, compiled) -> response | nil, err
-- response = { data, errors, status, headers }: what core graphql.ts classifies.
-- ctx = { credentials = fn, host, tracer, span, attempt, timeout, user_agent, propagate }
function M.send(spec, ctx, compiled)
  local tracer = ctx.tracer or noop
  local span = ctx.span or noop.NOOP_SPAN
  local host = ctx.host or EMPTY
  local attempt = ctx.attempt or {}
  local name = spec.name or "GraphQL"

  local creds, cerr = tracer:with("distilled.credentials", { debug = true }, function()
    return ctx.credentials()
  end)
  if creds == nil then
    return nil, cerr
  end
  local auth, aerr = auth_header(spec, creds, host)
  if auth == nil and aerr ~= nil then
    return nil, aerr
  end
  local url = endpoint(spec, creds, host)
  local body, jerr = json.encode(graphql.request_body(compiled))
  if body == nil then
    return nil,
      errors.new(graphql.GqlError, {
        message = "the variables cannot be sent as JSON: " .. tostring(jerr and jerr.message),
      })
  end
  local headers = {
    ["content-type"] = "application/json",
    accept = spec.accept or "application/json",
  }
  if auth then
    headers[string.lower(auth[1])] = auth[2]
  end
  local ua = ctx.user_agent
  if ua == nil and spec.user_agent then
    ua = option_or_env(EMPTY, host, nil, { spec.user_agent.env }) or spec.user_agent.default
  end
  headers["user-agent"] = ua or M.USER_AGENT
  if ctx.propagate == "w3c" then
    local tp = tracer:traceparent()
    if tp then
      headers.traceparent = tp
    end
  end
  local req = { method = "POST", url = url, headers = headers, body = body, timeout = ctx.timeout }

  local server, port = host_and_port(url)
  span:set("http.request.method", "POST")
  span:set("server.address", server)
  span:set("server.port", port)
  attempt.host = server

  local transport = host.transport
  if transport == nil then
    return nil,
      errors.new("ConfigError", {
        message = "no transport; " .. require("distilled.host").TRANSPORT_HINT,
        key = "transport",
      })
  end
  local res, terr = tracer:with("distilled.transport", {
    debug = true,
    attributes = { ["http.request.method"] = "POST", ["server.address"] = server },
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
  if type(res) ~= "table" or type(res.status) ~= "number" then
    return nil,
      transport_error({
        message = name .. " GraphQL HTTP request failed",
        cause = terr or "the transport returned no status",
      })
  end
  local status = res.status
  local rheaders = lower_headers(res.headers)
  attempt.status = status
  span:set("http.response.status_code", status)
  local retry_after = graphql._retry_after_seconds(rheaders["retry-after"])
  local meta = { status = status, headers = rheaders }
  local text = res.body or ""
  if type(text) ~= "string" then
    text = tostring(text)
  end
  local parsed, perr = json.decode(text)
  if parsed == nil then
    return nil,
      transport_error({
        message = status >= 400
            and (name .. " HTTP " .. status .. " returned a non-GraphQL response")
          or (name .. " GraphQL response is not JSON"),
        status = status,
        retry_after = retry_after,
        cause = perr,
      }),
      meta
  end
  local envelope = is_record(parsed) and parsed or EMPTY
  local list = {}
  if json.is_array(envelope.errors) then
    for i = 1, #envelope.errors do
      local e = envelope.errors[i]
      list[i] = spec.error_type_code and normalize_type_code(e) or e
    end
  end
  if status >= 400 and #list == 0 then
    local detail
    for _, field in ipairs(spec.http_detail or EMPTY) do
      if type(envelope[field]) == "string" then
        detail = envelope[field]
        break
      end
    end
    return nil,
      transport_error({
        message = detail and (name .. " HTTP " .. status .. ": " .. detail)
          or (name .. " HTTP " .. status .. " returned no GraphQL errors"),
        status = status,
        retry_after = retry_after,
      }),
      meta
  end
  return {
    data = envelope.data,
    errors = json.array(list),
    status = status,
    headers = rheaders,
  },
    nil,
    meta
end

---------------------------------------------------------------------------------------
-- the document span (graphql.ts documentInfo)
---------------------------------------------------------------------------------------

local function transform(rule, value)
  return require("distilled.operation")._transform(rule, value)
end

--- M.document_info(telemetry, compiled) -> { name, attributes, input = { { name, value } } }
-- One span per document: <prefix>.<rootField>, or <prefix>.<kind> when the document
-- selects several root fields. Arguments named by the telemetry `fields` rules become
-- attributes (never a secret: arguments passed as secrets are skipped).
function M.document_info(telemetry, compiled)
  local roots, seen = {}, {}
  for _, node in ipairs(compiled.tree.children) do
    if not seen[node.field] then
      seen[node.field] = true
      roots[#roots + 1] = node.field
    end
  end
  local single = #roots == 1 and roots[1] or nil
  local target = single or compiled.kind
  local prefix = telemetry.prefix or "GraphQL"
  local attributes = {}
  if telemetry.system ~= nil then
    attributes["rpc.system.name"] = telemetry.system
  end
  for k, v in pairs(telemetry.attributes or EMPTY) do
    attributes[k] = v
  end
  attributes["graphql.operation.type"] = compiled.kind
  if single then
    attributes["graphql.operation.name"] = single
  end
  attributes["rpc.method"] = prefix .. "/" .. target
  local input = {}
  for _, node in ipairs(compiled.tree.children) do
    local field_rules = telemetry.fields and telemetry.fields[compiled.kind .. "." .. node.field]
    if field_rules and node.args then
      for _, a in ipairs(node.args) do
        local rules = field_rules[a[1]]
        local raw = compiled.raw_variables and compiled.raw_variables[a[2]]
        if raw == nil then
          raw = compiled.variables[a[2]]
        end
        for _, rule in ipairs(rules or EMPTY) do
          local v = transform(rule, raw)
          if v ~= nil then
            input[#input + 1] = { rule.name, v }
          end
        end
      end
    end
  end
  return { name = prefix .. "." .. target, attributes = attributes, input = input }
end

local function annotate_response(telemetry, span, meta)
  if not meta or type(meta.headers) ~= "table" then
    return
  end
  for _, rule in ipairs(telemetry.response_headers or EMPTY) do
    local raw = meta.headers[string.lower(rule.header)]
    if raw ~= nil then
      local v = transform(rule, raw)
      if v ~= nil then
        span:set(rule.name, v)
      end
    end
  end
end

---------------------------------------------------------------------------------------
-- retries
---------------------------------------------------------------------------------------

-- the policy for one document: queries retry (graphql.ts execute), mutations never do
-- (an error can follow a side effect that already happened). The client's `retry`
-- option replaces the numbers; a preset named "none" (or max_retries = 0) turns it off.
local function policy_for(opts, compiled)
  local p = {
    when = function(err)
      return graphql.is_retryable(compiled, err)
    end,
    base_ms = M.RETRY.base_ms,
    factor = M.RETRY.factor,
    cap_ms = M.RETRY.cap_ms,
    max_retries = M.RETRY.max_retries,
  }
  local settings = {}
  local spec = opts.retry
  if spec ~= nil then
    local base = retry.policy_for(spec, nil)
    if base.name == "none" then
      p.max_retries = 0
    elseif base.name ~= "default" then
      -- a preset or the caller's own numbers; `when` stays GraphQL's unless given
      for _, k in ipairs({ "base_ms", "factor", "cap_ms", "max_retries", "jitter_ms" }) do
        if base[k] ~= nil then
          p[k] = base[k]
        end
      end
      p.full_jitter = base.full_jitter
      if type(spec) == "table" and not retry.is_preset(spec) and spec.when ~= nil then
        p.when = spec.when
      end
    end
    if type(spec) == "table" and not retry.is_preset(spec) then
      settings.deadline_s = spec.deadline_s
    end
  end
  settings.deadline_s = settings.deadline_s or opts.deadline_s
  if compiled.kind ~= "query" then
    p.max_retries = 0
  end
  return p, settings
end
M._policy_for = policy_for

---------------------------------------------------------------------------------------
-- execute: one compiled document, its span and its retries
---------------------------------------------------------------------------------------

local function execute(class, state, compiled)
  local ctx = state.ctx
  local holder = state.trace
  local tracer = holder.tracer
  local telemetry = class.telemetry
  local policy, settings = policy_for(state.opts, compiled)

  local function attempts(span)
    return retry.run(function(attempt)
      local response, err, meta = M.send(class.transport, {
        credentials = ctx.credentials,
        host = ctx.host,
        tracer = tracer,
        span = span,
        attempt = attempt,
        timeout = attempt.timeout,
        user_agent = ctx.user_agent,
        propagate = telemetry and telemetry.propagate,
      }, compiled)
      if response == nil then
        return nil, err, meta
      end
      local data, rerr = graphql.result(compiled, response)
      return data, rerr, meta
    end, {
      policy = policy,
      host = ctx.host,
      tracer = tracer,
      span = span,
      deadline_s = settings.deadline_s,
    })
  end

  if telemetry == nil or tracer.level == "off" then
    local data, err = attempts(noop.NOOP_SPAN)
    return data, err
  end
  local info = M.document_info(telemetry, compiled)
  local attributes = {}
  for k, v in pairs(info.attributes) do
    attributes[k] = v
  end
  for _, pair in ipairs(info.input) do
    attributes[pair[1]] = pair[2]
  end
  holder.depth = holder.depth + 1
  local r = compat.pack(compat.pcall(function()
    return tracer:with(info.name, { kind = "client", attributes = attributes }, function(span)
      local data, err, meta = attempts(span)
      annotate_response(telemetry, span, meta)
      if data == nil and type(err) == "table" and span.recording then
        err.trace_id = span.trace_id
      end
      return data, err
    end)
  end))
  holder.depth = holder.depth - 1
  if holder.depth == 0 then
    tracer:flush()
  end
  if not r[1] then
    error(r[2], 0)
  end
  return r[2], r[3]
end
M._execute = execute

---------------------------------------------------------------------------------------
-- define
---------------------------------------------------------------------------------------

local function unused_protocol()
  return nil, errors.new("SdkError", { message = "a GraphQL client has no REST operations" })
end

--- M.define{ name, transport, telemetry, options } -> Class
function M.define(spec)
  if type(spec) ~= "table" or type(spec.transport) ~= "table" then
    compat.raise("graphql.client.define: expected { name, transport, telemetry, options }", 2)
  end
  local name = spec.name or "GraphQL"
  local class = Client.define({
    name = name,
    service = { name = name, ops = {} },
    protocol = { call = unused_protocol },
    options = spec.options or {},
  })
  class.transport = spec.transport
  class.telemetry = spec.telemetry
  local methods = class.methods
  local mt = class.mt

  local function check_self(self, method)
    if getmetatable(self) ~= mt then
      compat.raise(
        name .. ": call client:" .. method .. "(...) with a colon, not client." .. method .. "(...)",
        3
      )
    end
  end

  local function executor(self)
    local state = self._state
    return function(compiled)
      return execute(class, state, compiled)
    end
  end

  --- client:run(plan, ...) -> value | nil, err. plan: a Query, a table holding Queries
  -- (any depth) and plain values, or a function returning one (called with ...).
  methods.run = function(self, plan, ...)
    check_self(self, "run")
    if type(plan) == "function" then
      plan = plan(...)
    end
    return graphql.evaluate(plan, executor(self))
  end

  --- client:pages(query) -> iterator over the pages of a Relay connection (each page a
  -- list of items, one request per page)
  methods.pages = function(self, query)
    check_self(self, "pages")
    return graphql.pages(query, executor(self), "pages")
  end

  --- client:items(query) -> iterator over every item of a Relay connection
  methods.items = function(self, query)
    check_self(self, "items")
    return graphql.pages(query, executor(self), "items")
  end

  --- client:compile(plan) -> compiled | false | nil, err: the document a run would send
  methods.compile = function(self, plan)
    check_self(self, "compile")
    return graphql.compile(plan)
  end

  return class
end

return M
