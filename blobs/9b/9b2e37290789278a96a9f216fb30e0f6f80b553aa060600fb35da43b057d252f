-- One operation call: its span, the retry loop, the protocol, and refresh-on-401.
-- Replaces Distilled's callOperation / callUntraced / applyRetry (api.ts) and the span
-- facts of telemetry.ts (operationInfo, readRules, annotateResponse).
--
--   operation.call(client, name, input) -> value, nil, meta | nil, err, meta
--
-- `client` is the internal state client.lua builds (see `operation.call` below for the
-- fields read). Input is never mutated: request.build and the paginator copy it.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local noop = require("distilled.trace.noop")
local retry = require("distilled.retry")
local schema = require("distilled.schema")
local secret = require("distilled.secret")

local operation = {}

local null = json.null

---------------------------------------------------------------------------------------
-- span facts (telemetry.ts operationInfo)
---------------------------------------------------------------------------------------

-- zoneId / zone-id / ZoneID -> zone_id, as Distilled spells label attributes
local function snake_case(name)
  local s = string.gsub(name, "([%l%d])(%u)", "%1_%2")
  s = string.gsub(s, "(%u+)(%u%l)", "%1_%2")
  s = string.gsub(s, "[^%w]+", "_")
  return string.lower(s)
end
operation._snake_case = snake_case

local function is_scalar(v)
  local t = type(v)
  return t == "string" or t == "number" or t == "boolean"
end

local function is_list(v)
  return type(v) == "table"
    and v ~= null
    and (json.is_array(v) or (#v > 0 and getmetatable(v) == nil))
end

local function field_of(value, path)
  local at = value
  for key in string.gmatch(path, "[^.]+") do
    if type(at) ~= "table" or at == null or secret.is(at) then
      return nil
    end
    at = rawget(at, key)
  end
  return at
end

-- a rule's value read from a member's value (telemetry.ts transform); nil records nothing
local function transform(rule, raw)
  local value = raw
  if rule.field ~= nil then
    value = field_of(raw, rule.field)
  end
  if value == nil or value == null or secret.is(value) then
    return nil
  end
  local t = rule.transform
  if t == nil then
    if is_scalar(value) then
      return value
    end
    if is_list(value) and #value > 0 then
      for i = 1, #value do
        if not is_scalar(value[i]) then
          return nil
        end
      end
      return value
    end
    return nil
  elseif t == "nonZero" then
    return (type(value) == "number" and value ~= 0) and value or nil
  elseif t == "list" then
    return type(value) == "string" and { value } or nil
  elseif t == "keys" then
    if type(value) ~= "table" then
      return nil
    end
    local ks = {}
    for k in pairs(value) do
      ks[#ks + 1] = tostring(k)
    end
    table.sort(ks)
    return ks
  elseif t == "count" then
    return is_list(value) and #value
      or (type(value) == "table" and json.is_array(value) and 0)
      or nil
  elseif t == "lastPathSegment" then
    return type(value) == "string" and (string.match(value, "([^/]*)$")) or nil
  elseif t == "arnResource" then
    return type(value) == "string" and (string.match(value, "([^:]*)$")) or nil
  elseif t == "arn" then
    return (type(value) == "string" and string.sub(value, 1, 4) == "arn:") and value or nil
  elseif t == "jsonList" then
    if is_list(value) then
      local out = {}
      for i = 1, #value do
        out[i] = json.encode(value[i]) or "null"
      end
      return out
    end
    if type(value) == "table" then
      return { json.encode(value) or "null" }
    end
    return nil
  end
  return nil
end
operation._transform = transform

local function flatten(rules)
  local out = {}
  if type(rules) ~= "table" then
    return out
  end
  local props = {}
  for property in pairs(rules) do
    props[#props + 1] = property
  end
  table.sort(props)
  for _, property in ipairs(props) do
    for _, rule in ipairs(rules[property]) do
      out[#out + 1] = { property, rule }
    end
  end
  return out
end

local function read_rules(rules, value, set)
  if #rules == 0 or type(value) ~= "table" or value == null or secret.is(value) then
    return
  end
  for _, pair in ipairs(rules) do
    local v = transform(pair[2], rawget(value, pair[1]))
    if v ~= nil then
      set(pair[2].name, v)
    end
  end
end

--- operation.info(service, op) -> { name, kind, attributes, input, output, response_headers }
-- From op.span (a string is just the op's model name) and service.telemetry, as
-- telemetry.ts derives them:
--   name          span.name, or <telemetry.prefix>.<op>, or op.name
--   rpc.method    span.method, or <telemetry.service>/<op>
--   url.template  the path of op.uri, unless telemetry.templates or span.template is false
--   input rules   each label member as <telemetry.labels>.<snake_case(name)>
--                 (telemetry.label_names[name] wins); span.input entries replace them
-- Fixed attributes: rpc.system.name = telemetry.system, telemetry.attributes, then
-- span.attributes (json.null drops one the service sets).
function operation.info(service, op)
  local telemetry = service.telemetry or {}
  local span = op.span
  if type(span) == "string" then
    span = { op = span }
  elseif type(span) ~= "table" then
    span = {}
  end
  local op_name = span.op
  local rules = span.input
  local template
  if op_name ~= nil then
    if telemetry.templates ~= false and span.template ~= false and type(op.uri) == "string" then
      template = string.match(op.uri, "^[^?]*")
    end
    if telemetry.labels ~= nil and op.input ~= nil then
      local node = schema.resolve(op.input, service.shapes)
      if node and node.t == "struct" then
        local derived = {}
        for _, m in ipairs(schema.plan(node).by_bind.label) do
          local names = telemetry.label_names or {}
          derived[m.name] =
            { { name = names[m.name] or (telemetry.labels .. "." .. snake_case(m.name)) } }
        end
        for k, v in pairs(rules or {}) do
          derived[k] = v
        end
        rules = derived
      end
    end
  end
  local attributes = {}
  if telemetry.system ~= nil then
    attributes["rpc.system.name"] = telemetry.system
  end
  for k, v in pairs(telemetry.attributes or {}) do
    attributes[k] = v
  end
  if template ~= nil then
    attributes["url.template"] = template
  end
  for k, v in pairs(span.attributes or {}) do
    if v == null then
      attributes[k] = nil
    else
      attributes[k] = v
    end
  end
  local method = span.method
  if method == nil and op_name ~= nil and telemetry.service ~= nil then
    method = telemetry.service .. "/" .. op_name
  end
  if method ~= nil then
    attributes["rpc.method"] = method
  end
  local name = span.name
  if name == nil and op_name ~= nil and telemetry.prefix ~= nil then
    name = telemetry.prefix .. "." .. op_name
  end
  return {
    name = name or op.name or "distilled.operation",
    kind = span.kind or "client",
    attributes = attributes,
    input = flatten(rules),
    output = flatten(span.output),
    response_headers = telemetry.response_headers or {},
  }
end

---------------------------------------------------------------------------------------
-- the call
---------------------------------------------------------------------------------------

-- one run of the retry loop over the protocol
local function run(client, name, op, input, span)
  local policy, settings = client.policy_for(name, op)
  local protocol = client.protocol
  local ctx_base = client.ctx
  local function attempt_fn(attempt)
    local ctx = {
      service = ctx_base.service,
      op_name = name,
      credentials = ctx_base.credentials,
      host = ctx_base.host,
      tracer = ctx_base.tracer,
      validation = ctx_base.validation,
      user_agent = ctx_base.user_agent,
      span = span,
      timeout = attempt.timeout,
      attempt = attempt,
    }
    return protocol.call(ctx, op, input)
  end
  return retry.run(attempt_fn, {
    policy = policy,
    host = ctx_base.host,
    tracer = ctx_base.tracer,
    span = span,
    deadline_s = settings.deadline_s,
    server_hint_cap_s = settings.server_hint_cap_s,
  })
end

-- the call with refresh-on-401: when it fails with Unauthorized and a credential source
-- is a function, the cache is cleared, the source resolved once more and the call
-- retried a single time
local function call_with_refresh(client, name, op, input, span)
  local value, err, meta = run(client, name, op, input, span)
  if value == nil and errors.is_tag(err, "Unauthorized") and client.refresh_credentials() then
    span:set("distilled.credentials.refreshed", true)
    value, err, meta = run(client, name, op, input, span)
  end
  return value, err, meta
end

local function annotate_response(info, span, meta)
  if not meta or type(meta.headers) ~= "table" then
    return
  end
  for _, rule in ipairs(info.response_headers) do
    local raw = meta.headers[string.lower(rule.header)]
    if raw ~= nil then
      local v = transform(rule, raw)
      if v ~= nil then
        span:set(rule.name, v)
      end
    end
  end
end

--- operation.call(client, name, input) -> value, nil, meta | nil, err, meta
-- client = { service, protocol, ctx = { service, credentials, host, tracer, validation,
--            user_agent }, trace = { tracer, depth }, info_for = fn(name, op) -> info,
--            policy_for = fn(name, op) -> policy, settings, refresh_credentials = fn() }
function operation.call(client, name, input)
  local op = client.service.ops[name]
  if op == nil then
    return nil, errors.new("SdkError", { message = "unknown operation " .. tostring(name) })
  end
  local holder = client.trace
  local tracer = holder.tracer
  if tracer.level == "off" then
    return call_with_refresh(client, name, op, input, noop.NOOP_SPAN)
  end

  local info = client.info_for(name, op)
  local attributes = {}
  for k, v in pairs(info.attributes) do
    attributes[k] = v
  end
  read_rules(info.input, input, function(k, v)
    attributes[k] = v
  end)
  holder.depth = holder.depth + 1
  local r = compat.pack(compat.pcall(function()
    return tracer:with(info.name, { kind = info.kind, attributes = attributes }, function(span)
      local value, err, meta = call_with_refresh(client, name, op, input, span)
      annotate_response(info, span, meta)
      if value ~= nil then
        read_rules(info.output, value, function(k, v)
          span:set(k, v)
        end)
      elseif type(err) == "table" and span.recording then
        -- the error points at its span in the trace file (tostring(err) shows it)
        err.trace_id = span.trace_id
      end
      return value, err, meta
    end)
  end))
  holder.depth = holder.depth - 1
  -- spans are exported when the outermost call on this tracer returns, so a Rex action
  -- never returns with spans still buffered
  if holder.depth == 0 then
    tracer:flush()
  end
  if not r[1] then
    error(r[2], 0)
  end
  return r[2], r[3], r[4]
end

---------------------------------------------------------------------------------------
-- streams (task 29): api.ts streamCall / makeStreaming
---------------------------------------------------------------------------------------

local STREAM_OPTS = { timeout = true, idle_timeout = true }

-- a host whose transport's stream/duplex entry points add the stream's own timeouts to
-- the request (curl_duplex reads max_time and idle_timeout), so no protocol needs to
-- know about them
local function stream_host(host, opts)
  if opts == nil or (opts.timeout == nil and opts.idle_timeout == nil) then
    return host
  end
  local base = host.transport
  if type(base) ~= "table" then
    return host
  end
  local function wrap(entry)
    local fn = rawget(base, entry)
    if fn == nil then
      return nil
    end
    return function(req)
      local copy = {}
      for k, v in pairs(req) do
        copy[k] = v
      end
      copy.max_time = opts.timeout
      copy.idle_timeout = opts.idle_timeout
      return fn(copy)
    end
  end
  local transport = setmetatable({ stream = wrap("stream"), duplex = wrap("duplex") }, {
    __call = function(_, req)
      return base(req)
    end,
  })
  local h = {}
  for k, v in pairs(host) do
    h[k] = v
  end
  h.transport = transport
  return h
end

-- the input `.stream()` sends: op.stream.set_input over the caller's (Distilled's
-- streamInput: Boat's executeSandboxCommand with stream = true)
local function stream_input(op, input)
  local fixed = op.stream.set_input
  if fixed == nil then
    return input
  end
  local copy = {}
  if type(input) == "table" then
    for k, v in pairs(input) do
      copy[k] = v
    end
    setmetatable(copy, getmetatable(input))
  end
  for k, v in pairs(fixed) do
    copy[k] = v
  end
  return copy
end

-- opens the stream under the retry loop. Retry happens only before the first item:
-- an attempt opens the transfer and reads the first item, so a failure there (a status,
-- a TransportError before any item) is retried as a call would be; an in-band error
-- (an error event, a bad frame) is the stream's first result, and after the first item
-- an error ends the stream. A duplex stream (input events) is not peeked: its server may wait for input.
local function open_stream(client, name, op, input, span, host)
  local policy, settings = client.policy_for(name, op)
  local protocol = client.protocol
  local ctx_base = client.ctx
  local peek = not (op.stream.input ~= nil)
  local function attempt_fn(attempt)
    local ctx = {
      service = ctx_base.service,
      op_name = name,
      credentials = ctx_base.credentials,
      host = host,
      tracer = ctx_base.tracer,
      validation = ctx_base.validation,
      user_agent = ctx_base.user_agent,
      span = span,
      timeout = attempt.timeout,
      attempt = attempt,
    }
    local parts, err, meta = protocol.stream(ctx, op, input)
    if parts == nil then
      return nil, err, meta
    end
    local opened = { parts = parts }
    if peek and not parts.send then
      local first, ferr = parts.next()
      if first == nil and ferr ~= nil then
        if errors.is_tag(ferr, "TransportError") then
          -- the connection failed before any item: retried like a failed call
          if parts.close then
            compat.pcall(parts.close)
          end
          return nil, ferr, meta
        end
        -- an answer from the server (an error event, a bad frame): the stream's first
        -- result, not retried
        opened.first_err = ferr
        return opened, nil, meta
      end
      opened.first = first
      opened.ended = first == nil
    end
    return opened, nil, meta
  end
  local opened, err, meta = retry.run(attempt_fn, {
    policy = policy,
    host = ctx_base.host,
    tracer = ctx_base.tracer,
    span = span,
    deadline_s = settings.deadline_s,
    server_hint_cap_s = settings.server_hint_cap_s,
  })
  if opened == nil and errors.is_tag(err, "Unauthorized") and client.refresh_credentials() then
    span:set("distilled.credentials.refreshed", true)
    opened, err, meta = retry.run(attempt_fn, {
      policy = policy,
      host = ctx_base.host,
      tracer = ctx_base.tracer,
      span = span,
      deadline_s = settings.deadline_s,
      server_hint_cap_s = settings.server_hint_cap_s,
    })
  end
  return opened, err, meta
end

--- operation.stream(client, name, input [, opts]) -> stream | nil, err
-- opts = { timeout = seconds (the whole transfer), idle_timeout = seconds (stop when
-- nothing arrives for that long; at least 1) }. One span covers the stream: it opens
-- with the call and ends at the last item, an error, or stream:close(); it records
-- distilled.stream.items and distilled.stream.end ("end" | "error" | "closed").
function operation.stream(client, name, input, opts)
  local stream_lib = require("distilled.stream")
  local op = client.service.ops[name]
  if op == nil then
    return nil, errors.new("SdkError", { message = "unknown operation " .. tostring(name) })
  end
  if type(op.stream) ~= "table" then
    return nil, errors.new("SdkError", { message = tostring(op.name) .. " does not stream" })
  end
  if opts ~= nil then
    if type(opts) ~= "table" then
      compat.raise(tostring(name) .. "_stream: options must be a table", 3)
    end
    for k, v in pairs(opts) do
      if not STREAM_OPTS[k] then
        compat.raise(
          tostring(name) .. "_stream: unknown option " .. tostring(k) .. " (timeout, idle_timeout)",
          3
        )
      end
      if type(v) ~= "number" then
        compat.raise(tostring(name) .. "_stream: option " .. k .. " must be a number of seconds", 3)
      end
    end
  end
  local protocol = client.protocol
  if type(protocol.stream) ~= "function" then
    -- api.ts cannotStream
    return nil,
      errors.new("SdkError", { message = tostring(op.name) .. ": its protocol can't stream" })
  end
  local host = stream_host(client.ctx.host, opts)
  input = stream_input(op, input)
  local holder = client.trace
  local tracer = holder.tracer
  if tracer.level == "off" then
    local opened, err = open_stream(client, name, op, input, noop.NOOP_SPAN, host)
    if opened == nil then
      return nil, err
    end
    return stream_lib.new(
      opened.parts,
      { first = opened.first, first_err = opened.first_err, ended = opened.ended }
    )
  end

  local info = client.info_for(name, op)
  local attributes = {}
  for k, v in pairs(info.attributes) do
    attributes[k] = v
  end
  read_rules(info.input, input, function(k, v)
    attributes[k] = v
  end)
  attributes["distilled.stream"] = true
  local span = tracer:start(info.name, { kind = info.kind, attributes = attributes })
  holder.depth = holder.depth + 1
  local r = compat.pack(compat.pcall(open_stream, client, name, op, input, span, host))
  holder.depth = holder.depth - 1
  -- the span stays open across pulls, off the tracer's stack (spans the caller starts
  -- between pulls are not its children)
  if tracer.detach then
    tracer:detach(span)
  end
  local function flush()
    if holder.depth == 0 then
      tracer:flush()
    end
  end
  if not r[1] then
    span:fail(errors.new("SdkError", { message = tostring(r[2]) }))
    span:finish()
    flush()
    error(r[2], 0)
  end
  local opened, err, meta = r[2], r[3], r[4]
  annotate_response(info, span, meta)
  if opened == nil then
    if type(err) == "table" and span.recording then
      err.trace_id = span.trace_id
    end
    span:fail(err)
    span:finish()
    flush()
    return nil, err
  end
  return stream_lib.new(opened.parts, {
    first = opened.first,
    first_err = opened.first_err,
    ended = opened.ended, -- an empty stream ends (with its span) at once
    on_end = function(e, count, reason)
      span:set("distilled.stream.items", count)
      span:set("distilled.stream.end", reason)
      if e ~= nil then
        if type(e) == "table" and span.recording then
          e.trace_id = span.trace_id
        end
        span:fail(e)
      end
      span:finish()
      flush()
    end,
  })
end

return operation
