-- Connect unary calls over JSON (connectrpc.com), as Distilled's e2b and namespacelabs
-- SDKs make them: plain REST through distilled.protocol.rest. Each RPC is
-- `POST /<package>.<Service>/<Method>` with a proto3 JSON body, and a failure is a
-- `{ code, message, details? }` body (string codes such as "not_found") under an HTTP
-- status the server maps the code to, which the REST decoder classifies.
--
--   local protocol = connect.new{
--     prepare = rpc.prepare(settings),   -- fn(creds, host) -> settings | nil, err
--     ...every rest.new option (base_url, headers, unknown_tag, parse_tag, ...)
--   }
--
-- What Connect adds over rest.new: `empty_json_body` defaults to true (a unary call
-- posts `{}` for an empty message: e2b's envd answers a bodyless one with 415), and
-- `prepare` derives settings (distilled.protocol.rpc) before the request is built.
--
-- Server streams (task 30; Distilled's packages/e2b/src/connect.ts serverStream):
--
--   connect.stream(protocol, ctx, op, input, opts) -> parts, nil, meta | nil, err, meta
--   connect.stream_method{ op = { name, uri, errors }, fail = fn(info) -> err,
--                          decode = fn(message, info) -> item | nil, err }
--     -> fn(client, input) -> stream | nil, err      (a client method)
--
-- The request is the protocol's (URL, headers, the JSON body) with that body sent as one
-- envelope (distilled.stream.connect) as `application/connect+json`. The reply is a
-- sequence of envelopes delivered one by one; the end-of-stream envelope's `error`
-- ends the stream with `fail{ phase = "end", status = 200, error, body }`. A non-2xx
-- reply is a unary Connect error body: `fail{ phase = "status", status, error, body }`
-- (error = { code, message } read from the body, as connect.ts errorOf). Without `fail`
-- both become the protocol's unknown error class.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local envelopes = require("distilled.stream.connect")
local json = require("distilled.json")
local noop = require("distilled.trace.noop")
local rest = require("distilled.protocol.rest")

local connect = {}

--- connect.with_prepare(protocol, prepare) -> protocol whose credentials go through
-- prepare(creds, host) first (any protocol with call / encode / decode)
function connect.with_prepare(protocol, prepare)
  if prepare == nil then
    return protocol
  end
  local function wrap(ctx)
    ctx = ctx or {}
    local inner = ctx.credentials
    local copy = {}
    for k, v in pairs(ctx) do
      copy[k] = v
    end
    copy.credentials = function()
      local creds = {}
      if inner then
        local c, err = inner()
        if c == nil then
          return nil, err
        end
        creds = c
      end
      local r = compat.pack(compat.pcall(prepare, creds, ctx.host or {}))
      if not r[1] then
        if errors.is(r[2]) then
          return nil, r[2]
        end
        return nil,
          errors.new(
            "SdkError",
            { message = "the protocol's prepare raised: " .. tostring(r[2]), cause = r[2] }
          )
      end
      return r[2], r[3]
    end
    return copy
  end
  local out = {}
  for k, v in pairs(protocol) do
    out[k] = v
  end
  function out.call(ctx, op, input)
    return protocol.call(wrap(ctx), op, input)
  end
  function out.encode(ctx, op, input, creds)
    if creds ~= nil then
      return protocol.encode(ctx, op, input, creds)
    end
    return protocol.encode(wrap(ctx), op, input)
  end
  function out.decode(ctx, op, res)
    return protocol.decode(ctx, op, res)
  end
  return out
end

-- the transport's streaming entry point (distilled.stream contract), or nil
local function stream_entry(transport)
  if
    (type(transport) == "table" or type(transport) == "userdata")
    and type(transport.stream) == "function"
  then
    return transport.stream
  end
  return nil
end

-- connect.ts errorOf: `{ code, message }` of json.error when it is an object
local function error_of(value)
  if type(value) ~= "table" or value == json.null then
    return nil
  end
  local e = value.error
  if type(e) ~= "table" or e == json.null or json.is_array(e) then
    return nil
  end
  return {
    code = type(e.code) == "string" and e.code or nil,
    message = type(e.message) == "string" and e.message or nil,
  }
end
connect.error_of = error_of

local function default_fail(protocol)
  return function(info)
    local e = info.error or {}
    return errors.new(protocol.unknown_class or "SdkError", {
      status = info.status,
      code = e.code,
      message = e.message or e.code or ("HTTP " .. tostring(info.status)),
      body = info.body,
    })
  end
end

-- a fail hook's answer, always an error table
local function failure(fail, info)
  local r = compat.pack(compat.pcall(fail, info))
  if r[1] and errors.is(r[2]) then
    return r[2]
  end
  if not r[1] and errors.is(r[2]) then
    return r[2]
  end
  return errors.new("SdkError", {
    message = "the Connect stream's fail hook returned no error"
      .. (r[1] and "" or (": " .. tostring(r[2]))),
  })
end

--- connect.stream(protocol, ctx, op, input, opts) -> parts, nil, meta | nil, err, meta
-- parts = { status, headers, next = fn() -> item | nil, nil | nil, err, close = fn() }
function connect.stream(protocol, ctx, op, input, opts)
  opts = opts or {}
  ctx = ctx or {}
  local fail = opts.fail or default_fail(protocol)
  local decode = opts.decode
  local tracer = ctx.tracer or noop
  local host = ctx.host or {}
  local req, berr = protocol.encode(ctx, op, input)
  if req == nil then
    return nil, berr
  end
  local body = req.body
  if body == nil or body == "" then
    body = "{}"
  end
  local headers = {}
  for k, v in pairs(req.headers or {}) do
    local lower = string.lower(k)
    if lower ~= "content-type" and lower ~= "content-length" then
      headers[lower] = v
    end
  end
  headers["content-type"] = "application/connect+json"
  local traceparent = tracer:traceparent()
  if
    traceparent
    and not (ctx.service and ctx.service.telemetry and ctx.service.telemetry.propagate == false)
  then
    headers["traceparent"] = traceparent
  end
  if headers["user-agent"] == nil then
    headers["user-agent"] = ctx.user_agent or rest.USER_AGENT
  end
  req.headers = headers
  -- the JSON body as is (the bytes the protocol built), in one envelope
  req.body = envelopes.frame(body)
  req.timeout = ctx.timeout

  local transport = host.transport
  if transport == nil then
    return nil,
      errors.new("ConfigError", {
        message = "no transport; " .. require("distilled.host").TRANSPORT_HINT,
        key = "transport",
      })
  end
  local send = stream_entry(transport)
  if send == nil then
    return nil,
      errors.new("ConfigError", {
        message = "the transport cannot stream (it has no `stream` entry point); "
          .. require("distilled.host").TRANSPORT_HINT,
        key = "transport",
      })
  end
  local res, terr = send(req)
  if type(res) ~= "table" then
    if res == nil and terr ~= nil then
      if not errors.is(terr) then
        terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
      end
      return nil, terr
    end
    return nil,
      errors.new("ConfigError", {
        message = "the transport's stream entry point returned no response",
        key = "transport",
      })
  end
  local reader = res.body
  if type(res.status) ~= "number" or type(reader) ~= "table" then
    if type(reader) == "table" and type(reader.close) == "function" then
      reader:close()
    end
    return nil,
      errors.new("TransportError", { message = "the transport returned no status or body reader" })
  end
  local rh = {}
  for k, v in pairs(res.headers or {}) do
    rh[type(k) == "string" and string.lower(k) or k] = v
  end
  local meta = { status = res.status, headers = rh }
  local closed = false
  local function close()
    if not closed then
      closed = true
      reader:close()
    end
  end
  local info = { method = op.uri, op = op }
  if res.status < 200 or res.status >= 300 then
    -- a failure before the stream starts is a unary Connect error body
    local text, rerr = reader:read_all()
    close()
    if text == nil then
      return nil, rerr, meta
    end
    local value = json.decode(text)
    local e = error_of({ error = value }) or {}
    info.phase, info.status, info.error, info.body, info.headers =
      "status", res.status, e, value, rh
    info.text = text
    return nil, failure(fail, info), meta
  end

  local decoder = envelopes.new(reader)
  local finished = false
  local function stop(err)
    finished = true
    close()
    return nil, err
  end
  local function next_item()
    while not finished do
      local env, err = decoder:next()
      if env == nil then
        if err ~= nil and errors.is_tag(err, "ParseError") and protocol.parse_class then
          err = errors.new(protocol.parse_class, { message = err.message, cause = err })
        end
        return stop(err)
      end
      if env.end_stream then
        local e = error_of(env.json)
        if e == nil then
          return stop(nil)
        end
        return stop(failure(fail, {
          phase = "end",
          status = 200,
          error = e,
          body = env.json,
          headers = rh,
          method = op.uri,
          op = op,
        }))
      end
      if decode == nil then
        return env.json
      end
      local item, derr = decode(env.json, info)
      if item ~= nil then
        return item
      end
      if derr ~= nil then
        return stop(derr)
      end
      -- nil, nil: the decoder skipped this message
    end
    return nil, nil
  end
  return { status = res.status, headers = rh, next = next_item, close = close }, nil, meta
end

--- connect.as_stream(parts) -> stream: task 29's Stream object (distilled.stream)
function connect.as_stream(parts)
  return require("distilled.stream").new(parts)
end

--- connect.stream_method{ op, fail, decode } -> fn(client, input) -> stream | nil, err
-- A client method for a server-streaming Connect RPC that no model declares (e2b's
-- connect.ts calls): op = { name, uri = "/<package>.<Service>/<Method>", errors }.
-- `fail` and `decode` are connect.stream's; both receive info.client (the client's
-- state: service, protocol) so a glue can reach the client's error classes.
function connect.stream_method(spec)
  if type(spec) ~= "table" or type(spec.op) ~= "table" or type(spec.op.uri) ~= "string" then
    compat.raise("connect.stream_method: expected { op = { name, uri }, fail, decode }", 2)
  end
  local op = {
    name = spec.op.name,
    method = "POST",
    uri = spec.op.uri,
    code = 200,
    errors = spec.op.errors or {},
    stream = { framing = "connect" },
  }
  return function(client, input)
    local state = type(client) == "table" and rawget(client, "_state")
    if type(state) ~= "table" or type(state.protocol) ~= "table" then
      compat.raise("call client:" .. tostring(spec.op.name) .. "(...) with a colon", 2)
    end
    local base = state.ctx or {}
    local ctx = {}
    for k, v in pairs(base) do
      ctx[k] = v
    end
    ctx.op_name = op.name
    local function with_state(fn)
      if fn == nil then
        return nil
      end
      return function(a, info)
        if info == nil then
          a.client = state
        else
          info.client = state
        end
        return fn(a, info)
      end
    end
    local parts, err = connect.stream(state.protocol, ctx, op, input or json.object({}), {
      fail = with_state(spec.fail),
      decode = with_state(spec.decode),
    })
    if parts == nil then
      return nil, err
    end
    return connect.as_stream(parts)
  end
end

--- connect.new(opts) -> protocol
function connect.new(opts)
  if type(opts) ~= "table" then
    compat.raise("connect.new: expected an options table", 2)
  end
  local rest_opts = {}
  for k, v in pairs(opts) do
    if k ~= "prepare" then
      rest_opts[k] = v
    end
  end
  if rest_opts.empty_json_body == nil then
    rest_opts.empty_json_body = true
  end
  return connect.with_prepare(rest.new(rest_opts), opts.prepare)
end

return connect
