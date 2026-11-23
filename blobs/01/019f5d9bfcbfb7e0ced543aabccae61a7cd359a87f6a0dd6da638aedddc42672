-- Unary gRPC and server streams (collected or incremental) over the transport. Port of Distilled's
-- core protocol-grpc.ts (makeGrpcProtocol).
--
-- Proto clients are generated as REST-shaped operations: each RPC is
-- `POST /<package>.<Service>/<Method>` with a proto3 JSON body. This protocol builds the
-- request with the REST protocol (distilled.protocol.rest) and speaks gRPC on the wire:
--
-- * Request: the proto3 JSON body is transcoded to one protobuf message
--   (distilled.protobuf, with the generated descriptors) in one gRPC frame, sent as
--   `application/grpc` with `te: trailers`; with `web = true` as
--   `application/grpc-web+proto` with `x-grpc-web: 1` (servers such as tonic-web answer
--   that over HTTP/1.1, with the trailers as the last frame of the body).
-- * Transport: any distilled transport. HTTP/1.1 by default (Modal's envoy bridges it,
--   as Distilled's fetch); `http2 = true` (or fn(creds) -> boolean) sets request.http2,
--   which the curl transports send as HTTP/2 (prior knowledge over http://).
-- * Status: grpc-status from the trailers (response.trailers, which the curl transports
--   fill when the server sends HTTP trailers, or a gRPC-Web trailer frame), else from
--   the headers of a trailers-only reply. A response without trailers is read like
--   Distilled's fetch reads one: a reply with messages and no status is OK.
-- * Errors: a non-zero status becomes the operation's typed error. The REST decoder
--   receives `{ code, status, message, details }` (`{ code = 5, status = "NOT_FOUND" }`)
--   with the HTTP status grpc-gateway maps the code to (NOT_FOUND -> 404, UNAVAILABLE ->
--   503), so matchers key on the numeric gRPC code and categories and retries follow
--   the HTTP status. `status_error = fn(info) -> err` replaces that mapping for codes no
--   typed error matches.
-- * Response: protobuf messages are transcoded back to proto3 JSON and decoded by the
--   operation's output schema through the REST decoder, so schemas, sensitive values and
--   validation behave exactly as for REST. A server-streaming method's plain call
--   returns `{ items = { message, ... } }`: the whole stream collected from one HTTP
--   response, as Distilled's plain call does.
-- * Streams (task 30): `protocol.stream(ctx, op, input)` sends the call through the
--   transport's `stream` entry point and returns parts whose next() decodes one message
--   as soon as its frame has arrived (distilled.stream.grpc; Distilled's streamReply):
--   each item is read by the output schema as `{ items = { message } }`. Failures known
--   before the first message (a non-gRPC reply, a trailers-only status) are returned at
--   once; the status in HTTP trailers or a gRPC-Web trailer frame ends the stream, with
--   the operation's typed error when it is not OK; a dropped connection ends it with the
--   transport's error; a truncated last frame is INTERNAL once the status is OK.
--
--   local protocol = grpc.new{
--     descriptors = require("modal.app.descriptors"),
--     web = false, http2 = false,
--     status_error = nil,                      -- fn({ code, message, details, headers })
--     prepare = nil,                           -- fn(creds, host) -> creds | nil, err
--     ...every rest.new option (base_url, headers, unknown_tag, parse_tag, ...)
--   }
--
-- Not ported: Distilled's `Deadline` (grpc-timeout and its own timer; the client's
-- deadline_s bounds the transport instead), the HTTP/2 transports (curl is ours) and
-- hpack.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local noop = require("distilled.trace.noop")
local protobuf = require("distilled.protobuf")
local rest = require("distilled.protocol.rest")
local frames = require("distilled.stream.grpc")
local retry = require("distilled.retry")

local grpc = {}

--- gRPC status code -> name
grpc.STATUS_NAMES = {
  [0] = "OK",
  [1] = "CANCELLED",
  [2] = "UNKNOWN",
  [3] = "INVALID_ARGUMENT",
  [4] = "DEADLINE_EXCEEDED",
  [5] = "NOT_FOUND",
  [6] = "ALREADY_EXISTS",
  [7] = "PERMISSION_DENIED",
  [8] = "RESOURCE_EXHAUSTED",
  [9] = "FAILED_PRECONDITION",
  [10] = "ABORTED",
  [11] = "OUT_OF_RANGE",
  [12] = "UNIMPLEMENTED",
  [13] = "INTERNAL",
  [14] = "UNAVAILABLE",
  [15] = "DATA_LOSS",
  [16] = "UNAUTHENTICATED",
}

--- gRPC status code -> HTTP status (grpc-gateway's mapping)
grpc.HTTP_STATUS = {
  [0] = 200,
  [1] = 499,
  [2] = 500,
  [3] = 400,
  [4] = 504,
  [5] = 404,
  [6] = 409,
  [7] = 403,
  [8] = 429,
  [9] = 400,
  [10] = 409,
  [11] = 400,
  [12] = 501,
  [13] = 500,
  [14] = 503,
  [15] = 500,
  [16] = 401,
}

--- gRPC's mapping of an HTTP status, for a reply that carries no gRPC status
grpc.HTTP_GRPC_STATUS = {
  [400] = 13,
  [401] = 16,
  [403] = 7,
  [404] = 12,
  [429] = 14,
  [502] = 14,
  [503] = 14,
  [504] = 14,
}

local STATUS_DESCRIPTORS = {
  messages = {
    ["google.rpc.Status"] = {
      { 1, "code", "int32" },
      { 2, "message", "string" },
      { 3, "details", "message", "google.protobuf.Any", 1 },
    },
  },
  enums = {},
  methods = {},
}

-- the details of grpc-status-details-bin (base64, padding optional); malformed details
-- do not hide the status itself
local function details_of(raw)
  if raw == nil or raw == "" then
    return json.array({})
  end
  local padded = raw .. string.rep("=", (4 - #raw % 4) % 4)
  padded = string.gsub(string.gsub(padded, "%-", "+"), "_", "/")
  local bytes = require("distilled.crypto.base64").decode(padded)
  if not bytes then
    return json.array({})
  end
  local status = protobuf.decode(STATUS_DESCRIPTORS, "google.rpc.Status", bytes)
  if type(status) ~= "table" or type(status.details) ~= "table" then
    return json.array({})
  end
  return status.details
end
grpc._details_of = details_of

-- decodeURIComponent, or the text as sent when it is not valid percent-encoding
local function percent_decoded(text)
  if not string.find(text, "%", 1, true) then
    return text
  end
  local bad = false
  local out = string.gsub(text, "%%(..)", function(h)
    if not string.find(h, "^%x%x$") then
      bad = true
      return ""
    end
    return string.char(tonumber(h, 16))
  end)
  if bad or string.find(string.gsub(text, "%%%x%x", ""), "%", 1, true) then
    return text
  end
  if protobuf.utf8_fix(out) ~= out then
    return text -- decodeURIComponent refuses bytes that are not UTF-8
  end
  return out
end
grpc._percent_decoded = percent_decoded

local function message_of(raw, status)
  local m = percent_decoded(raw or "")
  if m ~= "" then
    return m
  end
  return grpc.STATUS_NAMES[status] or ("gRPC status " .. tostring(status))
end

-- headers without content-length and content-type (plainHeaders)
local function plain_headers(headers)
  local out = {}
  for k, v in pairs(headers or {}) do
    if k ~= "content-length" and k ~= "content-type" then
      out[k] = v
    end
  end
  return out
end

local function lower_headers(h)
  local out = {}
  for k, v in pairs(h or {}) do
    out[type(k) == "string" and string.lower(k) or k] = v
  end
  return out
end

local function method_path(op)
  return (string.match(op.uri or "", "^[^?#]*"))
end

local function sdk_error(message)
  return errors.new("SdkError", { message = message })
end

local TRANSPORT_HINT = require("distilled.host").TRANSPORT_HINT

--- grpc.stream_entry(transport) -> fn(request) -> res | nil: the transport's streaming
-- entry point (distilled.stream contract: `transport.stream(request)`), or nil
function grpc.stream_entry(transport)
  local ok_table = type(transport) == "table"
    or (type(transport) == "userdata" and getmetatable(transport) ~= nil)
  if ok_table and type(transport.stream) == "function" then
    return transport.stream
  end
  return nil
end

--- grpc.trailers_of(res, reader) -> { [lowercase name] = value } | nil
-- The HTTP trailers of a streamed reply, once its body has ended: the transport may put
-- them on the response (res.trailers), on the reader (reader.trailers) or offer
-- reader:trailers(). nil when it reports none (then, as with fetch, a reply with
-- messages and no status is OK).
function grpc.trailers_of(res, reader)
  local tr = res.trailers
  if tr == nil and type(reader) == "table" then
    tr = rawget(reader, "trailers")
    if type(tr) == "function" then
      tr = tr(reader)
    elseif tr == nil and type(reader.trailers) == "function" then
      tr = reader:trailers()
    end
  end
  if type(tr) ~= "table" then
    return nil
  end
  return lower_headers(tr)
end

--- grpc.new(opts) -> protocol { call, encode, decode, rest }
function grpc.new(opts)
  if type(opts) ~= "table" then
    compat.raise("grpc.new: expected an options table", 2)
  end
  local d = opts.descriptors
  if type(d) ~= "table" or type(d.messages) ~= "table" or type(d.methods) ~= "table" then
    compat.raise("grpc.new: descriptors must be { messages, enums, methods }", 2)
  end
  if opts.prepare ~= nil and type(opts.prepare) ~= "function" then
    compat.raise("grpc.new: prepare must be a function(creds, host)", 2)
  end
  local rest_opts = {}
  for k, v in pairs(opts) do
    if
      k ~= "descriptors"
      and k ~= "web"
      and k ~= "http2"
      and k ~= "status_error"
      and k ~= "prepare"
    then
      rest_opts[k] = v
    end
  end
  local inner = rest.new(rest_opts)
  local web = opts.web == true

  local protocol = {
    rest = inner,
    descriptors = d,
    unknown_class = inner.unknown_class,
    parse_class = inner.parse_class,
  }

  local class_cache = {}
  local function classes_of(service, op)
    local list = class_cache[op]
    if not list then
      list = {}
      local declared = (service and service.errors) or {}
      for _, name in ipairs(op.errors or {}) do
        local class = declared[name] or errors.classes[name]
        if errors.is_class(class) then
          list[#list + 1] = class
        end
      end
      class_cache[op] = list
    end
    return list
  end

  -- the credentials, through `prepare` (settings derived after the client's options)
  local function credentials(ctx)
    local creds = {}
    if ctx.credentials then
      local c, err = ctx.credentials()
      if c == nil then
        return nil, err
      end
      creds = c
    end
    if opts.prepare then
      local r = compat.pack(compat.pcall(opts.prepare, creds, ctx.host or {}))
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
      if r[2] == nil then
        return nil, r[3] or sdk_error("the protocol's prepare returned nothing")
      end
      creds = r[2]
    end
    return creds
  end
  protocol.credentials = credentials

  --- protocol.encode(ctx, op, input [, creds]) -> request | nil, err
  -- The REST request with its JSON body as one gRPC frame of protobuf.
  function protocol.encode(ctx, op, input, creds)
    ctx = ctx or {}
    if creds == nil then
      local c, err = credentials(ctx)
      if c == nil then
        return nil, err
      end
      creds = c
    end
    local path = method_path(op)
    local method = d.methods[path]
    if not method then
      return nil, sdk_error("no gRPC descriptor for " .. tostring(path))
    end
    local req, err = inner.encode(ctx, op, input, creds)
    if not req then
      return nil, err
    end
    local value = json.object({})
    if req.body ~= nil and req.body ~= "" then
      local v = json.decode(req.body)
      if v == nil then
        return nil, sdk_error("gRPC requests need a JSON body (" .. tostring(op.name) .. ")")
      end
      value = v
    end
    local payload, perr = protobuf.encode(d, method[1], value)
    if not payload then
      return nil, perr
    end
    local headers = {}
    for k, v in pairs(req.headers or {}) do
      local lower = string.lower(k)
      if lower ~= "content-type" and lower ~= "content-length" then
        headers[lower] = v
      end
    end
    if web then
      headers["content-type"] = "application/grpc-web+proto"
      headers["x-grpc-web"] = "1"
    else
      headers["content-type"] = "application/grpc"
      headers["te"] = "trailers"
    end
    req.headers = headers
    req.body = protobuf.frame(payload)
    local http2 = opts.http2
    if type(http2) == "function" then
      http2 = http2(creds)
    end
    if http2 then
      req.http2 = true
    end
    return req
  end

  -- a gRPC status as the operation's typed error (failWith)
  local function fail_with(ctx, op, headers, status, message, details)
    local http = grpc.HTTP_STATUS[status] or 500
    local body = json.object({
      code = status,
      status = grpc.STATUS_NAMES[status] or tostring(status),
      message = message_of(message, status),
      details = details or json.array({}),
    })
    local plain = plain_headers(headers)
    if opts.status_error then
      local typed = errors.match(classes_of(ctx.service, op), {
        status = http,
        code = status,
        message = body.message,
        body = body,
        headers = plain,
      })
      if typed then
        return typed
      end
      local r = compat.pack(compat.pcall(opts.status_error, {
        code = status,
        message = body.message,
        details = body.details,
        headers = plain,
      }))
      if r[1] and errors.is(r[2]) then
        return r[2]
      end
      return sdk_error("the protocol's status_error did not return an error")
    end
    local text = json.encode(body)
    local value, err = inner.decode(ctx, op, { status = http, headers = plain, body = text })
    if value ~= nil or err == nil then
      return sdk_error("gRPC status " .. tostring(status) .. " decoded as a success")
    end
    return err
  end

  -- a reply that is not gRPC: a status other than 200, or another content type
  local function not_grpc(ctx, op, res)
    local ct = res.headers["content-type"] or ""
    local is_grpc = string.sub(ct, 1, 16) == "application/grpc"
    if res.status == 200 and is_grpc then
      return nil
    end
    if res.status ~= 200 and not opts.status_error then
      local value, err = inner.decode(ctx, op, res)
      if value ~= nil or err == nil then
        -- a 2xx other than 200 that is not gRPC
        return fail_with(ctx, op, res.headers, 2, "HTTP " .. tostring(res.status))
      end
      return err
    end
    if res.status ~= 200 then
      return fail_with(
        ctx,
        op,
        res.headers,
        grpc.HTTP_GRPC_STATUS[res.status] or 2,
        "HTTP " .. tostring(res.status)
      )
    end
    return fail_with(ctx, op, res.headers, 2, "unexpected content-type " .. json.encode(ct))
  end

  -- the call's failure, if any, once its body has ended (endOf)
  local function end_of(ctx, op, res, trailers, saw_body, transport_trailers)
    local headers = res.headers
    local ct = headers["content-type"] or ""
    local reads_trailers = transport_trailers or string.sub(ct, 1, 20) == "application/grpc-web"
    local source
    if trailers["grpc-status"] ~= nil then
      source = trailers
    elseif not saw_body or not reads_trailers then
      source = headers
    end
    local raw = source and source["grpc-status"]
    local status = nil
    if raw ~= nil and raw ~= "" then
      status = tonumber(raw)
    end
    if source == nil or status == nil then
      if reads_trailers then
        return fail_with(ctx, op, headers, 13, "server ended the call without a grpc-status")
      end
      if saw_body then
        return nil
      end
      return fail_with(ctx, op, headers, 2, "gRPC response carried no message and no grpc-status")
    end
    if status == 0 then
      return nil
    end
    return fail_with(
      ctx,
      op,
      headers,
      status,
      source["grpc-message"],
      details_of(source["grpc-status-details-bin"])
    )
  end

  local function parse_failure(op, size, cause)
    local why = type(cause) == "table" and cause.message or tostring(cause)
    return errors.new(inner.parse_class, {
      message = "cannot decode the response of " .. tostring(op.name) .. ": " .. tostring(why),
      -- the protobuf bytes are not shown: they may hold a sensitive value
      body = "<" .. size .. " bytes of protobuf>",
      cause = cause,
    })
  end

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    ctx = ctx or {}
    res = {
      status = res.status,
      headers = lower_headers(res.headers),
      body = res.body or "",
      trailers = res.trailers and lower_headers(res.trailers) or nil,
    }
    local failed = not_grpc(ctx, op, res)
    if failed then
      return nil, failed
    end
    local path = method_path(op)
    local method = d.methods[path]
    if not method then
      return nil, sdk_error("no gRPC descriptor for " .. tostring(path))
    end
    local body = res.body
    local trailers = res.trailers or {}
    local framed, ferr = protobuf.unframe(body)
    if not framed then
      local e = end_of(ctx, op, res, trailers, true, res.trailers ~= nil)
      if e then
        return nil, e
      end
      return nil, fail_with(ctx, op, res.headers, 13, ferr.message)
    end
    local all = {}
    for k, v in pairs(trailers) do
      all[k] = v
    end
    for k, v in pairs(framed.trailers) do
      all[k] = v
    end
    local e = end_of(ctx, op, res, all, #body > 0, res.trailers ~= nil)
    if e then
      return nil, e
    end
    if framed.rest ~= 0 then
      return nil, fail_with(ctx, op, res.headers, 13, "truncated gRPC frame")
    end
    local stream = method[3] == 1 or method[3] == true
    local frames = framed.messages
    if not stream and #frames ~= 1 then
      return nil,
        fail_with(
          ctx,
          op,
          res.headers,
          12,
          "expected one response message, got " .. tostring(#frames)
        )
    end
    local value
    if stream then
      local items = json.array({})
      for i, f in ipairs(frames) do
        local v, derr = protobuf.decode(d, method[2], f, { nonfinite = "null" })
        if v == nil then
          return nil, parse_failure(op, #body, derr)
        end
        items[i] = v
      end
      value = json.object({ items = items })
    else
      local v, derr = protobuf.decode(d, method[2], frames[1], { nonfinite = "null" })
      if v == nil then
        return nil, parse_failure(op, #body, derr)
      end
      value = v
    end
    local text, jerr = json.encode(value)
    if not text then
      return nil, parse_failure(op, #body, jerr)
    end
    return inner.decode(
      ctx,
      op,
      { status = 200, headers = plain_headers(res.headers), body = text }
    )
  end

  -- the request built and sent: res (lowercased headers), meta | nil, err [, meta].
  -- `streaming` sends it through the transport's stream entry point, so res.body is a
  -- reader (distilled.stream contract) instead of a string.
  local function send(ctx, op, input, streaming)
    local tracer = ctx.tracer or noop
    local span = ctx.span or noop.NOOP_SPAN
    local host = ctx.host or {}
    local attempt = ctx.attempt or {}

    local creds, cerr = tracer:with("distilled.credentials", { debug = true }, function()
      return credentials(ctx)
    end)
    if creds == nil then
      return nil, cerr
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
      h["user-agent"] = ctx.user_agent or opts.user_agent or rest.USER_AGENT
    end
    req.timeout = ctx.timeout

    local server = retry.host_of(req.url)
    span:set("http.request.method", req.method)
    span:set("server.address", server)
    attempt.host = server

    local transport = host.transport
    if transport == nil then
      return nil,
        errors.new(
          "ConfigError",
          { message = "no transport; " .. TRANSPORT_HINT, key = "transport" }
        )
    end
    local send_fn = transport
    if streaming then
      send_fn = grpc.stream_entry(transport)
      if send_fn == nil then
        return nil,
          errors.new("ConfigError", {
            message = "the transport cannot stream (it has no `stream` entry point); "
              .. TRANSPORT_HINT,
            key = "transport",
          })
      end
    end
    local res, terr = tracer:with("distilled.transport", {
      debug = true,
      attributes = { ["http.request.method"] = req.method, ["server.address"] = server },
    }, function(s)
      local r, e = send_fn(req)
      if type(r) == "table" then
        s:set("http.response.status_code", r.status)
      end
      return r, e
    end)
    if type(res) ~= "table" then
      if res == nil and terr ~= nil then
        if not errors.is(terr) then
          terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
        end
        return nil, terr
      end
      return nil,
        errors.new("ConfigError", {
          message = "the transport returned "
            .. (res == nil and "nothing" or ("a " .. type(res)))
            .. " instead of a response table or nil, err; "
            .. TRANSPORT_HINT,
          key = "transport",
        })
    end
    if type(res.status) ~= "number" then
      if streaming and type(res.body) == "table" and type(res.body.close) == "function" then
        res.body:close()
      end
      return nil, errors.new("TransportError", { message = "the transport returned no status" })
    end
    local headers = lower_headers(res.headers)
    local meta = { status = res.status, headers = headers }
    attempt.status = res.status
    if res.status >= 300 then
      attempt.hint_ms = retry.bounded_hint_ms(headers)
    end
    span:set("http.response.status_code", res.status)
    return {
      status = res.status,
      headers = headers,
      body = res.body,
      trailers = res.trailers,
    },
      meta
  end

  --- protocol.call(ctx, op, input) -> value, nil, meta | nil, err, meta
  function protocol.call(ctx, op, input)
    local res, meta = send(ctx, op, input, false)
    if res == nil then
      return nil, meta
    end
    local tracer = ctx.tracer or noop
    local value, derr = tracer:with("distilled.decode", { debug = true }, function()
      return protocol.decode(ctx, op, res)
    end)
    if value == nil and derr ~= nil then
      return nil, derr, meta
    end
    return value, nil, meta
  end

  -- one message of a server stream as the operation's output schema reads it: decoded
  -- as `{ items = { message } }` (the collected form's shape) and taken out again, as
  -- Distilled's streamReply does, so sensitive members and validation apply per item
  local function stream_item(ctx, op, method, headers, payload)
    local v, derr = protobuf.decode(d, method[2], payload, { nonfinite = "null" })
    if v == nil then
      return nil, parse_failure(op, #payload, derr)
    end
    local text, jerr = json.encode(json.object({ items = json.array({ v }) }))
    if not text then
      return nil, parse_failure(op, #payload, jerr)
    end
    local out, err =
      inner.decode(ctx, op, { status = 200, headers = plain_headers(headers), body = text })
    if out == nil then
      return nil, err
    end
    if type(out) ~= "table" or type(out.items) ~= "table" then
      return nil, sdk_error("the output of " .. tostring(op.name) .. " has no items list")
    end
    return out.items[1]
  end

  --- protocol.stream(ctx, op, input) -> parts, nil, meta | nil, err, meta
  -- A server-streaming call delivered message by message (Distilled's `.stream`):
  -- parts = { status, headers, next = fn() -> item | nil, nil | nil, err, close = fn() }
  -- (distilled.stream wraps them into a Stream). Failures known before the first message
  -- (transport, a non-gRPC reply, a trailers-only reply's status) are returned here, so
  -- the retry loop can retry them; later ones end the stream through next().
  function protocol.stream(ctx, op, input)
    ctx = ctx or {}
    local path = method_path(op)
    local method = d.methods[path]
    if not method then
      return nil, sdk_error("no gRPC descriptor for " .. tostring(path))
    end
    local res, meta = send(ctx, op, input, true)
    if res == nil then
      return nil, meta
    end
    local reader = res.body
    if type(reader) ~= "table" or type(reader.read_exact) ~= "function" then
      return nil,
        errors.new("ConfigError", {
          message = "the transport's stream entry point returned no body reader",
          key = "transport",
        }),
        meta
    end
    local closed = false
    local function close()
      if not closed then
        closed = true
        reader:close()
      end
    end
    -- whole-body cases: not gRPC, or a trailers-only reply (grpc-status in the headers)
    local ct = res.headers["content-type"] or ""
    local whole = res.status ~= 200
      or string.sub(ct, 1, 16) ~= "application/grpc"
      or res.headers["grpc-status"] ~= nil
    if whole then
      local body, rerr = reader:read_all()
      close()
      if body == nil then
        return nil, rerr, meta
      end
      local full = {
        status = res.status,
        headers = res.headers,
        body = body,
        trailers = grpc.trailers_of(res, reader),
      }
      local failed = not_grpc(ctx, op, full)
      if failed then
        return nil, failed, meta
      end
      if body == "" then
        local e = end_of(ctx, op, full, full.trailers or {}, false, full.trailers ~= nil)
        if e then
          return nil, e, meta
        end
        return {
          status = res.status,
          headers = res.headers,
          next = function()
            return nil, nil
          end,
          close = close,
        },
          nil,
          meta
      end
      -- a body after all: read it as a collected stream would be, then replay its items
      local value, derr = protocol.decode(ctx, op, full)
      if value == nil then
        return nil, derr, meta
      end
      local items, i = value.items or {}, 0
      return {
        status = res.status,
        headers = res.headers,
        next = function()
          i = i + 1
          return items[i]
        end,
        close = close,
      },
        nil,
        meta
    end

    local decoder = frames.new(reader)
    local finished = false
    local function stop(err)
      finished = true
      close()
      return nil, err
    end
    local function next_item()
      if finished then
        return nil, nil
      end
      local payload, ferr = decoder:next()
      if payload ~= nil then
        local item, ierr = stream_item(ctx, op, method, res.headers, payload)
        if item == nil then
          return stop(ierr or sdk_error("empty stream item"))
        end
        return item
      end
      if ferr ~= nil then
        if errors.is_tag(ferr, "ParseError") and ferr.protobuf then
          -- a compressed frame: gRPC's INTERNAL (badFrame)
          return stop(fail_with(ctx, op, res.headers, 13, ferr.message))
        end
        return stop(ferr)
      end
      -- the body ended: the call's status decides (endOf), then a truncated frame
      local transport_trailers = grpc.trailers_of(res, reader)
      local all = {}
      for k, v in pairs(transport_trailers or {}) do
        all[k] = v
      end
      for k, v in pairs(decoder.trailers) do
        all[k] = v
      end
      local e = end_of(ctx, op, res, all, decoder.saw_body, transport_trailers ~= nil)
      if e then
        return stop(e)
      end
      if decoder.rest ~= 0 then
        return stop(fail_with(ctx, op, res.headers, 13, "truncated gRPC frame"))
      end
      return stop(nil)
    end
    return { status = res.status, headers = res.headers, next = next_item, close = close },
      nil,
      meta
  end

  return protocol
end

return grpc
