-- AWS event stream operations: the part of distilled.aws.protocol that reads and writes
-- application/vnd.amazon.eventstream bodies.
--
-- Distilled: aws/src/protocols/{rest-json,aws-json}.ts (deserializeStream ->
-- parseEventStreamToUnion; serialize -> serializeInputEventStreamWithSchema) and
-- s3/src/eventstream/. Differences, on purpose:
--   * an exception event (`:message-type exception`) ends the stream with the operation's
--     modeled error class, and an `error` message with the class its `:error-code` names
--     (or UnknownAwsError), as the AWS SDKs throw them. Distilled yields both as union
--     members ({ modelStreamErrorException = {...} }, { UnmodeledError = {...} }).
--   * `@eventHeader` members are read from the message headers, and an `@eventPayload`
--     structure is decoded from the payload document (Distilled base64-encodes any
--     payload member and leaves headers out).
--   * input events are signed (SigV4 event signing, :date and :chunk-signature, the
--     request signed with STREAMING-AWS4-HMAC-SHA256-EVENTS) and the stream ends with a
--     signed empty frame, as the AWS SDKs send them. Distilled sends the events unsigned.
--   * the `initial-response` event of the RPC protocols fills the output members that are
--     not the stream (stream.output); Distilled passes it through as an event.
--
-- M.stream(kit, ctx, op, input) -> parts, nil, meta | nil, err, meta
--   parts = { status, headers, output, next, close, send?, close_input? }
-- M.collect(kit, ctx, op, res) -> output with the stream member a list of events | nil, err
--   (a plain, non-streaming call: the whole body was read)
-- kit: the protocol's internals (distilled.aws.protocol builds it).
local codec = require("distilled.aws.codec")
local errors = require("distilled.errors")
local es = require("distilled.aws.eventstream")
local framing = require("distilled.stream.aws_eventstream")
local json = require("distilled.json")
local schema = require("distilled.schema")
local secret = require("distilled.secret")

local M = {}

M.CONTENT_TYPE = "application/vnd.amazon.eventstream"
M.STREAMING_PAYLOAD = "STREAMING-AWS4-HMAC-SHA256-EVENTS"

local function shallow(t)
  local out = {}
  for k, v in pairs(t) do
    out[k] = v
  end
  return out
end

local function without(node, name)
  local copy = shallow(node)
  local members = {}
  for _, m in ipairs(node.members or {}) do
    if m.name ~= name then
      members[#members + 1] = m
    end
  end
  copy.members = members
  return copy
end

-- One union member's event: a pseudo-operation whose output node reads the event's
-- payload as a response body (payload member bound to the body, header members left out:
-- they come from the message headers), and its header members.
local function event_reader(op, union_member, registry)
  local target = codec.resolve(union_member.schema, registry)
  if not target or target.t ~= "struct" then
    return { node = target }
  end
  local members, headers = {}, {}
  for _, m in ipairs(target.members or {}) do
    if m.event == "header" then
      headers[#headers + 1] = m
    else
      local copy = shallow(m)
      if m.event == "payload" then
        copy.bind = "payload"
      else
        copy.bind = nil
      end
      members[#members + 1] = copy
    end
  end
  local node = shallow(target)
  node.members = members
  local pseudo = shallow(op)
  pseudo.output = node
  pseudo.name = op.name .. " event " .. union_member.name
  pseudo._aws_withhold = nil
  pseudo._aws_errors = nil
  return { op = pseudo, node = target, headers = headers }
end

-- the derived descriptors of an event stream operation, cached on the descriptor (a
-- long-lived table)
local function derived(op, registry)
  local d = op._aws_event_stream
  if d then
    return d
  end
  local st = op.stream
  local out_node = codec.resolve(op.output, registry)
  local head = shallow(op)
  head.output = without(out_node, st.member)
  head._aws_withhold = nil
  local enc = op
  local input_union
  if st.input then
    enc = shallow(op)
    enc.input = without(codec.resolve(op.input, registry), st.input.member)
    enc._aws_event_input = true
    enc._aws_withhold = nil
    input_union = codec.resolve(st.input.item, registry)
  end
  local union = codec.resolve(st.item, registry)
  local by_name = {}
  for _, m in ipairs(union and union.members or {}) do
    by_name[m.name] = m
  end
  local in_by_name = {}
  for _, m in ipairs(input_union and input_union.members or {}) do
    in_by_name[m.name] = m
  end
  d = {
    head = head,
    encode = enc,
    union = union,
    members = by_name,
    readers = {},
    input_union = input_union,
    input_members = in_by_name,
  }
  op._aws_event_stream = d
  return d
end
M.derived = derived

-- a payload document: JSON (the JSON protocols) or XML (restXml), or Distilled's
-- jsonPayloadParser fallback { payload = text }
local function parse_document(kit, payload)
  if payload == "" then
    return json.object({})
  end
  if kit.args.protocol == "restXml" then
    local tree = require("distilled.xml").decode(payload)
    if tree ~= nil then
      return tree
    end
    return { payload = payload }
  end
  local v = json.decode(payload)
  if v ~= nil then
    return v
  end
  return { payload = payload }
end

-- a typed message header as the value of an @eventHeader member
local function header_value(member, h, registry)
  local target = codec.resolve(member.schema, registry)
  local v = h.value
  if h.type == "timestamp" then
    v = v / 1000
  end
  if target and target.t == "timestamp" and type(v) == "number" and h.type ~= "timestamp" then
    v = v / 1000
  end
  if member.sensitive or (target and target.sensitive) then
    v = secret(v)
  end
  return v
end

-- the decoded union item of one event message | nil, err | false (consumed: initial-response)
local function decode_event(kit, ctx, op, d, state, ev)
  local registry = kit.service.shapes
  if ev.kind == "event" then
    if ev.event_type == es.INITIAL_RESPONSE_EVENT_TYPE then
      -- the RPC protocols' initial response: the output members that are not the stream
      local out, err = kit.decode_success(ctx, d.head, {
        status = state.status,
        headers = {},
        body = ev.payload,
      })
      if out == nil and err then
        return nil, err
      end
      for k, v in pairs(type(out) == "table" and out or {}) do
        state.output[k] = v
      end
      return false
    end
    local member = d.members[ev.event_type]
    if not member or member.error then
      -- an event the schema does not know: passed through as read (Distilled does too)
      return { [ev.event_type] = parse_document(kit, ev.payload) }
    end
    local r = d.readers[member.name]
    if not r then
      r = event_reader(op, member, registry)
      d.readers[member.name] = r
    end
    if not r.op then
      return { [member.name] = parse_document(kit, ev.payload) }
    end
    local value, err = kit.decode_success(ctx, r.op, {
      status = 200,
      headers = {},
      body = ev.payload,
    })
    if value == nil and err then
      return nil,
        errors.new("ParseError", {
          message = "Event " .. member.name .. " does not match its schema: " .. tostring(
            err.message
          ),
        })
    end
    if type(value) ~= "table" then
      value = json.object({})
    end
    for _, hm in ipairs(r.headers) do
      local h = es.header(ev.headers, hm.name)
      if h then
        value[hm.name] = header_value(hm, h, registry)
      end
    end
    return { [member.name] = value }
  end
  local res = { status = state.status, headers = state.headers or {} }
  if ev.kind == "exception" then
    local member = d.members[ev.exception_type]
    local code = member and member.error or ev.exception_type
    local data = parse_document(kit, ev.payload)
    if type(data) ~= "table" or schema.is_array_value(data) then
      data = {}
    end
    local copy = {}
    for k, v in pairs(data) do
      if v ~= json.null then
        copy[k] = v
      end
    end
    return nil, kit.build_error(ctx, op, res, code, copy)
  end
  -- :message-type error, unmodeled
  return nil, kit.build_error(ctx, op, res, ev.error_code, { message = ev.error_message })
end

-- the stream's item iterator over a message source
local function items(kit, ctx, op, d, state, next_message, on_end)
  local finished = false
  return function()
    while true do
      if finished then
        return nil, nil
      end
      local ev, err = framing.next_event(next_message)
      if ev == nil then
        finished = true
        on_end()
        return nil, err
      end
      local item, ierr = decode_event(kit, ctx, op, d, state, ev)
      if item == nil then
        finished = true
        on_end()
        return nil, ierr
      end
      if item ~= false then
        return item
      end
    end
  end
end

-- a reader over a string (a whole body)
local function string_reader(s)
  local at = 1
  return {
    read_exact = function(_, n)
      if at > #s then
        return nil, nil
      end
      local piece = string.sub(s, at, at + n - 1)
      at = at + n
      if #piece < n then
        return nil, { eof = true, partial = piece }
      end
      return piece
    end,
    close = function() end,
  }
end
M.string_reader = string_reader

--- M.collect(kit, ctx, op, res) -> output | nil, err: a plain call of an output-stream
-- operation, its whole body read: the events as a list in the stream member
function M.collect(kit, ctx, op, res)
  local registry = kit.service.shapes
  local d = derived(op, registry)
  local output, err = kit.decode_success(ctx, d.head, {
    status = res.status,
    headers = res.headers,
    body = "",
  })
  if output == nil and err then
    return nil, err
  end
  if type(output) ~= "table" then
    output = json.object({})
  end
  local state = { status = res.status, headers = res.headers, output = output }
  local next_item = items(
    kit,
    ctx,
    op,
    d,
    state,
    framing.messages(string_reader(res.body or "")),
    function() end
  )
  local list = {}
  while true do
    local item, ierr = next_item()
    if item == nil then
      if ierr then
        return nil, ierr
      end
      break
    end
    list[#list + 1] = item
  end
  output[op.stream.member] = json.array(list)
  return output
end

---------------------------------------------------------------------------------------
-- input events
---------------------------------------------------------------------------------------

local INT32_MIN, INT32_MAX = -2147483648, 2147483647

-- an @eventHeader member's value as a typed header (Distilled's toHeaderValue)
local function to_header(name, member, v, registry)
  v = secret.unwrap(v)
  local target = codec.resolve(member.schema, registry)
  local t = target and target.t
  if t == "timestamp" and type(v) == "number" then
    return { name = name, type = "timestamp", value = math.floor(v * 1000) }
  end
  if type(v) == "string" then
    if t == "blob" then
      return { name = name, type = "binary", value = v }
    end
    return { name = name, type = "string", value = v }
  elseif type(v) == "boolean" then
    return { name = name, type = "boolean", value = v }
  elseif type(v) == "number" then
    if v == math.floor(v) and v >= INT32_MIN and v <= INT32_MAX then
      return { name = name, type = "integer", value = v }
    end
    local n = v >= 0 and math.floor(v) or -math.floor(-v)
    return { name = name, type = "long", value = n }
  end
  return nil
end

local PAYLOAD_CONTENT_TYPE = {
  blob = "application/octet-stream",
  string = "text/plain",
  structure = "application/json",
}

--- M.encode_input_event(kit, op, event) -> the encoded event message | nil, err
-- event: { <member> = value }, a member of the input union (Smithy union form), or
-- { _tag = <member>, ... } (Distilled's tagged form).
function M.encode_input_event(kit, op, event)
  local registry = kit.service.shapes
  local d = derived(op, registry)
  if type(event) ~= "table" then
    return nil, errors.new("InvalidInput", { message = "an input event must be a table" })
  end
  local name, value
  if type(event._tag) == "string" then
    name = event._tag
    value = shallow(event)
    value._tag = nil
  else
    for k, v in pairs(event) do
      if name ~= nil then
        return nil,
          errors.new("InvalidInput", {
            message = "an input event has exactly one member ({ <EventName> = { ... } })",
          })
      end
      name, value = k, v
    end
  end
  local member = d.input_members[name]
  if not member then
    local known = {}
    for k in pairs(d.input_members) do
      known[#known + 1] = k
    end
    table.sort(known)
    return nil,
      errors.new("InvalidInput", {
        message = "unknown input event "
          .. tostring(name)
          .. " (expected one of: "
          .. table.concat(known, ", ")
          .. ")",
        member = tostring(name),
      })
  end
  local target = codec.resolve(member.schema, registry)
  if type(value) ~= "table" then
    value = {}
  end
  local headers = {}
  local payload_member
  local body_node = target
  if target and target.t == "struct" then
    local members = {}
    for _, m in ipairs(target.members or {}) do
      if m.event == "header" then
        local v = value[m.name]
        if v ~= nil and v ~= json.null then
          local h = to_header(m.name, m, v, registry)
          if h then
            headers[#headers + 1] = h
          end
        end
      elseif m.event == "payload" then
        payload_member = payload_member or m
      else
        members[#members + 1] = m
      end
    end
    body_node = shallow(target)
    body_node.members = members
  end
  local env = {
    registry = registry,
    timestamp = kit.args.default_ts,
    wire_keys = true,
  }
  local function encode_json(node, v, path)
    local wire, f = codec.encode(node, v, env)
    if f then
      return nil,
        codec.parse_error(
          "event "
            .. name
            .. " does not match its schema: "
            .. codec.failure_message(codec.within(f, path), true)
        )
    end
    return json.encode(wire)
  end
  local payload, content_type
  if payload_member then
    local ptarget = codec.resolve(payload_member.schema, registry)
    local kind = "structure"
    if ptarget and ptarget.t == "blob" then
      kind = "blob"
    elseif ptarget and (ptarget.t == "string" or ptarget.t == "enum") then
      kind = "string"
    end
    local v = secret.unwrap(value[payload_member.name])
    if v == nil or v == json.null then
      payload = ""
    elseif kind == "structure" then
      local text, err = encode_json(payload_member.schema, v, payload_member.name)
      if not text then
        return nil, err
      end
      payload = text
    else
      if type(v) ~= "string" then
        return nil,
          codec.parse_error(
            "event "
              .. name
              .. ' does not match its schema: Expected a string at ["'
              .. payload_member.name
              .. '"]'
          )
      end
      payload = v
    end
    content_type = PAYLOAD_CONTENT_TYPE[kind]
  else
    local text, err = encode_json(body_node, value, nil)
    if not text then
      return nil, err
    end
    payload = text
    content_type = "application/json"
  end
  return es.encode_event({
    kind = "event",
    event_type = name,
    content_type = content_type,
    payload = payload,
    headers = headers,
  })
end

---------------------------------------------------------------------------------------
-- the streaming call
---------------------------------------------------------------------------------------

local function sdk_error(message)
  return errors.new("SdkError", { message = message })
end

-- the transport's entry point of a kind ("stream" or "duplex"), on a table transport
local function entry(transport, kind)
  if type(transport) == "table" then
    local f = transport[kind]
    if type(f) == "function" or (type(f) == "table" and getmetatable(f)) then
      return f
    end
  end
  return nil
end
M.entry = entry

-- the event signer for one request: the seed signature and scope come from the signed
-- request (its Authorization header and x-amz-date)
local function signer_for(req, identity, now)
  local auth = req.headers and req.headers.authorization or ""
  local seed = string.match(auth, "Signature=(%x+)$")
  local region, service = string.match(auth, "Credential=[^/]+/%d+/([^/]+)/([^/]+)/aws4_request")
  if not seed or not region then
    return nil
  end
  local sigv4 = require("distilled.sigv4")
  local prior = seed
  local keys = {}
  return function(payload)
    local epoch = math.floor(now())
    local date = string.sub(sigv4.amz_datetime(epoch), 1, 8)
    local key = keys[date]
    if not key then
      key = sigv4.signing_key(identity.secret_access_key, date, region, service)
      keys = { [date] = key }
    end
    local frame, signature = es.sign_frame({
      payload = payload,
      prior_signature = prior,
      signing_key = key,
      scope = date .. "/" .. region .. "/" .. service .. "/aws4_request",
      epoch_ms = epoch * 1000,
    })
    if frame then
      prior = signature
    end
    return frame, signature
  end
end
M.signer_for = signer_for

--- M.stream(kit, ctx, op, input) -> parts, nil, meta | nil, err, meta
function M.stream(kit, ctx, op, input)
  local st = op.stream
  if type(st) ~= "table" or st.framing ~= "aws_eventstream" then
    return nil, sdk_error(kit.what(op) .. " has no event stream")
  end
  local registry = kit.service.shapes
  local d = derived(op, registry)
  local host = ctx.host or {}
  local tracer = ctx.tracer or require("distilled.trace.noop")
  local transport = host.transport
  if transport == nil then
    return nil,
      errors.new("ConfigError", {
        message = 'no transport; pass host = require("distilled.host.popen")() (or transport = ...)',
        key = "transport",
      })
  end
  local duplex = st.input ~= nil
  local open = entry(transport, duplex and "duplex" or "stream")
  if not open then
    if duplex then
      return nil,
        sdk_error(
          kit.what(op)
            .. " streams events both ways, which needs a duplex transport (transport.duplex: "
            .. "the request body written while the response is read); this host's transport ("
            .. tostring(host.name or "custom")
            .. ") has none"
        )
    end
    return nil,
      errors.new("ConfigError", {
        message = "the transport cannot stream (it has no `stream` entry point); "
          .. 'use require("distilled.host.popen")() or require("distilled.host.rex")()',
        key = "transport",
      })
  end
  if type(input) == "table" and duplex then
    input = shallow(input)
    input[st.input.member] = nil
  end

  local req, opts_or_err = kit.prepare(ctx, d.encode, input)
  if req == nil then
    return nil, opts_or_err
  end
  local sign
  if duplex then
    local identity = kit.identity(opts_or_err, host)
    local now = host.epoch or os.time
    sign = identity and signer_for(req, identity, now)
    if not sign then
      return nil,
        sdk_error(kit.what(op) .. ": the request has no SigV4 signature to chain events to")
    end
  end
  local meta = {}
  local res, conn, terr
  tracer:with("distilled.transport", {
    debug = true,
    attributes = { ["http.request.method"] = req.method },
  }, function(s)
    if duplex then
      conn, terr = open(req)
    else
      res, terr = open(req)
      if type(res) == "table" then
        s:set("http.response.status_code", res.status)
      end
    end
  end)
  if duplex then
    if type(conn) ~= "table" then
      return nil,
        errors.is(terr) and terr or errors.new("TransportError", { message = tostring(terr) })
    end
  elseif type(res) ~= "table" then
    if not errors.is(terr) then
      terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
    end
    return nil, terr
  end

  local state = { output = json.object({}) }
  local parts = { output = state.output }
  local closed = false
  local reader
  local function close()
    if closed then
      return
    end
    closed = true
    if reader then
      reader:close()
    end
    if conn then
      conn:close()
    end
  end
  parts.close = close

  -- the response head: status, headers, the output members bound to headers; a non-2xx
  -- reply is read whole and decoded as an error
  local head_err
  local function begin(r)
    local headers = {}
    for k, v in pairs(r.headers or {}) do
      headers[string.lower(k)] = v
    end
    reader = r.body
    state.status, state.headers = r.status, headers
    parts.status, parts.headers = r.status, headers
    meta.status, meta.headers = r.status, headers
    if type(r.status) ~= "number" then
      return errors.new("TransportError", { message = "the transport returned no status" })
    end
    if r.status < 200 or r.status >= 300 then
      local body, rerr = "", nil
      if reader then
        body, rerr = reader:read_all()
      end
      close()
      if body == nil then
        return rerr
      end
      local _, err = kit.decode(ctx, op, { status = r.status, headers = headers, body = body })
      return err or sdk_error("HTTP " .. r.status)
    end
    if type(reader) ~= "table" or type(reader.read_exact) ~= "function" then
      close()
      return errors.new("ConfigError", {
        message = "the transport's stream entry point returned no body reader",
        key = "transport",
      })
    end
    local out, err =
      kit.decode_success(ctx, d.head, { status = r.status, headers = headers, body = "" })
    if out == nil and err then
      close()
      return err
    end
    for k, v in pairs(type(out) == "table" and out or {}) do
      state.output[k] = v
    end
    return nil
  end

  local next_item
  local function iterator()
    if not next_item then
      next_item = items(kit, ctx, op, d, state, framing.messages(reader), close)
    end
    return next_item
  end

  if not duplex then
    head_err = begin(res)
    if head_err then
      return nil, head_err, meta
    end
    parts.next = function()
      return iterator()()
    end
    return parts, nil, meta
  end

  -- both ways: events go out through send(), the response is read on the first next()
  local input_closed = false
  local started = false
  parts.next = function()
    if not started then
      started = true
      local r, rerr = conn:response()
      if r == nil then
        close()
        head_err = rerr or errors.new("TransportError", { message = "no response" })
      else
        head_err = begin(r)
      end
    end
    if head_err then
      local e = head_err
      head_err = nil
      next_item = function()
        return nil, nil
      end
      return nil, e
    end
    return iterator()()
  end
  parts.send = function(_, event)
    if event == nil then
      event = _
    end
    if input_closed or closed then
      return nil, sdk_error("the input event stream is closed")
    end
    local message, err = M.encode_input_event(kit, op, event)
    if not message then
      return nil, err
    end
    local frame, ferr = sign(message)
    if not frame then
      return nil, ferr
    end
    return conn:write(frame)
  end
  parts.close_input = function()
    if input_closed or closed then
      return true
    end
    input_closed = true
    -- the signed empty frame that ends the input (the AWS SDKs' end-of-stream marker)
    local frame, ferr = sign("")
    if not frame then
      return nil, ferr
    end
    local ok, werr = conn:write(frame)
    conn:close_input()
    if not ok then
      return nil, werr
    end
    return true
  end
  return parts, nil, meta
end

return M
