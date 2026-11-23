-- The tracer: spans, the no-op tracer, ids and timestamps. Replaces the parts of
-- Distilled's telemetry.ts (and Effect's tracer) the Lua core needs.
--
-- The core is synchronous, so "the current span" is a stack inside the tracer: start()
-- pushes, finish() pops. Finished spans are buffered as plain records (the exporter
-- contract in docs/interfaces.md) and handed to exporters on tracer:flush().
--
-- Nothing here raises for a runtime failure; an exporter that fails or raises is
-- reported by flush() as nil, err and never reaches the traced call.
local compat = require("distilled.compat")
local secret = require("distilled.secret")
local json = require("distilled.json")

local trace = {}

local floor = math.floor
local format = string.format

-- the no-op tracer and the shared non-recording span live in distilled.trace.noop, which
-- requires nothing, so a client with tracing off never loads this module
local noop = require("distilled.trace.noop")
local NOOP_SPAN = noop.NOOP_SPAN
trace.NOOP_SPAN = NOOP_SPAN
trace.noop = noop

---------------------------------------------------------------------------------------
-- ids
---------------------------------------------------------------------------------------

local function default_random()
  return math.random()
end

-- hex_id(random, chars) -> lowercase hex, never all zero. Built from 16-bit chunks so
-- every chunk is an exact integer in float64 whatever the random source's precision.
local function hex_id(random, chars)
  for _ = 1, 8 do
    local parts = {}
    local nonzero = false
    for i = 1, chars / 4 do
      local r = random()
      if type(r) ~= "number" or r ~= r then
        r = 0
      end
      local chunk = floor(r * 65536)
      if chunk < 0 then
        chunk = 0
      elseif chunk > 65535 then
        chunk = 65535
      end
      if chunk ~= 0 then
        nonzero = true
      end
      parts[i] = format("%04x", chunk)
    end
    if nonzero then
      return table.concat(parts)
    end
  end
  -- a random source that keeps returning 0: still never an all-zero (invalid) id
  return string.rep("0", chars - 1) .. "1"
end
trace._hex_id = hex_id

---------------------------------------------------------------------------------------
-- traceparent (W3C Trace Context, version 00)
---------------------------------------------------------------------------------------

local ZERO_TRACE = string.rep("0", 32)
local ZERO_SPAN = string.rep("0", 16)

--- trace.parse_traceparent(s) -> { trace_id, span_id, flags } | nil
-- Lowercase hex only, as the spec requires; version ff and all-zero ids are invalid.
-- A future version may append fields after the flags ("-..."); version 00 may not.
function trace.parse_traceparent(s)
  if type(s) ~= "string" then
    return nil
  end
  local version, trace_id, span_id, flags, rest = string.match(
    s,
    "^(%x%x)%-(" .. string.rep("%x", 32) .. ")%-(" .. string.rep("%x", 16) .. ")%-(%x%x)(.*)$"
  )
  if not version then
    return nil
  end
  if string.find(s, "%u") then
    return nil
  end
  if version == "ff" or trace_id == ZERO_TRACE or span_id == ZERO_SPAN then
    return nil
  end
  if version == "00" and rest ~= "" then
    return nil
  end
  if rest ~= "" and string.sub(rest, 1, 1) ~= "-" then
    return nil
  end
  return { trace_id = trace_id, span_id = span_id, flags = flags }
end

---------------------------------------------------------------------------------------
-- time: nanoseconds since the epoch as a decimal string
---------------------------------------------------------------------------------------

-- Nanoseconds since 1970 are ~1.8e18, past 2^53, so a float64 cannot hold them exactly.
-- A timestamp is kept as (whole seconds, nanoseconds) and printed as two integers.
local function split_seconds(s)
  local whole = floor(s)
  local ns = floor((s - whole) * 1e9 + 0.5)
  if ns >= 1e9 then
    whole = whole + 1
    ns = ns - 1e9
  end
  return whole, ns
end

local function ns_string(whole, ns)
  if whole <= 0 then
    return format("%.0f", ns)
  end
  return format("%.0f", whole) .. format("%09.0f", ns)
end
trace._ns_string = ns_string

--- trace.ns_diff_ms(a, b) -> milliseconds from decimal string a to b (a number).
-- Splits each string into seconds and nanoseconds so the subtraction stays exact.
function trace.ns_diff_ms(a, b)
  local function parts(s)
    s = tostring(s or "0")
    local n = #s
    if n <= 9 then
      return 0, tonumber(s) or 0
    end
    return tonumber(string.sub(s, 1, n - 9)) or 0, tonumber(string.sub(s, n - 8)) or 0
  end
  local as, an = parts(a)
  local bs, bn = parts(b)
  return (bs - as) * 1e3 + (bn - an) / 1e6
end

---------------------------------------------------------------------------------------
-- attribute values
---------------------------------------------------------------------------------------

local function scalar(v)
  local tv = type(v)
  if tv == "string" or tv == "number" or tv == "boolean" then
    return v
  end
  if secret.is(v) then
    return secret.REDACTED
  end
  return tostring(v)
end

local function is_list(v)
  if getmetatable(v) ~= nil then
    -- json-marked arrays are lists; any other metatable (errors, secrets) is not
    if not json.is_array(v) then
      return false
    end
  end
  local n = #v
  local count = 0
  for _ in pairs(v) do
    count = count + 1
  end
  if count ~= n then
    return false
  end
  return n > 0 or getmetatable(v) ~= nil
end

--- trace.attribute_value(v) -> a value safe to record: string, number, boolean or a
-- list of those. Secrets become "<redacted>"; anything else goes through tostring.
function trace.attribute_value(v)
  if type(v) == "table" and not secret.is(v) and is_list(v) then
    local out = {}
    for i = 1, #v do
      out[i] = scalar(v[i])
    end
    return out
  end
  return scalar(v)
end
local attribute_value = trace.attribute_value

local function copy_attributes(attrs)
  local out = {}
  if type(attrs) == "table" then
    for k, v in pairs(attrs) do
      if type(k) == "string" and v ~= nil then
        out[k] = attribute_value(v)
      end
    end
  end
  return out
end

---------------------------------------------------------------------------------------
-- recording spans
---------------------------------------------------------------------------------------

local Span = {}
Span.__index = Span

--- span:set(key, value): record an attribute; nil removes it. Ignored after finish.
function Span:set(key, value)
  if self._done or type(key) ~= "string" then
    return
  end
  if value == nil then
    self._record.attributes[key] = nil
  else
    self._record.attributes[key] = attribute_value(value)
  end
end

--- span:event(name, attrs): a timestamped event on the span.
function Span:event(name, attrs)
  if self._done then
    return
  end
  local events = self._record.events
  events[#events + 1] = {
    name = tostring(name),
    time_ns = self._tracer:_now_ns(),
    attributes = copy_attributes(attrs),
  }
end

-- the tag Distilled's tagOf would give: err._tag there, err.tag here
local function tag_of(err)
  if type(err) == "table" and type(rawget(err, "tag")) == "string" then
    return err.tag
  end
  return "_OTHER"
end
trace.tag_of = tag_of

local function message_of(err)
  if type(err) == "table" then
    local m = rawget(err, "message")
    if m ~= nil then
      return tostring(m)
    end
  end
  if secret.is(err) then
    return secret.REDACTED
  end
  return tostring(err)
end

--- span:fail(err): status error, error.type = the error's tag ("_OTHER" without one).
function Span:fail(err)
  if self._done then
    return
  end
  local rec = self._record
  rec.status = { code = "error", message = err ~= nil and message_of(err) or nil }
  rec.attributes["error.type"] = tag_of(err)
end

local function end_one(span)
  span._done = true
  local tracer = span._tracer
  span._record.end_ns = tracer:_now_ns()
  tracer._finished[#tracer._finished + 1] = span._record
end

--- span:finish(): ends the span (idempotent) and buffers it for flush(). Spans opened
-- under it and still open (a raise skipped their finish) end first: in synchronous code
-- a child cannot outlive its parent, and the stack stays balanced.
function Span:finish()
  if self._done then
    return
  end
  local stack = self._tracer._stack
  local at
  for i = #stack, 1, -1 do
    if stack[i] == self then
      at = i
      break
    end
  end
  if at then
    for i = #stack, at + 1, -1 do
      end_one(stack[i])
      stack[i] = nil
    end
    stack[at] = nil
  end
  end_one(self)
end

---------------------------------------------------------------------------------------
-- tracer
---------------------------------------------------------------------------------------

local Tracer = {}
Tracer.__index = Tracer

local KINDS = { internal = true, client = true, server = true, producer = true, consumer = true }

local function host_fn(host, name, default)
  local f = type(host) == "table" and host[name] or nil
  if type(f) == "function" then
    return f
  end
  return default
end

--- trace.new{ level, exporter, host, service_name, parent } -> tracer
function trace.new(opts)
  opts = opts or {}
  if type(opts) ~= "table" then
    compat.raise("trace.new: expected an options table", 2)
  end
  local level = opts.level or "operation"
  if level ~= "operation" and level ~= "debug" then
    compat.raise('trace.new: level must be "operation" or "debug", got ' .. tostring(level), 2)
  end
  local exporters = {}
  local e = opts.exporter
  if
    type(e) == "function" or (type(e) == "table" and getmetatable(e) and getmetatable(e).__call)
  then
    exporters[1] = e
  elseif type(e) == "table" then
    for i = 1, #e do
      exporters[i] = e[i]
    end
  elseif e ~= nil then
    compat.raise("trace.new: exporter must be a function or a list of functions", 2)
  end
  local host = opts.host
  local now = host_fn(host, "now", os.time)
  local epoch = host_fn(host, "epoch", os.time)
  local self = setmetatable({
    level = level,
    service_name = opts.service_name,
    _exporters = exporters,
    _now = now,
    _random = host_fn(host, "random", default_random),
    _stack = {},
    _finished = {},
    _seq = 0,
    _remote = trace.parse_traceparent(opts.parent),
  }, Tracer)
  -- one epoch reading, then offsets from host.now(): see split_seconds
  self._epoch_s, self._epoch_ns = split_seconds(tonumber(epoch()) or 0)
  self._t0 = tonumber(now()) or 0
  self._last_s, self._last_ns = self._epoch_s, self._epoch_ns
  return self
end

-- the current time as a decimal ns string, never earlier than the last one taken
function Tracer:_now_ns()
  local offset = (tonumber(self._now()) or self._t0) - self._t0
  if offset < 0 then
    offset = 0
  end
  local os_, ons = split_seconds(offset)
  local s, ns = self._epoch_s + os_, self._epoch_ns + ons
  if ns >= 1e9 then
    s = s + 1
    ns = ns - 1e9
  end
  if s < self._last_s or (s == self._last_s and ns < self._last_ns) then
    s, ns = self._last_s, self._last_ns
  end
  self._last_s, self._last_ns = s, ns
  return ns_string(s, ns)
end

--- tracer:start(name, { kind, attributes, debug }) -> span
function Tracer:start(name, opts)
  opts = opts or {}
  if opts.debug and self.level ~= "debug" then
    return NOOP_SPAN
  end
  local kind = opts.kind or "internal"
  if not KINDS[kind] then
    kind = "internal"
  end
  local parent = self._stack[#self._stack]
  local trace_id, parent_span_id
  if parent then
    trace_id, parent_span_id = parent.trace_id, parent.span_id
  elseif self._remote then
    trace_id, parent_span_id = self._remote.trace_id, self._remote.span_id
  else
    trace_id = hex_id(self._random, 32)
  end
  local span_id = hex_id(self._random, 16)
  self._seq = self._seq + 1
  local record = {
    trace_id = trace_id,
    span_id = span_id,
    parent_span_id = parent_span_id,
    name = tostring(name),
    kind = kind,
    start_ns = self:_now_ns(),
    end_ns = nil,
    attributes = copy_attributes(opts.attributes),
    events = {},
    status = { code = "unset" },
    _seq = self._seq,
  }
  local span = setmetatable({
    trace_id = trace_id,
    span_id = span_id,
    recording = true,
    _record = record,
    _tracer = self,
    _done = false,
  }, Span)
  self._stack[#self._stack + 1] = span
  return span
end

--- tracer:with(name, opts, fn) -> fn's results. Ends the span on a normal return, on
-- `nil, err` (span failed with error.type = err.tag; results returned unchanged) and on
-- a raise (span failed and ended, then the original value is re-raised).
function Tracer:with(name, opts, fn)
  local span = self:start(name, opts)
  if not span.recording then
    return fn(span)
  end
  -- compat.pcall runs fn in a coroutine: safe from gopher-lua's protected-call bugs
  -- inside a caller's pcall, and a yield in fn passes through to the caller
  local r = compat.pack(compat.pcall(fn, span))
  if not r[1] then
    span:fail(r[2])
    span:finish()
    error(r[2], 0)
  end
  if r[2] == nil and r.n >= 3 and r[3] ~= nil then
    span:fail(r[3])
  end
  span:finish()
  return compat.unpack(r, 2, r.n)
end

--- tracer:current() -> the innermost open recording span, or nil
function Tracer:current()
  return self._stack[#self._stack]
end

local function stack_index(stack, span)
  for i = #stack, 1, -1 do
    if stack[i] == span then
      return i
    end
  end
  return nil
end

--- tracer:detach(span) -> true | false. Takes an open span off the active stack while
-- keeping it open: spans started afterwards are not its children, until attach(span).
-- Only the innermost span can be detached (a span with open children cannot leave the
-- stack without orphaning them); anything else, a non-recording span or a span not on
-- the stack, returns false and changes nothing. Used by long-lived spans that are active
-- only part of the time, e.g. the pagination traversal span between page fetches.
function Tracer:detach(span)
  local stack = self._stack
  if type(span) ~= "table" or not span.recording or stack[#stack] ~= span then
    return false
  end
  stack[#stack] = nil
  return true
end

--- tracer:attach(span) -> true | false. Makes a detached open span the current one
-- again (pushed as the innermost span). A non-recording span (NOOP_SPAN), a finished
-- span, or a span already on the stack returns false and changes nothing. A span of
-- another tracer is misuse and raises.
function Tracer:attach(span)
  if type(span) ~= "table" or not span.recording then
    return false
  end
  if span._tracer ~= self then
    compat.raise("tracer:attach: the span belongs to another tracer", 2)
  end
  local stack = self._stack
  if span._done or stack_index(stack, span) then
    return false
  end
  stack[#stack + 1] = span
  return true
end

--- tracer:traceparent() -> "00-<trace_id>-<span_id>-01" for the current span, or nil
function Tracer:traceparent()
  local span = self._stack[#self._stack]
  if not span then
    return nil
  end
  return "00-" .. span.trace_id .. "-" .. span.span_id .. "-01"
end

--- tracer:flush() -> true | nil, err. Hands finished spans (in start order) to every
-- exporter as fn(spans, { service_name }). Every exporter runs even if one fails; the
-- first failure is returned as an SdkError. Spans still open stay with the tracer.
function Tracer:flush()
  local finished = self._finished
  if #finished == 0 then
    return true
  end
  self._finished = {}
  table.sort(finished, function(a, b)
    return a._seq < b._seq
  end)
  local spans = {}
  for i, rec in ipairs(finished) do
    rec._seq = nil
    spans[i] = rec
  end
  local meta = { service_name = self.service_name }
  local failures = {}
  for _, exporter in ipairs(self._exporters) do
    local ok, res, err = compat.pcall(exporter, spans, meta)
    if not ok then
      failures[#failures + 1] = "raised: " .. message_of(res)
    elseif res == nil or res == false then
      failures[#failures + 1] = err ~= nil and message_of(err) or "returned no result"
    end
  end
  if #failures > 0 then
    local errors = require("distilled.errors")
    return nil,
      errors.new("SdkError", {
        message = "trace export failed: " .. table.concat(failures, "; "),
      })
  end
  return true
end

-- exporters are loaded on first use
setmetatable(trace, {
  __index = function(t, k)
    if k == "exporters" then
      local m = require("distilled.trace.exporters")
      rawset(t, k, m)
      return m
    end
    return nil
  end,
})

return trace
