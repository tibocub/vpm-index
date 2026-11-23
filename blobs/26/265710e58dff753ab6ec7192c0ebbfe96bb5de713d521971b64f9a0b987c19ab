-- Streaming responses (task 29): the Stream object a client's `<op>_stream` method
-- returns, the framing registry, and reader helpers. Port of the parts of Distilled's
-- API.makeStreaming / `.stream()` (core/src/api.ts) and StreamFraming
-- (core/src/protocol-rest.ts) that are not protocol specific.
--
--   local stream, err = client:execute_sandbox_command_stream(input [, opts])
--   for item, item_err in stream:iter() do ... end   -- item is false when item_err is set
--   stream:next() -> item | nil, nil (the end) | nil, err
--   stream:collect([limit]) -> list | nil, err
--   stream:close()                                   -- idempotent; stops the transfer
--   stream.status, stream.headers, stream.output (AWS initial response), stream.err
--   stream:send(event), stream:close_input()          -- duplex operations only (AWS)
--
-- A reader (transport.stream's `body`, docs/interfaces.md "Streams"):
--   reader:read_line()   -> line without "\n" (and a trailing "\r") | nil, nil | nil, err
--   reader:read_exact(n) -> n bytes | nil, nil at a clean EOF | nil, err (a body that
--                           ends inside the n bytes: err.eof = true, err.partial = bytes)
--   reader:read_all()    -> the rest | nil, err
--   reader:close()
--
-- Framings: stream.framing(name) -> fn(reader) -> frames, where frames:next() returns
-- one frame | nil, nil | nil, err. "ndjson" and "sse" live here (distilled.stream.ndjson,
-- .sse); "grpc", "connect" (task 30) and "aws_eventstream" (task 31) are read by their
-- protocols directly, which know their frames' meaning.
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local M = {}

---------------------------------------------------------------------------------------
-- framing registry
---------------------------------------------------------------------------------------

M.FRAMINGS = { ndjson = true, sse = true, grpc = true, connect = true, aws_eventstream = true }

local registered = {}

--- stream.register_framing(name, fn): fn(reader) -> frames (for a provider's own framing)
function M.register_framing(name, fn)
  if type(name) ~= "string" or type(fn) ~= "function" then
    compat.raise("stream.register_framing: expected (name, fn(reader) -> frames)", 2)
  end
  registered[name] = fn
end

--- stream.framing(name) -> fn(reader) -> frames | nil: the built-in ones load on first use
function M.framing(name)
  local fn = registered[name]
  if fn == nil and (name == "ndjson" or name == "sse") then
    fn = require("distilled.stream." .. name).frames
    registered[name] = fn
  end
  return fn
end

---------------------------------------------------------------------------------------
-- readers
---------------------------------------------------------------------------------------

--- stream.string_reader(text) -> reader over a string (a plain call that collects a
-- framed body, and tests)
function M.string_reader(text)
  local pos = 1
  local len = #text
  local r = { closed = false }
  function r:read_line()
    if pos > len then
      return nil, nil
    end
    local i = string.find(text, "\n", pos, true)
    local line
    if i then
      line = string.sub(text, pos, i - 1)
      pos = i + 1
    else
      line = string.sub(text, pos)
      pos = len + 1
    end
    return (string.gsub(line, "\r$", ""))
  end
  function r:read_exact(n)
    if pos > len then
      return nil, nil
    end
    if pos + n - 1 > len then
      local partial = string.sub(text, pos)
      pos = len + 1
      return nil,
        errors.new("TransportError", {
          message = "the response body ended inside a frame",
          eof = true,
          partial = partial,
        })
    end
    local s = string.sub(text, pos, pos + n - 1)
    pos = pos + n
    return s
  end
  function r:read_all()
    local s = string.sub(text, pos)
    pos = len + 1
    return s
  end
  function r:close()
    r.closed = true
  end
  return r
end

---------------------------------------------------------------------------------------
-- the Stream object
---------------------------------------------------------------------------------------

local Stream = {}
Stream.__index = Stream
M.Stream = Stream

local function finish(self, err, reason)
  if self.done then
    return
  end
  self.done = true
  self.err = err
  local close = self._parts.close
  if close then
    compat.pcall(close)
  end
  local on_end = self._on_end
  self._on_end = nil
  if on_end then
    on_end(err, self.count, reason)
  end
end

--- stream.new(parts [, hooks]) -> stream
-- parts = { status, headers, output?, next = fn() -> item | nil, nil | nil, err,
--           close = fn(), send?, close_input? } (a protocol's protocol.stream result)
-- hooks = { first = <item already read> | nil, first_err = <its error> | nil, ended = true (no items at all), on_end = fn(err_or_nil, count, reason) }
-- on_end runs once: at the end of the items, at an error, or at close.
function M.new(parts, hooks)
  if type(parts) ~= "table" or type(parts.next) ~= "function" then
    compat.raise("stream.new: expected parts with a next function", 2)
  end
  hooks = hooks or {}
  local self = setmetatable({
    status = parts.status,
    headers = parts.headers,
    output = parts.output,
    count = 0,
    done = false,
    _parts = parts,
    _first = hooks.first,
    _first_err = hooks.first_err,
    _on_end = hooks.on_end,
  }, Stream)
  if hooks.ended then
    finish(self, nil, "end")
  end
  return self
end

function M.is(v)
  return getmetatable(v) == Stream
end

--- stream:next() -> item | nil, nil at the end | nil, err once (then nil, nil; the
-- error stays in stream.err)
function Stream:next()
  if self.done then
    return nil, nil
  end
  local item, err
  if self._first_err ~= nil then
    err = self._first_err
    self._first_err = nil
  elseif self._first ~= nil then
    item = self._first
    self._first = nil
  else
    local r = compat.pack(compat.pcall(self._parts.next))
    if not r[1] then
      -- a raise inside a protocol's frame decoder is a bug, but it must still reap curl
      err = errors.new("SdkError", { message = "the stream raised: " .. tostring(r[2]) })
    else
      item, err = r[2], r[3]
    end
  end
  if item == nil then
    if err ~= nil and not errors.is(err) then
      err = errors.new("TransportError", { message = tostring(err) })
    end
    finish(self, err, err and "error" or "end")
    return nil, err
  end
  self.count = self.count + 1
  return item
end

--- stream:iter() -> iterator for a generic for: item, nil per item; false, err once
-- for an error (so the loop body sees it), then the loop ends
function Stream:iter()
  local stopped = false
  return function()
    if stopped then
      return nil
    end
    local item, err = self:next()
    if item == nil then
      stopped = true
      if err ~= nil then
        return false, err
      end
      return nil
    end
    return item, nil
  end
end

--- stream:collect([limit]) -> list | nil, err: the remaining items (at most limit, then
-- the stream is closed)
function Stream:collect(limit)
  local list = {}
  while limit == nil or #list < limit do
    local item, err = self:next()
    if item == nil then
      if err ~= nil then
        return nil, err
      end
      return list
    end
    list[#list + 1] = item
  end
  self:close()
  return list
end

--- stream:close(): stops the transfer (kills curl) and ends the span; idempotent
function Stream:close()
  finish(self, nil, "closed")
end

--- stream:send(event) -> true | nil, err (duplex operations: AWS input event streams)
function Stream:send(event)
  local send = self._parts.send
  if send == nil then
    return nil, errors.new("SdkError", { message = "this stream takes no input events" })
  end
  if self.done then
    return nil, errors.new("SdkError", { message = "the stream is closed" })
  end
  return send(event)
end

--- stream:close_input() -> true | nil, err: no more input events (duplex operations)
function Stream:close_input()
  local close_input = self._parts.close_input
  if close_input == nil then
    return nil, errors.new("SdkError", { message = "this stream takes no input events" })
  end
  return close_input()
end

Stream.__tostring = function(self)
  return "distilled stream (" .. tostring(self.status) .. ")"
end

return M
