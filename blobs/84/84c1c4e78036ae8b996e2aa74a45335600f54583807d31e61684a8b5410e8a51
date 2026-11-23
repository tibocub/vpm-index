-- Connect streaming envelopes on a streaming body reader (task 30). Port of
-- takeEnvelopes in Distilled's packages/e2b/src/connect.ts, pulled one envelope at a
-- time, so a message is returned as soon as its last byte has arrived.
--
-- An envelope is one flags byte, a 4-byte big-endian length, then that many bytes of
-- JSON (application/connect+json). Flag 0x02 marks the end-of-stream envelope, whose JSON
-- is `{ error?: { code, message, details }, metadata? }`.
--
--   local envelopes = require("distilled.stream.connect")
--   local decoder = envelopes.new(reader)    -- reader:read_exact(n) (distilled.stream)
--   local env, err = decoder:next()  -- { end_stream = bool, json = value } | nil, nil | nil, err
--   envelopes.encode(value) -> bytes         -- one envelope (encodeEnvelope)
--   envelopes.frame(bytes [, flags]) -> bytes -- one envelope around JSON text
--
-- As in connect.ts, a payload that is not JSON becomes `{ __invalidJson = text }` (the
-- caller's item decoder then fails it) and the text is read as UTF-8 with bad bytes
-- replaced (TextDecoder). Deliberate difference: an envelope cut short by the end of the
-- body is a ParseError here; takeEnvelopes keeps it as a remainder nobody reads, so the
-- TS stream ends as if complete.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local protobuf = require("distilled.protobuf")

local envelopes = {}

envelopes.END_STREAM_FLAG = 2
envelopes.COMPRESSED_FLAG = 1

local byte, char = string.byte, string.char

local function be32(n)
  local b4 = n % 256
  n = (n - b4) / 256
  local b3 = n % 256
  n = (n - b3) / 256
  local b2 = n % 256
  local b1 = (n - b2) / 256
  return char(b1, b2, b3, b4)
end

--- envelopes.frame(bytes [, flags]) -> one envelope around bytes
function envelopes.frame(bytes, flags)
  return char(flags or 0) .. be32(#bytes) .. bytes
end

--- envelopes.encode(value [, flags]) -> bytes | nil, err: value as one JSON envelope
function envelopes.encode(value, flags)
  local text, err = json.encode(value)
  if not text then
    return nil, err
  end
  return envelopes.frame(text, flags)
end

--- envelopes.parse_json(bytes) -> value (connect.ts parseJson)
function envelopes.parse_json(bytes)
  local text = protobuf.utf8_fix(bytes)
  local value = json.decode(text)
  if value == nil then
    return json.object({ __invalidJson = text })
  end
  return value
end

local Decoder = {}
Decoder.__index = Decoder

--- envelopes.new(reader) -> decoder
function envelopes.new(reader)
  if type(reader) ~= "table" or type(reader.read_exact) ~= "function" then
    compat.raise("distilled.stream.connect: expected a reader with read_exact", 2)
  end
  return setmetatable({ reader = reader, done = false }, Decoder)
end

local function truncated()
  return errors.new("ParseError", { message = "truncated Connect envelope" })
end

--- decoder:next() -> { end_stream, flags, json } | nil, nil | nil, err
function Decoder:next()
  if self.done then
    return nil, nil
  end
  local reader = self.reader
  local flag, err = reader:read_exact(1)
  if flag == nil then
    self.done = true
    return nil, err
  end
  local head
  head, err = reader:read_exact(4)
  if head == nil then
    self.done = true
    return nil, err or truncated()
  end
  local b1, b2, b3, b4 = byte(head, 1, 4)
  local len = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
  local payload = ""
  if len > 0 then
    payload, err = reader:read_exact(len)
    if payload == nil then
      self.done = true
      return nil, err or truncated()
    end
  end
  local f = byte(flag)
  if f % 2 == 1 then
    -- connect.ts never asks for compression and would parse the bytes as JSON; say why
    self.done = true
    return nil,
      errors.new("ParseError", { message = "compressed Connect envelopes are not supported" })
  end
  local is_end = f % 4 >= envelopes.END_STREAM_FLAG
  return { end_stream = is_end, flags = f, json = envelopes.parse_json(payload) }
end

return envelopes
