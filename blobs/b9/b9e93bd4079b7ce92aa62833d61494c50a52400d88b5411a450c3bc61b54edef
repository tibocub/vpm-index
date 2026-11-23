-- AWS event stream framing on a streaming reader (docs/interfaces.md, the stream section):
-- the messages of an application/vnd.amazon.eventstream body, one at a time, as they
-- arrive.
--
--   local framing = require("distilled.stream.aws_eventstream")
--   local next_message = framing.messages(reader)
--   local message, err = next_message()   -- message | nil, nil at the end | nil, err
--   local event, err = framing.next_event(next_message)  -- parse_event on the next one
--
-- Each message is read with two read_exact calls: the 12-byte prelude, then the rest.
-- The prelude CRC is checked before the rest is read (as the AWS SDKs' decoders do), so
-- a corrupted length fails at once instead of waiting for bytes that never come; then
-- distilled.aws.eventstream.decode_message checks the whole message (Distilled's
-- decodeMessage, its messages). A body that ends inside a message is Distilled's
-- "Stream ended with N bytes of incomplete message data". Errors are ParseError, or the
-- reader's own (TransportError, TimeoutError) passed through.
local crc32 = require("distilled.crypto.crc32")
local errors = require("distilled.errors")
local es = require("distilled.aws.eventstream")

local M = {}

-- The largest message decode_message could accept: prelude, the header and payload
-- limits, the CRC. A bigger total_length is refused before reading it.
M.MAX_MESSAGE_LENGTH = es.PRELUDE_LENGTH
  + es.MAX_HEADERS_LENGTH
  + es.MAX_PAYLOAD_LENGTH
  + es.MESSAGE_CRC_LENGTH

local function parse_error(message)
  return errors.new("ParseError", { message = message })
end

local function incomplete(n)
  return parse_error("Stream ended with " .. n .. " bytes of incomplete message data")
end

-- bytes a failed read_exact had already read (the proposed err.partial), else 0
local function partial_of(err)
  return type(err) == "table" and type(err.partial) == "string" and #err.partial or 0
end

--- M.messages(reader) -> next() -> message | nil, nil (clean end) | nil, err
function M.messages(reader)
  local done = false
  return function()
    if done then
      return nil, nil
    end
    local prelude, err = reader:read_exact(es.PRELUDE_LENGTH)
    if prelude == nil then
      done = true
      if err == nil then
        return nil, nil
      end
      if type(err) == "table" and err.eof then
        return nil, incomplete(partial_of(err))
      end
      return nil, err
    end
    if #prelude < es.PRELUDE_LENGTH then
      done = true
      return nil, incomplete(#prelude)
    end
    local total = es.read_u32(prelude, 1)
    local want = es.read_u32(prelude, 9)
    local got = crc32.crc32(string.sub(prelude, 1, 8))
    if got ~= want then
      done = true
      return nil, parse_error("Prelude CRC mismatch: expected " .. want .. ", got " .. got)
    end
    if total < es.MIN_MESSAGE_LENGTH then
      done = true
      return nil,
        parse_error(
          "Message length " .. total .. " is below the " .. es.MIN_MESSAGE_LENGTH .. "-byte minimum"
        )
    end
    if total > M.MAX_MESSAGE_LENGTH then
      done = true
      return nil,
        parse_error(
          "Message length " .. total .. " exceeds the " .. M.MAX_MESSAGE_LENGTH .. "-byte maximum"
        )
    end
    local rest, rerr = reader:read_exact(total - es.PRELUDE_LENGTH)
    if rest == nil then
      done = true
      if rerr == nil or (type(rerr) == "table" and rerr.eof) then
        return nil, incomplete(es.PRELUDE_LENGTH + partial_of(rerr))
      end
      return nil, rerr
    end
    if #rest < total - es.PRELUDE_LENGTH then
      done = true
      return nil, incomplete(es.PRELUDE_LENGTH + #rest)
    end
    local message, merr = es.decode_message(prelude .. rest)
    if not message then
      done = true
      return nil, merr
    end
    return message
  end
end

--- M.next_event(next_message) -> event | nil, nil | nil, err (eventstream.parse_event)
function M.next_event(next_message)
  local message, err = next_message()
  if not message then
    return nil, err
  end
  return es.parse_event(message)
end

return M
