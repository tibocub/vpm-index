-- The AWS event stream message codec (application/vnd.amazon.eventstream).
--
-- Port of Distilled's packages/s3/src/eventstream/codec.ts, byte for byte, plus the
-- event signing of AWS SDKs (@smithy/signature-v4 signEvent, the SDKs' event signing
-- stream), which Distilled does not do.
--
-- A message on the wire:
--   total_length (4) | headers_length (4) | prelude_crc (4) | headers | payload | message_crc (4)
-- all big-endian; prelude_crc is the CRC-32 of the first 8 bytes, message_crc the CRC-32 of
-- everything before it. A header is name_length (1) | name | type (1) | value.
--
-- Headers are an ordered list (Lua tables have no order, and the order is on the wire):
--   { { name = ":message-type", type = "string", value = "event" }, ... }
-- Types and values:
--   boolean   true | false          (wire type 0 for true, 1 for false)
--   byte      -128..127             (2)
--   short     -32768..32767         (3)
--   integer   int32                 (4)
--   long      int64 as a number     (5) exact up to 2^53; decoding also gives `raw`, the 8 bytes
--   binary    a byte string         (6) at most 65535 bytes
--   string    UTF-8 text            (7) at most 65535 bytes
--   timestamp milliseconds since the epoch (8)
--   uuid      16 raw bytes          (9)
--
--   eventstream.encode_message{ headers, payload } -> bytes | nil, err (InvalidInput)
--   eventstream.decode_message(bytes) -> message, consumed | nil, err (ParseError)
--     message = { headers, payload, total_length, headers_length }
--   eventstream.message_length(buffer) -> total length of the first message | 0
--   eventstream.header(headers, name) -> header | nil; .string_header(headers, name)
--   eventstream.parse_event(message) -> event | nil, err (ParseError)
--     event = { kind = "event", event_type, content_type, payload, headers }
--           | { kind = "exception", exception_type, content_type, payload, headers }
--           | { kind = "error", error_code, error_message, headers }
--   eventstream.encode_event(event) -> bytes | nil, err
--   eventstream.sign_frame{ payload, prior_signature, signing_key, scope, epoch_ms }
--     -> frame bytes, signature hex: one signed envelope (see sign_frame below)
local compat = require("distilled.compat")
local crc32 = require("distilled.crypto.crc32")
local errors = require("distilled.errors")

local M = {}

local byte, char, sub = string.byte, string.char, string.sub
local floor = math.floor

M.PRELUDE_LENGTH = 12
M.MESSAGE_CRC_LENGTH = 4
M.MIN_MESSAGE_LENGTH = 16
M.MAX_PAYLOAD_LENGTH = 25165824 -- 24 MiB
M.MAX_HEADERS_LENGTH = 131072 -- 128 KiB

M.HEADER_MESSAGE_TYPE = ":message-type"
M.HEADER_EVENT_TYPE = ":event-type"
M.HEADER_EXCEPTION_TYPE = ":exception-type"
M.HEADER_ERROR_CODE = ":error-code"
M.HEADER_ERROR_MESSAGE = ":error-message"
M.HEADER_CONTENT_TYPE = ":content-type"
M.INITIAL_REQUEST_EVENT_TYPE = "initial-request"
M.INITIAL_RESPONSE_EVENT_TYPE = "initial-response"

-- wire type numbers, by name and back
M.TYPES = {
  boolean = true, -- 0 or 1, by value
  byte = 2,
  short = 3,
  integer = 4,
  long = 5,
  binary = 6,
  string = 7,
  timestamp = 8,
  uuid = 9,
}
local TYPE_NAMES = {
  [0] = "boolean",
  [1] = "boolean",
  [2] = "byte",
  [3] = "short",
  [4] = "integer",
  [5] = "long",
  [6] = "binary",
  [7] = "string",
  [8] = "timestamp",
  [9] = "uuid",
}
M.TYPE_NAMES = TYPE_NAMES

local function parse_error(message)
  return errors.new("ParseError", { message = message })
end

local function encode_error(message)
  return errors.new("InvalidInput", { message = message })
end

---------------------------------------------------------------------------------------
-- big-endian integers
---------------------------------------------------------------------------------------

local function u32(n)
  return char(floor(n / 16777216) % 256, floor(n / 65536) % 256, floor(n / 256) % 256, n % 256)
end
M.u32 = u32

local function u16(n)
  return char(floor(n / 256) % 256, n % 256)
end

local function read_u32(s, at)
  local a, b, c, d = byte(s, at, at + 3)
  return ((a * 256 + b) * 256 + c) * 256 + d
end
M.read_u32 = read_u32

local function read_u16(s, at)
  local a, b = byte(s, at, at + 1)
  return a * 256 + b
end

-- two's complement of a signed integer that fits in `bytes` bytes
-- 256^n as integer literals, so Lua 5.3+ keeps integers (2 ^ n is a float there)
local RANGE = { 256, 65536, 16777216, 4294967296 }

local function signed_bytes(v, bytes)
  local out = {}
  local range = RANGE[bytes]
  if v < 0 then
    v = v + range
  end
  for i = bytes, 1, -1 do
    out[i] = char(v % 256)
    v = floor(v / 256)
  end
  return table.concat(out)
end

local function read_signed(s, at, bytes)
  local v = 0
  for i = at, at + bytes - 1 do
    v = v * 256 + byte(s, i)
  end
  if byte(s, at) >= 128 then
    v = v - RANGE[bytes]
  end
  return v
end

-- int64 from a number: split into two 32-bit halves so no step needs more than 53 bits
local function int64(v)
  local hi = floor(v / 4294967296)
  local lo = v - hi * 4294967296
  if hi < 0 then
    hi = hi + 4294967296
  end
  return u32(hi) .. u32(lo)
end
M.int64 = int64

local function read_int64(s, at)
  local hi, lo = read_u32(s, at), read_u32(s, at + 4)
  if hi >= 2147483648 then
    hi = hi - 4294967296
  end
  return hi * 4294967296 + lo
end

local function crc(s)
  return crc32.crc32(s)
end

---------------------------------------------------------------------------------------
-- encoding
---------------------------------------------------------------------------------------

local function is_integer(v, lo, hi)
  return type(v) == "number" and v == floor(v) and v >= lo and v <= hi
end

-- encodeHeaderValue: the type byte and the value; nil, message for a value its type
-- cannot hold
local function encode_value(h)
  local t, v = h.type, h.value
  if t == "boolean" then
    if type(v) ~= "boolean" then
      return nil, "a boolean header needs true or false"
    end
    return char(v and 0 or 1)
  elseif t == "byte" then
    if not is_integer(v, -128, 127) then
      return nil, "a byte header needs an integer in [-128, 127]"
    end
    return char(2) .. signed_bytes(v, 1)
  elseif t == "short" then
    if not is_integer(v, -32768, 32767) then
      return nil, "a short header needs an integer in [-32768, 32767]"
    end
    return char(3) .. signed_bytes(v, 2)
  elseif t == "integer" then
    if not is_integer(v, -2147483648, 2147483647) then
      return nil, "an integer header needs an int32"
    end
    return char(4) .. signed_bytes(v, 4)
  elseif t == "long" or t == "timestamp" then
    local code = t == "long" and 5 or 8
    if type(h.raw) == "string" and #h.raw == 8 then
      return char(code) .. h.raw
    end
    if not is_integer(v, -9223372036854775808, 9223372036854775807) then
      return nil, "a " .. t .. " header needs an integer"
    end
    return char(code) .. int64(v)
  elseif t == "binary" or t == "string" then
    if type(v) ~= "string" then
      return nil, "a " .. t .. " header needs a string"
    end
    if #v > 65535 then
      return nil, "a " .. t .. " header value is at most 65535 bytes"
    end
    return char(t == "binary" and 6 or 7) .. u16(#v) .. v
  elseif t == "uuid" then
    if type(v) ~= "string" or #v ~= 16 then
      return nil, "a uuid header needs 16 bytes"
    end
    return char(9) .. v
  end
  return nil, "unknown header type " .. tostring(t)
end

--- M.encode_headers(headers) -> bytes | nil, err
function M.encode_headers(headers)
  if type(headers) ~= "table" then
    compat.raise("eventstream.encode_headers: headers must be a list", 2)
  end
  local parts = {}
  for i = 1, #headers do
    local h = headers[i]
    local name = type(h) == "table" and h.name
    if type(name) ~= "string" or #name == 0 or #name > 255 then
      return nil, encode_error("Header name must be 1-255 bytes: " .. tostring(name))
    end
    local value, why = encode_value(h)
    if not value then
      return nil, encode_error("Header " .. name .. ": " .. why)
    end
    parts[#parts + 1] = char(#name) .. name .. value
  end
  local out = compat.concat(parts)
  if #out > M.MAX_HEADERS_LENGTH then
    return nil,
      encode_error("Headers exceed maximum length: " .. #out .. " > " .. M.MAX_HEADERS_LENGTH)
  end
  return out
end

--- M.encode_message{ headers = list, payload = string } -> bytes | nil, err
function M.encode_message(message)
  if type(message) ~= "table" then
    compat.raise("eventstream.encode_message: expected { headers, payload }", 2)
  end
  local payload = message.payload or ""
  if type(payload) ~= "string" then
    compat.raise("eventstream.encode_message: payload must be a string", 2)
  end
  local headers, err = M.encode_headers(message.headers or {})
  if not headers then
    return nil, err
  end
  if #payload > M.MAX_PAYLOAD_LENGTH then
    return nil,
      encode_error("Payload exceeds maximum length: " .. #payload .. " > " .. M.MAX_PAYLOAD_LENGTH)
  end
  local total = M.PRELUDE_LENGTH + #headers + #payload + M.MESSAGE_CRC_LENGTH
  local prelude = u32(total) .. u32(#headers)
  local prelude_crc = crc(prelude)
  local body = prelude .. u32(prelude_crc) .. headers .. payload
  -- the message CRC continues the prelude's checksum over the rest
  return body .. u32(crc32.crc32(sub(body, 9), prelude_crc))
end

---------------------------------------------------------------------------------------
-- decoding
---------------------------------------------------------------------------------------

local FIXED = { [2] = 1, [3] = 2, [4] = 4, [5] = 8, [8] = 8, [9] = 16 }

-- decodeHeaderValue: header, size | nil, err. `block` is the header block, `at` the
-- 1-based position of the type byte.
local function decode_value(block, at)
  local t = byte(block, at)
  local available = #block - at + 1
  local offset = at - 1
  local function past_end(size)
    return nil,
      parse_error(
        "Header value of type "
          .. t
          .. " needs "
          .. size
          .. " bytes at offset "
          .. offset
          .. ", but the header block has "
          .. available
      )
  end
  if t == 0 or t == 1 then
    return { type = "boolean", value = t == 0 }, 1
  end
  local n = FIXED[t]
  if n then
    if available < n + 1 then
      return past_end(n + 1)
    end
    local h = { type = TYPE_NAMES[t] }
    if t == 9 then
      h.value = sub(block, at + 1, at + 16)
    elseif t == 5 or t == 8 then
      h.value = read_int64(block, at + 1)
      h.raw = sub(block, at + 1, at + 8)
    else
      h.value = read_signed(block, at + 1, n)
    end
    return h, n + 1
  end
  if t == 6 or t == 7 then
    local size = available < 3 and 3 or 3 + read_u16(block, at + 1)
    if available < size then
      return past_end(size)
    end
    return { type = TYPE_NAMES[t], value = sub(block, at + 3, at + size - 1) }, size
  end
  return nil, parse_error("Unknown header type: " .. tostring(t))
end

--- M.decode_headers(block) -> headers (list) | nil, err
-- A repeated name keeps its first position and takes the last value, as Distilled's
-- decodeHeaders (headers[name] = value on a plain object) does.
function M.decode_headers(block)
  local headers, index = {}, {}
  local at, len = 1, #block
  while at <= len do
    local name_length = byte(block, at)
    if (at - 1) + 1 + name_length >= len then
      return nil,
        parse_error(
          "Header name of "
            .. name_length
            .. " bytes at offset "
            .. (at - 1)
            .. " leaves no room for its value in the "
            .. len
            .. "-byte header block"
        )
    end
    local name = sub(block, at + 1, at + name_length)
    at = at + 1 + name_length
    local h, size = decode_value(block, at)
    if not h then
      return nil, size
    end
    h.name = name
    if index[name] then
      headers[index[name]] = h
    else
      headers[#headers + 1] = h
      index[name] = #headers
    end
    at = at + size
  end
  return headers
end

--- M.decode_message(data) -> message, consumed | nil, err
-- Checks are in Distilled's order (decodeMessage): length, prelude CRC, message CRC,
-- then the header length.
function M.decode_message(data)
  if type(data) ~= "string" then
    compat.raise("eventstream.decode_message: data must be a string", 2)
  end
  if #data < M.MIN_MESSAGE_LENGTH then
    return nil, parse_error("Message too short: " .. #data .. " < " .. M.MIN_MESSAGE_LENGTH)
  end
  local total = read_u32(data, 1)
  local headers_length = read_u32(data, 5)
  local prelude_crc = read_u32(data, 9)
  if total < M.MIN_MESSAGE_LENGTH then
    return nil,
      parse_error(
        "Message length " .. total .. " is below the " .. M.MIN_MESSAGE_LENGTH .. "-byte minimum"
      )
  end
  if #data < total then
    return nil, parse_error("Incomplete message: have " .. #data .. ", need " .. total)
  end
  local computed_prelude = crc(sub(data, 1, 8))
  if computed_prelude ~= prelude_crc then
    return nil,
      parse_error("Prelude CRC mismatch: expected " .. prelude_crc .. ", got " .. computed_prelude)
  end
  local message_crc = read_u32(data, total - 3)
  local computed = crc(sub(data, 1, total - 4))
  if computed ~= message_crc then
    return nil,
      parse_error("Message CRC mismatch: expected " .. message_crc .. ", got " .. computed)
  end
  if headers_length > total - M.PRELUDE_LENGTH - M.MESSAGE_CRC_LENGTH then
    return nil,
      parse_error(
        "Headers length " .. headers_length .. " exceeds the " .. total .. "-byte message"
      )
  end
  local headers, herr = M.decode_headers(sub(data, 13, 12 + headers_length))
  if not headers then
    return nil, herr
  end
  return {
    headers = headers,
    payload = sub(data, 13 + headers_length, total - 4),
    total_length = total,
    headers_length = headers_length,
    prelude_crc = prelude_crc,
    message_crc = message_crc,
  },
    total
end

--- M.message_length(buffer) -> the first message's total length when it is complete, else 0
function M.message_length(buffer)
  if #buffer < M.PRELUDE_LENGTH then
    return 0
  end
  local total = read_u32(buffer, 1)
  if #buffer < total then
    return 0
  end
  return total
end

--- M.header(headers, name) -> the header | nil
function M.header(headers, name)
  for i = 1, #headers do
    if headers[i].name == name then
      return headers[i]
    end
  end
  return nil
end

--- M.string_header(headers, name) -> its value when it is a string header, else nil
function M.string_header(headers, name)
  local h = M.header(headers, name)
  if h and h.type == "string" then
    return h.value
  end
  return nil
end

---------------------------------------------------------------------------------------
-- events (codec.ts parseEvent / encodeEvent)
---------------------------------------------------------------------------------------

--- M.parse_event(message) -> event | nil, err
function M.parse_event(message)
  local headers, payload = message.headers, message.payload
  local message_type = M.string_header(headers, M.HEADER_MESSAGE_TYPE)
  if not message_type or message_type == "" then
    return nil, parse_error("Missing " .. M.HEADER_MESSAGE_TYPE .. " header")
  end
  if message_type == "event" then
    local event_type = M.string_header(headers, M.HEADER_EVENT_TYPE)
    if not event_type or event_type == "" then
      return nil, parse_error("Missing " .. M.HEADER_EVENT_TYPE .. " header for event message")
    end
    return {
      kind = "event",
      event_type = event_type,
      content_type = M.string_header(headers, M.HEADER_CONTENT_TYPE),
      payload = payload,
      headers = headers,
    }
  elseif message_type == "exception" then
    local exception_type = M.string_header(headers, M.HEADER_EXCEPTION_TYPE)
    if not exception_type or exception_type == "" then
      return nil,
        parse_error("Missing " .. M.HEADER_EXCEPTION_TYPE .. " header for exception message")
    end
    return {
      kind = "exception",
      exception_type = exception_type,
      content_type = M.string_header(headers, M.HEADER_CONTENT_TYPE),
      payload = payload,
      headers = headers,
    }
  elseif message_type == "error" then
    local code = M.string_header(headers, M.HEADER_ERROR_CODE)
    local text = M.string_header(headers, M.HEADER_ERROR_MESSAGE)
    if not code or code == "" then
      return nil, parse_error("Missing " .. M.HEADER_ERROR_CODE .. " header for error message")
    end
    if not text or text == "" then
      return nil, parse_error("Missing " .. M.HEADER_ERROR_MESSAGE .. " header for error message")
    end
    return { kind = "error", error_code = code, error_message = text, headers = headers }
  end
  return nil, parse_error("Unknown message type: " .. message_type)
end

local function str(name, value)
  return { name = name, type = "string", value = value }
end
M.string = str

-- the standard headers, then the event's own, except those it repeats: Distilled
-- spreads the event's headers over the standard ones ({ ...std, ...event.headers }),
-- so a repeated name keeps its first position and takes the event's value
local function merge(standard, own)
  local out, index = {}, {}
  for _, h in ipairs(standard) do
    out[#out + 1] = h
    index[h.name] = #out
  end
  for _, h in ipairs(own or {}) do
    if index[h.name] then
      out[index[h.name]] = h
    else
      out[#out + 1] = h
      index[h.name] = #out
    end
  end
  return out, index
end

--- M.encode_event(event) -> bytes | nil, err
function M.encode_event(ev)
  if ev.kind == "event" then
    local headers, index = merge(
      { str(M.HEADER_MESSAGE_TYPE, "event"), str(M.HEADER_EVENT_TYPE, ev.event_type) },
      ev.headers
    )
    if ev.content_type and ev.content_type ~= "" then
      local h = str(M.HEADER_CONTENT_TYPE, ev.content_type)
      if index[h.name] then
        headers[index[h.name]] = h
      else
        headers[#headers + 1] = h
      end
    end
    return M.encode_message({ headers = headers, payload = ev.payload or "" })
  elseif ev.kind == "exception" then
    local headers, index = merge({
      str(M.HEADER_MESSAGE_TYPE, "exception"),
      str(M.HEADER_EXCEPTION_TYPE, ev.exception_type),
    }, ev.headers)
    if ev.content_type and ev.content_type ~= "" then
      local h = str(M.HEADER_CONTENT_TYPE, ev.content_type)
      if index[h.name] then
        headers[index[h.name]] = h
      else
        headers[#headers + 1] = h
      end
    end
    return M.encode_message({ headers = headers, payload = ev.payload or "" })
  elseif ev.kind == "error" then
    local headers = merge({
      str(M.HEADER_MESSAGE_TYPE, "error"),
      str(M.HEADER_ERROR_CODE, ev.error_code),
      str(M.HEADER_ERROR_MESSAGE, ev.error_message),
    }, ev.headers)
    return M.encode_message({ headers = headers, payload = "" })
  end
  compat.raise("eventstream.encode_event: kind must be event, exception or error", 2)
end

---------------------------------------------------------------------------------------
-- event signing (SigV4 for event streams)
---------------------------------------------------------------------------------------

--- M.sign_frame{ payload, prior_signature, signing_key, scope, epoch_ms } -> frame, signature
-- One signed envelope, as the AWS SDKs send each input event (and a last empty one):
--   string to sign = "AWS4-HMAC-SHA256-PAYLOAD" \n <YYYYMMDDTHHMMSSZ> \n <scope> \n
--                    <prior signature hex> \n hex(sha256(<the :date header bytes>)) \n
--                    hex(sha256(payload))
--   signature      = hmac_sha256(signing key, string to sign)
--   frame          = a message with headers :date (timestamp) and :chunk-signature
--                    (binary, the 32 signature bytes), whose payload is the encoded event
-- The first prior signature is the request's own (the seed signature); each frame's
-- signature is the next one's prior. `epoch_ms` is whole seconds in milliseconds.
function M.sign_frame(args)
  local crypto = require("distilled.crypto")
  local sigv4 = require("distilled.sigv4")
  local payload = args.payload or ""
  local date = { name = ":date", type = "timestamp", value = args.epoch_ms }
  local date_bytes, err = M.encode_headers({ date })
  if not date_bytes then
    return nil, err
  end
  local string_to_sign = table.concat({
    "AWS4-HMAC-SHA256-PAYLOAD",
    sigv4.amz_datetime(floor(args.epoch_ms / 1000)),
    args.scope,
    args.prior_signature,
    crypto.hex.encode(crypto.sha256(date_bytes)),
    crypto.hex.encode(crypto.sha256(payload)),
  }, "\n")
  local raw = crypto.hmac_sha256(args.signing_key, string_to_sign)
  local frame, ferr = M.encode_message({
    headers = { date, { name = ":chunk-signature", type = "binary", value = raw } },
    payload = payload,
  })
  if not frame then
    return nil, ferr
  end
  return frame, crypto.hex.encode(raw)
end

return M
