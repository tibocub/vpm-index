-- gRPC message framing on a streaming body reader (task 30). Port of the FrameReader in
-- Distilled's core/src/protocol-grpc.ts, pulled one frame at a time instead of pushed
-- chunk by chunk, so a frame is returned as soon as its last byte has arrived.
--
-- A frame is one flags byte, a 4-byte big-endian length and that many bytes:
--
--   flags 0x00   a message (its payload is one protobuf message)
--   flags 0x01   a compressed message: refused (Distilled's FrameReader refuses it too)
--   flags 0x80   a gRPC-Web trailer frame: `name: value` lines, CRLF separated, that
--                carry grpc-status / grpc-message; collected into decoder.trailers
--
--   local frames = require("distilled.stream.grpc")
--   local decoder = frames.new(reader)   -- reader:read_exact(n) (distilled.stream)
--   local payload, err = decoder:next()  -- bytes | nil, nil (the body ended) | nil, err
--   decoder.trailers   -- { [lowercase name] = value } from gRPC-Web trailer frames
--   decoder.saw_body   -- true once any byte of the body was read
--   decoder.rest       -- bytes of an incomplete last frame (0 when the body ended cleanly)
--
-- An incomplete last frame (a clean end of the body, or a read_exact error marked
-- `eof = true`, inside a frame) is not an error here: like Distilled, the protocol first reads
-- the call's status (a failed call may well end mid-frame) and only then reports
-- "truncated gRPC frame" when the status was OK. A reader error (transport drop,
-- timeout) is passed through untouched.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local protobuf = require("distilled.protobuf")

local frames = {}

local byte, sub, find = string.byte, string.sub, string.find

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

--- frames.parse_trailers(payload, into) -> into: a gRPC-Web trailer frame's lines
function frames.parse_trailers(payload, into)
  into = into or {}
  for line in string.gmatch(protobuf.utf8_fix(payload) .. "\r\n", "(.-)\r\n") do
    local colon = find(line, ":", 1, true)
    if colon and colon > 1 then
      into[string.lower(trim(sub(line, 1, colon - 1)))] = trim(sub(line, colon + 1))
    end
  end
  return into
end

local Decoder = {}
Decoder.__index = Decoder

--- frames.new(reader) -> decoder
function frames.new(reader)
  if type(reader) ~= "table" or type(reader.read_exact) ~= "function" then
    compat.raise("distilled.stream.grpc: expected a reader with read_exact", 2)
  end
  return setmetatable(
    { reader = reader, trailers = {}, saw_body = false, rest = 0, done = false },
    Decoder
  )
end

-- a reader's "the body ended in the middle of read_exact" (err.eof = true, with
-- err.partial bytes read; see STATUS.md 30): a truncated frame, not a transport failure
local function ended(err)
  return type(err) == "table" and err.eof == true
end

local function partial(err)
  return type(err) == "table" and tonumber(err.partial) or 0
end

-- the end of the body: later calls keep answering nil, nil
local function finish(self, rest)
  self.done = true
  self.rest = rest or 0
  return nil, nil
end

--- decoder:next() -> payload | nil, nil | nil, err
-- Trailer frames are consumed on the way (into decoder.trailers), never returned.
function Decoder:next()
  while not self.done do
    local reader = self.reader
    -- the flags byte alone first: a clean end of the body is an end before it
    local flag, err = reader:read_exact(1)
    if flag == nil then
      if err ~= nil then
        self.done = true
        return nil, err
      end
      return finish(self, 0)
    end
    self.saw_body = true
    local head
    head, err = reader:read_exact(4)
    if head == nil then
      if err ~= nil and not ended(err) then
        self.done = true
        return nil, err
      end
      return finish(self, 1 + partial(err))
    end
    local b1, b2, b3, b4 = byte(head, 1, 4)
    local len = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
    local f = byte(flag)
    local is_trailer = f >= 128
    if f % 2 == 1 and not is_trailer then
      self.done = true
      return nil,
        errors.new("ParseError", {
          message = "compressed gRPC frames are not supported",
          protobuf = "ProtobufDecodeError",
        })
    end
    local payload = ""
    if len > 0 then
      payload, err = reader:read_exact(len)
      if payload == nil then
        if err ~= nil and not ended(err) then
          self.done = true
          return nil, err
        end
        return finish(self, 5 + partial(err))
      end
    end
    if is_trailer then
      frames.parse_trailers(payload, self.trailers)
    else
      return payload
    end
  end
  return nil, nil
end

return frames
