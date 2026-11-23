-- Hexadecimal encoding of byte strings.
--
--   hex.encode(s) -> lowercase hex          hex.decode(h) -> bytes | nil, err
--
-- decode accepts upper and lower case; an odd length or a non-hex character is an
-- InvalidInput error (the message gives the position, never the text).
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local hex = {}

local char, format, gsub, find = string.char, string.format, string.gsub, string.find

local ENCODE, DECODE = {}, {}
for b = 0, 255 do
  local c, h = char(b), format("%02x", b)
  ENCODE[c] = h
  DECODE[h] = c
  DECODE[string.upper(h)] = c
  DECODE[string.upper(string.sub(h, 1, 1)) .. string.sub(h, 2)] = c
  DECODE[string.sub(h, 1, 1) .. string.upper(string.sub(h, 2))] = c
end

function hex.encode(s)
  if type(s) ~= "string" then
    compat.raise("hex.encode: expected a string, got " .. type(s), 2)
  end
  return (gsub(s, ".", ENCODE))
end

function hex.decode(h)
  if type(h) ~= "string" then
    compat.raise("hex.decode: expected a string, got " .. type(h), 2)
  end
  if #h % 2 ~= 0 then
    return nil, errors.new("InvalidInput", { message = "hex: odd length " .. #h })
  end
  local bad = find(h, "[^0-9A-Fa-f]")
  if bad then
    return nil,
      errors.new("InvalidInput", { message = "hex: invalid character at position " .. bad })
  end
  return (gsub(h, "..", DECODE))
end

return hex
