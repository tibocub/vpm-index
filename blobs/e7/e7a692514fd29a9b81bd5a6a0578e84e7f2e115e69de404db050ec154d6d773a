-- Base64 (RFC 4648 section 4) and base64url (section 5) encoding of byte strings.
--
--   base64.encode(s) -> padded base64
--   base64.decode(text) -> bytes | nil, err
--   base64.url_encode(s [, pad]) -> base64url, unpadded unless pad is true (JWTs use
--                                   unpadded; Polymarket's signature keeps the padding)
--   base64.url_decode(text) -> bytes | nil, err
--
-- Decoding is strict about the alphabet (no whitespace, no mixing "+/" with "-_") and
-- accepts input with or without its "=" padding; misplaced padding, a stray character
-- or an impossible length (4n + 1) is an InvalidInput error. Unused trailing bits are
-- ignored, as Node's decoder does.
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local base64 = {}

local byte, char, sub, find = string.byte, string.char, string.sub, string.find
local floor = math.floor

local STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

-- For each alphabet: PAIR[n] = the two characters of a 12-bit value n (so three input
-- bytes need two lookups), ONE[n] = the character of a 6-bit value, VALUE[byte] = 6 bits,
-- REJECT = a pattern matching any character outside the alphabet.
local function alphabet(chars, reject)
  local one, value, pair = {}, {}, {}
  for i = 0, 63 do
    one[i] = sub(chars, i + 1, i + 1)
    value[byte(chars, i + 1)] = i
  end
  for n = 0, 4095 do
    pair[n] = one[floor(n / 64)] .. one[n % 64]
  end
  return { one = one, value = value, pair = pair, reject = reject }
end

local alphabets = {}
local function get(name)
  local a = alphabets[name]
  if not a then
    if name == "url" then
      a = alphabet(URL, "[^A-Za-z0-9%-_]")
    else
      a = alphabet(STD, "[^A-Za-z0-9%+/]")
    end
    alphabets[name] = a
  end
  return a
end

local function encode(s, a, pad)
  local pair, one = a.pair, a.one
  local out, n = {}, 0
  local len = #s
  local full = len - len % 3
  for i = 1, full, 3 do
    local b1, b2, b3 = byte(s, i, i + 2)
    local v = (b1 * 256 + b2) * 256 + b3
    local hi = floor(v / 4096)
    n = n + 1
    out[n] = pair[hi] .. pair[v - hi * 4096]
  end
  local rest = len - full
  if rest == 1 then
    local b1 = byte(s, len)
    n = n + 1
    out[n] = one[floor(b1 / 4)] .. one[(b1 % 4) * 16] .. (pad and "==" or "")
  elseif rest == 2 then
    local b1, b2 = byte(s, len - 1, len)
    local v = b1 * 256 + b2
    n = n + 1
    out[n] = one[floor(v / 1024)]
      .. one[floor(v / 16) % 64]
      .. one[(v % 16) * 4]
      .. (pad and "=" or "")
  end
  return compat.concat(out)
end

local function invalid(what, message)
  return nil, errors.new("InvalidInput", { message = what .. ": " .. message })
end

local function decode(text, a, what)
  local value = a.value
  local len = #text
  -- strip the padding: at most two "=", only at the end, and only to a multiple of 4
  local body_len = len
  while body_len > 0 and byte(text, body_len) == 61 do
    body_len = body_len - 1
  end
  local padding = len - body_len
  if padding > 0 and (padding > 2 or len % 4 ~= 0) then
    return invalid(what, "misplaced padding")
  end
  local bad = find(text, a.reject)
  if bad and bad <= body_len then
    return invalid(what, "invalid character at position " .. bad)
  end
  if body_len % 4 == 1 then
    return invalid(what, "invalid length " .. body_len)
  end
  local out, n = {}, 0
  local full = body_len - body_len % 4
  for i = 1, full, 4 do
    local c1, c2, c3, c4 = byte(text, i, i + 3)
    local v = ((value[c1] * 64 + value[c2]) * 64 + value[c3]) * 64 + value[c4]
    n = n + 1
    out[n] = char(floor(v / 65536), floor(v / 256) % 256, v % 256)
  end
  local rest = body_len - full
  if rest == 2 then
    local c1, c2 = byte(text, full + 1, body_len)
    n = n + 1
    out[n] = char(value[c1] * 4 + floor(value[c2] / 16))
  elseif rest == 3 then
    local c1, c2, c3 = byte(text, full + 1, body_len)
    local v = (value[c1] * 64 + value[c2]) * 64 + value[c3]
    n = n + 1
    out[n] = char(floor(v / 1024), floor(v / 4) % 256)
  end
  return compat.concat(out)
end

local function check(s, fname)
  if type(s) ~= "string" then
    compat.raise("base64." .. fname .. ": expected a string, got " .. type(s), 3)
  end
end

function base64.encode(s)
  check(s, "encode")
  return encode(s, get("std"), true)
end

function base64.decode(text)
  check(text, "decode")
  return decode(text, get("std"), "base64")
end

function base64.url_encode(s, pad)
  check(s, "url_encode")
  return encode(s, get("url"), pad == true)
end

function base64.url_decode(text)
  check(text, "url_decode")
  return decode(text, get("url"), "base64url")
end

return base64
