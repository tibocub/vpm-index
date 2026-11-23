-- gzip (RFC 1952) for @requestCompression bodies, in pure Lua 5.1 (no bit operators).
--
-- Distilled's middleware/compression.ts gzips a request body of at least
-- MIN_COMPRESSION_SIZE_BYTES when the operation lists "gzip" (CloudWatch PutMetricData),
-- appending "gzip" to Content-Encoding. Deflate here is one fixed-Huffman block (RFC 1951
-- 3.2.6) with a hash-chain LZ77 matcher: smaller output than a dynamic-Huffman encoder
-- would give, but valid for every inflater and far simpler.
--
--   gzip.compress(text) -> gzipped text
local crc32 = require("distilled.crypto.crc32")
local compat = require("distilled.compat")

local gzip = {}

gzip.MIN_COMPRESSION_SIZE_BYTES = 10240

local byte, char, sub, floor = string.byte, string.char, string.sub, math.floor

local WINDOW = 32768
local MAX_MATCH = 258
local MAX_CHAIN = 16

-- length codes 257..285: base length and extra bits
local LEN_BASE, LEN_EXTRA = {}, {}
do
  local bases = {
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    13,
    15,
    17,
    19,
    23,
    27,
    31,
    35,
    43,
    51,
    59,
    67,
    83,
    99,
    115,
    131,
    163,
    195,
    227,
    258,
  }
  local extra =
    { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 }
  for i = 1, 29 do
    LEN_BASE[i] = bases[i]
    LEN_EXTRA[i] = extra[i]
  end
end
-- distance codes 0..29
local DIST_BASE, DIST_EXTRA = {}, {}
do
  local base, i = 1, 0
  for code = 0, 29 do
    local extra = code < 2 and 0 or floor(code / 2) - 1
    DIST_BASE[code] = base
    DIST_EXTRA[code] = extra
    base = base + 2 ^ extra
    i = i + 1
  end
end

-- the length code index (1-based into LEN_BASE) for a match length
local LEN_CODE = {}
for i = 1, 29 do
  local hi = i < 29 and (LEN_BASE[i + 1] - 1) or 258
  if i == 28 then
    hi = 257
  end
  for len = LEN_BASE[i], hi do
    LEN_CODE[len] = i
  end
end

local function dist_code(d)
  local code = 0
  while code < 29 and DIST_BASE[code + 1] <= d do
    code = code + 1
  end
  return code
end

-- a bit writer: values LSB first; Huffman codes are reversed before writing
local function writer()
  local w = { out = {}, acc = 0, nbits = 0 }
  function w.bits(value, n)
    w.acc = w.acc + value * 2 ^ w.nbits
    w.nbits = w.nbits + n
    while w.nbits >= 8 do
      local b = w.acc % 256
      w.out[#w.out + 1] = char(b)
      w.acc = (w.acc - b) / 256
      w.nbits = w.nbits - 8
    end
  end
  function w.flush()
    if w.nbits > 0 then
      w.out[#w.out + 1] = char(w.acc % 256)
      w.acc, w.nbits = 0, 0
    end
    return compat.concat(w.out)
  end
  return w
end

local function reverse(code, n)
  local r = 0
  for _ = 1, n do
    r = r * 2 + code % 2
    code = floor(code / 2)
  end
  return r
end

-- the fixed Huffman code of a literal/length symbol
local FIXED_CODE, FIXED_LEN = {}, {}
for s = 0, 287 do
  local code, n
  if s <= 143 then
    code, n = 48 + s, 8
  elseif s <= 255 then
    code, n = 400 + s - 144, 9
  elseif s <= 279 then
    code, n = s - 256, 7
  else
    code, n = 192 + s - 280, 8
  end
  FIXED_CODE[s] = reverse(code, n)
  FIXED_LEN[s] = n
end
local DIST_CODE_REV = {}
for d = 0, 29 do
  DIST_CODE_REV[d] = reverse(d, 5)
end

local function symbol(w, s)
  w.bits(FIXED_CODE[s], FIXED_LEN[s])
end

--- gzip.deflate(text) -> raw deflate stream (one fixed-Huffman block)
function gzip.deflate(text)
  local w = writer()
  w.bits(1, 1) -- BFINAL
  w.bits(1, 2) -- BTYPE = 01, fixed Huffman
  local n = #text
  local head, prev = {}, {}
  local i = 1
  local function insert(pos)
    if pos + 2 <= n then
      local key = sub(text, pos, pos + 2)
      prev[pos] = head[key]
      head[key] = pos
    end
  end
  while i <= n do
    local best_len, best_dist = 0, 0
    if i + 2 <= n then
      local candidate = head[sub(text, i, i + 2)]
      local chain = 0
      local limit = n - i + 1
      if limit > MAX_MATCH then
        limit = MAX_MATCH
      end
      while candidate and i - candidate <= WINDOW and chain < MAX_CHAIN do
        local len = 3
        while len < limit and byte(text, candidate + len) == byte(text, i + len) do
          len = len + 1
        end
        if len > best_len then
          best_len, best_dist = len, i - candidate
          if len == limit then
            break
          end
        end
        candidate = prev[candidate]
        chain = chain + 1
      end
    end
    if best_len >= 3 then
      local li = LEN_CODE[best_len]
      symbol(w, 256 + li)
      if LEN_EXTRA[li] > 0 then
        w.bits(best_len - LEN_BASE[li], LEN_EXTRA[li])
      end
      local dc = dist_code(best_dist)
      w.bits(DIST_CODE_REV[dc], 5)
      if DIST_EXTRA[dc] > 0 then
        w.bits(best_dist - DIST_BASE[dc], DIST_EXTRA[dc])
      end
      for k = i, i + best_len - 1 do
        insert(k)
      end
      i = i + best_len
    else
      symbol(w, byte(text, i))
      insert(i)
      i = i + 1
    end
  end
  symbol(w, 256)
  return w.flush()
end

local function le32(v)
  return char(v % 256, floor(v / 256) % 256, floor(v / 65536) % 256, floor(v / 16777216) % 256)
end

--- gzip.compress(text) -> gzip member: header, deflate, CRC-32, size mod 2^32
function gzip.compress(text)
  return "\31\139\8\0\0\0\0\0\0\255"
    .. gzip.deflate(text)
    .. le32(crc32.crc32(text))
    .. le32(#text % 4294967296)
end

return gzip
