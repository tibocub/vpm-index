-- CRC-32 (IEEE 802.3, as zlib and S3's x-amz-checksum-crc32) and CRC-32C (Castagnoli,
-- S3's x-amz-checksum-crc32c), table-driven, in pure Lua 5.1.
--
--   crc32.crc32(message [, crc])  -> number in [0, 2^32)
--   crc32.crc32c(message [, crc]) -> number
--   crc32.bytes(n) -> the 4-byte big-endian string of a checksum (what S3 base64-encodes)
--
-- Passing the previous result as `crc` continues a checksum over a message given in
-- pieces. The register is kept as four bytes and XOR is a table lookup (see
-- distilled.crypto.bytes).
local compat = require("distilled.compat")
local bytes = require("distilled.crypto.bytes")

local crc32 = {}

local byte, char = string.byte, string.char
local floor = math.floor

-- Reflected polynomials
local POLY = { crc32 = "edb88320", crc32c = "82f63b78" }

local made = {}

-- The 256-entry table of a reflected CRC, as four byte tables T0 (low) .. T3 (high).
local function table_for(name)
  local t = made[name]
  if t then
    return t
  end
  local X = bytes.tables().X
  local p = bytes.words_from_hex(POLY[name], 4)[1]
  local T0, T1, T2, T3 = {}, {}, {}, {}
  for n = 0, 255 do
    local c0, c1, c2, c3 = n, 0, 0, 0
    for _ = 1, 8 do
      local low = c0 % 2
      -- shift the 32-bit register right by one bit
      c0 = floor(c0 / 2) + (c1 % 2) * 128
      c1 = floor(c1 / 2) + (c2 % 2) * 128
      c2 = floor(c2 / 2) + (c3 % 2) * 128
      c3 = floor(c3 / 2)
      if low == 1 then
        c0 = X[c0][p[0]]
        c1 = X[c1][p[1]]
        c2 = X[c2][p[2]]
        c3 = X[c3][p[3]]
      end
    end
    T0[n], T1[n], T2[n], T3[n] = c0, c1, c2, c3
  end
  t = { T0, T1, T2, T3 }
  made[name] = t
  return t
end

local CHUNK = 256

local function run(name, message, crc)
  if type(message) ~= "string" then
    compat.raise("crc32." .. name .. ": message must be a string, got " .. type(message), 3)
  end
  if
    crc ~= nil and (type(crc) ~= "number" or crc < 0 or crc >= 4294967296 or crc ~= floor(crc))
  then
    compat.raise("crc32." .. name .. ": crc must be an integer in [0, 2^32)", 3)
  end
  local X = bytes.tables().X
  local t = table_for(name)
  local T0, T1, T2, T3 = t[1], t[2], t[3], t[4]
  -- the register starts as NOT crc (crc = 0 for a new checksum)
  crc = 4294967295 - (crc or 0)
  local c0 = crc % 256
  local c1 = floor(crc / 256) % 256
  local c2 = floor(crc / 65536) % 256
  local c3 = floor(crc / 16777216)
  local len = #message
  for at = 1, len, CHUNK do
    local last = at + CHUNK - 1
    if last > len then
      last = len
    end
    local chunk = { byte(message, at, last) }
    for i = 1, #chunk do
      -- crc = T[(crc XOR b) AND 0xff] XOR (crc >> 8), byte by byte. Assigned one at a
      -- time in this order on purpose: each line reads the next byte before it changes
      -- (gopher-lua does a multiple assignment to locals sequentially anyway).
      local n = X[c0][chunk[i]]
      c0 = X[c1][T0[n]]
      c1 = X[c2][T1[n]]
      c2 = X[c3][T2[n]]
      c3 = T3[n]
    end
  end
  return 4294967295 - (((c3 * 256 + c2) * 256 + c1) * 256 + c0)
end

function crc32.crc32(message, crc)
  return run("crc32", message, crc)
end

function crc32.crc32c(message, crc)
  return run("crc32c", message, crc)
end

function crc32.bytes(n)
  if type(n) ~= "number" or n < 0 or n >= 4294967296 or n ~= floor(n) then
    compat.raise("crc32.bytes: expected an integer in [0, 2^32)", 2)
  end
  return char(floor(n / 16777216), floor(n / 65536) % 256, floor(n / 256) % 256, n % 256)
end

return crc32
