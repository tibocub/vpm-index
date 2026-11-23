-- MD5 (RFC 1321) in pure Lua 5.1.
--
--   md5.digest(message) -> 16-byte binary digest
--
-- Same technique as distilled.crypto.sha2 (bytes and lookup tables, generated code; see
-- `md5.source()`). All 64 steps are unrolled because each has its own shift amount and
-- message word. MD5 is broken for collision resistance; it is here for checksums the
-- APIs require (S3's Content-MD5, Mailchimp's subscriber hash).
local compat = require("distilled.compat")
local bytes = require("distilled.crypto.bytes")
local codegen = require("distilled.crypto.codegen")

local md5 = {}

local char, rep = string.char, string.rep
local floor = math.floor

-- RFC 1321 section 3.4: shift amounts per step (four per round), T[i] = floor(2^32 * abs(sin(i)))
-- (written out, so no runtime's sin can change them).
local SHIFTS = { { 7, 12, 17, 22 }, { 5, 9, 14, 20 }, { 4, 11, 16, 23 }, { 6, 10, 15, 21 } }
local S = {}
for i = 0, 63 do
  S[i + 1] = SHIFTS[floor(i / 16) + 1][i % 4 + 1]
end
local T = bytes.words_from_hex(
  [[
d76aa478 e8c7b756 242070db c1bdceee f57c0faf 4787c62a a8304613 fd469501
698098d8 8b44f7af ffff5bb1 895cd7be 6b901122 fd987193 a679438e 49b40821
f61e2562 c040b340 265e5a51 e9b6c7aa d62f105d 02441453 d8a1e681 e7d3fbc8
21e1cde6 c33707d6 f4d50d87 455a14ed a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
fffa3942 8771f681 6d9d6122 fde5380c a4beea44 4bdecfa9 f6bb4b60 bebfbc70
289b7ec6 eaa127fa d4ef3085 04881d05 d9d4d039 e6db99e5 1fa27cf8 c4ac5665
f4292244 432aff97 ab9423a7 fc93a039 655b59c3 8f0ccc92 ffeff47d 85845dd1
6fa87e4f fe2ce6e0 a3014314 4e0811a1 f7537e82 bd3af235 2ad7d2bb eb86d391]],
  4
)
local IV = bytes.words_from_hex("67452301 efcdab89 98badcfe 10325476", 4)

-- the auxiliary functions per byte; F's and G's halves have no common bit (added)
local AUX = {
  function(b, c, d, k) -- F = (b AND c) OR (NOT b AND d)
    return string.format("A[%s%d][%s%d] + NA[%s%d][%s%d]", b, k, c, k, b, k, d, k)
  end,
  function(b, c, d, k) -- G = (b AND d) OR (c AND NOT d)
    return string.format("A[%s%d][%s%d] + NA[%s%d][%s%d]", d, k, b, k, d, k, c, k)
  end,
  function(b, c, d, k) -- H = b XOR c XOR d
    return string.format("X[X[%s%d][%s%d]][%s%d]", b, k, c, k, d, k)
  end,
  function(b, c, d, k) -- I = c XOR (b OR NOT d); b OR NOT d = NOT (d AND NOT b)
    return string.format("X[%s%d][255 - NA[%s%d][%s%d]]", c, k, b, k, d, k)
  end,
}

local compress, source

local function generate()
  local lines, w = codegen.writer()
  local rot, names = {}, {}
  local L = {}
  for _, s in ipairs(S) do
    if not rot[s] then
      local tables, plan = bytes.linear(4, { { "rotl", s } })
      rot[s] = { plan = plan, names = codegen.names("R" .. s .. "_", #tables) }
      L["R" .. s] = tables
      for i = 1, #tables do
        names[#names + 1] = { "R" .. s .. "_" .. i, "L.R" .. s .. "[" .. i .. "]" }
      end
    end
  end
  w("local tb, L = ...")
  w("local byte = string.byte")
  w("local M = {}")
  w("return function(H, s, off)")
  w("local X, A, NA, LO, HI = tb.X, tb.A, tb.NA, tb.LO, tb.HI")
  for _, n in ipairs(names) do
    w("local %s = %s", n[1], n[2])
  end
  w("local M = M")
  -- 16 little-endian words: M[4 * g + k + 1] is byte k of word g
  w("for i = 1, 64, 16 do")
  w(
    "M[i], M[i + 1], M[i + 2], M[i + 3], M[i + 4], M[i + 5], M[i + 6], M[i + 7], M[i + 8], M[i + 9],"
  )
  w(
    "  M[i + 10], M[i + 11], M[i + 12], M[i + 13], M[i + 14], M[i + 15] = byte(s, off + i, off + i + 15)"
  )
  w("end")
  local letters = { "a", "b", "c", "d" }
  local state, loads = {}, {}
  for i, l in ipairs(letters) do
    for k = 0, 3 do
      state[#state + 1] = l .. k
      loads[#loads + 1] = string.format("H[%d]", (i - 1) * 4 + k + 1)
    end
  end
  w("local %s = %s", table.concat(state, ", "), table.concat(loads, ", "))
  for i = 0, 63 do
    local round = floor(i / 16)
    local g
    if round == 0 then
      g = i
    elseif round == 1 then
      g = (5 * i + 1) % 16
    elseif round == 2 then
      g = (3 * i + 5) % 16
    else
      g = (7 * i) % 16
    end
    -- roles rotate: step i reads a, b, c, d from these variables and writes a
    local function var(role)
      return letters[(role - i) % 4 + 1]
    end
    local a, b, c, d = var(0), var(1), var(2), var(3)
    local aux, t, s = AUX[round + 1], T[i + 1], S[i + 1]
    w("do")
    -- x = a + aux(b, c, d) + T[i] + M[g], normalised (it is rotated next)
    for k = 0, 3 do
      local sum =
        string.format("%s%d + %s + %d + M[%d]", a, k, aux(b, c, d, k), t[k], 4 * g + k + 1)
      if k == 0 then
        w("local t = %s", sum)
      else
        w("t = %s + HI[t]", sum)
      end
      w("local x%d = LO[t]", k)
    end
    -- a = b + rotl(x, s)
    codegen.linear(w, 4, rot[s].plan, rot[s].names, "r", "x", true)
    w("t = %s0 + r0", b)
    w("%s0 = LO[t]", a)
    for k = 1, 3 do
      w("t = %s%d + r%d + HI[t]", b, k, k)
      w("%s%d = LO[t]", a, k)
    end
    w("end")
  end
  for i, l in ipairs(letters) do
    w("do")
    for k = 0, 3 do
      local at = (i - 1) * 4 + k + 1
      if k == 0 then
        w("local t = H[%d] + %s0", at, l)
      else
        w("t = H[%d] + %s%d + HI[t]", at, l, k)
      end
      w("H[%d] = LO[t]", at)
    end
    w("end")
  end
  w("end")
  return lines, L
end

local function compressor()
  if not compress then
    local lines, L = generate()
    compress, source = codegen.compile(lines, "distilled.crypto.md5", bytes.tables(), L)
  end
  return compress
end

function md5.digest(message)
  if type(message) ~= "string" then
    compat.raise("md5.digest: message must be a string, got " .. type(message), 2)
  end
  local fn = compressor()
  local H = {}
  for i, word in ipairs(IV) do
    for k = 0, 3 do
      H[(i - 1) * 4 + k + 1] = word[k]
    end
  end
  -- padding: 0x80, zeros, the length in bits as a 64-bit little-endian integer
  local len = #message
  local bits = len * 8
  local tail = {}
  for i = 1, 8 do
    local b = bits % 256
    tail[i] = char(b)
    bits = (bits - b) / 256
  end
  local padded = message .. "\128" .. rep("\0", (64 - (len + 9) % 64) % 64) .. table.concat(tail)
  for off = 0, #padded - 1, 64 do
    fn(H, padded, off)
  end
  -- little-endian output
  return char(compat.unpack(H, 1, 16))
end

function md5.source()
  compressor()
  return source
end

return md5
