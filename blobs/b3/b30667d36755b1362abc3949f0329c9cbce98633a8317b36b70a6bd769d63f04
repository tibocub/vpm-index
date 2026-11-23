-- SHA-224, SHA-256, SHA-384 and SHA-512 (FIPS 180-4) in pure Lua 5.1.
--
--   sha2.digest(name, message) -> binary digest string
--   name: "sha224" | "sha256" | "sha384" | "sha512"
--
-- Words are kept as separate bytes and every bitwise operation is a table lookup (see
-- distilled.crypto.bytes for why). The compression function is generated as Lua source
-- the first time a variant is used and compiled with compat.load: it is the same few
-- lines of logic repeated for every byte of every word and unrolled over eight rounds,
-- which nobody should write or review by hand. `sha2.source(name)` returns the source.
--
-- Byte k of a word is its k-th least significant byte. The state H is a flat array:
-- H[(i - 1) * width + k + 1] is byte k of word i.
local compat = require("distilled.compat")
local bytes = require("distilled.crypto.bytes")
local codegen = require("distilled.crypto.codegen")

local sha2 = {}

local char, rep = string.char, string.rep
local floor = math.floor

local K256 = [[
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2]]

local K512 = [[
428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538
59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe
243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235
c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 983e5152ee66dfab
a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725
06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed
53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218
d69906245565a910 f40e35855771202a 106aa07032bbd1b8 19a4c116b8d2d0c8 1e376c085141ab53
2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373
682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c
d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6
113f9804bef90dae 1b710b35131c471b 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc
431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817]]

-- Each family: word width in bytes, rounds, the four linear functions (FIPS 180-4
-- section 4.1.2 and 4.1.3), the round constants. Variants add the initial hash value
-- and the digest length.
local FAMILY = {
  [4] = {
    rounds = 64,
    S0 = { { "rotr", 2 }, { "rotr", 13 }, { "rotr", 22 } },
    S1 = { { "rotr", 6 }, { "rotr", 11 }, { "rotr", 25 } },
    s0 = { { "rotr", 7 }, { "rotr", 18 }, { "shr", 3 } },
    s1 = { { "rotr", 17 }, { "rotr", 19 }, { "shr", 10 } },
    K = K256,
  },
  [8] = {
    rounds = 80,
    S0 = { { "rotr", 28 }, { "rotr", 34 }, { "rotr", 39 } },
    S1 = { { "rotr", 14 }, { "rotr", 18 }, { "rotr", 41 } },
    s0 = { { "rotr", 1 }, { "rotr", 8 }, { "shr", 7 } },
    s1 = { { "rotr", 19 }, { "rotr", 61 }, { "shr", 6 } },
    K = K512,
  },
}

local VARIANTS = {
  sha224 = {
    width = 4,
    out = 28,
    iv = "c1059ed8 367cd507 3070dd17 f70e5939 ffc00b31 68581511 64f98fa7 befa4fa4",
  },
  sha256 = {
    width = 4,
    out = 32,
    iv = "6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19",
  },
  sha384 = {
    width = 8,
    out = 48,
    iv = [[cbbb9d5dc1059ed8 629a292a367cd507 9159015a3070dd17 152fecd8f70e5939
      67332667ffc00b31 8eb44a8768581511 db0c2e0d64f98fa7 47b5481dbefa4fa4]],
  },
  sha512 = {
    width = 8,
    out = 64,
    iv = [[6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1
      510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179]],
  },
}

-- The generated chunk receives (tb, L) where tb = bytes.tables() and L holds the linear
-- tables and constants; it returns compress(H, s, off) for one block at byte offset off.
local function generate(width, family)
  local lines, w = codegen.writer()
  local rounds = family.rounds
  local S0, S0_plan = bytes.linear(width, family.S0)
  local S1, S1_plan = bytes.linear(width, family.S1)
  local s0, s0_plan = bytes.linear(width, family.s0)
  local s1, s1_plan = bytes.linear(width, family.s1)
  local nS0, nS1 = codegen.names("S0_", #S0), codegen.names("S1_", #S1)
  local ns0, ns1 = codegen.names("s0_", #s0), codegen.names("s1_", #s1)
  local Wn, KWn = {}, {}
  for k = 0, width - 1 do
    Wn[#Wn + 1] = "W" .. k
    KWn[#KWn + 1] = "KW" .. k
  end
  w("local tb, L = ...")
  w("local byte = string.byte")
  -- message schedule W (normalised bytes) and K + W (unnormalised: only ever summed)
  w("local %s = %s", codegen.list(Wn), codegen.list(Wn, "{}"))
  w("local %s = %s", codegen.list(KWn), codegen.list(KWn, "{}"))
  w("local K = L.K")

  w("local function schedule(s, off)")
  w("local X, LO, HI = tb.X, tb.LO, tb.HI")
  w("local %s = %s", codegen.list(Wn), codegen.list(Wn))
  w("local %s = %s", codegen.list(KWn), codegen.list(KWn))
  codegen.bind(w, ns0, "L.s0[%d]")
  codegen.bind(w, ns1, "L.s1[%d]")
  -- words are big-endian in the message: the first byte read is byte width-1
  local reads = {}
  for k = width - 1, 0, -1 do
    reads[#reads + 1] = "W" .. k .. "[j]"
  end
  w("for j = 1, 16 do")
  w("%s = byte(s, off + 1, off + %d)", table.concat(reads, ", "), width)
  w("off = off + %d", width)
  w("end")
  w("for j = 17, %d do", rounds)
  -- v = W[j - 15] (input of sigma0), u = W[j - 2] (input of sigma1)
  local vn, v, un, u = {}, {}, {}, {}
  for k = 0, width - 1 do
    vn[#vn + 1], v[#v + 1] = "v" .. k, string.format("W%d[j - 15]", k)
    un[#un + 1], u[#u + 1] = "u" .. k, string.format("W%d[j - 2]", k)
  end
  w("local %s = %s", table.concat(vn, ", "), table.concat(v, ", "))
  w("local %s = %s", table.concat(un, ", "), table.concat(u, ", "))
  codegen.linear(w, width, s0_plan, ns0, "p", "v")
  codegen.linear(w, width, s1_plan, ns1, "q", "u")
  w("local t = p0 + q0 + W0[j - 7] + W0[j - 16]")
  w("W0[j] = LO[t]")
  for k = 1, width - 1 do
    w("t = p%d + q%d + W%d[j - 7] + W%d[j - 16] + HI[t]", k, k, k, k)
    w("W%d[j] = LO[t]", k)
  end
  w("end")
  w("for j = 1, %d do", rounds)
  w("local k = K[j]")
  for k = 0, width - 1 do
    w("KW%d[j] = k[%d] + W%d[j]", k, k, k)
  end
  w("end")
  w("end")

  w("return function(H, s, off)")
  w("schedule(s, off)")
  w("local X, A, NA, LO, HI = tb.X, tb.A, tb.NA, tb.LO, tb.HI")
  w("local %s = %s", codegen.list(KWn), codegen.list(KWn))
  codegen.bind(w, nS0, "L.S0[%d]")
  codegen.bind(w, nS1, "L.S1[%d]")
  local letters = { "a", "b", "c", "d", "e", "f", "g", "h" }
  local state, loads = {}, {}
  for i, l in ipairs(letters) do
    for k = 0, width - 1 do
      state[#state + 1] = l .. k
      loads[#loads + 1] = string.format("H[%d]", (i - 1) * width + k + 1)
    end
  end
  w("local %s = %s", table.concat(state, ", "), table.concat(loads, ", "))
  w("for j = 1, %d, 8 do", rounds)
  for r = 0, 7 do
    -- after r rounds the variable holding role a (0) ... h (7) is letters[role - r]
    local function var(role)
      return letters[(role - r) % 8 + 1]
    end
    local a, b, c, d, e, f, g, h = var(0), var(1), var(2), var(3), var(4), var(5), var(6), var(7)
    w("do")
    w("local jj = j + %d", r)
    codegen.linear(w, width, S1_plan, nS1, "x", e) -- Sigma1(e)
    codegen.linear(w, width, S0_plan, nS0, "y", a) -- Sigma0(a)
    -- T1 = h + Sigma1(e) + Ch(e, f, g) + K + W, unnormalised. Ch's two halves have no
    -- bit in common, so their sum is their XOR.
    for k = 0, width - 1 do
      w(
        "local u%d = %s%d + x%d + A[%s%d][%s%d] + NA[%s%d][%s%d] + KW%d[jj]",
        k,
        h,
        k,
        k,
        e,
        k,
        f,
        k,
        e,
        k,
        g,
        k,
        k
      )
    end
    -- new e = d + T1, written over d
    w("local t = %s0 + u0", d)
    w("%s0 = LO[t]", d)
    for k = 1, width - 1 do
      w("t = %s%d + u%d + HI[t]", d, k, k)
      w("%s%d = LO[t]", d, k)
    end
    -- new a = T1 + Sigma0(a) + Maj(a, b, c), written over h.
    -- Maj = (a AND b) + (c AND (a XOR b)): again two halves with no common bit.
    for k = 0, width - 1 do
      local maj =
        string.format("A[%s%d][%s%d] + A[%s%d][X[%s%d][%s%d]]", a, k, b, k, c, k, a, k, b, k)
      if k == 0 then
        w("t = u0 + y0 + %s", maj)
      else
        w("t = u%d + y%d + %s + HI[t]", k, k, maj)
      end
      w("%s%d = LO[t]", h, k)
    end
    w("end")
  end
  w("end")
  for i, l in ipairs(letters) do
    w("do")
    for k = 0, width - 1 do
      local at = (i - 1) * width + k + 1
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
  local L = { S0 = S0, S1 = S1, s0 = s0, s1 = s1, K = bytes.words_from_hex(family.K, width) }
  return lines, L
end

-- Compiled compression functions and their sources, by word width.
local compiled, sources = {}, {}

local function compressor(width)
  local fn = compiled[width]
  if fn then
    return fn
  end
  local lines, L = generate(width, FAMILY[width])
  local source
  fn, source = codegen.compile(
    lines,
    "distilled.crypto.sha2(" .. width * 8 .. "-bit words)",
    bytes.tables(),
    L
  )
  compiled[width], sources[width] = fn, source
  return fn
end

-- The message with its padding: 0x80, zeros, and the length in bits as a big-endian
-- integer of 2 * width bytes (64 or 128 bits).
local function pad(message, block, width)
  local len = #message
  local zeros = (block - (len + 1 + 2 * width) % block) % block
  local bits = len * 8
  local tail = {}
  for i = 2 * width, 1, -1 do
    local b = bits % 256
    tail[i] = char(b)
    bits = (bits - b) / 256
  end
  return message .. "\128" .. rep("\0", zeros) .. table.concat(tail)
end

function sha2.digest(name, message)
  local variant = VARIANTS[name]
  if not variant then
    compat.raise("sha2.digest: unknown variant " .. tostring(name), 2)
  end
  if type(message) ~= "string" then
    compat.raise("sha2.digest: message must be a string, got " .. type(message), 2)
  end
  local width = variant.width
  local compress = compressor(width)
  local H = {}
  for i, word in ipairs(bytes.words_from_hex(variant.iv, width)) do
    for k = 0, width - 1 do
      H[(i - 1) * width + k + 1] = word[k]
    end
  end
  local block = 16 * width
  local padded = pad(message, block, width)
  for off = 0, #padded - 1, block do
    compress(H, padded, off)
  end
  -- big-endian output, truncated for SHA-224 / SHA-384
  local out = {}
  for i = 1, variant.out / width do
    for k = width - 1, 0, -1 do
      out[#out + 1] = H[(i - 1) * width + k + 1]
    end
  end
  return char(compat.unpack(out))
end

-- The generated source of the compression function for a variant (for reading/debugging).
function sha2.source(name)
  local variant = VARIANTS[name]
  if not variant then
    compat.raise("sha2.source: unknown variant " .. tostring(name), 2)
  end
  compressor(variant.width)
  return sources[variant.width]
end

sha2.VARIANTS = VARIANTS

return sha2
