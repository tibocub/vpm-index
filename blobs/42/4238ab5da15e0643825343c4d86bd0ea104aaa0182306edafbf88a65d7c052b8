-- SHA-1 (FIPS 180-4) in pure Lua 5.1.
--
--   sha1.digest(message) -> 20-byte binary digest
--
-- Same technique as distilled.crypto.sha2: words are kept as bytes (byte k is the k-th
-- least significant), bitwise operations are table lookups, and the compression
-- function is generated once as Lua source (`sha1.source()` returns it), unrolled over
-- five rounds so the five working variables never move.
--
-- SHA-1 is broken for collision resistance; it is here for the protocols that still
-- name it (AWS SSO cache file names, HMAC-SHA1 signatures).
local compat = require("distilled.compat")
local bytes = require("distilled.crypto.bytes")
local codegen = require("distilled.crypto.codegen")

local sha1 = {}

local char, rep = string.char, string.rep

local K = bytes.words_from_hex("5a827999 6ed9eba1 8f1bbcdc ca62c1d6", 4)
local IV = bytes.words_from_hex("67452301 efcdab89 98badcfe 10325476 c3d2e1f0", 4)

-- f(b, c, d) per byte for each group of 20 rounds. Ch's and Maj's two halves have no
-- bit in common, so they are added rather than XORed.
local F = {
  function(b, c, d, k) -- Ch
    return string.format("A[%s%d][%s%d] + NA[%s%d][%s%d]", b, k, c, k, b, k, d, k)
  end,
  function(b, c, d, k) -- Parity
    return string.format("X[X[%s%d][%s%d]][%s%d]", b, k, c, k, d, k)
  end,
  function(b, c, d, k) -- Maj
    return string.format("A[%s%d][%s%d] + A[%s%d][X[%s%d][%s%d]]", b, k, c, k, d, k, b, k, c, k)
  end,
  function(b, c, d, k) -- Parity
    return string.format("X[X[%s%d][%s%d]][%s%d]", b, k, c, k, d, k)
  end,
}

local compress, source

local function generate()
  local lines, w = codegen.writer()
  local R1, R1_plan = bytes.linear(4, { { "rotl", 1 } })
  local R5, R5_plan = bytes.linear(4, { { "rotl", 5 } })
  local R30, R30_plan = bytes.linear(4, { { "rotl", 30 } })
  local nR1, nR5, nR30 =
    codegen.names("R1_", #R1), codegen.names("R5_", #R5), codegen.names("R30_", #R30)
  w("local tb, L = ...")
  w("local byte = string.byte")
  w("local W0, W1, W2, W3, KW0, KW1, KW2, KW3 = {}, {}, {}, {}, {}, {}, {}, {}")
  w("return function(H, s, off)")
  w("local X, A, NA, LO, HI = tb.X, tb.A, tb.NA, tb.LO, tb.HI")
  w("local W0, W1, W2, W3, KW0, KW1, KW2, KW3 = W0, W1, W2, W3, KW0, KW1, KW2, KW3")
  codegen.bind(w, nR1, "L.R1[%d]")
  codegen.bind(w, nR5, "L.R5[%d]")
  codegen.bind(w, nR30, "L.R30[%d]")
  -- message schedule: W[t] = rotl1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])
  w("for j = 1, 16 do")
  w("W3[j], W2[j], W1[j], W0[j] = byte(s, off + 1, off + 4)")
  w("off = off + 4")
  w("end")
  w("for j = 17, 80 do")
  for k = 0, 3 do
    w("local x%d = X[X[W%d[j - 3]][W%d[j - 8]]][X[W%d[j - 14]][W%d[j - 16]]]", k, k, k, k, k)
  end
  codegen.linear(w, 4, R1_plan, nR1, "y", "x", true)
  w("W0[j], W1[j], W2[j], W3[j] = y0, y1, y2, y3")
  w("end")
  -- K + W, unnormalised (only ever summed)
  w("for j = 1, 80 do")
  w("local k = L.K[(j - 1 - (j - 1) % 20) / 20 + 1]")
  w("KW0[j], KW1[j], KW2[j], KW3[j] = k[0] + W0[j], k[1] + W1[j], k[2] + W2[j], k[3] + W3[j]")
  w("end")
  local letters = { "a", "b", "c", "d", "e" }
  local state, loads = {}, {}
  for i, l in ipairs(letters) do
    for k = 0, 3 do
      state[#state + 1] = l .. k
      loads[#loads + 1] = string.format("H[%d]", (i - 1) * 4 + k + 1)
    end
  end
  w("local %s = %s", table.concat(state, ", "), table.concat(loads, ", "))
  for group = 1, 4 do
    local f = F[group]
    w("for j = %d, %d, 5 do", (group - 1) * 20 + 1, group * 20)
    for r = 0, 4 do
      local function var(role)
        return letters[(role - r) % 5 + 1]
      end
      local a, b, c, d, e = var(0), var(1), var(2), var(3), var(4)
      w("do")
      w("local jj = j + %d", r)
      codegen.linear(w, 4, R5_plan, nR5, "r", a, true)
      -- T = rotl5(a) + f(b, c, d) + e + K + W, written over e
      for k = 0, 3 do
        local sum = string.format("r%d + %s + %s%d + KW%d[jj]", k, f(b, c, d, k), e, k, k)
        if k == 0 then
          w("local t = %s", sum)
        else
          w("t = %s + HI[t]", sum)
        end
        w("%s%d = LO[t]", e, k)
      end
      -- b = rotl30(b), in place
      codegen.linear(w, 4, R30_plan, nR30, "q", b, true)
      w("%s0, %s1, %s2, %s3 = q0, q1, q2, q3", b, b, b, b)
      w("end")
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
  return lines, { R1 = R1, R5 = R5, R30 = R30, K = K }
end

local function compressor()
  if not compress then
    local lines, L = generate()
    compress, source = codegen.compile(lines, "distilled.crypto.sha1", bytes.tables(), L)
  end
  return compress
end

function sha1.digest(message)
  if type(message) ~= "string" then
    compat.raise("sha1.digest: message must be a string, got " .. type(message), 2)
  end
  local fn = compressor()
  local H = {}
  for i, word in ipairs(IV) do
    for k = 0, 3 do
      H[(i - 1) * 4 + k + 1] = word[k]
    end
  end
  -- padding: 0x80, zeros, the length in bits as a 64-bit big-endian integer
  local len = #message
  local bits = len * 8
  local tail = {}
  for i = 8, 1, -1 do
    local b = bits % 256
    tail[i] = char(b)
    bits = (bits - b) / 256
  end
  local padded = message .. "\128" .. rep("\0", (64 - (len + 9) % 64) % 64) .. table.concat(tail)
  for off = 0, #padded - 1, 64 do
    fn(H, padded, off)
  end
  local out = {}
  for i = 1, 5 do
    for k = 3, 0, -1 do
      out[#out + 1] = H[(i - 1) * 4 + k + 1]
    end
  end
  return char(compat.unpack(out))
end

function sha1.source()
  compressor()
  return source
end

return sha1
