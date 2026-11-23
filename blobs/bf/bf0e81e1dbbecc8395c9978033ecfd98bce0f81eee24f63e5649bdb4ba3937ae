-- Byte-level lookup tables shared by the hash functions in distilled.crypto.
--
-- Lua 5.1 has no bitwise operators and gopher-lua (Rex) has no bit library, so the hashes
-- work on bytes: a 32-bit or 64-bit word is kept as separate byte values, and every
-- bitwise operation is a table lookup. Measured in Rex, a table lookup costs about the
-- same as one arithmetic operation (~10 ns), and a 32-bit XOR done with arithmetic needs
-- dozens of operations, so byte tables are several times faster than arithmetic
-- emulation on every runtime (see verify/features/crypto.md for the numbers).
--
--   bytes.tables() -> { X, A, NA, LO, HI }   (built once, on first use)
--     X[a][b]  = a XOR b        A[a][b] = a AND b       NA[a][b] = (NOT a) AND b
--     LO[t], HI[t] = t % 256, floor(t / 256) for 0 <= t < 8192 (carry propagation)
--   bytes.linear(width, terms) -> list of tables, plan
--     a GF(2)-linear function of a word (XOR of rotations and shifts), as per-byte tables
--   bytes.words_from_hex(hex, width) -> list of byte arrays (constants written in hex)
local bytes = {}

local floor = math.floor

local cache

-- Bitwise op on two small non-negative integers below 2^bits, one bit at a time. Only
-- used to build the tables.
local function slow_op(a, b, bits, op)
  local r, m = 0, 1
  for _ = 1, bits do
    local x, y = a % 2, b % 2
    local z
    if op == "and" then
      z = (x == 1 and y == 1) and 1 or 0
    else
      z = (x ~= y) and 1 or 0
    end
    r = r + z * m
    a, b, m = (a - x) / 2, (b - y) / 2, m * 2
  end
  return floor(r) -- an integer subtype on 5.3+, so results print and index the same
end

function bytes.tables()
  if cache then
    return cache
  end
  -- 4-bit tables first, then the 8-bit ones from nibbles (65,536 entries each, cheap)
  local X4, A4 = {}, {}
  for a = 0, 15 do
    X4[a], A4[a] = {}, {}
    for b = 0, 15 do
      X4[a][b] = slow_op(a, b, 4, "xor")
      A4[a][b] = slow_op(a, b, 4, "and")
    end
  end
  local X, A, NA = {}, {}, {}
  for a = 0, 255 do
    local al = a % 16
    local ah = floor(a / 16)
    local xl, xh, andl, andh = X4[al], X4[ah], A4[al], A4[ah]
    local xr, ar = {}, {}
    for b = 0, 255 do
      local bl = b % 16
      local bh = floor(b / 16)
      xr[b] = xh[bh] * 16 + xl[bl]
      ar[b] = andh[bh] * 16 + andl[bl]
    end
    X[a], A[a] = xr, ar
  end
  for a = 0, 255 do
    NA[a] = A[255 - a] -- (NOT a) AND b is a row of A: no extra memory
  end
  local LO, HI = {}, {}
  for t = 0, 8191 do
    LO[t] = t % 256
    HI[t] = floor(t / 256)
  end
  cache = { X = X, A = A, NA = NA, LO = LO, HI = HI }
  return cache
end

-- bytes.linear(width, terms) -> tables, plan
--
-- A function F of a word of `width` bytes that is an XOR of rotations and right shifts
-- (`terms` = { { "rotr", n } | { "shr", n } | { "rotl", n } | { "shl", n }, ... }) is
-- GF(2)-linear, so byte j of F(x) is the XOR over input bytes d of T[j][d][x_d], where
-- T[j][d][b] is byte j of F(b << 8d). `plan[j]` lists `{ d, index }` pairs: the input
-- bytes that reach output byte j and the index of their table in `tables`. Identical
-- tables are shared (for pure rotations T[j][d] depends only on d - j), which keeps the
-- generated code under Lua's 200-locals limit for 64-bit words.
function bytes.linear(width, terms)
  local t = bytes.tables()
  local X = t.X
  local nbits = width * 8
  -- mask[d][i][j]: byte j of F(1 << (8d + i))
  local mask = {}
  for d = 0, width - 1 do
    mask[d] = {}
    for i = 0, 7 do
      local m = {}
      for j = 0, width - 1 do
        m[j] = 0
      end
      local p = 8 * d + i
      for _, term in ipairs(terms) do
        local kind, n = term[1], term[2]
        local q
        if kind == "rotr" then
          q = (p - n) % nbits
        elseif kind == "rotl" then
          q = (p + n) % nbits
        elseif kind == "shr" then
          q = p - n >= 0 and p - n or nil
        elseif kind == "shl" then
          q = p + n < nbits and p + n or nil
        else
          error("bytes.linear: unknown term " .. tostring(kind), 2)
        end
        if q then
          local j = floor(q / 8)
          m[j] = X[m[j]][2 ^ (q % 8)]
        end
      end
      mask[d][i] = m
    end
  end
  local tables, by_key, plan = {}, {}, {}
  for j = 0, width - 1 do
    plan[j] = {}
    for d = 0, width - 1 do
      local zero = true
      for i = 0, 7 do
        if mask[d][i][j] ~= 0 then
          zero = false
        end
      end
      if not zero then
        local tb = { [0] = 0 }
        for b = 1, 255 do
          -- tb[b] = tb[b without its lowest set bit] XOR image of that bit
          local i, low = 0, 1
          while b % (low * 2) == 0 do
            low, i = low * 2, i + 1
          end
          tb[b] = X[tb[b - low]][mask[d][i][j]]
        end
        local key = table.concat(tb, ",", 1, 255)
        local index = by_key[key]
        if not index then
          tables[#tables + 1] = tb
          index = #tables
          by_key[key] = index
        end
        plan[j][#plan[j] + 1] = { d, index }
      end
    end
  end
  return tables, plan
end

-- bytes.words_from_hex("428a2f98 71374491 ...", 4) -> { { [0] = lsb, ..., [3] = msb }, ... }
-- Constants wider than 2^53 cannot be Lua number literals, so they are written in hex.
function bytes.words_from_hex(hex, width)
  local words = {}
  for word in string.gmatch(hex, "%x+") do
    if #word ~= width * 2 then
      error("bytes.words_from_hex: " .. word .. " is not " .. width .. " bytes", 2)
    end
    local w = {}
    for k = 0, width - 1 do
      local at = #word - 2 * k - 1
      w[k] = tonumber(string.sub(word, at, at + 1), 16)
    end
    words[#words + 1] = w
  end
  return words
end

return bytes
