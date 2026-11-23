-- Non-negative arbitrary-precision integers and Montgomery arithmetic modulo an odd
-- number, in pure Lua 5.1 (doubles only), sized for RSA-4096 and 256-bit curves.
--
--   bigint.from_bytes(s) / bigint.to_bytes(x [, len])     big-endian unsigned
--   bigint.from_hex(h) / bigint.to_hex(x)                 lower-case, no leading zeros
--   bigint.from_number(v)                                 0 <= v < 2^53, integral
--   bigint.cmp(a, b) -> -1 | 0 | 1, add, sub (a >= b), mul, bits, bit, is_zero, is_odd
--   bigint.mont(m) -> ctx                                 m odd, m > 1
--     ctx:mod(x)            x mod m (any size)            -- plain numbers
--     ctx:to(x) / ctx:from(a)                             plain <-> Montgomery form
--     ctx:mul(a, b [, out]) / ctx:sqr(a [, out])          Montgomery product a*b/R
--     ctx:add(a, b), ctx:sub(a, b), ctx:neg(a)            mod m, either form
--     ctx:pow(a, e)         a^e (a Montgomery, e plain) -> Montgomery
--     ctx:inv(a)            a^(m-2): the inverse when m is prime (Montgomery form)
--     ctx:eq(a, b), ctx:is_zero(a), ctx.one (R mod m), ctx.k (limbs)
--     ctx:compile()         switch to generated straight-line products now (see below)
--
-- Representation: a little-endian array of 22-bit limbs (x[1] least significant).
-- Plain numbers may carry zero limbs on top; Montgomery elements always have exactly
-- ctx.k limbs. 22 bits is the widest limb whose products (< 2^44) can be summed 2^9
-- times without leaving the 53 bits a double holds exactly, so a whole column of a
-- product is accumulated before any carry is taken ("lazy carries"): the inner loops
-- are one multiply-add per limb pair and nothing else. That bounds a Montgomery modulus
-- to MAX_LIMBS (4,400 bits) and `mul` operands to the same.
--
-- Not constant time: timing depends on the values (operand lengths, final
-- subtractions, exponent bits). An interpreter gives no timing guarantees anyway; do not
-- use this where an attacker can time many signatures with the same key.
local compat = require("distilled.compat")

local bigint = {}

local W = 22
local B = 4194304 -- 2^22
local floor = math.floor
local byte, char = string.byte, string.char

bigint.LIMB_BITS = W
bigint.BASE = B
-- 2 * MAX_LIMBS products below 2^44 plus a carry stay below 2^53
bigint.MAX_LIMBS = 200

local POW = {}
do
  local v = 1
  for i = 0, 60 do
    POW[i] = v
    v = v * 2
  end
end
bigint.POW = POW

local function strip(x)
  local n = #x
  while n > 0 and x[n] == 0 do
    x[n] = nil
    n = n - 1
  end
  return x
end

local function len(x)
  local n = #x
  while n > 0 and x[n] == 0 do
    n = n - 1
  end
  return n
end
bigint.len = len

function bigint.from_bytes(s)
  if type(s) ~= "string" then
    compat.raise("bigint.from_bytes: expected a string, got " .. type(s), 2)
  end
  local x, n = {}, 0
  local acc, bits = 0, 0
  for i = #s, 1, -1 do
    acc = acc + byte(s, i) * POW[bits]
    bits = bits + 8
    if bits >= W then
      local lo = acc % B
      n = n + 1
      x[n] = lo
      acc = (acc - lo) / B
      bits = bits - W
    end
  end
  if acc > 0 then
    n = n + 1
    x[n] = acc
  end
  return strip(x)
end

-- bigint.to_bytes(x [, len]) -> big-endian string, left-padded with zeros to len; nil
-- when x needs more than len bytes. Without len: the minimal encoding ("" for zero).
function bigint.to_bytes(x, size)
  local out, n = {}, 0
  local acc, bits = 0, 0
  local nx = len(x)
  for i = 1, nx do
    acc = acc + x[i] * POW[bits]
    bits = bits + W
    while bits >= 8 do
      local lo = acc % 256
      n = n + 1
      out[n] = lo
      acc = (acc - lo) / 256
      bits = bits - 8
    end
  end
  while acc > 0 do
    local lo = acc % 256
    n = n + 1
    out[n] = lo
    acc = (acc - lo) / 256
  end
  while n > 0 and out[n] == 0 do
    out[n] = nil
    n = n - 1
  end
  size = size or n
  if n > size then
    return nil
  end
  local parts = {}
  for i = 1, size - n do
    parts[i] = "\0"
  end
  local base = size - n
  for i = 1, n do
    parts[base + i] = char(out[n + 1 - i])
  end
  return compat.concat(parts)
end

function bigint.from_hex(h)
  if type(h) ~= "string" or h:find("[^%x]") then
    compat.raise("bigint.from_hex: expected a hex string", 2)
  end
  if #h % 2 == 1 then
    h = "0" .. h
  end
  return bigint.from_bytes((h:gsub("..", function(p)
    return char(tonumber(p, 16))
  end)))
end

function bigint.to_hex(x)
  local s = bigint.to_bytes(x)
  local h = s:gsub(".", function(c)
    return string.format("%02x", byte(c))
  end)
  h = h:gsub("^0", "")
  return h == "" and "0" or h
end

function bigint.from_number(v)
  if type(v) ~= "number" or v < 0 or v ~= floor(v) or v >= POW[53] then
    compat.raise("bigint.from_number: expected an integer in [0, 2^53)", 2)
  end
  local x, n = {}, 0
  while v > 0 do
    local lo = v % B
    n = n + 1
    x[n] = lo
    v = (v - lo) / B
  end
  return x
end

-- small integer value of x, when x < 2^53 (for tests and exponents like 65537)
function bigint.to_number(x)
  local v = 0
  for i = len(x), 1, -1 do
    v = v * B + x[i]
  end
  return v
end

function bigint.copy(x)
  local y = {}
  for i = 1, #x do
    y[i] = x[i]
  end
  return y
end

function bigint.is_zero(x)
  return len(x) == 0
end

function bigint.is_odd(x)
  return (x[1] or 0) % 2 == 1
end

function bigint.cmp(a, b)
  local na, nb = len(a), len(b)
  if na ~= nb then
    return na < nb and -1 or 1
  end
  for i = na, 1, -1 do
    local x, y = a[i], b[i]
    if x ~= y then
      return x < y and -1 or 1
    end
  end
  return 0
end

-- number of significant bits
function bigint.bits(x)
  local n = len(x)
  if n == 0 then
    return 0
  end
  local top, b = x[n], 0
  while top >= 1 do
    top = floor(top / 2)
    b = b + 1
  end
  return (n - 1) * W + b
end

-- bit i (0 = least significant) as 0 or 1
function bigint.bit(x, i)
  local limb = x[floor(i / W) + 1]
  if not limb then
    return 0
  end
  return floor(limb / POW[i % W]) % 2
end

function bigint.add(a, b)
  local na, nb = #a, #b
  local n = na > nb and na or nb
  local out, carry = {}, 0
  for i = 1, n do
    local v = (a[i] or 0) + (b[i] or 0) + carry
    if v >= B then
      out[i] = v - B
      carry = 1
    else
      out[i] = v
      carry = 0
    end
  end
  if carry > 0 then
    out[n + 1] = carry
  end
  return strip(out)
end

-- a - b, for a >= b (raises otherwise: that is a bug in the caller)
function bigint.sub(a, b)
  local out, borrow = {}, 0
  local na = #a
  for i = 1, na do
    local v = a[i] - (b[i] or 0) - borrow
    if v < 0 then
      out[i] = v + B
      borrow = 1
    else
      out[i] = v
      borrow = 0
    end
  end
  if borrow > 0 or len(b) > na then
    compat.raise("bigint.sub: negative result", 2)
  end
  return strip(out)
end

-- a * b, by columns with lazy carries
function bigint.mul(a, b)
  local na, nb = len(a), len(b)
  if na == 0 or nb == 0 then
    return {}
  end
  if (na < nb and na or nb) > bigint.MAX_LIMBS then
    compat.raise("bigint.mul: operands too large", 2)
  end
  local out = {}
  local acc = 0
  for c = 2, na + nb do -- 1-based: pairs a[i] * b[c - i]
    local lo_i = c - nb
    if lo_i < 1 then
      lo_i = 1
    end
    local hi_i = c - 1
    if hi_i > na then
      hi_i = na
    end
    for i = lo_i, hi_i do
      acc = acc + a[i] * b[c - i]
    end
    local lo = acc % B
    out[c - 1] = lo
    acc = (acc - lo) / B
  end
  local n = na + nb - 1
  while acc > 0 do
    local lo = acc % B
    n = n + 1
    out[n] = lo
    acc = (acc - lo) / B
  end
  return strip(out)
end

-- x * 2^s, s < W, plus a small addend (for building numbers bit by bit)
local function shl_small(x, s, add)
  local out, carry = {}, add or 0
  local f = POW[s]
  for i = 1, #x do
    local v = x[i] * f + carry
    local lo = v % B
    out[i] = lo
    carry = (v - lo) / B
  end
  if carry > 0 then
    out[#x + 1] = carry
  end
  return out
end
bigint.shl_small = shl_small

-- x / 2^s (floor), s >= 0
function bigint.shr(x, s)
  local limbs = floor(s / W)
  local r = s % W
  local f = POW[r]
  local g = POW[W - r]
  local out = {}
  local n = len(x)
  for i = limbs + 1, n do
    local lo = floor(x[i] / f)
    local hi = x[i + 1] and (x[i + 1] % f) * g or 0
    out[i - limbs] = lo + hi
  end
  return strip(out)
end

---------------------------------------------------------------------------------------
-- Montgomery arithmetic
---------------------------------------------------------------------------------------

local Mont = {}
Mont.__index = Mont

local generate -- defined with the code generator below

local function pad(x, k)
  local out = {}
  for i = 1, k do
    out[i] = x[i] or 0
  end
  return out
end

-- compare a k-limb value (whose top limb may exceed B) with m
local function ge(t, m, k)
  for i = k, 1, -1 do
    local x, y = t[i], m[i]
    if x ~= y then
      return x > y
    end
  end
  return true
end

local function sub_in_place(t, m, k)
  local borrow = 0
  for i = 1, k do
    local v = t[i] - m[i] - borrow
    if v < 0 then
      t[i] = v + B
      borrow = 1
    else
      t[i] = v
      borrow = 0
    end
  end
end

-- out = a * b / R mod m. out may be a or b: column c writes limb c - k only after
-- every read of the limbs below it.
-- Generated code replaces the loops after GENERATE_AFTER products on a context: RSA
-- public-key checks (about 35 products each) mostly do not pay for compiling it.
bigint.GENERATE_AFTER = 256

local function compile(self)
  if self.generate and not self.source and self.k <= bigint.CODEGEN_WIDE_LIMBS then
    local mul, mul_source = generate(self, false)
    local sqr, sqr_source = generate(self, true)
    self.mul, self.sqr = mul, sqr
    self.source = { mul = mul_source, sqr = sqr_source }
  end
end

-- ctx:compile(): generate now (no-op for generic contexts or ones already compiled)
Mont.compile = compile

local function count_use(self)
  local uses = self.uses + 1
  self.uses = uses
  if uses == bigint.GENERATE_AFTER and bigint.GENERATE then
    compile(self)
  end
end

function Mont:mul(a, b, out)
  count_use(self)
  local m, k, minv, q = self.m, self.k, self.minv, self.q
  out = out or {}
  local acc = 0
  for c = 1, k do
    local cc = c + 1
    for j = 1, c - 1 do
      local i = cc - j
      acc = acc + a[j] * b[i] + q[j] * m[i]
    end
    acc = acc + a[c] * b[1]
    local qc = ((acc % B) * minv) % B
    q[c] = qc
    acc = (acc + qc * m[1]) / B
  end
  for c = k + 1, 2 * k - 1 do
    local cc = c + 1
    for j = c - k + 1, k do
      local i = cc - j
      acc = acc + a[j] * b[i] + q[j] * m[i]
    end
    local lo = acc % B
    out[c - k] = lo
    acc = (acc - lo) / B
  end
  out[k] = acc
  if ge(out, m, k) then
    sub_in_place(out, m, k)
  end
  return out
end

-- out = a * a / R mod m: each cross product once, doubled
function Mont:sqr(a, out)
  count_use(self)
  local m, k, minv, q = self.m, self.k, self.minv, self.q
  out = out or {}
  local acc = 0
  for c = 1, k do
    local cc = c + 1
    local s = 0
    for j = 1, floor(c / 2) do
      s = s + a[j] * a[cc - j]
    end
    acc = acc + 2 * s
    if c % 2 == 1 then
      local h = a[(c + 1) / 2]
      acc = acc + h * h
    end
    for j = 1, c - 1 do
      acc = acc + q[j] * m[cc - j]
    end
    local qc = ((acc % B) * minv) % B
    q[c] = qc
    acc = (acc + qc * m[1]) / B
  end
  for c = k + 1, 2 * k - 1 do
    local cc = c + 1
    local s = 0
    local lo_j = c - k + 1
    for j = lo_j, floor(c / 2) do
      s = s + a[j] * a[cc - j]
    end
    acc = acc + 2 * s
    if c % 2 == 1 then
      local h = a[(c + 1) / 2]
      acc = acc + h * h
    end
    for j = lo_j, k do
      acc = acc + q[j] * m[cc - j]
    end
    local lo = acc % B
    out[c - k] = lo
    acc = (acc - lo) / B
  end
  out[k] = acc
  if ge(out, m, k) then
    sub_in_place(out, m, k)
  end
  return out
end

-- REDC of y (2k limbs, y < m * R): y / R mod m
function Mont:redc(y)
  local m, k, minv, q = self.m, self.k, self.minv, self.q
  local out = {}
  local acc = 0
  for c = 1, k do
    local cc = c + 1
    acc = acc + (y[c] or 0)
    for j = 1, c - 1 do
      acc = acc + q[j] * m[cc - j]
    end
    local qc = ((acc % B) * minv) % B
    q[c] = qc
    acc = (acc + qc * m[1]) / B
  end
  for c = k + 1, 2 * k do
    local cc = c + 1
    acc = acc + (y[c] or 0)
    for j = c - k + 1, k do
      acc = acc + q[j] * m[cc - j]
    end
    local lo = acc % B
    out[c - k] = lo
    acc = (acc - lo) / B
  end
  -- the result is below 2m < 2R, so what is left over is at most 1
  out[k] = out[k] + acc * B
  if ge(out, m, k) then
    sub_in_place(out, m, k)
  end
  return out
end

-- x mod m for any x: Horner over k-limb chunks from the top. Each step reduces
-- r * R + chunk (< m * R) with REDC and multiplies the R^-1 back out.
function Mont:mod(x)
  local k = self.k
  local n = len(x)
  local r = pad({}, k)
  local chunks = floor((n + k - 1) / k)
  for c = chunks, 1, -1 do
    local y = {}
    local base = (c - 1) * k
    for i = 1, k do
      y[i] = x[base + i] or 0
      y[k + i] = r[i]
    end
    r = self:mul(self:redc(y), self.r2)
  end
  return r
end

function Mont:to(x)
  return self:mul(self:mod(x), self.r2)
end

function Mont:from(a)
  return self:mul(a, self.plain_one)
end

function Mont:add(a, b)
  local m, k = self.m, self.k
  local out, carry = {}, 0
  for i = 1, k do
    local v = a[i] + b[i] + carry
    if v >= B then
      out[i] = v - B
      carry = 1
    else
      out[i] = v
      carry = 0
    end
  end
  out[k] = out[k] + carry * B
  if ge(out, m, k) then
    sub_in_place(out, m, k)
  end
  return out
end

function Mont:sub(a, b)
  local m, k = self.m, self.k
  local out, borrow = {}, 0
  for i = 1, k do
    local v = a[i] - b[i] - borrow
    if v < 0 then
      out[i] = v + B
      borrow = 1
    else
      out[i] = v
      borrow = 0
    end
  end
  if borrow > 0 then -- went negative: add m back
    local carry = 0
    for i = 1, k do
      local v = out[i] + m[i] + carry
      if v >= B then
        out[i] = v - B
        carry = 1
      else
        out[i] = v
        carry = 0
      end
    end
  end
  return out
end

function Mont:neg(a)
  return self:sub(self.zero, a)
end

function Mont:is_zero(a)
  for i = 1, self.k do
    if a[i] ~= 0 then
      return false
    end
  end
  return true
end

function Mont:eq(a, b)
  for i = 1, self.k do
    if a[i] ~= b[i] then
      return false
    end
  end
  return true
end

-- a^e, a in Montgomery form, e a plain bigint; 4-bit fixed windows from the top
function Mont:pow(a, e)
  local nbits = bigint.bits(e)
  if nbits == 0 then
    return pad(self.one, self.k)
  end
  if nbits >= 128 and bigint.GENERATE then -- a long exponent: 128+ products follow
    compile(self)
  end
  local tbl = { [0] = self.one, a }
  for i = 2, 15 do
    tbl[i] = self:mul(tbl[i - 1], a)
  end
  local windows = floor((nbits + 3) / 4)
  local r
  for w = windows - 1, 0, -1 do
    local bitpos = w * 4
    local v = bigint.bit(e, bitpos)
      + 2 * bigint.bit(e, bitpos + 1)
      + 4 * bigint.bit(e, bitpos + 2)
      + 8 * bigint.bit(e, bitpos + 3)
    if r == nil then
      r = pad(tbl[v], self.k)
    else
      self:sqr(r, r)
      self:sqr(r, r)
      self:sqr(r, r)
      self:sqr(r, r)
      if v ~= 0 then
        self:mul(r, tbl[v], r)
      end
    end
  end
  return r
end

function Mont:inv(a)
  return self:pow(a, self.m_minus_2)
end

---------------------------------------------------------------------------------------
-- Generated Montgomery products
--
-- For moduli up to CODEGEN_LIMBS limbs (RSA-2048's CRT halves are 47, a 256-bit field
-- 12) the product is generated as straight-line Lua for that one modulus: operand limbs
-- in locals, the modulus limbs and -m^-1 as numeric constants, one statement per
-- column. That removes the loop, index arithmetic and table reads of the generic
-- version (about 3x faster in every runtime). 3k + 2 locals must stay under Lua's limit
-- of 200, hence the bound. The source is kept on the context (ctx.source.mul / .sqr).
---------------------------------------------------------------------------------------

--
-- Not on LuaJIT: its trace compiler turns the loops into machine code but gives up on
-- functions this long, so there the generated code is about 6x slower than the loops
-- (measured, RS256-2048: 0.011 s with loops, 0.064 s generated). bigint.GENERATE is the
-- default; ctx:compile() generates regardless (the spec tests both everywhere).
bigint.GENERATE = rawget(_G, "jit") == nil

bigint.CODEGEN_LIMBS = 60
-- above CODEGEN_LIMBS the generated code indexes the operand tables (RSA-4096's CRT
-- halves, 94 limbs, and RSA-3072's, 70); up to this bound
bigint.CODEGEN_WIDE_LIMBS = 100

function generate(ctx, square)
  local k, m = ctx.k, ctx.m
  local L = {}
  local function w(line)
    L[#L + 1] = line
  end
  local function list(prefix, from, to)
    local t = {}
    for i = from, to do
      t[#t + 1] = prefix .. i
    end
    return table.concat(t, ", ")
  end
  local function reads(prefix, var)
    local t = {}
    for i = 1, k do
      t[i] = var .. "[" .. i .. "]"
    end
    return "local " .. list(prefix, 1, k) .. " = " .. table.concat(t, ", ")
  end
  -- wide moduli (more limbs than locals allow) read the operands from their tables
  local wide = k > bigint.CODEGEN_LIMBS
  local A = wide and function(i)
    return "a[" .. i .. "]"
  end or function(i)
    return "a" .. i
  end
  local Bf = wide and function(i)
    return "b[" .. i .. "]"
  end or function(i)
    return "b" .. i
  end
  local Q = wide and function(i)
    return "q[" .. i .. "]"
  end or function(i)
    return "q" .. i
  end
  w("local ge, sub_in_place, M = ...")
  w("return function(self, a, " .. (square and "" or "b, ") .. "out)")
  if wide then
    -- out may alias a or b: write into a fresh table, copy at the end
    w("local dst = out")
    w("out = {}")
    w("local q = self.q")
  else
    w("out = out or {}")
    w(reads("a", "a"))
    if not square then
      w(reads("b", "b"))
    end
    w("local " .. list("q", 1, k))
  end
  w("local acc, lo = 0, 0")
  -- terms of column c (1-based; pairs i + j = c + 1), q terms for j < c (or all in phase 2)
  local function column(c)
    local terms = {}
    local lo_j = c - k + 1
    if lo_j < 1 then
      lo_j = 1
    end
    local hi_j = c < k and c or k
    if square then
      local cross = {}
      for j = lo_j, hi_j do
        local i = c + 1 - j
        if j < i then
          cross[#cross + 1] = A(j) .. " * " .. A(i)
        end
      end
      if #cross > 0 then
        terms[#terms + 1] = "2 * (" .. table.concat(cross, " + ") .. ")"
      end
      if c % 2 == 1 then
        local h = floor((c + 1) / 2)
        terms[#terms + 1] = A(h) .. " * " .. A(h)
      end
    else
      for j = lo_j, hi_j do
        terms[#terms + 1] = A(j) .. " * " .. Bf(c + 1 - j)
      end
    end
    local q_hi = c <= k and c - 1 or k
    for j = lo_j, q_hi do
      local mi = m[c + 1 - j]
      if mi ~= 0 then
        terms[#terms + 1] = Q(j) .. string.format(" * %d", mi)
      end
    end
    if #terms > 0 then
      w("acc = acc + " .. table.concat(terms, " + "))
    end
  end
  for c = 1, k do
    column(c)
    w(string.format("%s = ((acc %% %d) * %d) %% %d", Q(c), B, ctx.minv, B))
    w(string.format("acc = (acc + %s * %d) / %d", Q(c), m[1], B))
  end
  for c = k + 1, 2 * k - 1 do
    column(c)
    w(string.format("lo = acc %% %d", B))
    w(string.format("out[%d] = lo", c - k))
    w(string.format("acc = (acc - lo) / %d", B))
  end
  w(string.format("out[%d] = acc", k))
  w(string.format("if ge(out, M, %d) then sub_in_place(out, M, %d) end", k, k))
  if wide then
    w("if dst then")
    w(string.format("for i = 1, %d do dst[i] = out[i] end", k))
    w("return dst")
    w("end")
  end
  w("return out")
  w("end")
  local source = table.concat(L, "\n")
  local chunk = assert(compat.load(source, "=distilled.crypto.bigint.mont"))
  return chunk(ge, sub_in_place, m), source
end

-- bigint.mont(m [, opts]) -> ctx for the odd modulus m > 1
-- opts.generic = true keeps the loop versions of mul and sqr (for tests)
function bigint.mont(m, opts)
  local k = len(m)
  if k == 0 or not bigint.is_odd(m) or (k == 1 and m[1] == 1) then
    compat.raise("bigint.mont: the modulus must be odd and greater than 1", 2)
  end
  if k > bigint.MAX_LIMBS then
    compat.raise("bigint.mont: modulus larger than " .. bigint.MAX_LIMBS * W .. " bits", 2)
  end
  local ctx = setmetatable({ k = k, m = pad(m, k), q = {}, uses = 0 }, Mont)
  -- minv = -m^-1 mod B by Newton's iteration (x = m is right to 3 bits for odd m)
  local m1 = m[1]
  local x = m1
  for _ = 1, 5 do
    x = (x * ((2 - (m1 * x) % B) % B)) % B
  end
  ctx.minv = (B - x) % B
  ctx.zero = pad({}, k)
  ctx.plain_one = pad({ 1 }, k)
  -- R mod m and R^2 mod m. Doubling j times from R gives 2^j * R; squaring that s
  -- times in Montgomery form gives 2^(j * 2^s) * R. With j * 2^s = k * W that is R^2.
  local function double(v)
    local out, carry = {}, 0
    for i = 1, k do
      local d = v[i] * 2 + carry
      if d >= B then
        out[i] = d - B
        carry = 1
      else
        out[i] = d
        carry = 0
      end
    end
    out[k] = out[k] + carry * B
    if ge(out, ctx.m, k) then
      sub_in_place(out, ctx.m, k)
    end
    return out
  end
  -- R mod m: 2^(k*W) mod m by doubling 1
  local r = pad({ 1 }, k)
  for _ = 1, k * W do
    r = double(r)
  end
  ctx.one = r
  local total, s = k * W, 0
  while total % 2 == 0 do
    total = total / 2
    s = s + 1
  end
  local v = r
  for _ = 1, total do
    v = double(v)
  end
  for _ = 1, s do
    v = ctx:mul(v, v)
  end
  ctx.r2 = v
  ctx.m_minus_2 = bigint.sub(m, { 2 })
  ctx.generate = not (opts and opts.generic)
  return ctx
end

return bigint
