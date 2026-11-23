-- Protobuf binary wire codec over generated descriptors. Port of Distilled's core
-- protobuf.ts (encodeMessage, decodeMessage, frame, FrameReader).
--
-- Proto-sourced clients keep their values in proto3 JSON shape: camelCase wire names,
-- 64-bit integers as decimal strings, bytes as base64, enums by name, Timestamp and
-- Duration as text. Servers that only speak binary gRPC need protobuf bytes, so this
-- module transcodes between the two with a descriptor table the generator emits next to
-- each client (`descriptors.lua`, from Distilled's `src/descriptors.ts`):
--
--   d.messages[name] = { { number, json_name, kind, ref?, repeated?, presence? }, ... }
--     ref: the message or enum name (kind "message" / "enum"), or { key_kind,
--     value_kind, value_ref? } for kind "map"; 0 or nil when there is none.
--     repeated: 1 for repeated fields. presence: 1 for proto3 `optional`, n >= 2 for the
--     members of the message's oneof n. Message fields always have presence.
--   d.enums[name] = { VALUE_NAME = number, ... }
--   d.methods["/<package>.<Service>/<Method>"] = { request, response, server_stream? }
--
--   protobuf.encode(d, name, value) -> bytes | nil, err      (err: InvalidInput)
--   protobuf.decode(d, name, bytes [, { nonfinite = "null" }]) -> value | nil, err
--                                                             (err: ParseError)
--   protobuf.frame(payload) -> one gRPC message frame
--   protobuf.unframe(body) -> { messages = { ... }, trailers = { ... }, rest = n } | nil, err
--
-- Decoding follows proto3: a field without presence reads as its default when the wire
-- omits it ("", 0, "0" for 64-bit integers, false, the enum's zero name, [], {}); fields
-- with presence are omitted when absent. Unknown fields are skipped.
--
-- 64-bit integers: decoded as decimal strings (proto3 JSON, as Distilled); encoded from a
-- number, a decimal string or a JSON number's text ("1e5"). Internally a 64-bit value is
-- two 32-bit halves held in doubles, so every runtime computes them exactly.
--
-- Differences from protobuf.ts, all deliberate:
-- * Nesting is limited to protobuf.MAX_DEPTH (100, protobuf's own default) levels of
--   messages or Struct values: gopher-lua's call stack holds about 250 frames, and the
--   codec recurses once per level (inside compat.pcall, which gives it a fresh stack).
-- * Map and Struct entries are written in JavaScript's key order for a JSON object
--   (array-index keys ascending, then the others; a Lua table has no insertion order,
--   so "the others" are sorted bytewise).
-- * Strings are bytes: invalid UTF-8 is replaced by U+FFFD both ways (TextEncoder and
--   TextDecoder do the same to a JS string).
-- * A bad base64 value fails with "<field>: invalid base64" (atob's DOMException text
--   in Distilled).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local base64 = require("distilled.crypto.base64")

local protobuf = {}

protobuf.MAX_DEPTH = 100

local byte, char, sub, find, format =
  string.byte, string.char, string.sub, string.find, string.format
local floor = math.floor
local concat = compat.concat
local null = json.null

local INF = 1 / 0
-- floats on purpose: on Lua 5.3+ integer arithmetic would wrap at 2^63 (2^32 * 2^32 is 0)
local TWO_32 = 2 ^ 32
local TWO_31 = 2 ^ 31
local TWO_53 = 2 ^ 53
local TWO_64 = 2 ^ 64
local MAX_FIELD_NUMBER = 536870911
local FLOAT_MAX = 3.4028234663852886e38

---------------------------------------------------------------------------------------
-- failures: raised inside the codec as tables, turned into nil, err at the boundary
---------------------------------------------------------------------------------------

local FAILURE = {}

local function fail(kind, message)
  error(setmetatable({ kind = kind, message = message }, FAILURE), 0)
end

local function encode_fail(message)
  fail("ProtobufEncodeError", message)
end

local function decode_fail(message)
  fail("ProtobufDecodeError", message)
end

-- JSON.stringify of a value, for messages
local function js_stringify(v)
  if v == nil then
    return "undefined"
  end
  if v == null then
    return "null"
  end
  local t = type(v)
  if t == "number" then
    return json._format_number(v) or "null"
  end
  if t == "string" or t == "table" or t == "boolean" then
    local s = json.encode(v)
    if s then
      return s
    end
  end
  return tostring(v)
end

-- `${n}` of a JavaScript number
local function js_number(n)
  if n ~= n then
    return "NaN"
  end
  if n == INF then
    return "Infinity"
  end
  if n == -INF then
    return "-Infinity"
  end
  return json._format_number(n)
end

---------------------------------------------------------------------------------------
-- 64-bit integers as (hi, lo): two 32-bit unsigned halves
---------------------------------------------------------------------------------------

local function u64_negate(hi, lo)
  -- two's complement: ~x + 1
  hi = TWO_32 - 1 - hi
  lo = TWO_32 - 1 - lo + 1
  if lo == TWO_32 then
    lo = 0
    hi = hi + 1
    if hi == TWO_32 then
      hi = 0
    end
  end
  return hi, lo
end

-- decimal text of an unsigned (hi, lo)
local function u64_to_decimal(hi, lo)
  if hi == 0 then
    return format("%.0f", lo)
  end
  if hi < 2097152 then -- below 2^53: exact as one double
    return format("%.0f", hi * TWO_32 + lo)
  end
  local digits = {}
  while hi > 0 or lo > 0 do
    local r = hi % 10
    hi = (hi - r) / 10
    local x = r * TWO_32 + lo
    local r2 = x % 10
    lo = (x - r2) / 10
    digits[#digits + 1] = char(48 + r2)
  end
  local n = #digits
  for i = 1, floor(n / 2) do
    local tmp = digits[i]
    digits[i] = digits[n - i + 1]
    digits[n - i + 1] = tmp
  end
  return concat(digits)
end

-- signed decimal text of a two's complement (hi, lo)
local function i64_to_decimal(hi, lo)
  if hi >= TWO_31 then
    local h, l = u64_negate(hi, lo)
    return "-" .. u64_to_decimal(h, l)
  end
  return u64_to_decimal(hi, lo)
end

-- a signed (hi, lo) as a number (exact below 2^53, which is all its callers need)
local function i64_to_number(hi, lo)
  if hi >= TWO_31 then
    local h, l = u64_negate(hi, lo)
    return -(h * TWO_32 + l)
  end
  return hi * TWO_32 + lo
end

-- An integer value: { neg, hi, lo, text } where (hi, lo) is the magnitude, or
-- { neg, over = true, text } when the magnitude is 2^64 or more. text is BigInt's
-- decimal rendering (for messages).
local function int_from_digits(neg, digits)
  digits = string.gsub(digits, "^0+", "")
  if digits == "" then
    return { neg = false, hi = 0, lo = 0, text = "0" }
  end
  local text = (neg and "-" or "") .. digits
  if #digits > 20 then
    return { neg = neg, over = true, text = text }
  end
  local hi, lo = 0, 0
  for i = 1, #digits do
    local d = byte(digits, i) - 48
    local x = lo * 10 + d
    local carry = floor(x / TWO_32)
    lo = x - carry * TWO_32
    hi = hi * 10 + carry
    if hi >= TWO_32 then
      return { neg = neg, over = true, text = text }
    end
  end
  return { neg = neg, hi = hi, lo = lo, text = text }
end

local function int_from_number(n)
  local neg = n < 0
  local mag = neg and -n or n
  if mag >= TWO_64 then
    return { neg = neg, over = true, text = format("%.0f", n) }
  end
  if mag == 0 then
    return { neg = false, hi = 0, lo = 0, text = "0" }
  end
  local hi = floor(mag / TWO_32)
  local lo = mag - hi * TWO_32
  local text
  if mag < TWO_53 then
    text = format("%.0f", n)
  else
    text = (neg and "-" or "") .. u64_to_decimal(hi, lo)
  end
  return { neg = neg, hi = hi, lo = lo, text = text }
end

-- the two's complement (hi, lo) of an integer value (asUintN(64))
local function int_bits(v)
  if v.neg then
    return u64_negate(v.hi, v.lo)
  end
  return v.hi, v.lo
end

-- in range for the kind (INT_RANGES)
local function int_in_range(v, kind)
  if v.over then
    return false
  end
  local hi, lo, neg = v.hi, v.lo, v.neg
  if kind == "int32" or kind == "sint32" or kind == "sfixed32" or kind == "enum" then
    if hi ~= 0 then
      return false
    end
    return neg and lo <= TWO_31 or (not neg and lo < TWO_31)
  elseif kind == "uint32" or kind == "fixed32" then
    return not neg and hi == 0
  elseif kind == "int64" or kind == "sint64" or kind == "sfixed64" then
    if neg then
      return hi < TWO_31 or (hi == TWO_31 and lo == 0)
    end
    return hi < TWO_31
  elseif kind == "uint64" or kind == "fixed64" then
    return not neg
  end
  return true
end

-- A JSON number's text (what a quoted number may be):
-- ^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$
local function is_json_number(s)
  local pos = 1
  if sub(s, 1, 1) == "-" then
    pos = 2
  end
  local c = sub(s, pos, pos)
  if c == "0" then
    pos = pos + 1
  elseif find(c, "^[1-9]$") then
    local _, e = find(s, "^%d+", pos)
    pos = e + 1
  else
    return false
  end
  if sub(s, pos, pos) == "." then
    local _, e = find(s, "^%d+", pos + 1)
    if not e then
      return false
    end
    pos = e + 1
  end
  local ec = sub(s, pos, pos)
  if ec == "e" or ec == "E" then
    pos = pos + 1
    local sc = sub(s, pos, pos)
    if sc == "+" or sc == "-" then
      pos = pos + 1
    end
    local _, e = find(s, "^%d+", pos)
    if not e then
      return false
    end
    pos = e + 1
  end
  return pos == #s + 1
end

-- Number(text) of a JSON number's text (tonumber is unreliable in gopher-lua)
local function json_number_value(s)
  local v = json.decode(s)
  if type(v) ~= "number" then
    return INF
  end
  return v
end

local function is_integral(n)
  return n == n and n ~= INF and n ~= -INF and n == floor(n)
end

-- toBigInt: an integer field's value, range-checked for kind
local function to_int(value, field, kind)
  local v
  local t = type(value)
  if t == "number" and is_integral(value) then
    v = int_from_number(value)
  elseif t == "string" and find(value, "^%-?%d+$") then
    local neg = sub(value, 1, 1) == "-"
    v = int_from_digits(neg, neg and sub(value, 2) or value)
  elseif t == "string" and is_json_number(value) then
    local n = json_number_value(value)
    if is_integral(n) then
      v = int_from_number(n)
    end
  end
  if v == nil then
    encode_fail(field .. ": expected an integer, got " .. js_stringify(value))
  end
  if not int_in_range(v, kind) then
    encode_fail(field .. ": " .. v.text .. " is out of range for " .. kind)
  end
  return v
end

-- toNumber: a float or double field's value
local function to_float(value, field, kind)
  local n
  local t = type(value)
  if t == "number" then
    n = value
  elseif value == "NaN" then
    n = 0 / 0
  elseif value == "Infinity" then
    n = INF
  elseif value == "-Infinity" then
    n = -INF
  elseif t == "string" and is_json_number(value) then
    n = json_number_value(value)
    if n == INF or n == -INF then
      encode_fail(field .. ": " .. value .. " is out of range for " .. kind)
    end
  end
  if n == nil then
    encode_fail(field .. ": expected a number, got " .. js_stringify(value))
  end
  if
    kind == "float"
    and n == n
    and n ~= INF
    and n ~= -INF
    and (n > FLOAT_MAX or n < -FLOAT_MAX)
  then
    encode_fail(field .. ": " .. js_number(n) .. " is out of range for float")
  end
  return n
end

---------------------------------------------------------------------------------------
-- varints and fixed-width bytes
---------------------------------------------------------------------------------------

-- unsigned varint of a non-negative number below 2^53
local function uvarint(n)
  if n < 128 then
    return char(n)
  end
  local out = {}
  while n > 127 do
    local b = n % 128
    out[#out + 1] = char(b + 128)
    n = (n - b) / 128
  end
  out[#out + 1] = char(n)
  return concat(out)
end

-- varint of a 64-bit (hi, lo)
local function varint64(hi, lo)
  if hi == 0 then
    return uvarint(lo)
  end
  local out = {}
  while hi > 0 or lo > 127 do
    local b = lo % 128
    out[#out + 1] = char(b + 128)
    local hb = hi % 128
    lo = (lo - b) / 128 + hb * 33554432 -- 2^25
    hi = (hi - hb) / 128
  end
  out[#out + 1] = char(lo)
  return concat(out)
end

local function le32(n)
  local b1 = n % 256
  n = (n - b1) / 256
  local b2 = n % 256
  n = (n - b2) / 256
  local b3 = n % 256
  local b4 = (n - b3) / 256
  return char(b1, b2, b3, b4)
end

local function tag_bytes(num, wire)
  return uvarint(num * 8 + wire)
end

---------------------------------------------------------------------------------------
-- IEEE-754 packing (no string.pack in Lua 5.1)
---------------------------------------------------------------------------------------

local math_frexp = rawget(math, "frexp")

-- x = m * 2^e with m in [1, 2), for finite x > 0
local function frexp1(x)
  if math_frexp then
    local m, e = math_frexp(x)
    return m * 2, e - 1
  end
  local e = floor(math.log(x) / math.log(2))
  if e < -1074 then
    e = -1074
  end
  local p = 2 ^ e
  while x < p do
    e = e - 1
    p = 2 ^ e
  end
  while x >= p * 2 do
    e = e + 1
    p = 2 ^ e
  end
  return x / p, e
end

local function round_half_even(v)
  local f = floor(v)
  local d = v - f
  if d > 0.5 or (d == 0.5 and f % 2 == 1) then
    return f + 1
  end
  return f
end

local function is_negative(x)
  return x < 0 or (x == 0 and 1 / x < 0)
end

local function pack_double(x)
  local sign, exp, mant = 0, 0, 0
  if x ~= x then
    exp, mant = 2047, 2251799813685248 -- 2^51: the quiet NaN V8 writes
  else
    if is_negative(x) then
      sign = 1
      x = -x
    end
    if x == INF then
      exp = 2047
    elseif x ~= 0 then
      local m, e = frexp1(x)
      if e < -1022 then
        mant = x / 2 ^ -1074
      else
        exp = e + 1023
        mant = (m - 1) * 4503599627370496 -- 2^52
      end
    end
  end
  local mant_hi = floor(mant / TWO_32)
  local mant_lo = mant - mant_hi * TWO_32
  return le32(mant_lo) .. le32(sign * TWO_31 + exp * 1048576 + mant_hi)
end

local function pack_float(x)
  local word
  if x ~= x then
    word = 2143289344 -- 0x7FC00000
  else
    local sign = 0
    if is_negative(x) then
      sign = 1
      x = -x
    end
    local bits
    if x == INF then
      bits = 2139095040 -- 255 * 2^23
    elseif x == 0 then
      bits = 0
    else
      local m, e = frexp1(x)
      if e < -126 then
        bits = round_half_even(x / 2 ^ -149) -- 2^23 here is the smallest normal
      else
        local r = round_half_even((m - 1) * 8388608)
        local ex = e + 127
        if r == 8388608 then
          r = 0
          ex = ex + 1
        end
        if ex >= 255 then
          bits = 2139095040
        else
          bits = ex * 8388608 + r
        end
      end
    end
    word = sign * TWO_31 + bits
  end
  return le32(word)
end

local function word_at(s, pos)
  local b1, b2, b3, b4 = byte(s, pos, pos + 3)
  return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

local function unpack_double(s, pos)
  local lo = word_at(s, pos)
  local hi = word_at(s, pos + 4)
  local negative = hi >= TWO_31
  if negative then
    hi = hi - TWO_31
  end
  local exp = floor(hi / 1048576)
  local mant = (hi - exp * 1048576) * TWO_32 + lo
  local v
  if exp == 2047 then
    if mant ~= 0 then
      return 0 / 0
    end
    v = INF
  elseif exp == 0 then
    v = mant * 2 ^ -1074
  else
    v = (mant + 4503599627370496) * 2 ^ (exp - 1075)
  end
  if negative then
    return -v
  end
  return v
end

local function unpack_float(s, pos)
  local w = word_at(s, pos)
  local negative = w >= TWO_31
  if negative then
    w = w - TWO_31
  end
  local exp = floor(w / 8388608)
  local mant = w - exp * 8388608
  local v
  if exp == 255 then
    if mant ~= 0 then
      return 0 / 0
    end
    v = INF
  elseif exp == 0 then
    v = mant * 2 ^ -149
  else
    v = (mant + 8388608) * 2 ^ (exp - 150)
  end
  if negative then
    return -v
  end
  return v
end

protobuf._pack_double = pack_double
protobuf._pack_float = pack_float
protobuf._unpack_double = unpack_double
protobuf._unpack_float = unpack_float

---------------------------------------------------------------------------------------
-- UTF-8 (TextEncoder / TextDecoder replace what is not valid with U+FFFD)
---------------------------------------------------------------------------------------

local REPLACEMENT = "\239\191\189"

--- protobuf.utf8_fix(s) -> s with every invalid UTF-8 sequence replaced by U+FFFD
-- (WHATWG decode: one replacement per maximal invalid subpart)
local function utf8_fix(s)
  if not find(s, "[\128-\255]") then
    return s
  end
  local out = {}
  local n = #s
  local i = 1
  local run = 1 -- start of the current valid run
  while i <= n do
    local c = byte(s, i)
    if c < 128 then
      i = i + 1
    else
      local need, lo, hi = 0, 128, 191
      if c >= 194 and c <= 223 then
        need = 1
      elseif c == 224 then
        need, lo = 2, 160
      elseif (c >= 225 and c <= 236) or c == 238 or c == 239 then
        need = 2
      elseif c == 237 then
        need, hi = 2, 159
      elseif c == 240 then
        need, lo = 3, 144
      elseif c >= 241 and c <= 243 then
        need = 3
      elseif c == 244 then
        need, hi = 3, 143
      end
      local j = i + 1
      local ok = need > 0
      for k = 1, need do
        local b = byte(s, j)
        local l, h = 128, 191
        if k == 1 then
          l, h = lo, hi
        end
        if b == nil or b < l or b > h then
          ok = false
          break
        end
        j = j + 1
      end
      if ok then
        i = j
      else
        out[#out + 1] = sub(s, run, i - 1)
        out[#out + 1] = REPLACEMENT
        -- the maximal subpart: the lead and the continuation bytes that were valid
        if need > 0 then
          i = j
        else
          i = i + 1
        end
        run = i
      end
    end
  end
  if run == 1 then
    return s
  end
  out[#out + 1] = sub(s, run)
  return concat(out)
end
protobuf.utf8_fix = utf8_fix

---------------------------------------------------------------------------------------
-- base64 (proto3 JSON bytes; atob accepts both alphabets, no padding, whitespace)
---------------------------------------------------------------------------------------

local function base64_to_bytes(value, field)
  local normal =
    string.gsub(string.gsub(string.gsub(value, "[\t\n\f\r ]", ""), "%-", "+"), "_", "/")
  local out = base64.decode(normal)
  if out == nil then
    encode_fail(field .. ": invalid base64")
  end
  return out
end

---------------------------------------------------------------------------------------
-- descriptor helpers
---------------------------------------------------------------------------------------

local WIRE = {
  double = 1,
  fixed64 = 1,
  sfixed64 = 1,
  float = 5,
  fixed32 = 5,
  sfixed32 = 5,
  string = 2,
  bytes = 2,
  message = 2,
  map = 2,
}

local function wire_type_of(kind)
  return WIRE[kind] or 0
end

local function is_packable(kind)
  return kind ~= "string" and kind ~= "bytes" and kind ~= "message" and kind ~= "map"
end

local function ref_of(f)
  local r = f[4]
  if r == 0 or r == json.null then
    return nil
  end
  return r
end

local function repeated_of(f)
  return f[5] == 1 or f[5] == true
end

local function presence_of(f)
  local p = f[6]
  if type(p) ~= "number" or p == 0 then
    return nil
  end
  return p
end

-- caches keyed by descriptor tables (long-lived: generated modules)
local index_cache = setmetatable({}, { __mode = "k" })
local oneof_cache = setmetatable({}, { __mode = "k" })
local enum_names_cache = setmetatable({}, { __mode = "k" })

local function field_index(fields)
  local idx = index_cache[fields]
  if not idx then
    idx = {}
    for _, f in ipairs(fields) do
      idx[f[1]] = f
    end
    index_cache[fields] = idx
  end
  return idx
end

local function oneofs_of(fields)
  local groups = oneof_cache[fields]
  if not groups then
    groups = {}
    for _, f in ipairs(fields) do
      local p = presence_of(f)
      if p and p >= 2 then
        groups[p] = groups[p] or {}
        table.insert(groups[p], f[2])
      end
    end
    oneof_cache[fields] = groups
  end
  return groups
end

-- number -> name of an enum
local function enum_names(values)
  local names = enum_names_cache[values]
  if not names then
    names = {}
    local keys = {}
    for k in pairs(values) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    for _, k in ipairs(keys) do
      local n = values[k]
      if names[n] == nil then
        names[n] = k
      end
    end
    enum_names_cache[values] = names
  end
  return names
end

---------------------------------------------------------------------------------------
-- values: object keys in JavaScript's order, arrays
---------------------------------------------------------------------------------------

local function is_index_key(k)
  if type(k) == "number" then
    return k >= 0 and k == floor(k) and k < TWO_32 - 1
  end
  if type(k) ~= "string" or not find(k, "^%d+$") then
    return false
  end
  if k ~= "0" and sub(k, 1, 1) == "0" then
    return false
  end
  return #k <= 10 and tonumber(k) < TWO_32 - 1
end

-- the keys of an object in the order Object.entries gives them for a JSON object:
-- array-index keys ascending, then the other keys (sorted: no insertion order in Lua)
local function js_keys(t)
  local index, other = {}, {}
  for k in pairs(t) do
    if is_index_key(k) then
      index[#index + 1] = k
    else
      other[#other + 1] = k
    end
  end
  table.sort(index, function(a, b)
    return tonumber(a) < tonumber(b)
  end)
  table.sort(other, function(a, b)
    return tostring(a) < tostring(b)
  end)
  for _, k in ipairs(other) do
    index[#index + 1] = k
  end
  return index
end

-- an array as JSON would see it: marked arrays, and unmarked tables with keys 1..n
local function is_array(t)
  if type(t) ~= "table" or t == null then
    return false
  end
  if json.is_array(t) then
    return true
  end
  if json.is_object(t) then
    return false
  end
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" then
      return false
    end
    n = n + 1
  end
  return n > 0 and n == #t
end

-- a list value for a repeated field (an empty unmarked table counts as [])
local function as_list(v)
  if is_array(v) then
    return v
  end
  if type(v) == "table" and v ~= null and next(v) == nil and not json.is_object(v) then
    return v
  end
  return nil
end

---------------------------------------------------------------------------------------
-- encode
---------------------------------------------------------------------------------------

local write_message -- forward

local function delimited(num, payload)
  return tag_bytes(num, 2) .. uvarint(#payload) .. payload
end

local function write_scalar(d, kind, ref, value, field)
  if kind == "double" then
    return pack_double(to_float(value, field, kind))
  elseif kind == "float" then
    return pack_float(to_float(value, field, kind))
  elseif kind == "int32" or kind == "int64" or kind == "uint32" or kind == "uint64" then
    return varint64(int_bits(to_int(value, field, kind)))
  elseif kind == "sint32" or kind == "sint64" then
    local v = to_int(value, field, kind)
    -- zigzag: n >= 0 -> 2n; n < 0 -> 2|n| - 1 (both fit in 64 bits for the kind's range)
    local hi, lo = v.hi * 2, v.lo * 2
    if lo >= TWO_32 then
      lo = lo - TWO_32
      hi = hi + 1
    end
    if v.neg then
      if lo == 0 then
        lo = TWO_32 - 1
        hi = hi - 1
      else
        lo = lo - 1
      end
    end
    return varint64(hi, lo)
  elseif kind == "fixed32" or kind == "sfixed32" then
    local _, lo = int_bits(to_int(value, field, kind))
    return le32(lo)
  elseif kind == "fixed64" or kind == "sfixed64" then
    local hi, lo = int_bits(to_int(value, field, kind))
    return le32(lo) .. le32(hi)
  elseif kind == "bool" then
    if type(value) ~= "boolean" then
      encode_fail(field .. ": expected a boolean, got " .. js_stringify(value))
    end
    return value and "\1" or "\0"
  elseif kind == "enum" then
    if type(value) == "number" then
      return varint64(int_bits(to_int(value, field, "enum")))
    end
    local values = ref and d.enums[ref]
    local n = type(value) == "string" and values and values[value] or nil
    if n == nil then
      encode_fail(field .. ": unknown enum value " .. js_stringify(value))
    end
    return varint64(int_bits(int_from_number(n)))
  end
  encode_fail(field .. ": " .. tostring(kind) .. " is not a scalar")
end

local function write_value(d, num, kind, ref, value, field, depth)
  if kind == "string" then
    if type(value) ~= "string" then
      encode_fail(field .. ": expected a string, got " .. js_stringify(value))
    end
    return delimited(num, utf8_fix(value))
  elseif kind == "bytes" then
    if type(value) ~= "string" then
      encode_fail(field .. ": expected bytes (base64 string or Uint8Array)")
    end
    return delimited(num, base64_to_bytes(value, field))
  elseif kind == "message" then
    return delimited(num, write_message(d, ref, value, field, depth + 1))
  end
  return tag_bytes(num, wire_type_of(kind))
    .. write_scalar(d, kind, type(ref) == "string" and ref or nil, value, field)
end

-- Timestamp range: 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999999Z
local MIN_TIMESTAMP = -62135596800
local MAX_TIMESTAMP = 253402300799
local MAX_DURATION = 315576000000

local function days_from_civil(y, m, d)
  if m <= 2 then
    y = y - 1
  end
  local era = floor(y / 400)
  local yoe = y - era * 400
  local mp = (m + 9) % 12
  local doy = floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + floor(yoe / 4) - floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

local function civil_from_days(z)
  z = z + 719468
  local era = floor(z / 146097)
  local doe = z - era * 146097
  local yoe = floor((doe - floor(doe / 1460) + floor(doe / 36524) - floor(doe / 146096)) / 365)
  local y = yoe + era * 400
  local doy = doe - (365 * yoe + floor(yoe / 4) - floor(yoe / 100))
  local mp = floor((5 * doy + 2) / 153)
  local d = doy - floor((153 * mp + 2) / 5) + 1
  local m = mp < 10 and mp + 3 or mp - 9
  if m <= 2 then
    y = y + 1
  end
  return y, m, d
end

local function days_in_month(y, m)
  if m == 2 then
    local leap = (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0
    return leap and 29 or 28
  end
  if m == 4 or m == 6 or m == 9 or m == 11 then
    return 30
  end
  return 31
end

local function nanos_of(frac)
  if frac == nil or frac == "" then
    return 0
  end
  return tonumber(frac .. string.rep("0", 9 - #frac))
end

-- RFC 3339: ^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$
local function parse_timestamp(value, field)
  local y, mo, dd, hh, mi, ss, rest
  if type(value) == "string" then
    y, mo, dd, hh, mi, ss, rest =
      string.match(value, "^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)(.*)$")
  end
  local frac, sign, oh, om
  local ok = y ~= nil
  if ok then
    local f, after = string.match(rest, "^%.(%d+)(.*)$")
    if f then
      if #f > 9 then
        ok = false
      end
      frac, rest = f, after
    end
    if ok then
      if rest == "Z" then
        sign = nil
      else
        sign, oh, om = string.match(rest, "^([+-])(%d%d):(%d%d)$")
        ok = sign ~= nil
      end
    end
  end
  if not ok then
    encode_fail(field .. ": expected an RFC 3339 timestamp, got " .. js_stringify(value))
  end
  y, mo, dd, hh, mi, ss =
    tonumber(y), tonumber(mo), tonumber(dd), tonumber(hh), tonumber(mi), tonumber(ss)
  if mo < 1 or mo > 12 or dd < 1 or dd > days_in_month(y, mo) or hh > 23 or mi > 59 or ss > 59 then
    encode_fail(field .. ": invalid timestamp " .. js_stringify(value))
  end
  local offset = 0
  if sign then
    offset = (sign == "-" and -1 or 1) * (tonumber(oh) * 3600 + tonumber(om) * 60)
  end
  local seconds = days_from_civil(y, mo, dd) * 86400 + hh * 3600 + mi * 60 + ss - offset
  if seconds < MIN_TIMESTAMP or seconds > MAX_TIMESTAMP then
    encode_fail(field .. ": timestamp " .. value .. " is out of range")
  end
  return seconds, nanos_of(frac)
end

-- a Duration's proto3 JSON ("-1.5s"), or a number of seconds
local function parse_duration(value, field)
  if type(value) == "number" and value == value and value ~= INF and value ~= -INF then
    local whole = value < 0 and -floor(-value) or floor(value)
    local nanos = floor((value - whole) * 1e9 + 0.5)
    return whole, nanos
  end
  local neg, digits, rest
  if type(value) == "string" then
    neg, digits, rest = string.match(value, "^(%-?)(%d+)(.-)s$")
  end
  local frac
  if digits then
    if rest ~= "" then
      frac = string.match(rest, "^%.(%d+)$")
      if not frac or #frac > 9 then
        digits = nil
      end
    end
  end
  if not digits then
    encode_fail(field .. ': expected a duration like "1.5s", got ' .. js_stringify(value))
  end
  local stripped = string.gsub(digits, "^0+", "")
  if #stripped > 12 or (stripped ~= "" and tonumber(stripped) > MAX_DURATION) then
    encode_fail(field .. ": duration " .. value .. " is out of range")
  end
  local seconds = stripped == "" and 0 or tonumber(stripped)
  local nanos = nanos_of(frac)
  if neg == "-" then
    return -seconds, -nanos
  end
  return seconds, nanos
end

local function signed_varint(n)
  return varint64(int_bits(int_from_number(n)))
end

local function seconds_nanos(seconds, nanos)
  local out = ""
  if seconds ~= 0 then
    out = tag_bytes(1, 0) .. signed_varint(seconds)
  end
  if nanos ~= 0 then
    out = out .. tag_bytes(2, 0) .. signed_varint(nanos)
  end
  return out
end

local function check_depth(depth, field)
  if depth > protobuf.MAX_DEPTH then
    encode_fail(field .. ": nesting deeper than " .. protobuf.MAX_DEPTH .. " levels")
  end
end

local write_struct -- forward

-- google.protobuf.Value: null_value=1, number_value=2, string_value=3, bool_value=4,
-- struct_value=5, list_value=6
local function write_struct_value(value, field, depth)
  check_depth(depth, field)
  if value == nil or value == null then
    return "\8\0"
  end
  local t = type(value)
  if t == "number" then
    return "\17" .. pack_double(value)
  elseif t == "string" then
    return delimited(3, utf8_fix(value))
  elseif t == "boolean" then
    return value and "\32\1" or "\32\0"
  elseif t == "table" and is_array(value) then
    local items = {}
    for i = 1, #value do
      items[i] = delimited(1, write_struct_value(value[i], field, depth + 1))
    end
    return delimited(6, concat(items))
  elseif t == "table" then
    return delimited(5, write_struct(value, field, depth + 1))
  end
  encode_fail(field .. ": " .. t .. " is not a JSON value")
end

-- google.protobuf.Struct: map<string, Value> fields = 1
write_struct = function(value, field, depth)
  check_depth(depth, field)
  if type(value) ~= "table" or value == null then
    -- Object.entries of a non-object has no entries
    return ""
  end
  local out = {}
  if is_array(value) then
    -- Object.entries of an array: keys "0", "1", ...
    for i = 1, #value do
      local entry = delimited(1, tostring(i - 1))
        .. delimited(2, write_struct_value(value[i], field, depth + 1))
      out[#out + 1] = delimited(1, entry)
    end
    return concat(out)
  end
  for _, k in ipairs(js_keys(value)) do
    local key = tostring(k)
    local entry = delimited(1, utf8_fix(key))
      .. delimited(2, write_struct_value(value[k], field, depth + 1))
    out[#out + 1] = delimited(1, entry)
  end
  return concat(out)
end

local WRAPPER_KINDS = {
  ["google.protobuf.DoubleValue"] = "double",
  ["google.protobuf.FloatValue"] = "float",
  ["google.protobuf.Int64Value"] = "int64",
  ["google.protobuf.UInt64Value"] = "uint64",
  ["google.protobuf.Int32Value"] = "int32",
  ["google.protobuf.UInt32Value"] = "uint32",
  ["google.protobuf.BoolValue"] = "bool",
  ["google.protobuf.StringValue"] = "string",
  ["google.protobuf.BytesValue"] = "bytes",
}

-- well-known types whose proto3 JSON is not an object of their fields
local CUSTOM_JSON = {
  ["google.protobuf.Any"] = true,
  ["google.protobuf.Timestamp"] = true,
  ["google.protobuf.Duration"] = true,
  ["google.protobuf.FieldMask"] = true,
  ["google.protobuf.Struct"] = true,
  ["google.protobuf.Value"] = true,
  ["google.protobuf.ListValue"] = true,
}
for name in pairs(WRAPPER_KINDS) do
  CUSTOM_JSON[name] = true
end

local function type_name_of(url)
  return string.match(url, "([^/]*)$")
end

local function is_known_message(d, name)
  return CUSTOM_JSON[name] or name == "google.protobuf.Empty" or d.messages[name] ~= nil
end

-- a FieldMask path from proto3 JSON: fooBar.baz -> foo_bar.baz
local function path_from_json(path, field)
  if find(path, "_") or not find(path, "^[A-Za-z0-9.]*$") then
    encode_fail(field .. ": invalid FieldMask path " .. js_stringify(path))
  end
  return (string.gsub(path, "%u", function(c)
    return "_" .. string.lower(c)
  end))
end

-- a well-known type's bytes, or nil when name is not one
local function write_well_known(d, name, value, field, depth)
  if sub(name, 1, 16) ~= "google.protobuf." then
    return nil
  end
  if name == "google.protobuf.Empty" then
    return ""
  elseif name == "google.protobuf.Timestamp" then
    return seconds_nanos(parse_timestamp(value, field))
  elseif name == "google.protobuf.Duration" then
    return seconds_nanos(parse_duration(value, field))
  elseif name == "google.protobuf.Struct" then
    return write_struct(value, field, depth)
  elseif name == "google.protobuf.Value" then
    return write_struct_value(value, field, depth)
  elseif name == "google.protobuf.ListValue" then
    local out = {}
    if type(value) == "table" and value ~= null then
      for i = 1, #value do
        out[i] = delimited(1, write_struct_value(value[i], field, depth + 1))
      end
    end
    return concat(out)
  elseif name == "google.protobuf.FieldMask" then
    if type(value) ~= "string" then
      encode_fail(field .. ": expected a FieldMask string, got " .. js_stringify(value))
    end
    local out = {}
    if value ~= "" then
      for path in string.gmatch(value .. ",", "([^,]*),") do
        out[#out + 1] = delimited(1, path_from_json(path, field))
      end
    end
    return concat(out)
  elseif name == "google.protobuf.Any" then
    -- { "@type": url, ...fields }, or { "@type": url, value } for a well-known type with
    -- its own JSON; a type the descriptors don't know is { "@type": url, value: base64 }
    if type(value) ~= "table" or value == null or is_array(value) then
      encode_fail(field .. ": expected an Any object")
    end
    local type_url = value["@type"]
    local rest = {}
    local any_rest = false
    for k, v in pairs(value) do
      if k ~= "@type" then
        rest[k] = v
        any_rest = true
      end
    end
    if type_url == nil and not any_rest then
      return ""
    end
    if type(type_url) ~= "string" or not find(type_url, "/", 1, true) then
      encode_fail(field .. ': an Any needs an "@type" type URL')
    end
    local t = type_name_of(type_url)
    local inner
    if not is_known_message(d, t) then
      if type(rest.value) ~= "string" then
        encode_fail(field .. ": unknown Any type " .. type_url)
      end
      inner = base64_to_bytes(rest.value, field)
    else
      local v = rest
      if CUSTOM_JSON[t] then
        v = rest.value -- may be false: no `and`/`or` here
      end
      if v == null and t ~= "google.protobuf.Value" then
        encode_fail(t .. ": expected a message, got null")
      end
      inner = write_message(d, t, v, t, depth + 1)
    end
    local out = delimited(1, type_url)
    if #inner > 0 then
      out = out .. delimited(2, inner)
    end
    return out
  end
  local kind = WRAPPER_KINDS[name]
  if not kind then
    return nil
  end
  return write_value(d, 1, kind, nil, value, field, depth)
end

-- whether v is the proto3 default of a scalar or enum field (-0.0 is not)
local function is_default(d, kind, ref, v)
  if kind == "string" or kind == "bytes" then
    return v == ""
  elseif kind == "bool" then
    return v == false
  elseif kind == "enum" then
    if v == 0 then
      return true
    end
    local values = type(ref) == "string" and d.enums[ref]
    return type(v) == "string" and values ~= nil and values[v] == 0
  end
  return (v == 0 and 1 / v > 0) or v == "0"
end

write_message = function(d, name, value, path, depth)
  check_depth(depth, path)
  local wk = write_well_known(d, name, value, path, depth)
  if wk then
    return wk
  end
  local fields = d.messages[name]
  if not fields then
    encode_fail(path .. ": unknown message " .. tostring(name))
  end
  if value == nil or value == null then
    return ""
  end
  if type(value) ~= "table" then
    encode_fail(path .. ": expected an object for " .. name)
  end
  local out = {}
  local set = {}
  for _, f in ipairs(fields) do
    local num, jname, kind = f[1], f[2], f[3]
    local ref, repeated, presence = ref_of(f), repeated_of(f), presence_of(f)
    local v = value[jname]
    -- null is "not set", except in a google.protobuf.Value, where it is NullValue
    if v ~= nil and not (v == null and ref ~= "google.protobuf.Value") then
      local skip = false
      if presence and presence >= 2 then
        local other = set[presence]
        if other ~= nil then
          encode_fail(path .. ": " .. other .. " and " .. jname .. " are members of one oneof")
        end
        set[presence] = jname
      end
      -- proto3: a field without presence is not written at its default
      if not repeated and not presence and kind ~= "message" and kind ~= "map" then
        skip = is_default(d, kind, ref, v)
      end
      if not skip then
        local field = path .. "." .. jname
        if kind == "map" then
          local kk, vk, vr = ref[1], ref[2], ref[3]
          if vr == 0 or vr == null then
            vr = nil
          end
          if type(v) ~= "table" or v == null then
            encode_fail(field .. ": expected an object")
          end
          for _, k in ipairs(js_keys(v)) do
            local item = v[k]
            local key = tostring(k)
            local key_value = key
            if kk == "bool" then
              key_value = key == "true"
            end
            local entry = write_value(d, 1, kk, nil, key_value, field .. ".key", depth)
              .. write_value(d, 2, vk, vr, item, field .. "[" .. key .. "]", depth)
            out[#out + 1] = delimited(num, entry)
          end
        elseif repeated then
          local list = as_list(v)
          if not list then
            encode_fail(field .. ": expected an array")
          end
          if #list > 0 then
            if is_packable(kind) then
              local items = {}
              for i = 1, #list do
                items[i] = write_scalar(d, kind, ref, list[i], field)
              end
              out[#out + 1] = delimited(num, concat(items))
            else
              for i = 1, #list do
                out[#out + 1] = write_value(d, num, kind, ref, list[i], field, depth)
              end
            end
          end
        else
          out[#out + 1] = write_value(d, num, kind, ref, v, field, depth)
        end
      end
    end
  end
  return concat(out)
end

local function boundary_error(r)
  if getmetatable(r) == FAILURE then
    return r
  end
  return nil
end

--- protobuf.encode(d, name, value) -> bytes | nil, err
-- value: the proto3 JSON value of message `name` (decoded JSON). err is InvalidInput
-- with `member = name` and `protobuf = "ProtobufEncodeError"`.
function protobuf.encode(d, name, value)
  if type(d) ~= "table" or type(d.messages) ~= "table" then
    compat.raise("protobuf.encode: expected descriptors { messages, enums, methods }", 2)
  end
  if type(name) ~= "string" then
    compat.raise("protobuf.encode: expected a message name", 2)
  end
  local ok, result = compat.pcall(function()
    if value == null and name ~= "google.protobuf.Value" then
      encode_fail(name .. ": expected a message, got null")
    end
    return write_message(d, name, value, name, 0)
  end)
  if ok then
    return result
  end
  local f = boundary_error(result)
  if f then
    return nil,
      errors.new("InvalidInput", { message = f.message, member = name, protobuf = f.kind })
  end
  return nil, errors.new("SdkError", { message = "protobuf.encode failed: " .. tostring(result) })
end

---------------------------------------------------------------------------------------
-- decode
---------------------------------------------------------------------------------------

-- A reader is { s = bytes, pos = next index, limit = last index }.

local function read_varint64(r)
  local s, pos, limit = r.s, r.pos, r.limit
  local hi, lo = 0, 0
  for i = 0, 9 do
    if pos > limit then
      decode_fail("truncated varint")
    end
    local b = byte(s, pos)
    pos = pos + 1
    local v = b % 128
    local shift = 7 * i
    if shift + 7 <= 32 then
      lo = lo + v * 2 ^ shift
    elseif shift >= 32 then
      hi = hi + v * 2 ^ (shift - 32)
    else
      local low_bits = 32 - shift
      local low = v % 2 ^ low_bits
      lo = lo + low * 2 ^ shift
      hi = hi + (v - low) / 2 ^ low_bits
    end
    if b < 128 then
      r.pos = pos
      return hi % TWO_32, lo
    end
  end
  decode_fail("varint longer than ten bytes")
end

local function read_uvarint(r)
  local s, pos = r.s, r.pos
  if pos <= r.limit then
    local b = byte(s, pos)
    if b < 128 then
      r.pos = pos + 1
      return b
    end
  end
  local hi, lo = read_varint64(r)
  return hi * TWO_32 + lo
end

local function take(r, n)
  local start = r.pos
  if start + n - 1 > r.limit then
    decode_fail("truncated field")
  end
  r.pos = start + n
  return start, start + n - 1
end

local function read_delimited(r)
  local n = read_uvarint(r)
  return take(r, n)
end

local function read_tag(r)
  local start = r.pos
  local hi, lo = read_varint64(r)
  -- a tag is a 32-bit varint: at most five bytes
  if r.pos - start > 5 then
    decode_fail("overlong field tag")
  end
  local tag = hi * TWO_32 + lo
  local wire = lo % 8
  local num = (tag - wire) / 8
  if num < 1 or num > MAX_FIELD_NUMBER then
    decode_fail("invalid field number " .. format("%.0f", num))
  end
  if wire > 5 then
    decode_fail(format("invalid wire type %d", wire))
  end
  return num, wire
end

-- skip an unknown field's value; a group is skipped to its end tag (iteratively)
local function skip(r, wire, num)
  if wire == 0 then
    read_varint64(r)
  elseif wire == 1 then
    take(r, 8)
  elseif wire == 2 then
    take(r, read_uvarint(r))
  elseif wire == 5 then
    take(r, 4)
  elseif wire == 4 then
    decode_fail("unexpected end group")
  elseif wire == 3 then
    local open = { num }
    while #open > 0 do
      if r.pos > r.limit then
        decode_fail("unterminated group")
      end
      local n, w = read_tag(r)
      if w == 4 then
        if n ~= open[#open] then
          decode_fail("mismatched end group")
        end
        open[#open] = nil
      elseif w == 3 then
        open[#open + 1] = n
      else
        skip(r, w, n)
      end
    end
  else
    decode_fail(format("invalid wire type %d", wire))
  end
end

local function sub_reader(r, a, b)
  return { s = r.s, pos = a, limit = b }
end

local function bytes_to_base64(s, a, b)
  return base64.encode(sub(s, a, b))
end

local function low32_signed(lo)
  if lo >= TWO_31 then
    return lo - TWO_32
  end
  return lo
end

local function nonfinite_guard(opts, v)
  if opts.nonfinite_null and (v ~= v or v == INF or v == -INF) then
    return null
  end
  return v
end

local function read_scalar(d, r, kind, ref, opts)
  if kind == "double" then
    local a = take(r, 8)
    return nonfinite_guard(opts, unpack_double(r.s, a))
  elseif kind == "float" then
    local a = take(r, 4)
    return nonfinite_guard(opts, unpack_float(r.s, a))
  elseif kind == "int32" then
    local _, lo = read_varint64(r)
    return low32_signed(lo)
  elseif kind == "uint32" then
    local _, lo = read_varint64(r)
    return lo
  elseif kind == "int64" then
    return i64_to_decimal(read_varint64(r))
  elseif kind == "uint64" then
    return u64_to_decimal(read_varint64(r))
  elseif kind == "sint32" then
    local _, n = read_varint64(r)
    if n % 2 == 0 then
      return n / 2
    end
    return -(n + 1) / 2
  elseif kind == "sint64" then
    local hi, lo = read_varint64(r)
    local odd = lo % 2 == 1
    -- n >>> 1
    local hb = hi % 2
    hi = (hi - hb) / 2
    lo = (lo - (lo % 2)) / 2 + hb * TWO_31
    if not odd then
      return u64_to_decimal(hi, lo)
    end
    lo = lo + 1
    if lo == TWO_32 then
      lo = 0
      hi = hi + 1
    end
    return "-" .. u64_to_decimal(hi, lo)
  elseif kind == "fixed32" then
    local a = take(r, 4)
    return word_at(r.s, a)
  elseif kind == "sfixed32" then
    local a = take(r, 4)
    return low32_signed(word_at(r.s, a))
  elseif kind == "fixed64" then
    local a = take(r, 8)
    return u64_to_decimal(word_at(r.s, a + 4), word_at(r.s, a))
  elseif kind == "sfixed64" then
    local a = take(r, 8)
    return i64_to_decimal(word_at(r.s, a + 4), word_at(r.s, a))
  elseif kind == "bool" then
    local hi, lo = read_varint64(r)
    return hi ~= 0 or lo ~= 0
  elseif kind == "enum" then
    local _, lo = read_varint64(r)
    local n = low32_signed(lo)
    local values = ref and d.enums[ref]
    if values then
      local name = enum_names(values)[n]
      if name ~= nil then
        return name
      end
    end
    return n
  end
  decode_fail(tostring(kind) .. " is not a scalar")
end

local decode_message -- forward

local function read_value(d, r, wire, kind, ref, opts, depth)
  if kind == "string" then
    local a, b = read_delimited(r)
    return utf8_fix(sub(r.s, a, b))
  elseif kind == "bytes" then
    local a, b = read_delimited(r)
    return bytes_to_base64(r.s, a, b)
  elseif kind == "message" then
    local a, b = read_delimited(r)
    return decode_message(d, ref, sub_reader(r, a, b), opts, depth + 1)
  end
  if wire == 2 then
    decode_fail("unexpected length-delimited scalar")
  end
  return read_scalar(d, r, kind, type(ref) == "string" and ref or nil, opts)
end

local function check_decode_depth(depth)
  if depth > protobuf.MAX_DEPTH then
    decode_fail("nesting deeper than " .. protobuf.MAX_DEPTH .. " levels")
  end
end

local read_struct, read_list -- forward

local function read_struct_value(r, opts, depth)
  check_decode_depth(depth)
  local out = null
  while r.pos <= r.limit do
    local num, wire = read_tag(r)
    if num == 1 then
      read_varint64(r)
      out = null
    elseif num == 2 then
      local a = take(r, 8)
      out = nonfinite_guard(opts, unpack_double(r.s, a))
    elseif num == 3 then
      local a, b = read_delimited(r)
      out = utf8_fix(sub(r.s, a, b))
    elseif num == 4 then
      local hi, lo = read_varint64(r)
      out = hi ~= 0 or lo ~= 0
    elseif num == 5 then
      local a, b = read_delimited(r)
      out = read_struct(sub_reader(r, a, b), opts, depth + 1)
    elseif num == 6 then
      local a, b = read_delimited(r)
      out = read_list(sub_reader(r, a, b), opts, depth + 1)
    else
      skip(r, wire, num)
    end
  end
  return out
end

read_list = function(r, opts, depth)
  check_decode_depth(depth)
  local items = json.array({})
  while r.pos <= r.limit do
    local num, wire = read_tag(r)
    if num == 1 and wire == 2 then
      local a, b = read_delimited(r)
      items[#items + 1] = read_struct_value(sub_reader(r, a, b), opts, depth + 1)
    else
      skip(r, wire, num)
    end
  end
  return items
end

read_struct = function(r, opts, depth)
  check_decode_depth(depth)
  local out = json.object({})
  while r.pos <= r.limit do
    local num, wire = read_tag(r)
    if num ~= 1 or wire ~= 2 then
      skip(r, wire, num)
    else
      local a, b = read_delimited(r)
      local entry = sub_reader(r, a, b)
      local key, value = "", null
      while entry.pos <= entry.limit do
        local n, w = read_tag(entry)
        if n == 1 and w == 2 then
          local x, y = read_delimited(entry)
          key = utf8_fix(sub(entry.s, x, y))
        elseif n == 2 and w == 2 then
          local x, y = read_delimited(entry)
          value = read_struct_value(sub_reader(entry, x, y), opts, depth + 1)
        else
          skip(entry, w, n)
        end
      end
      out[key] = value
    end
  end
  return out
end

-- seconds and nanos of a Timestamp or Duration
local function read_seconds_nanos(r)
  local seconds, nanos, text = 0, 0, "0"
  while r.pos <= r.limit do
    local n, wire = read_tag(r)
    if n == 1 and wire == 0 then
      local hi, lo = read_varint64(r)
      seconds = i64_to_number(hi, lo)
      text = i64_to_decimal(hi, lo)
    elseif n == 2 and wire == 0 then
      local _, lo = read_varint64(r)
      nanos = low32_signed(lo)
    else
      skip(r, wire, n)
    end
  end
  return seconds, nanos, text
end

-- fractional seconds as proto3 JSON writes them: 0, 3, 6 or 9 digits
local function fraction(nanos)
  if nanos == 0 then
    return ""
  elseif nanos % 1000000 == 0 then
    return format(".%03d", nanos / 1000000)
  elseif nanos % 1000 == 0 then
    return format(".%06d", nanos / 1000)
  end
  return format(".%09d", nanos)
end

local function format_timestamp(seconds, nanos)
  local days = floor(seconds / 86400)
  local rem = seconds - days * 86400
  local y, m, d = civil_from_days(days)
  local hh = floor(rem / 3600)
  local mi = floor((rem - hh * 3600) / 60)
  local ss = rem - hh * 3600 - mi * 60
  return format("%04d-%02d-%02dT%02d:%02d:%02d", y, m, d, hh, mi, ss) .. fraction(nanos) .. "Z"
end

local function range_fail(message)
  fail("ProtobufJsonRangeError", message)
end

-- a FieldMask path in proto3 JSON: foo_bar.baz -> fooBar.baz
local function path_to_json(path)
  return (string.gsub(path, "_([a-z0-9])", function(c)
    return string.upper(c)
  end))
end

local function read_well_known(d, name, r, opts, depth)
  if sub(name, 1, 16) ~= "google.protobuf." then
    return false
  end
  if name == "google.protobuf.Empty" then
    return true, json.object({})
  elseif name == "google.protobuf.Timestamp" then
    local seconds, nanos, text = read_seconds_nanos(r)
    if seconds < MIN_TIMESTAMP or seconds > MAX_TIMESTAMP or nanos < 0 or nanos > 999999999 then
      range_fail(format("Timestamp %ss %dns is out of range", text, nanos))
    end
    return true, format_timestamp(seconds, nanos)
  elseif name == "google.protobuf.Duration" then
    local seconds, nanos, text = read_seconds_nanos(r)
    if
      seconds > MAX_DURATION
      or seconds < -MAX_DURATION
      or nanos > 999999999
      or nanos < -999999999
      or (seconds > 0 and nanos < 0)
      or (seconds < 0 and nanos > 0)
    then
      range_fail(format("Duration %ss %dns is out of range", text, nanos))
    end
    local negative = seconds < 0 or nanos < 0
    local abs_seconds = seconds < 0 and -seconds or seconds
    local abs_nanos = nanos < 0 and -nanos or nanos
    return true,
      (negative and "-" or "") .. format("%.0f", abs_seconds) .. fraction(abs_nanos) .. "s"
  elseif name == "google.protobuf.FieldMask" then
    local paths = {}
    while r.pos <= r.limit do
      local n, wire = read_tag(r)
      if n == 1 and wire == 2 then
        local a, b = read_delimited(r)
        paths[#paths + 1] = path_to_json(utf8_fix(sub(r.s, a, b)))
      else
        skip(r, wire, n)
      end
    end
    return true, concat(paths, ",")
  elseif name == "google.protobuf.Struct" then
    return true, read_struct(r, opts, depth)
  elseif name == "google.protobuf.Value" then
    return true, read_struct_value(r, opts, depth)
  elseif name == "google.protobuf.ListValue" then
    return true, read_list(r, opts, depth)
  elseif name == "google.protobuf.Any" then
    local type_url = ""
    local ia, ib = 1, 0
    while r.pos <= r.limit do
      local n, wire = read_tag(r)
      if n == 1 and wire == 2 then
        local a, b = read_delimited(r)
        type_url = utf8_fix(sub(r.s, a, b))
      elseif n == 2 and wire == 2 then
        ia, ib = read_delimited(r)
      else
        skip(r, wire, n)
      end
    end
    if type_url == "" then
      return true, json.object({})
    end
    local t = type_name_of(type_url)
    if not is_known_message(d, t) then
      local inner = ib >= ia and bytes_to_base64(r.s, ia, ib) or ""
      return true, json.object({ ["@type"] = type_url, value = inner })
    end
    local message = decode_message(d, t, sub_reader(r, ia, ib), opts, depth + 1)
    if CUSTOM_JSON[t] then
      return true, json.object({ ["@type"] = type_url, value = message })
    end
    local out = json.object({ ["@type"] = type_url })
    for k, v in pairs(message) do
      if k ~= "@type" then
        out[k] = v
      end
    end
    return true, out
  end
  local kind = WRAPPER_KINDS[name]
  if not kind then
    return false
  end
  local value = nil
  while r.pos <= r.limit do
    local n, wire = read_tag(r)
    if n == 1 and wire == wire_type_of(kind) then
      value = read_value(d, r, wire, kind, nil, opts, depth)
    else
      skip(r, wire, n)
    end
  end
  if value == nil then
    -- defaultOf(kind)
    if kind == "string" or kind == "bytes" then
      value = ""
    elseif kind == "bool" then
      value = false
    elseif kind == "int64" or kind == "uint64" then
      value = "0"
    else
      value = 0
    end
  end
  return true, value
end

-- the proto3 default of a scalar or enum field
local function default_of(d, kind, ref)
  if kind == "string" or kind == "bytes" then
    return ""
  elseif kind == "bool" then
    return false
  elseif
    kind == "int64"
    or kind == "uint64"
    or kind == "sint64"
    or kind == "fixed64"
    or kind == "sfixed64"
  then
    return "0"
  elseif kind == "enum" then
    local values = type(ref) == "string" and d.enums[ref]
    if values then
      local zero = enum_names(values)[0]
      if zero ~= nil then
        return zero
      end
    end
    return 0
  end
  return 0
end

local EMPTY_READER_S = ""

decode_message = function(d, name, r, opts, depth)
  check_decode_depth(depth)
  local is_wk, wk = read_well_known(d, name, r, opts, depth)
  if is_wk then
    return wk
  end
  local fields = d.messages[name]
  if not fields then
    decode_fail("unknown message " .. tostring(name))
  end
  local by_number = field_index(fields)
  local oneofs = oneofs_of(fields)
  local out = json.object({})
  -- a singular message field's occurrences, merged by decoding them as one
  local messages, message_order = {}, {}
  while r.pos <= r.limit do
    local num, wire = read_tag(r)
    local f = by_number[num]
    if not f then
      skip(r, wire, num)
    else
      local jname, kind = f[2], f[3]
      local ref, repeated, presence = ref_of(f), repeated_of(f), presence_of(f)
      local packed = repeated and wire == 2 and is_packable(kind)
      if wire ~= wire_type_of(kind) and not packed then
        skip(r, wire, num)
      else
        if presence and presence >= 2 then
          for _, other in ipairs(oneofs[presence] or {}) do
            if other ~= jname then
              out[other] = nil
              messages[other] = nil
            end
          end
        end
        if kind == "map" then
          local kk, vk, vr = ref[1], ref[2], ref[3]
          if vr == 0 or vr == null then
            vr = nil
          end
          local a, b = read_delimited(r)
          local entry = sub_reader(r, a, b)
          local key = default_of(d, kk, nil)
          local value
          if vk == "message" then
            value =
              decode_message(d, vr, { s = EMPTY_READER_S, pos = 1, limit = 0 }, opts, depth + 1)
          else
            value = default_of(d, vk, vr)
          end
          -- every occurrence is read as it comes (protobuf.ts order); the last one wins
          while entry.pos <= entry.limit do
            local n, w = read_tag(entry)
            if n == 1 and w == wire_type_of(kk) then
              key = read_value(d, entry, w, kk, nil, opts, depth)
            elseif n == 2 and w == wire_type_of(vk) then
              value = read_value(d, entry, w, vk, vr, opts, depth)
            else
              skip(entry, w, n)
            end
          end
          local map = out[jname]
          if map == nil then
            map = json.object({})
            out[jname] = map
          end
          local k = key
          if type(k) == "boolean" then
            k = k and "true" or "false"
          elseif type(k) == "number" then
            k = js_number(k)
          end
          map[k] = value
        elseif repeated then
          local list = out[jname]
          if list == nil then
            list = json.array({})
            out[jname] = list
          end
          if packed then
            local a, b = read_delimited(r)
            local items = sub_reader(r, a, b)
            while items.pos <= items.limit do
              list[#list + 1] = read_scalar(d, items, kind, ref, opts)
            end
          else
            list[#list + 1] = read_value(d, r, wire, kind, ref, opts, depth)
          end
        elseif kind == "message" then
          local a, b = read_delimited(r)
          local seen = messages[jname]
          if seen then
            seen.chunks[#seen.chunks + 1] = sub(r.s, a, b)
          else
            messages[jname] = { ref = ref, chunks = { sub(r.s, a, b) } }
            message_order[#message_order + 1] = jname
          end
        else
          out[jname] = read_value(d, r, wire, kind, ref, opts, depth)
        end
      end
    end
  end
  for _, jname in ipairs(message_order) do
    local m = messages[jname]
    if m then
      local s = concat(m.chunks)
      out[jname] = decode_message(d, m.ref, { s = s, pos = 1, limit = #s }, opts, depth + 1)
    end
  end
  for _, f in ipairs(fields) do
    local jname, kind = f[2], f[3]
    local repeated, presence = repeated_of(f), presence_of(f)
    -- a singular message field has presence; a repeated one reads as []
    if not (presence or (kind == "message" and not repeated) or out[jname] ~= nil) then
      if repeated then
        out[jname] = json.array({})
      elseif kind == "map" then
        out[jname] = json.object({})
      else
        out[jname] = default_of(d, kind, ref_of(f))
      end
    end
  end
  return out
end

--- protobuf.decode(d, name, bytes [, opts]) -> value | nil, err
-- The proto3 JSON value of message `name`. opts.nonfinite = "null" decodes NaN and the
-- infinities as json.null (what JSON.stringify writes for them). err is ParseError with
-- `protobuf = "ProtobufDecodeError" | "ProtobufJsonRangeError"`.
function protobuf.decode(d, name, bytes, opts)
  if type(d) ~= "table" or type(d.messages) ~= "table" then
    compat.raise("protobuf.decode: expected descriptors { messages, enums, methods }", 2)
  end
  if type(name) ~= "string" or type(bytes) ~= "string" then
    compat.raise("protobuf.decode: expected a message name and a byte string", 2)
  end
  local o = { nonfinite_null = opts ~= nil and opts.nonfinite == "null" }
  local ok, result = compat.pcall(function()
    return decode_message(d, name, { s = bytes, pos = 1, limit = #bytes }, o, 0)
  end)
  if ok then
    return result
  end
  local f = boundary_error(result)
  if f then
    return nil, errors.new("ParseError", { message = f.message, protobuf = f.kind })
  end
  return nil, errors.new("SdkError", { message = "protobuf.decode failed: " .. tostring(result) })
end

---------------------------------------------------------------------------------------
-- gRPC length-prefixed framing
---------------------------------------------------------------------------------------

local function be32(n)
  local b4 = n % 256
  n = (n - b4) / 256
  local b3 = n % 256
  n = (n - b3) / 256
  local b2 = n % 256
  local b1 = (n - b2) / 256
  return char(b1, b2, b3, b4)
end

--- protobuf.frame(payload [, flag]) -> [flag][u32 length BE][payload] (flag 0)
function protobuf.frame(payload, flag)
  return char(flag or 0) .. be32(#payload) .. payload
end

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

--- protobuf.unframe(body) -> { messages, trailers, rest } | nil, err
-- Splits a whole gRPC body into message payloads (FrameReader). A gRPC-Web trailer frame
-- (flag 0x80) is not a message: its `name: value` lines go to `trailers` (names
-- lower-case). `rest` is the number of bytes of an incomplete last frame (0 for a body
-- that ended cleanly). A compressed frame is a ParseError.
function protobuf.unframe(body)
  local messages, trailers = {}, {}
  local pos, n = 1, #body
  while pos + 4 <= n do
    local flag = byte(body, pos)
    local b1, b2, b3, b4 = byte(body, pos + 1, pos + 4)
    local len = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
    if pos + 4 + len > n then
      break
    end
    local is_trailer = flag >= 128
    if flag % 2 == 1 and not is_trailer then
      return nil,
        errors.new("ParseError", {
          message = "compressed gRPC frames are not supported",
          protobuf = "ProtobufDecodeError",
        })
    end
    local payload = sub(body, pos + 5, pos + 4 + len)
    if is_trailer then
      for line in string.gmatch(utf8_fix(payload) .. "\r\n", "(.-)\r\n") do
        local colon = find(line, ":", 1, true)
        if colon and colon > 1 then
          trailers[string.lower(trim(sub(line, 1, colon - 1)))] = trim(sub(line, colon + 1))
        end
      end
    else
      messages[#messages + 1] = payload
    end
    pos = pos + 5 + len
  end
  return { messages = messages, trailers = trailers, rest = n - pos + 1 }
end

return protobuf
