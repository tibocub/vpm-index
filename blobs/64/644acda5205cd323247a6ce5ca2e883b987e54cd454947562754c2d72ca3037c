-- A pure-Lua JSON codec that keeps what Patches depend on: `null` is a value
-- (json.null), and arrays are marked so `[]` and `{}` survive a round trip.
--
-- Both directions are iterative (explicit stacks), not recursive: gopher-lua (Rex) has a
-- Lua call stack of about 250 frames, so a recursive codec would overflow on nesting
-- that Node handles. Output is built in a table and joined once, so multi-megabyte
-- documents stay linear.
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local json = {}

local byte, sub, find, format = string.byte, string.sub, string.find, string.format
local concat = compat.concat
local floor = math.floor
-- gopher-lua defines math.huge as the largest finite double, not infinity; 1/0 is
-- infinity everywhere.
local huge = 1 / 0

-- Deepest array/object nesting accepted in either direction.
json.MAX_DEPTH = 1000

---------------------------------------------------------------------------------------
-- null and marks
---------------------------------------------------------------------------------------

local NULL_MT = {
  __tostring = function()
    return "null"
  end,
  __newindex = function()
    error("json.null is read-only", 2)
  end,
}
json.null = setmetatable({}, NULL_MT)

-- Marks live in a metatable. A table that already has its own metatable is marked in a
-- weak registry instead; note gopher-lua does not collect weak tables, so prefer
-- marking plain tables.
local ARRAY_MT = { __jsontype = "array" }
local OBJECT_MT = { __jsontype = "object" }
local foreign_marks = setmetatable({}, { __mode = "k" })

local function mark(t, kind, mt, fname)
  if type(t) ~= "table" or t == json.null then
    error(fname .. ": expected a table", 3)
  end
  local current = getmetatable(t)
  if current == nil or current == ARRAY_MT or current == OBJECT_MT then
    setmetatable(t, mt)
  else
    foreign_marks[t] = kind
  end
  return t
end

function json.array(t)
  return mark(t, "array", ARRAY_MT, "json.array")
end

function json.object(t)
  return mark(t, "object", OBJECT_MT, "json.object")
end

local function marked(t)
  local mt = getmetatable(t)
  if mt == ARRAY_MT then
    return "array"
  elseif mt == OBJECT_MT then
    return "object"
  end
  return foreign_marks[t]
end

function json.is_array(t)
  return type(t) == "table" and marked(t) == "array"
end

function json.is_object(t)
  return type(t) == "table" and marked(t) == "object"
end

---------------------------------------------------------------------------------------
-- numbers
---------------------------------------------------------------------------------------

local NEG_ZERO
do
  local zero = 0.0
  NEG_ZERO = -zero
end

-- gopher-lua's tonumber rejects exponent forms without a '.' ("1e5", "1E+5") and digit
-- strings past int64; adding ".0" to the integer part makes it parse them as floats.
local function to_float(int_part, frac, exp)
  return tonumber(int_part .. "." .. (frac ~= "" and frac or "0") .. exp)
end

-- When even that fails (gopher-lua reports overflow and underflow as nil), decide from
-- the decimal magnitude whether the value is out of range high or low.
local function out_of_range(negative, int_part, frac, exp_digits)
  local digits = int_part .. frac
  local first = find(digits, "[1-9]")
  if not first then
    return negative and NEG_ZERO or 0
  end
  local magnitude = #int_part - first + 1 + (tonumber(exp_digits) or 0)
  if magnitude > 0 then
    return negative and -huge or huge
  end
  return negative and NEG_ZERO or 0
end

-- Parse JSON number text already validated by the decoder.
local function number_from_parts(negative, int_part, frac, exp_text, exp_value)
  local v
  if frac == "" and exp_text == "" and #int_part <= 15 then
    v = tonumber(int_part)
  else
    v = to_float(int_part, frac, exp_text)
    if v == nil then
      return out_of_range(negative, int_part, frac, exp_value)
    end
  end
  if negative then
    if v == 0 then
      return NEG_ZERO
    end
    v = -v
  end
  return compat.normalize_number(v)
end

local TWO_53 = 9007199254740992

-- ECMAScript Number::toString, so output matches JSON.stringify byte for byte:
-- the shortest digit string that reads back as the same double, laid out in plain
-- notation for decimal exponents in [-6, 21) and in exponent form otherwise.
local function format_number(x)
  if x ~= x then
    return nil, "NaN"
  end
  if x == huge or x == -huge then
    return nil, "an infinite number"
  end
  if x == 0 then
    return "0" -- also -0, like JSON.stringify
  end
  if compat.is_integer_subtype(x) then
    return format("%d", x)
  end
  if x == floor(x) and x > -TWO_53 and x < TWO_53 then
    return format("%.0f", x)
  end
  local negative = x < 0
  local a = negative and -x or x
  local digits, exp
  for precision = 1, 17 do
    local s = format("%." .. (precision - 1) .. "e", a)
    local lead, rest, e = string.match(s, "^(%d)%.?(%d*)e([-+]%d+)$")
    local back = tonumber(lead .. "." .. (rest ~= "" and rest or "0") .. "e" .. e)
    if back == a or precision == 17 then
      digits = lead .. rest
      exp = tonumber(e)
      break
    end
  end
  digits = string.gsub(digits, "0+$", "")
  if digits == "" then
    digits = "0"
  end
  local k = #digits
  local n = exp + 1
  local out
  if k <= n and n <= 21 then
    out = digits .. string.rep("0", n - k)
  elseif 0 < n and n <= 21 then
    out = sub(digits, 1, n) .. "." .. sub(digits, n + 1)
  elseif -6 < n and n <= 0 then
    out = "0." .. string.rep("0", -n) .. digits
  else
    local e = n - 1
    local mantissa = k == 1 and digits or (sub(digits, 1, 1) .. "." .. sub(digits, 2))
    out = mantissa .. "e" .. (e < 0 and "-" or "+") .. tostring(e < 0 and -e or e)
  end
  return negative and ("-" .. out) or out
end
json._format_number = format_number

---------------------------------------------------------------------------------------
-- decode
---------------------------------------------------------------------------------------

local function position_text(text, pos)
  local line, last_nl = 1, 0
  local i = 1
  while true do
    local nl = find(text, "\n", i, true)
    if not nl or nl >= pos then
      break
    end
    line = line + 1
    last_nl = nl
    i = nl + 1
  end
  return line, pos - last_nl
end

local function decode_error(text, pos, what)
  local line, column = position_text(text, pos)
  local err = errors.new("ParseError", {
    message = format("json: %s at position %d (line %d, column %d)", what, pos, line, column),
  })
  err.position = pos
  return nil, err
end

local function describe_char(text, pos)
  if pos > #text then
    return "unexpected end of input"
  end
  local c = sub(text, pos, pos)
  local b = byte(c)
  if b < 32 or b > 126 then
    return format("unexpected byte 0x%02x", b)
  end
  return format("unexpected character '%s'", c)
end

local ESCAPES = {
  [34] = '"', -- "
  [92] = "\\",
  [47] = "/",
  [98] = "\b",
  [102] = "\f",
  [110] = "\n",
  [114] = "\r",
  [116] = "\t",
}

local function utf8_char(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(0xC0 + floor(cp / 0x40), 0x80 + cp % 0x40)
  elseif cp < 0x10000 then
    return string.char(0xE0 + floor(cp / 0x1000), 0x80 + floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  end
  return string.char(
    0xF0 + floor(cp / 0x40000),
    0x80 + floor(cp / 0x1000) % 0x40,
    0x80 + floor(cp / 0x40) % 0x40,
    0x80 + cp % 0x40
  )
end

local REPLACEMENT = utf8_char(0xFFFD)

-- Reads the string whose opening quote is at `pos`. Returns value, next position, or
-- nil, err.
local function decode_string(text, pos)
  local start = pos + 1
  local stop = find(text, '[%z\1-\31"\\]', start)
  if stop and byte(text, stop) == 34 then
    return sub(text, start, stop - 1), stop + 1 -- fast path: no escapes
  end
  local parts, np = {}, 0
  local i = start
  while true do
    stop = find(text, '[%z\1-\31"\\]', i)
    if not stop then
      return decode_error(text, pos, "unterminated string")
    end
    if stop > i then
      np = np + 1
      parts[np] = sub(text, i, stop - 1)
    end
    local b = byte(text, stop)
    if b == 34 then
      return concat(parts), stop + 1
    elseif b == 92 then
      local e = byte(text, stop + 1)
      if e == 117 then -- \u
        local hex = string.match(text, "^%x%x%x%x", stop + 2)
        if not hex then
          return decode_error(text, stop, "invalid \\u escape")
        end
        local cp = tonumber(hex, 16)
        i = stop + 6
        if cp >= 0xD800 and cp <= 0xDBFF then
          local low = string.match(text, "^\\u(%x%x%x%x)", i)
          local lcp = low and tonumber(low, 16)
          if lcp and lcp >= 0xDC00 and lcp <= 0xDFFF then
            cp = 0x10000 + (cp - 0xD800) * 0x400 + (lcp - 0xDC00)
            i = i + 6
          else
            cp = nil -- lone high surrogate
          end
        elseif cp >= 0xDC00 and cp <= 0xDFFF then
          cp = nil -- lone low surrogate
        end
        np = np + 1
        -- UTF-8 cannot carry a lone surrogate; use U+FFFD, as Go's encoding/json does
        parts[np] = cp and utf8_char(cp) or REPLACEMENT
      else
        local ch = e and ESCAPES[e]
        if not ch then
          if not e then
            return decode_error(text, pos, "unterminated string")
          end
          return decode_error(text, stop, "invalid escape '\\" .. string.char(e) .. "'")
        end
        np = np + 1
        parts[np] = ch
        i = stop + 2
      end
    else
      return decode_error(text, stop, format("control character 0x%02x in string", b))
    end
  end
end

-- Reads the number starting at `pos`. Returns value, next position, or nil, err.
local function decode_number(text, pos)
  local sign_end = pos
  local negative = byte(text, pos) == 45
  if negative then
    sign_end = pos + 1
  end
  local int_part = string.match(text, "^%d+", sign_end)
  if not int_part then
    return decode_error(text, sign_end, "invalid number: " .. describe_char(text, sign_end))
  end
  if #int_part > 1 and byte(int_part, 1) == 48 then
    return decode_error(text, sign_end, "invalid number: leading zero")
  end
  local i = sign_end + #int_part
  local frac = ""
  if byte(text, i) == 46 then
    frac = string.match(text, "^%d+", i + 1)
    if not frac then
      return decode_error(text, i + 1, "invalid number: expected a digit after '.'")
    end
    i = i + 1 + #frac
  end
  local exp_text, exp_value = "", ""
  local eb = byte(text, i)
  if eb == 101 or eb == 69 then
    local sign, digits = string.match(text, "^([-+]?)(%d+)", i + 1)
    if not digits then
      return decode_error(text, i + 1, "invalid number: expected a digit in the exponent")
    end
    exp_text = "e" .. sign .. digits
    exp_value = (sign == "-" and "-" or "") .. digits
    i = i + 1 + #sign + #digits
  end
  return number_from_parts(negative, int_part, frac, exp_text, exp_value), i
end

local WS = { [32] = true, [9] = true, [10] = true, [13] = true }

--- json.decode(text) -> value | nil, err (ParseError with err.position)
function json.decode(text)
  if type(text) ~= "string" then
    error("json.decode: expected a string, got " .. type(text), 2)
  end
  local len = #text
  local pos = 1
  local null = json.null
  -- frames: { t, is_array, n, key }
  local stack, depth = {}, 0
  local value, err

  local function skip_ws(p)
    if WS[byte(text, p)] then
      local _, e = find(text, "^[ \t\r\n]+", p)
      return e + 1
    end
    return p
  end

  -- Reads an object key and the ':' after it, starting at `p` (at the quote).
  local function read_key(p)
    if byte(text, p) ~= 34 then
      return decode_error(text, p, "expected a string key, " .. describe_char(text, p))
    end
    local key, np = decode_string(text, p)
    if key == nil then
      return nil, np
    end
    np = skip_ws(np)
    if byte(text, np) ~= 58 then
      return decode_error(text, np, "expected ':', " .. describe_char(text, np))
    end
    return key, np + 1
  end

  while true do
    -- read one value at pos
    pos = skip_ws(pos)
    local c = byte(text, pos)
    local complete = true
    if c == 123 or c == 91 then -- { or [
      local is_array = c == 91
      -- depth counts every container, empty ones included
      if depth >= json.MAX_DEPTH then
        return decode_error(text, pos, "nesting deeper than " .. json.MAX_DEPTH)
      end
      local np = skip_ws(pos + 1)
      if byte(text, np) == (is_array and 93 or 125) then
        value = is_array and setmetatable({}, ARRAY_MT) or {}
        pos = np + 1
      else
        local frame =
          { t = is_array and setmetatable({}, ARRAY_MT) or {}, is_array = is_array, n = 0 }
        depth = depth + 1
        stack[depth] = frame
        if is_array then
          pos = np
        else
          frame.key, pos = read_key(np)
          if frame.key == nil then
            return nil, pos
          end
        end
        complete = false
      end
    elseif c == 34 then
      value, pos = decode_string(text, pos)
      if value == nil then
        return nil, pos
      end
    elseif c == 45 or (c and c >= 48 and c <= 57) then
      value, pos = decode_number(text, pos)
      if value == nil then
        return nil, pos
      end
    elseif c == 116 and sub(text, pos, pos + 3) == "true" then
      value, pos = true, pos + 4
    elseif c == 102 and sub(text, pos, pos + 4) == "false" then
      value, pos = false, pos + 5
    elseif c == 110 and sub(text, pos, pos + 3) == "null" then
      value, pos = null, pos + 4
    else
      return decode_error(text, pos, describe_char(text, pos))
    end

    -- hand completed values to their containers until one wants another value
    while complete do
      if depth == 0 then
        pos = skip_ws(pos)
        if pos <= len then
          return decode_error(text, pos, "trailing garbage, " .. describe_char(text, pos))
        end
        return value
      end
      local frame = stack[depth]
      if frame.is_array then
        frame.n = frame.n + 1
        frame.t[frame.n] = value
      else
        frame.t[frame.key] = value
      end
      pos = skip_ws(pos)
      c = byte(text, pos)
      if c == 44 then -- ,
        if frame.is_array then
          pos = pos + 1
        else
          frame.key, pos = read_key(skip_ws(pos + 1))
          if frame.key == nil then
            return nil, pos
          end
        end
        complete = false
      elseif c == (frame.is_array and 93 or 125) then
        value = frame.t
        stack[depth] = nil
        depth = depth - 1
        pos = pos + 1
      else
        return decode_error(
          text,
          pos,
          (frame.is_array and "expected ',' or ']', " or "expected ',' or '}', ")
            .. describe_char(text, pos)
        )
      end
    end
  end
end

---------------------------------------------------------------------------------------
-- encode
---------------------------------------------------------------------------------------

local STRING_ESCAPES = {
  ['"'] = '\\"',
  ["\\"] = "\\\\",
  ["\b"] = "\\b",
  ["\f"] = "\\f",
  ["\n"] = "\\n",
  ["\r"] = "\\r",
  ["\t"] = "\\t",
}
for b = 0, 31 do
  local c = string.char(b)
  STRING_ESCAPES[c] = STRING_ESCAPES[c] or format("\\u%04x", b)
end

local function encode_string(s)
  if not find(s, '[%z\1-\31"\\]') then
    return '"' .. s .. '"'
  end
  return '"' .. string.gsub(s, '[%z\1-\31"\\]', STRING_ESCAPES) .. '"'
end
json._encode_string = encode_string

local function encode_error(what)
  return nil, errors.new("InvalidInput", { message = "json: cannot encode " .. what })
end

local function is_index(k)
  return type(k) == "number" and k >= 1 and k == floor(k) and k < huge
end

-- Classify a table: returns kind ("array"|"object"), and for objects a sorted list of
-- { string_key, original_key }; for arrays the length. Or nil, message.
local function classify(t)
  local kind = marked(t)
  if kind == "array" then
    local n = 0
    for k in pairs(t) do
      if not is_index(k) then
        return nil, "an array with the non-index key " .. tostring(k)
      end
      if k > n then
        n = k
      end
    end
    return "array", n
  end
  if kind == nil then
    local n, max = 0, 0
    for k in pairs(t) do
      if not is_index(k) then
        n = -1
        break
      end
      n = n + 1
      if k > max then
        max = k
      end
    end
    if n > 0 and n == max then
      return "array", n
    end
  end
  local keys, nk = {}, 0
  for k in pairs(t) do
    local tk = type(k)
    local sk
    if tk == "string" then
      sk = k
    elseif tk == "number" then
      local f, ferr = format_number(k)
      if not f then
        return nil, "a table key that is " .. ferr
      end
      sk = f
    else
      return nil, "a table key of type " .. tk
    end
    nk = nk + 1
    keys[nk] = { sk, k }
  end
  table.sort(keys, function(a, b)
    return a[1] < b[1]
  end)
  return "object", nk, keys
end

--- json.encode(value [, opts]) -> string | nil, err (InvalidInput)
-- opts.indent = true pretty-prints with two spaces, like JSON.stringify(v, null, 2).
function json.encode(root, opts)
  local indent = opts and opts.indent
  if indent == true then
    indent = "  "
  elseif indent ~= nil and type(indent) ~= "string" then
    indent = nil
  end
  local null = json.null
  local buf, nb = {}, 0
  local stack, depth = {}, 0
  local visiting = {}
  local value = root

  while true do
    local tv = type(value)
    if value == nil or value == null then
      nb = nb + 1
      buf[nb] = "null"
    elseif tv == "string" then
      nb = nb + 1
      buf[nb] = encode_string(value)
    elseif tv == "number" then
      local s, what = format_number(value)
      if not s then
        return encode_error(what)
      end
      nb = nb + 1
      buf[nb] = s
    elseif tv == "boolean" then
      nb = nb + 1
      buf[nb] = value and "true" or "false"
    elseif tv == "table" then
      local mt = getmetatable(value)
      if type(mt) == "table" and rawget(mt, "__distilled_secret") then
        return encode_error("a secret; unwrap it first")
      end
      if visiting[value] then
        return encode_error("a table that contains itself")
      end
      if depth >= json.MAX_DEPTH then
        return encode_error("nesting deeper than " .. json.MAX_DEPTH)
      end
      local kind, n, keys = classify(value)
      if not kind then
        return encode_error(n)
      end
      if n == 0 then
        nb = nb + 1
        buf[nb] = kind == "array" and "[]" or "{}"
      else
        depth = depth + 1
        stack[depth] = { t = value, is_array = kind == "array", n = n, keys = keys, i = 0 }
        visiting[value] = true
        nb = nb + 1
        buf[nb] = kind == "array" and "[" or "{"
      end
    else
      return encode_error("a " .. tv)
    end

    -- move to the next value, closing finished containers
    local more = false
    while depth > 0 do
      local f = stack[depth]
      f.i = f.i + 1
      if f.i <= f.n then
        if f.i > 1 then
          nb = nb + 1
          buf[nb] = ","
        end
        if indent then
          nb = nb + 1
          buf[nb] = "\n" .. string.rep(indent, depth)
        end
        if f.is_array then
          value = f.t[f.i]
        else
          local entry = f.keys[f.i]
          nb = nb + 1
          buf[nb] = encode_string(entry[1]) .. (indent and ": " or ":")
          value = f.t[entry[2]]
        end
        more = true
        break
      end
      visiting[f.t] = nil
      stack[depth] = nil
      depth = depth - 1
      if indent then
        nb = nb + 1
        buf[nb] = "\n" .. string.rep(indent, depth)
      end
      nb = nb + 1
      buf[nb] = f.is_array and "]" or "}"
    end
    if not more then
      break
    end
  end
  return concat(buf)
end

return json
