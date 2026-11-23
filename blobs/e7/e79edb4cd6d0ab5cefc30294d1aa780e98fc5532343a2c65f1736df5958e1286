-- Value conversion between Lua values and their AWS wire form, over schema nodes.
--
-- Port of Distilled's packages/s3/src/util/codec.ts (encode / decode), lite.ts (the
-- codec kinds) and util/timestamp.ts. Lua values:
--
--   timestamp  a number of seconds since the epoch (fractions allowed); on input an
--              RFC 3339 / ISO 8601 string or an http-date is accepted too
--   blob       a string of bytes (base64 on the JSON and XML wire)
--   secrets    distilled.secret values are accepted anywhere on input and unwrapped
--
-- `codec.encode(node, value, env)` checks an input the way Distilled's encoder does
-- (required members, primitive types, a list where a list belongs) and converts it to
-- its wire scalars, keyed by member name; protocols then name and place the values.
-- A mismatch is a ParseError whose message is Distilled's: `Expected string, got 1 at
-- ["Key"]` (the value withheld when the input can hold a secret).
--
-- `codec.decode(node, value, env)` converts what a protocol read off the wire. Lenient
-- (the default) never fails: a value that does not fit is kept as read. `exact = true`
-- fails on the first mismatch, `exact = "closed"` also on a key the schema does not
-- model (ResponseValidation strict). Only declared members are kept.
--
-- env = { registry, timestamp = "epoch-seconds" | "date-time" (the protocol's default
-- body format), by_name = true (decode: the value's keys are member names, as the XML
-- readers produce; else wire names), wire_keys = true (encode: key structures by wire
-- name, for JSON bodies), exact }
--
-- Both walk values recursively with a depth bound (MAX_DEPTH): gopher-lua's call stack
-- is short, and AWS values are not deep (DynamoDB allows 32 levels).
local errors = require("distilled.errors")
local json = require("distilled.json")
local schema = require("distilled.schema")
local secret = require("distilled.secret")

local codec = {}

local MAX_DEPTH = 64
codec.MAX_DEPTH = MAX_DEPTH

local floor, format = math.floor, string.format
local INF = 1 / 0

---------------------------------------------------------------------------------------
-- timestamps (lite.ts, util/timestamp.ts)
---------------------------------------------------------------------------------------

-- days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm)
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

-- JavaScript's Date keeps whole milliseconds (TimeClip truncates toward zero).
local function to_ms(seconds)
  local ms = seconds * 1000
  if ms >= 0 then
    return floor(ms)
  end
  return -floor(-ms)
end

local function split_ms(ms)
  local days = floor(ms / 86400000)
  local rest = ms - days * 86400000
  local y, mo, d = civil_from_days(days)
  local h = floor(rest / 3600000)
  rest = rest - h * 3600000
  local mi = floor(rest / 60000)
  rest = rest - mi * 60000
  local s = floor(rest / 1000)
  return y, mo, d, h, mi, s, rest - s * 1000, days
end

local WEEKDAYS = { "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" }
local MONTHS =
  { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }
local MONTH_NUMBER = {}
for i, m in ipairs(MONTHS) do
  MONTH_NUMBER[m] = i
end

local function year_text(y)
  if y >= 0 and y <= 9999 then
    return format("%04d", y)
  end
  return (y < 0 and "-" or "+") .. format("%06d", y < 0 and -y or y)
end

--- codec.iso8601(seconds) -> `2019-12-16T23:48:18Z` (formatDateTime: Date.toISOString
-- with ".000" dropped)
function codec.iso8601(seconds)
  local y, mo, d, h, mi, s, ms = split_ms(to_ms(seconds))
  local text = format("%s-%02d-%02dT%02d:%02d:%02d", year_text(y), mo, d, h, mi, s)
  if ms ~= 0 then
    text = text .. format(".%03d", ms)
  end
  return text .. "Z"
end

--- codec.http_date(seconds) -> `Tue, 29 Apr 2014 18:30:38 GMT` (Date.toUTCString)
function codec.http_date(seconds)
  local y, mo, d, h, mi, s, _, days = split_ms(to_ms(seconds))
  local wd = WEEKDAYS[(days % 7) + 1]
  local yt = y >= 0 and format("%04d", y) or ("-" .. format("%06d", -y))
  return format("%s, %02d %s %s %02d:%02d:%02d GMT", wd, d, MONTHS[mo], yt, h, mi, s)
end

--- codec.format_timestamp(seconds, fmt) -> the wire value: a number (whole seconds,
-- floored, as Distilled sends them) for epoch-seconds, else a string
function codec.format_timestamp(seconds, fmt)
  if fmt == "epoch-seconds" then
    return floor(to_ms(seconds) / 1000)
  elseif fmt == "http-date" then
    return codec.http_date(seconds)
  end
  return codec.iso8601(seconds)
end

local function valid_date(y, mo, d, h, mi, s)
  return mo >= 1 and mo <= 12 and d >= 1 and d <= 31 and h <= 24 and mi <= 59 and s <= 59
end

--- codec.parse_date(text) -> seconds | nil
-- The forms AWS sends and JavaScript's Date parses: ISO 8601 / RFC 3339 date-times
-- (fraction, `Z` or an offset), a bare date, and RFC 7231 http-dates (also with a
-- numeric offset). Anything else is nil (a lenient decode keeps the string).
function codec.parse_date(text)
  if type(text) ~= "string" then
    return nil
  end
  local y, mo, d, rest = string.match(text, "^%s*([+-]?%d%d%d%d%d?%d?)%-(%d%d)%-(%d%d)(.*)$")
  if y then
    y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
    local h, mi, s, frac, zone = 0, 0, 0, "", "Z"
    if rest ~= "" and not string.find(rest, "^%s*$") then
      local hh, mm, tail = string.match(rest, "^[Tt ](%d%d):(%d%d)(.*)$")
      if not hh then
        return nil
      end
      h, mi = tonumber(hh), tonumber(mm)
      local ss, tail2 = string.match(tail, "^:(%d%d)(.*)$")
      if ss then
        s, tail = tonumber(ss), tail2
        local f, tail3 = string.match(tail, "^[.,](%d+)(.*)$")
        if f then
          frac, tail = f, tail3
        end
      end
      tail = string.gsub(tail, "%s+$", "")
      if tail == "" then
        -- JavaScript reads a date-time without a zone as local time; AWS always sends
        -- a zone, and UTC is the only reading that does not depend on the machine
        zone = "Z"
      elseif tail == "Z" or tail == "z" then
        zone = "Z"
      elseif string.find(tail, "^[+-]%d%d:?%d%d$") then
        zone = tail
      else
        return nil
      end
    end
    if not valid_date(y, mo, d, h, mi, s) then
      return nil
    end
    local ms = 0
    if frac ~= "" then
      ms = floor(tonumber((string.sub(frac .. "00", 1, 3))))
    end
    local total = ((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + s
    if zone ~= "Z" then
      local sign, oh, om = string.match(zone, "^([+-])(%d%d):?(%d%d)$")
      local offset = (tonumber(oh) * 60 + tonumber(om)) * 60
      total = sign == "+" and total - offset or total + offset
    end
    return total + ms / 1000
  end
  -- http-date: "Tue, 29 Apr 2014 18:30:38 GMT" (the weekday is optional)
  local dd, mon, yy, hh, mm, ss, tz = string.match(
    text,
    "^%s*%a*,?%s*(%d%d?)[%s%-](%a%a%a)[%s%-](%d%d%d%d)%s+(%d%d):(%d%d):?(%d?%d?)%s*(.-)%s*$"
  )
  if dd and MONTH_NUMBER[mon] then
    local secs = ss ~= "" and tonumber(ss) or 0
    local total = (
      (days_from_civil(tonumber(yy), MONTH_NUMBER[mon], tonumber(dd)) * 24 + tonumber(hh)) * 60
      + tonumber(mm)
    )
        * 60
      + secs
    if tz == "" or tz == "GMT" or tz == "UTC" or tz == "Z" then
      return total
    end
    local sign, oh, om = string.match(tz, "^GMT([+-])(%d%d):?(%d%d)$")
    if not sign then
      sign, oh, om = string.match(tz, "^([+-])(%d%d):?(%d%d)$")
    end
    if sign then
      local offset = (tonumber(oh) * 60 + tonumber(om)) * 60
      return sign == "+" and total - offset or total + offset
    end
    return nil
  end
  return nil
end

--- codec.timestamp_seconds(v) -> seconds | nil: a Lua timestamp input (a number, or a
-- date string) as seconds
function codec.timestamp_seconds(v)
  v = secret.unwrap(v)
  if type(v) == "number" then
    if v ~= v or v == INF or v == -INF then
      return nil
    end
    return v
  end
  if type(v) == "string" then
    return codec.parse_date(v)
  end
  return nil
end

---------------------------------------------------------------------------------------
-- base64
---------------------------------------------------------------------------------------

local base64
local function b64()
  base64 = base64 or require("distilled.crypto.base64")
  return base64
end

function codec.to_base64(s)
  return b64().encode(s)
end

--- codec.from_base64(text) -> bytes | nil (not base64)
function codec.from_base64(text)
  local v = b64().decode(text)
  return v
end

---------------------------------------------------------------------------------------
-- shared helpers
---------------------------------------------------------------------------------------

local null = json.null

local function is_secret(v)
  return secret.is(v)
end

local function show(v)
  if v == nil then
    return "undefined"
  elseif type(v) == "string" then
    return json.encode(v)
  elseif v == null then
    return "null"
  elseif type(v) == "table" then
    if schema.is_array_value(v) then
      return "an array"
    end
    return "an object"
  end
  return require("distilled.url").text(v)
end

-- A failure carries Distilled's message parts; `path` grows outward.
local function mismatch(expected, actual)
  return { expected = expected, shown = show(actual), path = "" }
end

local function within(f, key)
  f.path = f.path .. " at [" .. json.encode(key) .. "]"
  return f
end
codec.mismatch = mismatch
codec.within = within

--- codec.failure_message(f, withhold) -> Distilled's CodecError message
function codec.failure_message(f, withhold)
  if withhold then
    return "Expected " .. f.expected .. ', got "[REDACTED]"' .. f.path
  end
  return "Expected " .. f.expected .. ", got " .. f.shown .. f.path
end

local function resolve(node, registry)
  local depth = 0
  while node and node.t == "ref" do
    depth = depth + 1
    if depth > 64 then
      return nil
    end
    node = registry[node.name]
  end
  return node
end
codec.resolve = resolve

local function is_record(v)
  return type(v) == "table" and v ~= null and not is_secret(v) and not schema.is_array_value(v)
end

local function is_list(v)
  return schema.is_list_value(v)
end

-- The timestamp format of a value: the member's `ts`, the node's `format`, else the
-- protocol's body default.
local function ts_format(member_ts, node, env)
  return member_ts or node.format or env.timestamp or "date-time"
end
codec.ts_format = ts_format

---------------------------------------------------------------------------------------
-- encode
---------------------------------------------------------------------------------------

local encode_value

local function encode_scalar(node, v, ts)
  local t = node.t
  if t == "string" then
    if type(v) ~= "string" then
      return nil, mismatch("string", v)
    end
    return v
  elseif t == "number" then
    if type(v) ~= "number" then
      return nil, mismatch("number", v)
    end
    -- JSON has no NaN or Infinity: AWS sends "NaN", "Infinity", "-Infinity"
    if v ~= v then
      return "NaN"
    elseif v == INF then
      return "Infinity"
    elseif v == -INF then
      return "-Infinity"
    end
    return v
  elseif t == "boolean" then
    if type(v) ~= "boolean" then
      return nil, mismatch("boolean", v)
    end
    return v
  elseif t == "enum" then
    local want = node.base == "number" and "number" or "string"
    if type(v) ~= want then
      return nil, mismatch(want, v)
    end
    return v
  elseif t == "blob" then
    if type(v) ~= "string" then
      return nil, mismatch("a string of bytes", v)
    end
    return codec.to_base64(v)
  elseif t == "timestamp" then
    local seconds = codec.timestamp_seconds(v)
    if seconds == nil then
      return nil, mismatch("a timestamp (seconds, or a date string)", v)
    end
    return codec.format_timestamp(seconds, ts)
  end
  -- unknown / document / null: as given (secrets unwrapped)
  return secret.unwrap_deep(v)
end

local function encode_struct(node, v, env, depth)
  if not is_record(v) then
    return nil, mismatch("an object", v)
  end
  local out = {}
  for _, m in ipairs(node.members or {}) do
    local x = v[m.name]
    if x == nil then
      if m.required then
        return nil, within(mismatch("a value", nil), m.name)
      end
    else
      local w, f = encode_value(m.schema, x, env, depth + 1, m.ts, m)
      if f then
        return nil, within(f, m.name)
      end
      out[env.wire_keys and (m.wire or m.name) or m.name] = w
    end
  end
  if node.open then
    local known = schema.plan(node).known
    for k, x in pairs(v) do
      if not known[k] then
        out[k] = secret.unwrap_deep(x)
      end
    end
  end
  return json.object(out)
end

encode_value = function(node, v, env, depth, member_ts, member)
  if depth > MAX_DEPTH then
    return nil, mismatch("a value nested at most " .. MAX_DEPTH .. " levels deep", v)
  end
  if is_secret(v) then
    v = secret.unwrap(v)
  end
  node = resolve(node, env.registry)
  if not node then
    return nil, mismatch("a value of a known shape", v)
  end
  if v == null then
    -- a null is an absent value; only a sparse element or a document keeps it
    return null
  end
  local t = node.t
  if t == "struct" then
    return encode_struct(node, v, env, depth)
  elseif t == "list" then
    if not is_list(v) then
      return nil, mismatch("an array", v)
    end
    local out = {}
    local item_ts = member and member.item_ts
    for i = 1, #v do
      local w, f = encode_value(node.item, v[i], env, depth + 1, item_ts)
      if f then
        return nil, within(f, i - 1)
      end
      out[i] = w
    end
    return json.array(out)
  elseif t == "map" then
    if not is_record(v) then
      return nil, mismatch("an object", v)
    end
    local out = {}
    for k, x in pairs(v) do
      if type(k) ~= "string" then
        return nil, mismatch("an object with string keys", v)
      end
      local w, f = encode_value(node.value, x, env, depth + 1)
      if f then
        return nil, within(f, k)
      end
      out[k] = w
    end
    return json.object(out)
  end
  local ts = t == "timestamp" and ts_format(member_ts, node, env) or nil
  return encode_scalar(node, v, ts)
end

--- codec.encode(node, value, env) -> encoded | nil, failure
-- failure = { expected, shown, path }; see codec.failure_message.
function codec.encode(node, value, env)
  return encode_value(node, value, env, 0)
end

--- codec.encode_member(member, value, env) -> the encoded value of one member
function codec.encode_member(member, value, env)
  return encode_value(member.schema, value, env, 0, member.ts, member)
end

---------------------------------------------------------------------------------------
-- decode
---------------------------------------------------------------------------------------

local decode_value

local NON_FINITE = { NaN = 0 / 0, Infinity = INF, ["-Infinity"] = -INF }

-- exact: a mismatch is a failure; lenient: the value is kept as read
local function lenient_or_fail(env, expected, v)
  if env.exact then
    return nil, mismatch(expected, v)
  end
  return v
end

local function decode_scalar(node, v, env, ts)
  local t = node.t
  if t == "timestamp" then
    local fmt = ts
    if fmt == "epoch-seconds" then
      if type(v) == "string" and tonumber(v) then
        v = tonumber(v)
      end
      if type(v) == "number" and v == v and v ~= INF and v ~= -INF then
        return to_ms(v) / 1000
      end
      return lenient_or_fail(env, "epoch seconds", v)
    end
    if type(v) == "number" then
      -- a number where a date string belongs: Distilled's `new Date(v)` reads it
      -- only as a string; keep it as read
      return lenient_or_fail(env, "a date string", v)
    end
    local seconds = codec.parse_date(v)
    if seconds ~= nil then
      return seconds
    end
    return lenient_or_fail(env, "a date string", v)
  elseif t == "blob" then
    if type(v) ~= "string" then
      return lenient_or_fail(env, "a base64 string", v)
    end
    if env.raw_blob then
      return v
    end
    local bytes = codec.from_base64(v)
    if bytes == nil then
      return lenient_or_fail(env, "a base64 string", v)
    end
    return bytes
  elseif t == "number" or (t == "enum" and node.base == "number") then
    if type(v) == "string" and NON_FINITE[v] then
      return NON_FINITE[v]
    end
    if type(v) ~= "number" then
      return lenient_or_fail(env, "number", v)
    end
    return v
  elseif t == "string" or t == "enum" then
    if type(v) ~= "string" then
      return lenient_or_fail(env, "string", v)
    end
    return v
  elseif t == "boolean" then
    if type(v) ~= "boolean" then
      return lenient_or_fail(env, "boolean", v)
    end
    return v
  end
  return v
end

local function decode_struct(node, v, env, depth)
  if not is_record(v) then
    return lenient_or_fail(env, "an object", v)
  end
  local out = {}
  local plan = schema.plan(node)
  local by_name = env.by_name
  for _, m in ipairs(plan.members) do
    local key = by_name and m.name or (m.wire or m.name)
    local x = v[key]
    if x == nil or x == null then
      if env.exact and m.required and not env.skip_required then
        return nil, within(mismatch("a value", nil), key)
      end
    else
      local d, f = decode_value(m.schema, x, env, depth + 1, m.ts, m)
      if f then
        return nil, within(f, key)
      end
      if d ~= nil then
        out[m.name] = d
      end
    end
  end
  if node.open then
    local known = by_name and plan.known or plan.by_wire
    for k, x in pairs(v) do
      if not known[k] then
        out[k] = x
      end
    end
  elseif env.exact == "closed" and #plan.members > 0 then
    local known = by_name and plan.known or plan.by_wire
    for k, x in pairs(v) do
      if not known[k] and x ~= null then
        return nil, within(mismatch("no value (the schema does not model this key)", x), k)
      end
    end
  end
  return json.object(out)
end

decode_value = function(node, v, env, depth, member_ts, member)
  if depth > MAX_DEPTH then
    return lenient_or_fail(env, "a value nested at most " .. MAX_DEPTH .. " levels deep", v)
  end
  local declared = node
  node = resolve(node, env.registry)
  if not node then
    return v
  end
  local t = node.t
  if t == "struct" then
    return decode_struct(node, v, env, depth)
  elseif t == "list" then
    if not is_list(v) then
      return lenient_or_fail(env, "an array", v)
    end
    local keep_null = schema.node_nullable(node.item, env.registry)
    local out = {}
    local item_ts = member and member.item_ts
    for i = 1, #v do
      local x = v[i]
      if x == null then
        if keep_null then
          out[#out + 1] = null
        end
      else
        local d, f = decode_value(node.item, x, env, depth + 1, item_ts)
        if f then
          return nil, within(f, i - 1)
        end
        out[#out + 1] = d
      end
    end
    return json.array(out)
  elseif t == "map" then
    if not is_record(v) then
      return lenient_or_fail(env, "an object", v)
    end
    local keep_null = schema.node_nullable(node.value, env.registry)
    local out = {}
    for k, x in pairs(v) do
      if x == null then
        if keep_null then
          out[k] = null
        end
      else
        local d, f = decode_value(node.value, x, env, depth + 1)
        if f then
          return nil, within(f, k)
        end
        out[k] = d
      end
    end
    return json.object(out)
  end
  local _ = declared
  local ts = t == "timestamp" and ts_format(member_ts, node, env) or nil
  return decode_scalar(node, v, env, ts)
end

--- codec.decode(node, value, env) -> decoded | nil, failure
function codec.decode(node, value, env)
  return decode_value(node, value, env, 0)
end

--- codec.decode_member(member, value, env)
function codec.decode_member(member, value, env)
  return decode_value(member.schema, value, env, 0, member.ts, member)
end

-- Distilled's AWS ParseError (s3/src/errors.ts) has no category: the core class has the
-- ParseError one. Same tag, so matching by tag is unchanged.
codec.ParseError = errors.define({ tag = "ParseError", categories = {} })

--- codec.parse_error(message) -> ParseError
function codec.parse_error(message, fields)
  local f = { message = message }
  for k, v in pairs(fields or {}) do
    f[k] = v
  end
  return errors.new(codec.ParseError, f)
end

return codec
