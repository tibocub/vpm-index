-- Percent-encoding, query strings and URI templates, byte-for-byte like the JavaScript
-- that Distilled's buildRequest uses:
--
--   url.encode_component(s)    encodeURIComponent (labels)
--   url.encode_form(s)         URLSearchParams' application/x-www-form-urlencoded
--                              serializer (query strings and form bodies)
--   url.encode_greedy_label(s) encodeGreedyLabel: `{name+}` labels keep their "/"
--   url.text(v)                JavaScript's String(v) for the values a request carries
--   url.query()                an ordered list of pairs: q:add(k, v), q:encode()
--   url.fill(uri, name, text, greedy)  replaces the first `{name}` / `{name+}`
--   url.placeholders(uri)      the template's placeholder names, in order
--
-- Strings are UTF-8 bytes; every byte outside the unreserved set is escaped, which is
-- what JavaScript produces for the same text (it encodes the UTF-8 of each character).
local compat = require("distilled.compat")

local url = {}

local byte, char, format = string.byte, string.char, string.format
local gsub, find, sub = string.gsub, string.find, string.sub

-- byte -> its escape, built once per scheme
local function escape_table(keep, space)
  local t = {}
  for b = 0, 255 do
    local c = char(b)
    if keep[b] then
      t[c] = c
    elseif space and b == 32 then
      t[c] = space
    else
      t[c] = format("%%%02X", b)
    end
  end
  return t
end

local function range_set(set, lo, hi)
  for b = byte(lo), byte(hi) do
    set[b] = true
  end
end

local function chars_set(set, chars)
  for k = 1, #chars do
    set[byte(chars, k)] = true
  end
end

local alnum = {}
range_set(alnum, "A", "Z")
range_set(alnum, "a", "z")
range_set(alnum, "0", "9")

-- encodeURIComponent: A-Z a-z 0-9 - _ . ! ~ * ' ( )
local component_keep = {}
for b in pairs(alnum) do
  component_keep[b] = true
end
chars_set(component_keep, "-_.!~*'()")
local COMPONENT = escape_table(component_keep)

-- URLSearchParams (WHATWG urlencoded serializer): A-Z a-z 0-9 * - . _ kept, space is +
local form_keep = {}
for b in pairs(alnum) do
  form_keep[b] = true
end
chars_set(form_keep, "*-._")
local FORM = escape_table(form_keep, "+")

function url.encode_component(s)
  return (gsub(s, ".", COMPONENT))
end

function url.encode_form(s)
  return (gsub(s, ".", FORM))
end

--- encodeGreedyLabel: drop leading slashes (the template supplies one), then encode
-- each "/"-separated segment on its own and keep the separators.
function url.encode_greedy_label(s)
  s = gsub(s, "^/+", "")
  local parts, n = {}, 0
  local start = 1
  while true do
    local at = find(s, "/", start, true)
    n = n + 1
    if not at then
      parts[n] = url.encode_component(sub(s, start))
      break
    end
    parts[n] = url.encode_component(sub(s, start, at - 1))
    start = at + 1
  end
  return compat.concat(parts, "/")
end

local json_module
local function json()
  json_module = json_module or require("distilled.json")
  return json_module
end

--- url.text(v): JavaScript's String(v) for request values. Numbers print like
-- JavaScript (1, 1.5, 1e+21), json.null is "null", a list joins with "," and any other
-- table is "[object Object]" (callers flatten objects before they get here).
function url.text(v)
  local tv = type(v)
  if tv == "string" then
    return v
  elseif tv == "number" then
    local J = json()
    local text = J._format_number(v)
    if text then
      return text
    end
    if v ~= v then
      return "NaN"
    end
    return v > 0 and "Infinity" or "-Infinity"
  elseif tv == "boolean" then
    return v and "true" or "false"
  elseif tv == "nil" then
    return "undefined"
  elseif tv == "table" then
    local J = json()
    if v == J.null then
      return "null"
    end
    if J.is_array(v) or (next(v) ~= nil and v[1] ~= nil) then
      local parts = {}
      for i = 1, #v do
        local item = v[i]
        -- String([null]) and String([undefined]) are ""
        parts[i] = (item == nil or item == J.null) and "" or url.text(item)
      end
      return compat.concat(parts, ",")
    end
    return "[object Object]"
  end
  return tostring(v)
end

---------------------------------------------------------------------------------------
-- query strings
---------------------------------------------------------------------------------------

local Query = {}
Query.__index = Query

--- url.query() -> q, an ordered list of name/value pairs
function url.query()
  return setmetatable({ n = 0, names = {}, values = {} }, Query)
end

function Query:add(name, value)
  local n = self.n + 1
  self.n = n
  self.names[n] = name
  self.values[n] = value
  return self
end

function Query:empty()
  return self.n == 0
end

--- q:encode() -> "a=1&b=2", in insertion order, form-encoded like URLSearchParams
function Query:encode()
  local parts = {}
  for i = 1, self.n do
    parts[i] = url.encode_form(self.names[i]) .. "=" .. url.encode_form(self.values[i])
  end
  return compat.concat(parts, "&")
end

---------------------------------------------------------------------------------------
-- URI templates
---------------------------------------------------------------------------------------

--- url.fill(uri, name, text, greedy) -> uri with the first `{name}` (or `{name+}` when
-- greedy) replaced by text, which must already be encoded. Plain text search, so names
-- with pattern characters are safe, and so is a "%" in text.
function url.fill(uri, name, text, greedy)
  local token = "{" .. name .. (greedy and "+}" or "}")
  local at = find(uri, token, 1, true)
  if not at then
    return uri
  end
  return sub(uri, 1, at - 1) .. text .. sub(uri, at + #token)
end

--- url.placeholders(uri) -> { { name = "id", greedy = false }, ... } in template order
function url.placeholders(uri)
  local out = {}
  for inner in string.gmatch(uri, "{([^{}]*)}") do
    local greedy = sub(inner, -1) == "+"
    out[#out + 1] = { name = greedy and sub(inner, 1, -2) or inner, greedy = greedy }
  end
  return out
end

return url
