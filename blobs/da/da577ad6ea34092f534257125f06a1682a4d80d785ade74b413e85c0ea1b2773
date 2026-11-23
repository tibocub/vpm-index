-- distilled.xml: a port of Distilled's core/src/xml.ts (parseXmlSync, escapeXml,
-- wrapTag). AWS restXml / query protocols, S3 and a few REST providers speak XML.
--
-- xml.decode parses DTD-free XML 1.0 into plain tables, the shape fast-xml-parser made
-- conventional and Distilled's protocols read:
--   - an element with only text is its text, a string ("" when empty);
--   - an element with children or attributes is a table: children by name, attributes
--     as "@_<name>", text as "#text" (see finish below for when text is kept);
--   - repeated children with the same name become a list, in document order;
--   - values stay strings; names are kept verbatim (no namespace resolution, so
--     "ns:x" and "@_xmlns:ns" are plain keys);
--   - comments and processing instructions are ignored, CDATA joins the text undecoded,
--     the five predefined entities and numeric character references are decoded once;
--   - an empty (or whitespace-only) body is {}.
--
-- Differences from xml.ts, all forced by Lua strings being bytes:
--   - Input is UTF-8. Invalid UTF-8 (including encoded surrogates) is "Invalid XML
--     character", like the controls, U+FFFE and U+FFFF that XML forbids. Distilled
--     decodes a body with TextDecoder first, which turns invalid bytes into U+FFFD.
--   - err.offset is a byte offset (0-based) and max_length counts bytes. err.line and
--     err.column are what Distilled reports (column in UTF-16 code units), so the
--     message ("<what> at <line>:<column>") is identical to Distilled's.
--   - Options are snake_case: max_depth, max_length.
--
-- No recursion over the document: the scanner keeps an explicit element stack, so depth
-- is bounded only by max_depth (gopher-lua's Lua stack is about 250 frames).
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local xml = {}

local byte, sub, find, gsub, match, char, format, lower =
  string.byte,
  string.sub,
  string.find,
  string.gsub,
  string.match,
  string.char,
  string.format,
  string.lower
local concat = compat.concat
local floor = math.floor

-- Defaults of xml.ts: open elements including the root, and input length.
xml.MAX_DEPTH = 256
xml.MAX_LENGTH = 64 * 1024 * 1024

local MAX_SAFE_INTEGER = 9007199254740991
local BOM = "\239\187\191"

---------------------------------------------------------------------------------------
-- errors
---------------------------------------------------------------------------------------

-- A parse failure travels as this table (raised inside the scanner, caught once by
-- xml.decode), so the scanner reads like xml.ts, which throws.
local FAIL_MT = {}

local function fail(message, at)
  error(setmetatable({ message = message, at = at }, FAIL_MT), 0)
end

-- UTF-16 code units of a valid UTF-8 string: one per lead byte, two for 4-byte forms.
-- A 4-byte form cut after its lead byte counts one, like the high surrogate xml.ts has
-- read when it fails one code unit into an astral character (xml[pos++]).
local function utf16_length(s)
  local _, units = gsub(s, "[^\128-\191]", "")
  local _, astral = gsub(s, "[\240-\244][\128-\191][\128-\191][\128-\191]", "")
  return units + astral
end

-- The ParseError for a failure at byte offset `offset` (0-based), with xml.ts's line and
-- column: lines split at \r\n, \r or \n; column counts UTF-16 code units, one-based.
local function parse_error(text, message, offset)
  if offset > #text then
    offset = #text
  end
  if offset < 0 then
    offset = 0
  end
  local prefix = sub(text, 1, offset)
  local line, line_start, i = 1, 1, 1
  while true do
    local s = find(prefix, "[\r\n]", i)
    if not s then
      break
    end
    if byte(prefix, s) == 13 and byte(prefix, s + 1) == 10 then
      s = s + 1
    end
    line = line + 1
    i = s + 1
    line_start = i
  end
  local column = utf16_length(sub(prefix, line_start)) + 1
  local err = errors.new("ParseError", { message = format("%s at %d:%d", message, line, column) })
  err.offset = offset
  err.position = offset + 1 -- 1-based, like json's err.position
  err.line = line
  err.column = column
  return err
end

---------------------------------------------------------------------------------------
-- characters and names
---------------------------------------------------------------------------------------

-- Byte index of the first character XML 1.0 forbids, or nil: C0 controls other than
-- tab, LF and CR; invalid UTF-8 (surrogates, overlong forms, past U+10FFFF, truncated
-- or stray bytes); U+FFFE and U+FFFF.
local function first_invalid_character(s)
  local control = find(s, "[%z\1-\8\11\12\14-\31]")
  local limit = control or (#s + 1)
  local p = find(s, "[\128-\255]")
  while p and p < limit do
    local b, c1, c2, c3 = byte(s, p, p + 3)
    local len
    if b >= 0xC2 and b <= 0xDF then
      if c1 and c1 >= 0x80 and c1 <= 0xBF then
        len = 2
      end
    elseif b >= 0xE0 and b <= 0xEF then
      local lo, hi = 0x80, 0xBF
      if b == 0xE0 then
        lo = 0xA0 -- overlong
      elseif b == 0xED then
        hi = 0x9F -- U+D800..U+DFFF are surrogates
      end
      if c1 and c2 and c1 >= lo and c1 <= hi and c2 >= 0x80 and c2 <= 0xBF then
        if not (b == 0xEF and c1 == 0xBF and c2 >= 0xBE) then -- U+FFFE, U+FFFF
          len = 3
        end
      end
    elseif b >= 0xF0 and b <= 0xF4 then
      local lo, hi = 0x80, 0xBF
      if b == 0xF0 then
        lo = 0x90 -- overlong
      elseif b == 0xF4 then
        hi = 0x8F -- past U+10FFFF
      end
      if c1 and c2 and c3 and c1 >= lo and c1 <= hi and c2 >= 0x80 and c2 <= 0xBF then
        if c3 >= 0x80 and c3 <= 0xBF then
          len = 4
        end
      end
    end
    if not len then
      return p
    end
    p = find(s, "[\128-\255]", p + len)
  end
  return control
end

-- The code point at byte p and its length in bytes; the input is valid UTF-8 here.
local function code_point_at(s, p)
  local b, c1, c2, c3 = byte(s, p, p + 3)
  if not b then
    return nil, 0
  elseif b < 0x80 then
    return b, 1
  elseif b < 0xE0 then
    return (b - 0xC0) * 64 + (c1 - 0x80), 2
  elseif b < 0xF0 then
    return (b - 0xE0) * 4096 + (c1 - 0x80) * 64 + (c2 - 0x80), 3
  end
  return (b - 0xF0) * 262144 + (c1 - 0x80) * 4096 + (c2 - 0x80) * 64 + (c3 - 0x80), 4
end

-- XML 1.0 (Fifth Edition) NameStartChar.
local function is_name_start(cp)
  if cp < 0x80 then
    return (cp >= 65 and cp <= 90) or (cp >= 97 and cp <= 122) or cp == 58 or cp == 95
  end
  return (cp >= 0xC0 and cp <= 0xD6)
    or (cp >= 0xD8 and cp <= 0xF6)
    or (cp >= 0xF8 and cp <= 0x2FF)
    or (cp >= 0x370 and cp <= 0x37D)
    or (cp >= 0x37F and cp <= 0x1FFF)
    or (cp >= 0x200C and cp <= 0x200D)
    or (cp >= 0x2070 and cp <= 0x218F)
    or (cp >= 0x2C00 and cp <= 0x2FEF)
    or (cp >= 0x3001 and cp <= 0xD7FF)
    or (cp >= 0xF900 and cp <= 0xFDCF)
    or (cp >= 0xFDF0 and cp <= 0xFFFD)
    or (cp >= 0x10000 and cp <= 0xEFFFF)
end

-- NameChar: NameStartChar plus "-", ".", digits, U+00B7, combining marks, U+203F-2040.
local function is_name_char(cp)
  if is_name_start(cp) then
    return true
  end
  return cp == 45
    or cp == 46
    or (cp >= 48 and cp <= 57)
    or cp == 0xB7
    or (cp >= 0x300 and cp <= 0x36F)
    or (cp >= 0x203F and cp <= 0x2040)
end

local function utf8_char(cp)
  if cp < 0x80 then
    return char(cp)
  elseif cp < 0x800 then
    return char(0xC0 + floor(cp / 0x40), 0x80 + cp % 0x40)
  elseif cp < 0x10000 then
    return char(0xE0 + floor(cp / 0x1000), 0x80 + floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  end
  return char(
    0xF0 + floor(cp / 0x40000),
    0x80 + floor(cp / 0x1000) % 0x40,
    0x80 + floor(cp / 0x40) % 0x40,
    0x80 + cp % 0x40
  )
end

---------------------------------------------------------------------------------------
-- entities and the XML declaration
---------------------------------------------------------------------------------------

local PREDEFINED = { amp = "&", lt = "<", gt = ">", quot = '"', apos = "'" }

-- "#65" or "#x1F600" -> the character, or nil plus the xml.ts message.
local function character_reference(entity)
  local digits = match(entity, "^#(%d+)$")
  local base = 10
  if not digits then
    digits = match(entity, "^#x(%x+)$")
    base = 16
    if not digits then
      return nil, "Unknown or invalid entity reference"
    end
  end
  -- leading zeros are allowed; anything longer than 8 digits is past U+10FFFF (and
  -- gopher-lua's tonumber rejects long digit strings)
  digits = gsub(digits, "^0+", "")
  local code = 0
  if #digits > 8 then
    code = nil
  elseif digits ~= "" then
    code = tonumber(digits, base)
  end
  if
    code
    and (
      code == 9
      or code == 10
      or code == 13
      or (code >= 0x20 and code <= 0xD7FF)
      or (code >= 0xE000 and code <= 0xFFFD)
      or (code >= 0x10000 and code <= 0x10FFFF)
    )
  then
    return utf8_char(code)
  end
  return nil, "Invalid character reference"
end

-- Text (attribute = false) or an attribute value (true), at byte `base` of the input.
-- Literal line endings are normalised (\r\n and \r to \n; in attributes \r\n, tab, \r
-- and \n to a space); character references are not, as XML 1.0 says.
local function decode_text(raw, base, attribute)
  local amp = find(raw, "&", 1, true)
  if not amp then
    if attribute then
      if not find(raw, "[\t\r\n]") then
        return raw
      end
      return (gsub(gsub(raw, "\r\n", " "), "[\t\r\n]", " "))
    end
    if not find(raw, "\r", 1, true) then
      return raw
    end
    return (gsub(raw, "\r\n?", "\n"))
  end
  local parts, np, from, len = {}, 0, 1, #raw
  while from <= len do
    amp = find(raw, "&", from, true)
    local literal = sub(raw, from, (amp or len + 1) - 1)
    if attribute then
      literal = gsub(gsub(literal, "\r\n", " "), "[\t\r\n]", " ")
    else
      literal = gsub(literal, "\r\n?", "\n")
    end
    np = np + 1
    parts[np] = literal
    if not amp then
      break
    end
    local semi = find(raw, ";", amp + 1, true)
    if not semi then
      fail("Unterminated entity reference", base + amp - 1)
    end
    local entity = sub(raw, amp + 1, semi - 1)
    local value = PREDEFINED[entity]
    if not value then
      local why
      value, why = character_reference(entity)
      if not value then
        fail(why, base + amp - 1)
      end
    end
    np = np + 1
    parts[np] = value
    from = semi + 1
  end
  return concat(parts)
end

local S = "[\t\n\r ]"

-- An optional `<space> name = "value"` group of the declaration, at p: the position
-- after it, or p when it is absent. The value is a Lua pattern for what is inside the
-- quotes. Taking a group that matches never blocks a later match (each group starts
-- with a different keyword), so this agrees with xml.ts's regular expression.
local function declaration_group(s, p, name, value)
  local head = "^" .. S .. "+" .. name .. S .. "*=" .. S .. "*"
  local _, e = find(s, head .. '"' .. value .. '"', p)
  if not e then
    _, e = find(s, head .. "'" .. value .. "'", p)
  end
  return e and e + 1 or p
end

-- xml.ts declarationPattern: version 1.0, then optional encoding, then optional
-- standalone, in that order.
local function valid_declaration(s)
  local _, e = find(s, "^xml" .. S .. "+version" .. S .. "*=" .. S .. "*[\"']1%.0[\"']")
  if not e or byte(s, e) ~= byte(s, e - 4) then -- the quotes must match
    return false
  end
  local p = e + 1
  p = declaration_group(s, p, "encoding", "[A-Za-z][A-Za-z0-9._%-]*")
  local q = declaration_group(s, p, "standalone", "yes")
  if q == p then
    q = declaration_group(s, p, "standalone", "no")
  end
  return find(s, "^" .. S .. "*$", q) ~= nil
end

---------------------------------------------------------------------------------------
-- the scanner
---------------------------------------------------------------------------------------

-- A limit option (a number: xml.decode checked the type): default when absent, nil when
-- it is not a safe integer >= min (xml.ts fails the parse then).
local function check_limit(value, default, min)
  if value == nil then
    return default
  end
  if value ~= value or value < min or value > MAX_SAFE_INTEGER or floor(value) ~= value then
    return nil
  end
  return value
end

local OPTIONS = { max_depth = true, max_length = true }

local function scan(text, options)
  local n = #text
  local pos = 1
  if sub(text, 1, 3) == BOM then
    pos = 4
  end
  local start = pos
  local max_depth = check_limit(options.max_depth, xml.MAX_DEPTH, 1)
  local max_length = check_limit(options.max_length, xml.MAX_LENGTH, 0)
  local stack, depth = {}, 0
  local document = {}
  local has_root = false

  if not max_depth then
    fail("Invalid max_depth", pos)
  end
  if not max_length then
    fail("Invalid max_length", pos)
  end
  if n > max_length then
    fail("XML input length limit exceeded", 1)
  end
  local invalid = first_invalid_character(text)
  if invalid then
    fail("Invalid XML character", invalid)
  end
  if find(text, "^[\t\n\r ]*$", start) then
    return document
  end

  local function skip_space()
    local b = byte(text, pos)
    if b ~= 32 and b ~= 9 and b ~= 10 and b ~= 13 then
      return false
    end
    local _, e = find(text, "^[\t\n\r ]+", pos)
    pos = e + 1
    return true
  end

  local function read_name()
    -- ASCII names (most documents) take one pattern; a name running into a non-ASCII
    -- byte (which may be a name character) takes the full XML 1.0 rules.
    local _, e = find(text, "^[A-Za-z_:][A-Za-z0-9_:.%-]*", pos)
    if e and (byte(text, e + 1) or 0) < 0x80 then
      local name = sub(text, pos, e)
      pos = e + 1
      return name
    end
    local cp, len = code_point_at(text, pos)
    if not cp or not is_name_start(cp) then
      fail("Expected XML name", pos)
    end
    local p = pos + len
    while true do
      cp, len = code_point_at(text, p)
      if not cp or not is_name_char(cp) then
        break
      end
      p = p + len
    end
    local name = sub(text, pos, p - 1)
    pos = p
    return name
  end

  -- Element records: name, object (created on the first attribute or child), text
  -- (first chunk) and parts (from the second chunk on, joined once in finish, so a
  -- container with many children stays linear), children, attributes, cdata.
  local function add_text(element, chunk)
    if chunk == "" then
      return
    end
    local parts = element.parts
    if parts then
      local np = element.np + 1
      parts[np] = chunk
      element.np = np
    elseif element.text then
      element.parts = { element.text, chunk }
      element.np = 2
    else
      element.text = chunk
    end
  end

  -- xml.ts finish(): an element with neither children nor attributes is its text.
  -- Otherwise text goes to "#text" when there is any and it is not layout: always for
  -- an element without children (text plus attributes), and in a container only when
  -- it is not whitespace-only or some of it came from CDATA.
  local function finish(element)
    local value
    local text_value = element.parts and concat(element.parts) or element.text or ""
    if not element.children and not element.attributes then
      value = text_value
    else
      value = element.object
      if
        text_value ~= ""
        and (not element.children or element.cdata or not find(text_value, "^[\t\n\r ]*$"))
      then
        value["#text"] = text_value
      end
    end
    local parent = stack[depth]
    local target = document
    if parent then
      target = parent.object
      if not target then
        target = {}
        parent.object = target
      end
      parent.children = true
    end
    local name = element.name
    local previous = target[name]
    if previous == nil then
      target[name] = value
    elseif type(previous) == "table" and previous[1] ~= nil then
      -- a list: objects only ever have string keys
      previous[#previous + 1] = value
    else
      target[name] = { previous, value }
    end
  end

  while pos <= n do
    local b = byte(text, pos)
    if b ~= 60 then -- text up to the next "<"
      local offset = pos
      local next_lt = find(text, "<", pos, true)
      pos = next_lt or n + 1
      local raw = sub(text, offset, pos - 1)
      local element = stack[depth]
      if not element then
        if not find(raw, "^[\t\n\r ]*$") then
          fail("Text outside root element", offset)
        end
      else
        local cdata_end = find(raw, "]]>", 1, true)
        if cdata_end then
          fail("Unexpected CDATA terminator", offset + cdata_end - 1)
        end
        add_text(element, decode_text(raw, offset, false))
      end
    else
      local b2 = byte(text, pos + 1)
      if b2 == 33 and sub(text, pos, pos + 3) == "<!--" then
        local _, e = find(text, "-->", pos + 4, true)
        if not e then
          fail("Unterminated comment", pos)
        end
        local comment = sub(text, pos + 4, e - 3)
        if find(comment, "--", 1, true) or byte(comment, -1) == 45 then
          fail("Invalid comment", pos)
        end
        pos = e + 1
      elseif b2 == 33 and sub(text, pos, pos + 8) == "<![CDATA[" then
        local element = stack[depth]
        if not element then
          fail("CDATA outside root element", pos)
        end
        local _, e = find(text, "]]>", pos + 9, true)
        if not e then
          fail("Unterminated CDATA", pos)
        end
        add_text(element, (gsub(sub(text, pos + 9, e - 3), "\r\n?", "\n")))
        element.cdata = true
        pos = e + 1
      elseif b2 == 63 then -- "<?": a processing instruction or the declaration
        local offset = pos
        pos = pos + 2
        local target = read_name()
        if sub(text, pos, pos + 1) ~= "?>" and not skip_space() then
          fail("Expected PI whitespace", pos)
        end
        local stop = find(text, "?>", pos, true)
        if not stop then
          fail("Unterminated processing instruction", offset)
        end
        if lower(target) == "xml" then
          if offset ~= start or not valid_declaration(sub(text, offset + 2, stop - 1)) then
            fail("Invalid or misplaced XML declaration", offset)
          end
        end
        pos = stop + 2
      elseif b2 == 33 then
        fail("DTDs and markup declarations are not supported", pos)
      elseif b2 == 47 then -- "</"
        pos = pos + 2
        local name = read_name()
        skip_space()
        if byte(text, pos) ~= 62 then
          fail("Expected closing tag terminator", pos)
        end
        local element = stack[depth]
        if not element or element.name ~= name then
          fail("Mismatched closing tag", pos)
        end
        stack[depth] = nil
        depth = depth - 1
        pos = pos + 1
        finish(element)
      else -- a start tag
        if depth >= max_depth then
          fail("XML depth limit exceeded", pos)
        end
        if depth == 0 then
          if has_root then
            fail("Multiple root elements", pos)
          end
          has_root = true
        end
        pos = pos + 1
        local element = { name = read_name(), children = false, attributes = false, cdata = false }
        while true do
          local spaced = skip_space()
          local c = byte(text, pos)
          if c == 47 and byte(text, pos + 1) == 62 then -- "/>"
            pos = pos + 2
            finish(element)
            break
          end
          if c == 62 then -- ">"
            pos = pos + 1
            depth = depth + 1
            stack[depth] = element
            break
          end
          if not spaced then
            fail("Expected whitespace or tag terminator", pos)
          end
          local key = "@_" .. read_name()
          local object = element.object
          if not object then
            object = {}
            element.object = object
          elseif object[key] ~= nil then
            fail("Duplicate attribute", pos)
          end
          skip_space()
          -- xml.ts reads xml[pos++], so these two report the position after the byte
          pos = pos + 1
          if byte(text, pos - 1) ~= 61 then -- "="
            fail("Expected attribute equals sign", pos)
          end
          skip_space()
          local quote = byte(text, pos)
          pos = pos + 1
          if quote ~= 34 and quote ~= 39 then
            fail("Expected quoted attribute", pos)
          end
          local stop = find(text, quote == 34 and '"' or "'", pos, true)
          if not stop then
            fail("Unterminated attribute", pos)
          end
          local raw = sub(text, pos, stop - 1)
          if find(raw, "<", 1, true) then
            fail("Unescaped '<' in attribute", pos)
          end
          object[key] = decode_text(raw, pos, true)
          element.attributes = true
          pos = stop + 1
        end
      end
    end
  end
  if depth > 0 then
    fail("Unclosed element", pos)
  end
  if not has_root then
    fail("Missing root element", pos)
  end
  return document
end

---------------------------------------------------------------------------------------
-- public API
---------------------------------------------------------------------------------------

--- xml.decode(text, options?) -> tree | nil, err
-- Distilled's parseXmlSync / parseXml. options: { max_depth = 256, max_length =
-- 64 MiB (bytes) }. A malformed document or an exceeded limit is a ParseError with
-- err.offset (0-based byte), err.position (1-based byte), err.line and err.column;
-- the message is Distilled's ("Unclosed element at 1:4"). Never raises for input;
-- raises (level 2) only when text is not a string or an option has the wrong type.
function xml.decode(text, options)
  if type(text) ~= "string" then
    compat.raise("xml.decode: text must be a string, got " .. type(text), 2)
  end
  if options ~= nil then
    if type(options) ~= "table" then
      compat.raise("xml.decode: options must be a table", 2)
    end
    for k in pairs(options) do
      if not OPTIONS[k] then
        compat.raise("xml.decode: unknown option " .. tostring(k) .. " (max_depth, max_length)", 2)
      end
    end
    -- type errors in options are misuse: check them outside the protected scan
    for name in pairs(OPTIONS) do
      local v = options[name]
      if v ~= nil and type(v) ~= "number" then
        compat.raise("xml.decode: options." .. name .. " must be a number", 2)
      end
    end
  end
  local ok, result = compat.pcall(scan, text, options or {})
  if ok then
    return result
  end
  if getmetatable(result) == FAIL_MT then
    return nil, parse_error(text, result.message, result.at - 1)
  end
  -- anything else the scanner raised (out of memory, ...) still means this document
  -- could not be parsed (xml.ts parseXml does the same)
  local err = errors.new("ParseError", {
    message = "XML could not be parsed: " .. tostring(result),
  })
  err.offset, err.position, err.line, err.column = 0, 1, 1, 1
  return nil, err
end

local ESCAPES =
  { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&apos;" }

--- xml.escape(s) -> string: Distilled's escapeXml (&, <, >, " and ').
function xml.escape(s)
  if type(s) ~= "string" then
    compat.raise("xml.escape: expected a string, got " .. type(s), 2)
  end
  return (gsub(s, "[&<>\"']", ESCAPES))
end

--- xml.wrap_tag(tag, content, xmlns?) -> "<tag xmlns=\"...\">content</tag>"
-- Distilled's wrapTag: content is inserted as is (escape it first); an absent or empty
-- xmlns adds no attribute.
function xml.wrap_tag(tag, content, xmlns)
  if type(tag) ~= "string" or type(content) ~= "string" then
    compat.raise("xml.wrap_tag: tag and content must be strings", 2)
  end
  if xmlns ~= nil and type(xmlns) ~= "string" then
    compat.raise("xml.wrap_tag: xmlns must be a string", 2)
  end
  local attr = ""
  if xmlns and xmlns ~= "" then
    attr = ' xmlns="' .. xml.escape(xmlns) .. '"'
  end
  return "<" .. tag .. attr .. ">" .. content .. "</" .. tag .. ">"
end

--- xml.is_list(v) -> boolean: true for the list decode makes of repeated children.
-- Element tables only have string keys ("name", "@_attr", "#text"), so a list is the
-- only decoded table with a [1].
function xml.is_list(v)
  return type(v) == "table" and v[1] ~= nil
end

return xml
