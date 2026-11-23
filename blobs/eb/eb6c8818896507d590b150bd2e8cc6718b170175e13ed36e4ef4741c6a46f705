-- multipart/form-data (RFC 7578) bodies, as a string. request.build uses it for operations
-- with `content_type = "multipart"` (Distilled: the multipart branch of `buildRequest` in
-- protocol-http.ts, which hands a `FormData` to the platform's encoder, undici in Node).
--
--   multipart.file{ data = "<bytes>", filename = "a.zip", content_type = "application/zip" }
--     -> a file value (Lua has no File/Blob). filename and content_type are optional.
--   multipart.is_file(v) -> boolean
--   multipart.encode(parts, { random = fn }) -> { body, content_type, boundary } | nil, err
--     parts: list of { name = string, value = string, filename = string | nil,
--                      content_type = string | nil }. A part with a filename is a file
--     part (Content-Type defaults to application/octet-stream); without, a text part.
--
-- What is copied from undici's FormData serializer, so the bytes match what Distilled
-- sends (checked against Node 24: `new Request(url, { body: formData })`):
-- - names: line breaks normalized to CRLF, then `"`, CR, LF escaped as %22, %0D, %0A;
-- - filenames: `"`, CR, LF escaped as %22, %0D, %0A (no normalization first);
-- - text values: line breaks (`\r\n`, lone `\r`, lone `\n`) normalized to CRLF;
-- - file data: sent byte for byte (NUL, CRLF, anything);
-- - a file's content type is lowercased (Blob does that); a file part always carries one.
-- The boundary is ours: `----distilled-lua-` and 24 characters from `random`, picked
-- again (up to 16 times) while it occurs anywhere in the parts.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local secret = require("distilled.secret")

local multipart = {}

-- the metatable marks file values; secret.unwrap_deep keeps metatables, so a copy of the
-- input still holds files
local FILE_MT = {
  __distilled_file = true,
  __tostring = function(f)
    local size = type(f.data) == "string" and #f.data or 0
    return "distilled.file(" .. tostring(f.filename or "?") .. ", " .. size .. " bytes)"
  end,
}

local function misuse(message)
  compat.raise("distilled.file: " .. message, 3)
end

--- multipart.file{ data, filename, content_type } -> file value
-- data is a string of bytes (or a secret holding one: it is unwrapped in request.build).
function multipart.file(spec)
  if type(spec) ~= "table" then
    misuse("expected a table { data = <bytes>, filename?, content_type? }")
  end
  local data = spec.data
  if type(data) ~= "string" and not secret.is(data) then
    misuse("data must be a string of bytes, got " .. type(data))
  end
  if spec.filename ~= nil and type(spec.filename) ~= "string" then
    misuse("filename must be a string")
  end
  local ct = spec.content_type
  if ct ~= nil then
    -- Blob drops a type with bytes outside 0x20-0x7E; here that is a mistake worth
    -- reporting, and it keeps CR/LF out of the part's headers
    if type(ct) ~= "string" or string.find(ct, "[^\32-\126]") then
      misuse("content_type must be a string of printable ASCII")
    end
    ct = string.lower(ct)
  end
  for k in pairs(spec) do
    if k ~= "data" and k ~= "filename" and k ~= "content_type" then
      misuse("unknown field " .. tostring(k) .. " (allowed: content_type, data, filename)")
    end
  end
  return setmetatable({ data = data, filename = spec.filename, content_type = ct }, FILE_MT)
end

--- multipart.is_file(v) -> boolean
function multipart.is_file(v)
  local mt = type(v) == "table" and getmetatable(v)
  return type(mt) == "table" and rawget(mt, "__distilled_file") == true
end

local function normalize_linefeeds(s)
  -- \r\n, lone \r and lone \n all become \r\n (undici's normalizeLinefeeds)
  s = string.gsub(s, "\r\n", "\n")
  s = string.gsub(s, "\r", "\n")
  return (string.gsub(s, "\n", "\r\n"))
end

local ESCAPES = { ['"'] = "%22", ["\r"] = "%0D", ["\n"] = "%0A" }

local function escape(s)
  return (string.gsub(s, '["\r\n]', ESCAPES))
end

--- multipart.escape_name(name) -> the name as it goes in `name="..."`
function multipart.escape_name(name)
  return escape(normalize_linefeeds(name))
end

--- multipart.escape_filename(filename) -> the filename as it goes in `filename="..."`
function multipart.escape_filename(filename)
  return escape(filename)
end

multipart.normalize_linefeeds = normalize_linefeeds

local ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
multipart.BOUNDARY_PREFIX = "----distilled-lua-"
multipart.MAX_BOUNDARY_TRIES = 16

--- multipart.boundary(random) -> a boundary string from random() in [0, 1)
function multipart.boundary(random)
  local chars = {}
  for i = 1, 24 do
    local r = random()
    local k = math.floor((tonumber(r) or 0) * 62) % 62 + 1
    chars[i] = string.sub(ALPHABET, k, k)
  end
  return multipart.BOUNDARY_PREFIX .. compat.concat(chars, "")
end

local default_random
local function fallback_random()
  if default_random == nil then
    -- distilled.host's private generator (seeded from the clock and an address); used
    -- only when the caller has no host
    default_random = require("distilled.host").default().random
  end
  return default_random
end

local function invalid(message)
  return errors.new("InvalidInput", { message = message })
end

--- multipart.encode(parts, opts) -> { body, content_type, boundary } | nil, err
function multipart.encode(parts, opts)
  if type(parts) ~= "table" then
    compat.raise("multipart.encode: parts must be a list", 2)
  end
  opts = opts or {}
  local random = opts.random or fallback_random()

  -- each part as { head, data }: head ends with the blank line, data is the content
  local rendered = {}
  for i, p in ipairs(parts) do
    if type(p.name) ~= "string" then
      return nil, invalid("multipart part " .. i .. ": the name must be a string")
    end
    if type(p.value) ~= "string" then
      return nil, invalid("multipart part " .. p.name .. ": the value must be a string of bytes")
    end
    local head, data
    if p.filename ~= nil then
      local ct = p.content_type or "application/octet-stream"
      if string.find(ct, "[^\32-\126]") then
        return nil, invalid("multipart part " .. p.name .. ": the content type holds a line break")
      end
      head = 'Content-Disposition: form-data; name="'
        .. multipart.escape_name(p.name)
        .. '"; filename="'
        .. multipart.escape_filename(p.filename)
        .. '"\r\nContent-Type: '
        .. ct
        .. "\r\n\r\n"
      data = p.value
    else
      head = 'Content-Disposition: form-data; name="'
        .. multipart.escape_name(p.name)
        .. '"\r\n\r\n'
      data = normalize_linefeeds(p.value)
    end
    rendered[i] = { head, data }
  end

  -- a boundary that occurs nowhere in the parts (RFC 2046 5.1.1: it must not appear in
  -- the encapsulated data); heads cannot hold one unless a name does, so check both
  local boundary
  for _ = 1, multipart.MAX_BOUNDARY_TRIES do
    local candidate = multipart.boundary(random)
    local clash = false
    for _, r in ipairs(rendered) do
      if string.find(r[2], candidate, 1, true) or string.find(r[1], candidate, 1, true) then
        clash = true
        break
      end
    end
    if not clash then
      boundary = candidate
      break
    end
  end
  if boundary == nil then
    return nil,
      errors.new("SdkError", {
        message = "multipart: no boundary absent from the data after "
          .. multipart.MAX_BOUNDARY_TRIES
          .. " tries (is host.random constant?)",
      })
  end

  local delimiter = "--" .. boundary .. "\r\n"
  local chunks, n = {}, 0
  for _, r in ipairs(rendered) do
    chunks[n + 1] = delimiter
    chunks[n + 2] = r[1]
    chunks[n + 3] = r[2]
    chunks[n + 4] = "\r\n"
    n = n + 4
  end
  chunks[n + 1] = "--" .. boundary .. "--\r\n"
  return {
    body = compat.concat(chunks, ""),
    content_type = "multipart/form-data; boundary=" .. boundary,
    boundary = boundary,
  }
end

return multipart
