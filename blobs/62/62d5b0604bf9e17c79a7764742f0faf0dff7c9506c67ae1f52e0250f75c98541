-- Newline-delimited JSON (application/x-ndjson) framing: port of core/src/ndjson.ts.
-- Each non-empty line is one frame (the line's text); the protocol parses it as JSON
-- and decodes it as one item. `collect` is the plain call's reading of the whole body.
local json = require("distilled.json")

local M = {}

M.CONTENT_TYPE = "application/x-ndjson"

local function non_empty(line)
  return string.find(line, "%S") ~= nil
end

--- ndjson.frames(reader) -> frames: frames:next() -> line | nil, nil | nil, err
function M.frames(reader)
  local frames = {}
  function frames.next()
    while true do
      local line, err = reader:read_line()
      if line == nil then
        return nil, err
      end
      if non_empty(line) then
        return line
      end
    end
  end
  return frames
end

--- ndjson.is_content_type(value) -> boolean (ndjson.ts: the media type, parameters cut)
function M.is_content_type(value)
  if type(value) ~= "string" then
    return false
  end
  local media = string.lower((string.gsub(string.match(value, "^[^;]*"), "^%s*(.-)%s*$", "%1")))
  return media == M.CONTENT_TYPE
end

--- ndjson.collect(text, content_type) -> { json = { items = {...} } } | { non_json = true }
-- | nil when the content type is not NDJSON (the body is then decoded as usual)
function M.collect(text, content_type)
  if not M.is_content_type(content_type) then
    return nil
  end
  local items = json.array({})
  for raw in string.gmatch(text, "[^\n]+") do
    local line = string.gsub(raw, "\r$", "")
    if non_empty(line) then
      local v = json.decode(line)
      if v == nil then
        return { non_json = true }
      end
      items[#items + 1] = v
    end
  end
  return { json = json.object({ items = items }) }
end

return M
