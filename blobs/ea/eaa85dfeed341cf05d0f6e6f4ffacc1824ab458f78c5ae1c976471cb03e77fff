-- Entire's error envelope (packages/entire/src/protocol.ts errorEnvelope).
local compat = require("distilled.compat")
local json = require("distilled.json")

local function text(v)
  if type(v) == "string" and v ~= "" then
    return v
  end
  return nil
end

local glue = {}

function glue.error_envelope(body)
  if type(body) ~= "table" or body == json.null then
    return nil
  end
  local parts = {}
  local head = text(rawget(body, "detail"))
    or text(rawget(body, "error"))
    or text(rawget(body, "title"))
  if head then
    parts[#parts + 1] = head
  end
  local list = rawget(body, "errors")
  if type(list) == "table" and json.is_array(list) then
    for _, e in ipairs(list) do
      if type(e) == "table" and e ~= json.null then
        local message = text(rawget(e, "message"))
        local location = text(rawget(e, "location"))
        if message then
          parts[#parts + 1] = location and (location .. ": " .. message) or message
        end
      end
    end
  end
  local message = #parts > 0 and compat.concat(parts, "; ") or nil
  return { code = text(rawget(body, "code")) or text(rawget(body, "title")), message = message }
end

return glue
