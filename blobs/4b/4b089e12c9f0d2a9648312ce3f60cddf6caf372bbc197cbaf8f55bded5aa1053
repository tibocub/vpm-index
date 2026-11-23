-- HydraDB's answer envelope (packages/hydradb/src/protocol.ts unwrapData): an object
-- with a boolean `success`, a `data` member and no members but success, data, error and
-- meta is replaced by its data.
local json = require("distilled.json")

local ENVELOPE = { success = true, data = true, error = true, meta = true }

local glue = {}

function glue.transform_response(body)
  if type(body) ~= "table" or body == json.null or json.is_array(body) then
    return body
  end
  if type(rawget(body, "success")) ~= "boolean" or rawget(body, "data") == nil then
    return body
  end
  for k in pairs(body) do
    if not ENVELOPE[k] then
      return body
    end
  end
  return rawget(body, "data")
end

return glue
