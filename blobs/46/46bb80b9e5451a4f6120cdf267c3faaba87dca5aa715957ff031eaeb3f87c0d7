-- ZeroSSL's in-band failures and numeric success flag (packages/zerossl/src/protocol.ts).
local json = require("distilled.json")

local function is_object(v)
  return type(v) == "table" and v ~= json.null and not json.is_array(v)
end

local glue = {}

-- success false or 0 in a 2xx answer: read it as a failure (envelope, matchers, ...)
function glue.classify_success(info)
  local body = info.body
  if is_object(body) then
    local ok = rawget(body, "success")
    if ok == false or ok == 0 then
      return true
    end
  end
  return nil
end

function glue.transform_response(body)
  if is_object(body) then
    local ok = rawget(body, "success")
    if ok == 1 or ok == 0 then
      local copy = {}
      for k, v in pairs(body) do
        copy[k] = v
      end
      copy.success = ok == 1
      return setmetatable(copy, getmetatable(body))
    end
  end
  return body
end

return glue
