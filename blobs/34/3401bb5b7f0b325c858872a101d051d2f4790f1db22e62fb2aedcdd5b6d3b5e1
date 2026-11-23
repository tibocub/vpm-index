-- Chronosphere's base URL (packages/chronosphere/src/credentials.ts originFrom).
local glue = {}

function glue.settings(s)
  local v = s.base_url
  if type(v) == "string" then
    v = string.gsub(v, "/+$", "")
    local lower = string.lower(v)
    if not (string.find(lower, "^https?://")) then
      if string.find(v, ".", 1, true) then
        v = "https://" .. v
      else
        v = "https://" .. v .. ".chronosphere.io"
      end
    end
    s.base_url = v
  end
  return s
end

return glue
