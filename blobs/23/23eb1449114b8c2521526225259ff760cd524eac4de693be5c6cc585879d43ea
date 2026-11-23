-- Fly.io's host normalization (packages/fly-io/src/credentials.ts normalizeApiBaseUrl).
local glue = {}

function glue.settings(s)
  if type(s.base_url) == "string" then
    local v = string.gsub(string.gsub(s.base_url, "^%s+", ""), "%s+$", "")
    v = string.gsub(v, "/+$", "")
    if v == "" then
      s.base_url = nil
    elseif string.sub(v, -3) == "/v1" then
      s.base_url = string.sub(v, 1, -4)
    else
      s.base_url = v
    end
  end
  return s
end

return glue
