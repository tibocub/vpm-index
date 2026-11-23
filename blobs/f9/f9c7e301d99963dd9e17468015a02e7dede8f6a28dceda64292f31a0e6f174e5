-- 1Password Connect's host (packages/onepassword/src/credentials.ts
-- connectHostToBaseUrl): used when no base URL is given.
local glue = {}

function glue.settings(s)
  if (s.base_url == nil or s.base_url == "") and type(s.connect_host) == "string" then
    local v = string.gsub(s.connect_host, "/+$", "")
    if string.lower(string.sub(v, -3)) ~= "/v1" then
      v = v .. "/v1"
    end
    s.base_url = v
  end
  return s
end

return glue
