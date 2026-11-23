-- Inngest's per-route base URL (packages/inngest/src/protocol.ts): routes under /v1/
-- use the origin of the (v2) base URL.
local DEFAULT_API_BASE_URL = "https://api.inngest.com/v2"

local glue = {}

function glue.base_url(s, route)
  local base = s.base_url or DEFAULT_API_BASE_URL
  local uri = route and route.uri or ""
  if string.sub(uri, 1, 4) == "/v1/" then
    local origin = string.match(base, "^([%a][%w+.-]*://[^/?#]+)")
    return origin or base
  end
  return base
end

return glue
