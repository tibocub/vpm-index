-- S2's per-route base URL (packages/s2/src/protocol.ts baseUrlFor).
local errors = require("distilled.errors")

local DEFAULT_ACCOUNT_BASE_URL = "https://a.s2.dev/v1"

local function is_basin_scoped(uri)
  return uri == "/streams" or string.sub(uri, 1, 9) == "/streams/"
end

local glue = {}

function glue.base_url(s, route)
  local uri = route and route.uri or ""
  if not is_basin_scoped(uri) then
    return s.account_endpoint or DEFAULT_ACCOUNT_BASE_URL
  end
  if s.basin == nil or s.basin == "" then
    return nil,
      errors.new("ConfigError", {
        message = "S2 operation on "
          .. uri
          .. " is basin-scoped ("
          .. tostring(s.basin_endpoint)
          .. "): configure a basin (S2_BASIN or basin = ...) to call it",
        key = "basin",
      })
  end
  -- a plain replacement: the basin is text, not a pattern
  local endpoint = s.basin_endpoint
  local i, j = string.find(endpoint, "{basin}", 1, true)
  if i then
    endpoint = string.sub(endpoint, 1, i - 1) .. s.basin .. string.sub(endpoint, j + 1)
  end
  return endpoint
end

return glue
