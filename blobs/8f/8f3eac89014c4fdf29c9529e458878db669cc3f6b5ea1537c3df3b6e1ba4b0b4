-- Iceberg's per-route base URL (packages/iceberg/src/protocol.ts baseUrlFor).
local errors = require("distilled.errors")

local UNPREFIXED_ROUTES = { ["/config"] = true }

local glue = {}

function glue.base_url(s, route)
  if type(s.uri) ~= "string" or s.uri == "" then
    return nil,
      errors.new("ConfigError", {
        message = "Iceberg: option uri is required: pass uri = ... or set ICEBERG_CATALOG_URI",
        key = "uri",
      })
  end
  local root = string.gsub(s.uri, "/+$", "") .. "/v1"
  local prefix = type(s.prefix) == "string" and s.prefix or ""
  prefix = string.gsub(string.gsub(prefix, "^/+", ""), "/+$", "")
  if UNPREFIXED_ROUTES[route and route.uri or ""] or prefix == "" then
    return root
  end
  return root .. "/" .. prefix
end

return glue
