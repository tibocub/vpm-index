-- STACKIT's per-operation base URL (packages/stackit/src/protocol.ts baseUrlFor and
-- applyRegion). route.base_url is the operation's http-trait baseUrl (task 12).
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local function replace_all(text, find, by)
  local out, start = {}, 1
  while true do
    local i, j = string.find(text, find, start, true)
    if not i then
      break
    end
    out[#out + 1] = string.sub(text, start, i - 1) .. by
    start = j + 1
  end
  out[#out + 1] = string.sub(text, start)
  return compat.concat(out, "")
end

local function apply_region(spec_url, region)
  if string.find(spec_url, "{region}", 1, true) then
    if region == "global" then
      return replace_all(spec_url, "{region}", "")
    end
    local glued = string.find(spec_url, "{region}stackit", 1, true) ~= nil
    local value = (glued and string.sub(region, -1) ~= ".") and (region .. ".") or region
    return replace_all(spec_url, "{region}", value)
  end
  if region == "global" then
    return spec_url
  end
  local lower = string.lower(spec_url)
  local host = string.match(lower, "^(https://[a-z0-9-]+)%.api%.stackit%.cloud")
  if host then
    local after = string.sub(spec_url, #host + #".api.stackit.cloud" + 1)
    if after == "" or string.find(after, "^[:/?]") then
      return string.sub(spec_url, 1, #host) .. ".api." .. region .. ".stackit.cloud" .. after
    end
  end
  return spec_url
end

local glue = {}

function glue.base_url(s, route)
  if type(s.base_url) == "string" and s.base_url ~= "" then
    return s.base_url
  end
  local server = route and route.base_url
  if type(server) ~= "string" or server == "" then
    return nil,
      errors.new("ConfigError", {
        message = "STACKIT operation has no server base URL: pass base_url = ... or set STACKIT_API_BASE_URL",
        key = "base_url",
      })
  end
  return apply_region(server, s.region)
end

return glue
