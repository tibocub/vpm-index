-- Daytona's per-route base URL (packages/daytona/src/protocol.ts baseUrlFor,
-- endpoints.ts TOOLBOX_ROOTS and ANALYTICS_PREFIX).
local compat = require("distilled.compat")
local errors = require("distilled.errors")

local DEFAULT_API_BASE_URL = "https://app.daytona.io/api"
local TOOLBOX_ROOTS = {
  computeruse = true,
  env = true,
  files = true,
  git = true,
  init = true,
  lsp = true,
  port = true,
  process = true,
  system = true,
  ["user-home-dir"] = true,
  version = true,
  ["work-dir"] = true,
}

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

local glue = {}

function glue.base_url(s, route)
  local uri = route and route.uri or ""
  if uri == "/organization" or string.sub(uri, 1, 14) == "/organization/" then
    return s.analytics_base_url
  end
  local first = string.match(uri, "^/*([^/]+)") or ""
  if not TOOLBOX_ROOTS[first] then
    return s.base_url or DEFAULT_API_BASE_URL
  end
  local toolbox = s.toolbox_base_url
  if not string.find(toolbox, "{sandboxId}", 1, true) then
    return toolbox
  end
  if s.sandbox_id == nil or s.sandbox_id == "" then
    return nil,
      errors.new("ConfigError", {
        message = "Daytona toolbox calls are sandbox-scoped ("
          .. toolbox
          .. "): configure a sandbox (DAYTONA_SANDBOX_ID or sandbox_id = ...) to call them",
        key = "sandbox_id",
      })
  end
  return replace_all(toolbox, "{sandboxId}", s.sandbox_id)
end

return glue
