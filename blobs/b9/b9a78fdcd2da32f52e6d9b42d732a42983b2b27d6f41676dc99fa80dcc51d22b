-- Namespace's per-route host (packages/namespacelabs/src/protocol.ts hostFor).
local DEFAULT_GLOBAL_BASE_URL = "https://global.namespaceapis.com"

local HOST_BY_PACKAGE_PREFIX = {
  { "namespace.cloud.compute.", "compute" },
  { "namespace.cloud.builder.", "compute" },
  { "namespace.experimental.compute.", "compute" },
  { "namespace.cloud.storage.", "storage" },
  { "namespace.cloud.github.", "private" },
  { "namespace.private.", "private" },
}

local glue = {}

function glue.base_url(s, route)
  local service = string.match(route and route.uri or "", "^/?([^/]*)") or ""
  local host = "global"
  for _, entry in ipairs(HOST_BY_PACKAGE_PREFIX) do
    if string.sub(service, 1, #entry[1]) == entry[1] then
      host = entry[2]
      break
    end
  end
  if host == "compute" then
    return s.compute_base_url or ("https://" .. s.region .. ".compute.namespaceapis.com")
  elseif host == "storage" then
    return s.storage_base_url or ("https://" .. s.region .. ".storage.namespaceapis.com")
  elseif host == "private" then
    return s.private_api_base_url
  end
  return s.global_base_url or DEFAULT_GLOBAL_BASE_URL
end

return glue
