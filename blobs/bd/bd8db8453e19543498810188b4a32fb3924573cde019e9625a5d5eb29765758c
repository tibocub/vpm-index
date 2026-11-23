-- How a GCP request picks a regional endpoint (Distilled's packages/gcp/src/region.ts).
--
-- GCP regions differ from AWS regions: most APIs are served from one global host, and a
-- resource's location is part of its name (projects/p/locations/us-east1/...). Hosts are
-- chosen per request by the client's `regional_endpoints` option:
--
-- - "required" (default): the regional host of the location in the resource name, only
--   where the global host rejects regional resources (Vertex AI, Secret Manager,
--   Parameter Manager).
-- - "prefer": every request whose resource name has a location goes to that location's
--   regional host whenever Google publishes one (data residency: TLS ends in the region).
-- - "never": always the global host.
--
-- There is no default-region environment variable (Google's SDKs have none); a region a
-- credentials provider carries is `config.region` (region.current).
local region = {}

region.MODES = { required = true, prefer = true, never = true }

-- the regional host table, loaded on first use (2,700 lines of data)
local endpoints
local function table_of()
  endpoints = endpoints or require("distilled.gcp.regional_endpoints")
  return endpoints
end

--- Services whose global host rejects regional resources.
region.REQUIRED = {
  ["https://aiplatform.googleapis.com/"] = true,
  ["https://secretmanager.googleapis.com/"] = true,
  ["https://parametermanager.googleapis.com/"] = true,
}

--- region.location_of(uri) -> the location in a path (`.../locations/<loc>/...`) | nil
-- Distilled's LOCATION regex: /(?:^|\/)locations\/([a-z0-9-]+)(?:\/|$)/, first match.
function region.location_of(uri)
  local start = 1
  while true do
    local s, e = string.find(uri, "locations/", start, true)
    if not s then
      return nil
    end
    if s == 1 or string.sub(uri, s - 1, s - 1) == "/" then
      local loc, after = string.match(uri, "^([a-z0-9%-]+)(.?)", e + 1)
      if loc and (after == "" or after == "/") then
        return loc
      end
    end
    start = s + 1
  end
end

--- region.endpoint_for(base_url, uri, mode) -> base URL for one request
-- base_url is the service's global base URL with its trailing "/" and uri the expanded
-- path without a leading "/" (Distilled's forms). The regional host of the location in
-- uri when `mode` calls for it and Google publishes one, else base_url.
function region.endpoint_for(base_url, uri, mode)
  if mode == "never" then
    return base_url
  end
  if mode == "required" and not region.REQUIRED[base_url] then
    return base_url
  end
  local location = region.location_of(uri)
  if location == nil or location == "global" or location == "-" then
    return base_url
  end
  local hosts = table_of()[base_url]
  for _, entry in ipairs(hosts or {}) do
    for _, l in ipairs(entry.locations) do
      if l == location then
        return (string.gsub(entry.template, "{location}", location))
      end
    end
  end
  return base_url
end

--- region.current(config [, override]) -> the default region: override, else the
-- credentials' region (config.region), else nil (Distilled's Region.current).
function region.current(config, override)
  if override ~= nil then
    return override
  end
  return type(config) == "table" and config.region or nil
end

return region
