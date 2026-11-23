-- The endpoint override for every GCP request (Distilled's packages/gcp/src/endpoint.ts):
-- emulators (Pub/Sub, Firestore, Storage) and private or proxied hosts. It replaces the
-- scheme and host of the request URL and keeps the service path. Clients take it as the
-- `endpoint` option; GOOGLE_API_ENDPOINT is the default.
local endpoint = {}

endpoint.ENV = "GOOGLE_API_ENDPOINT"

local DEFAULT_PORT = { http = "80", https = "443" }

--- endpoint.parse(text) -> { scheme, host, port, origin, path } | nil
-- An absolute http(s)-style URL (scheme://authority/path), what URL.canParse accepts for
-- an override. The origin is lower-cased and drops a default port, like WHATWG's.
function endpoint.parse(text)
  if type(text) ~= "string" then
    return nil
  end
  local scheme, authority, path = string.match(text, "^(%a[%w+.-]*)://([^/?#]*)([^?#]*)")
  if not scheme or authority == "" then
    return nil
  end
  scheme = string.lower(scheme)
  authority = string.gsub(authority, "^.*@", "")
  local host, port = string.match(authority, "^(.-):(%d*)$")
  if not host then
    host = authority
  end
  if host == "" then
    return nil
  end
  host = string.lower(host)
  if port == "" or port == DEFAULT_PORT[scheme] then
    port = nil
  end
  local origin = scheme .. "://" .. host .. (port and (":" .. port) or "")
  if path == "" then
    path = "/"
  end
  return { scheme = scheme, host = host, port = port, origin = origin, path = path }
end

--- endpoint.with_endpoint(base_url, override) -> url | nil
-- Replace the origin of base_url with override's, keeping base_url's path after the
-- override's own path (trailing slashes dropped): ("https://pubsub.googleapis.com/",
-- "http://localhost:8085") -> "http://localhost:8085/".
function endpoint.with_endpoint(base_url, override)
  local base = endpoint.parse(base_url)
  local target = endpoint.parse(override)
  if not base or not target then
    return nil
  end
  return target.origin .. string.gsub(target.path, "/+$", "") .. base.path
end

return endpoint
