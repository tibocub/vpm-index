-- The Google Workspace protocol: distilled.gcp.protocol in the shape of Distilled's
-- packages/google-workspace/src/protocol.ts (GoogleWorkspaceProtocol). The same request
-- and response rules, without what is GCP's own: no X-Goog-User-Project header, no
-- endpoint override, no regional endpoints; credentials are the client's `credentials`
-- provider, its `access_token`, or GOOGLE_ACCESS_TOKEN (ConfigError without one: no
-- Application Default Credentials, as google-workspace/src/credentials.ts).
--
--   local protocol = require("distilled.gcp.workspace")(service, {
--     unknown_tag = "UnknownGoogleWorkspaceError", parse_tag = "GoogleWorkspaceParseError",
--     base_url = "https://gmail.googleapis.com",
--   })
local gcp_protocol = require("distilled.gcp.protocol")

local workspace = {}

--- workspace.new(service, opts) -> protocol
function workspace.new(service, opts)
  local o = {}
  for k, v in pairs(opts or {}) do
    o[k] = v
  end
  o.workspace = true
  return gcp_protocol.new(service, o)
end

return setmetatable(workspace, {
  __call = function(_, service, opts)
    return workspace.new(service, opts)
  end,
})
