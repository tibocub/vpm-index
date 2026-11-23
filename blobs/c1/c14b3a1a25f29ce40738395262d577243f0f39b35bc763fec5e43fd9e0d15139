-- GCP's own error class: resolving credentials failed (Distilled's GCPCredentialsError,
-- packages/gcp/src/errors.ts). UnknownGCPError and GCPParseError are the protocol's
-- unknown and parse classes (distilled.gcp.protocol builds them from the generated tags).
--
--   err.tag == "GCPCredentialsError", err.message, err.status (the token endpoint's HTTP
--   status, when one answered), err.cause; category AuthError, never retried.
--
-- Messages never carry a token, a key or a refresh token.
local errors = require("distilled.errors")

local gcp_errors = {}

gcp_errors.GCPCredentialsError = errors.define({
  tag = "GCPCredentialsError",
  categories = { "AuthError" },
  fields = { "cause" },
})

--- gcp_errors.credentials(message [, status [, cause]]) -> GCPCredentialsError
function gcp_errors.credentials(message, status, cause)
  return errors.new(gcp_errors.GCPCredentialsError, {
    message = message,
    status = status,
    cause = cause,
  })
end

return gcp_errors
