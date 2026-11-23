-- Celld's error envelope (packages/celld/src/protocol.ts errorEnvelope).
local rest = require("distilled.protocol.rest")

local glue = {}

function glue.error_envelope(body)
  if type(body) == "table" and body.ok == false and type(body.error) == "table" then
    local kind, reason = body.error.kind, body.error.reason
    if type(kind) == "string" and type(reason) == "string" then
      return { message = kind .. ": " .. reason }
    end
  end
  return rest.default_error_envelope(body)
end

return glue
