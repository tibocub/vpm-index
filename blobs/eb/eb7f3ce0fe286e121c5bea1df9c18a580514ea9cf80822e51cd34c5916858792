-- Supabase's failure reading (packages/supabase/src/protocol.ts decode).
local errors = require("distilled.errors")

-- errors.ts FreeProjectLimitReached: a long-lived class, defined once with the module
local FreeProjectLimitReached =
  errors.define({ tag = "FreeProjectLimitReached", categories = { "QuotaError" } })

local glue = {}

function glue.classify_error(info)
  local message = type(info.message) == "string" and info.message or ""
  if string.find(message, "active free projects", 1, true) then
    return errors.new(
      FreeProjectLimitReached,
      { message = message, status = info.status, body = info.body }
    )
  end
  if info.status == 406 then
    return errors.new("NotFound", {
      message = info.message,
      status = info.status,
      body = info.body,
      headers = info.headers,
    })
  end
  return nil
end

return glue
