-- Technitium's answer envelope (packages/technitium/src/protocol.ts readEnvelope).
local errors = require("distilled.errors")
local json = require("distilled.json")

local ENVELOPE = {
  status = true,
  server = true,
  errorMessage = true,
  stackTrace = true,
  innerErrorMessage = true,
}
local ACCESS_DENIED = "Access was denied."

-- errors.ts; UnknownTechnitiumError has the tag of the protocol's unknown error
local TechnitiumError = errors.define({
  tag = "TechnitiumError",
  categories = { "BadRequestError" },
  fields = { "innerMessage" },
})
local TwoFactorAuthRequired =
  errors.define({ tag = "TwoFactorAuthRequired", categories = { "AuthError" } })
local UnknownTechnitiumError = errors.define({ tag = "UnknownTechnitiumError" })

local function is_object(v)
  return type(v) == "table" and v ~= json.null and not json.is_array(v)
end

local function text(v)
  return type(v) == "string" and v or nil
end

local glue = {}

function glue.classify_success(info)
  local body = info.body
  if not is_object(body) then
    return errors.new(UnknownTechnitiumError, {
      message = "Response is not a JSON object",
      status = info.status,
      body = body,
    })
  end
  local status = rawget(body, "status")
  local message = text(rawget(body, "errorMessage")) or ""
  if status == "ok" then
    return nil
  elseif status == "error" then
    if message == ACCESS_DENIED then
      return errors.new("Forbidden", { message = message, status = info.status })
    end
    return errors.new(TechnitiumError, {
      message = message,
      status = info.status,
      innerMessage = text(rawget(body, "innerErrorMessage")),
    })
  elseif status == "invalid-token" then
    return errors.new("Unauthorized", { message = message, status = info.status })
  elseif status == "2fa-required" then
    return errors.new(TwoFactorAuthRequired, { message = message, status = info.status })
  end
  return errors.new(UnknownTechnitiumError, {
    message = "Unknown status " .. (status == nil and "undefined" or json.encode(status)),
    status = info.status,
    body = body,
  })
end

function glue.transform_response(body)
  if not is_object(body) or rawget(body, "status") ~= "ok" then
    return body
  end
  local response = rawget(body, "response")
  if response ~= nil then
    return response
  end
  local payload = {}
  for k, v in pairs(body) do
    if not ENVELOPE[k] then
      payload[k] = v
    end
  end
  return setmetatable(payload, getmetatable(body))
end

return glue
