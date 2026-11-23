-- Azure Resource Manager errors: a port of Distilled's packages/azure/src/errors.ts and
-- the error-body parsing of its protocol.ts.
--
-- The data (180 classes, AZURE_ERROR_CODE_MAP, AZURE_ERROR_MESSAGE_MATCHERS) is in
-- errors_data.lua, written from the loaded TS module by verify/lib/azure_errors_port.mjs;
-- this module turns it into error classes and holds the matching rules:
--
--   azure_errors.classes[tag]       every Azure class, plus UnknownAzureError and
--                                   AzureParseError (also azure_errors.<Tag>)
--   azure_errors.codes[code]        the class an ARM `error.code` maps to
--   azure_errors.match_message(arm) the first message matcher's class (matchAzureErrorMessage)
--   azure_errors.class_for(arm)     message matchers first, then the code map
--   azure_errors.parse_arm(body)    parseArmError: { code, message, target, details } | nil
local errors = require("distilled.errors")
local json = require("distilled.json")
local data = require("distilled.azure.errors_data")

local azure_errors = {}

azure_errors.classes = {}
azure_errors.codes = {}
azure_errors.matchers = {}

for _, c in ipairs(data.classes) do
  local class = errors.define({
    tag = c.tag,
    categories = c.categories,
    retryable = c.retryable == true,
    throttling = c.throttling == true,
    -- AzureErrorFields: message, code, target (message and code are instance fields)
    fields = c.target and { "target" } or nil,
  })
  azure_errors.classes[c.tag] = class
  azure_errors[c.tag] = class
end

-- UnknownAzureError: UnknownErrorFields plus `target`; never retryable.
azure_errors.UnknownAzureError = errors.define({ tag = "UnknownAzureError", fields = { "target" } })
azure_errors.classes.UnknownAzureError = azure_errors.UnknownAzureError
-- AzureParseError: body and cause, category ParseError.
azure_errors.AzureParseError = errors.define({
  tag = "AzureParseError",
  categories = { "ParseError" },
  fields = { "body", "cause" },
})
azure_errors.classes.AzureParseError = azure_errors.AzureParseError

for code, tag in pairs(data.codes) do
  azure_errors.codes[code] = azure_errors.classes[tag]
end
for i, m in ipairs(data.matchers) do
  azure_errors.matchers[i] =
    { code = m.code, includes = m.includes, class = azure_errors.classes[m.tag] }
end

--- azure_errors.match_message(arm) -> class | nil
-- matchAzureErrorMessage: the first matcher whose code (when it has one) equals the ARM
-- code and whose text the message contains (plain substring, as String.includes).
function azure_errors.match_message(arm)
  local message = arm and arm.message
  if type(message) ~= "string" then
    return nil
  end
  for _, m in ipairs(azure_errors.matchers) do
    if (m.code == nil or m.code == arm.code) and string.find(message, m.includes, 1, true) then
      return m.class
    end
  end
  return nil
end

--- azure_errors.class_for(arm) -> class | nil: message matchers win over the code map
function azure_errors.class_for(arm)
  if arm == nil then
    return nil
  end
  local class = azure_errors.match_message(arm)
  if class == nil and arm.code ~= nil then
    class = azure_errors.codes[arm.code]
  end
  return class
end

-- `x !== null && typeof x === "object"` (objects and arrays; decoded objects are plain
-- tables, decoded arrays are json.array tables)
local function is_object(v)
  return type(v) == "table" and v ~= json.null
end

local function text(v)
  return type(v) == "string" and v or nil
end

--- azure_errors.parse_arm(body) -> { code, message, target, details } | nil
-- parseArmError: the `{ error: { code, message, target } }` envelope first, the flat
-- `{ code, message }` shape as a fallback; PascalCase `Code`/`Message` (Microsoft.Web and
-- other legacy RPs) when the camelCase key is absent; a bare JSON string (some RPs,
-- e.g. Microsoft.GuestConfiguration) is the message. `details` keeps the code and
-- message of each object entry of `error.details[]`.
function azure_errors.parse_arm(body)
  if type(body) == "string" then
    if body == "" then
      return nil
    end
    return { message = body }
  end
  if not is_object(body) then
    return nil
  end
  local inner = body
  if is_object(body.error) then
    inner = body.error
  end
  local function field(name)
    local v = inner[name]
    if v == nil or v == json.null then
      -- `??`: only a missing (or null) camelCase key falls back to the PascalCase one
      v = inner[string.upper(string.sub(name, 1, 1)) .. string.sub(name, 2)]
    end
    return text(v)
  end
  local code, message, target = field("code"), field("message"), field("target")
  if code == nil and message == nil then
    return nil
  end
  local details
  if json.is_array(inner.details) then
    details = {}
    for _, d in ipairs(inner.details) do
      if is_object(d) then
        details[#details + 1] = { code = text(d.code), message = text(d.message) }
      end
    end
  end
  return { code = code, message = message, target = target, details = details }
end

return azure_errors
