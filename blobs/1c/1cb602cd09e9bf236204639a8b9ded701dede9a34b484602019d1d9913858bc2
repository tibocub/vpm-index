-- Proxmox's endpoint rule (credentials.ts apiRoot), boolean inputs (protocol.ts toWire)
-- and error envelope (protocol.ts errorEnvelope).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")

local function config_error(message)
  return errors.new("ConfigError", { message = message, key = "endpoint" })
end

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

local glue = {}

function glue.settings(s)
  local endpoint = s.endpoint
  if type(endpoint) ~= "string" or endpoint == "" then
    return nil,
      config_error(
        "Proxmox: option endpoint is required: pass endpoint = ... or set PROXMOX_ENDPOINT"
      )
  end
  local scheme, authority, path = string.match(endpoint, "^(%a[%w+.-]*)://([^/?#]*)([^?#]*)$")
  if
    not scheme
    or string.lower(scheme) ~= "https"
    or authority == ""
    or string.find(authority, "@", 1, true)
  then
    return nil,
      config_error("Proxmox endpoint must be an HTTPS URL without credentials, query or fragment")
  end
  path = string.gsub(path, "/+$", "")
  if path ~= "" and path ~= "/api2/json" then
    return nil, config_error("Proxmox endpoint path must be /api2/json")
  end
  s.endpoint = "https://" .. string.lower(authority) .. "/api2/json"
  return s
end

function glue.transform_input(input)
  if type(input) ~= "table" then
    return input
  end
  local wire
  for k, v in pairs(input) do
    if type(v) == "boolean" then
      wire = wire or {}
      wire[k] = v and 1 or 0
    end
  end
  if not wire then
    return input
  end
  local copy = {}
  for k, v in pairs(input) do
    copy[k] = v
  end
  for k, v in pairs(wire) do
    copy[k] = v
  end
  return setmetatable(copy, getmetatable(input))
end

function glue.error_envelope(body)
  if type(body) ~= "table" or body == json.null or json.is_array(body) then
    return nil
  end
  local message = rawget(body, "message")
  message = type(message) == "string" and trim(message) or nil
  local fields = {}
  local list = rawget(body, "errors")
  if type(list) == "table" and list ~= json.null and not json.is_array(list) then
    local names = {}
    for name, reason in pairs(list) do
      if type(reason) == "string" then
        names[#names + 1] = name
      end
    end
    table.sort(names)
    for _, name in ipairs(names) do
      fields[#fields + 1] = name .. ": " .. trim(list[name])
    end
  end
  if #fields == 0 then
    return { message = message }
  end
  table.insert(fields, 1, message or "Parameter verification failed.")
  return { message = compat.concat(fields, "\n") }
end

return glue
