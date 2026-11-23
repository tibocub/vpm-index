-- Rivet's endpoint userinfo (packages/rivet/src/credentials.ts parseEndpoint) and
-- "group.code" error codes (protocol.ts errorEnvelope).
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")

local function url_decode(s)
  return (string.gsub(s, "%%(%x%x)", function(h)
    return string.char(tonumber(h, 16))
  end))
end

local glue = {}

function glue.settings(s)
  local endpoint = s.endpoint
  if type(endpoint) == "string" then
    local scheme, userinfo, rest = string.match(endpoint, "^([%a][%w+.-]*://)([^@/?#]*)@(.*)$")
    if scheme then
      local password = string.match(userinfo, ":(.*)$")
      if (s.token == nil or s.token == "") and password and password ~= "" then
        s.token = secret.wrap(url_decode(password))
      end
      endpoint = scheme .. rest
    end
    s.endpoint = string.gsub(endpoint, "/+$", "")
  end
  if s.token == nil or s.token == "" then
    return nil,
      errors.new("ConfigError", {
        message = "Rivet: RIVET_TOKEN is required (or put the token in RIVET_ENDPOINT's userinfo)",
        key = "token",
      })
  end
  return s
end

function glue.error_envelope(body)
  if type(body) ~= "table" or body == json.null then
    return nil
  end
  local group, code, message = rawget(body, "group"), rawget(body, "code"), rawget(body, "message")
  local out = { message = type(message) == "string" and message or nil }
  if type(group) == "string" and type(code) == "string" then
    out.code = group .. "." .. code
  elseif type(code) == "string" then
    out.code = code
  end
  return out
end

return glue
