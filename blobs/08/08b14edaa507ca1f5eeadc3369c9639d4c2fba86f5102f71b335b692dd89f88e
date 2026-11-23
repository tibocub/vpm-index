-- Polymarket's credential groups (packages/polymarket/src/credentials.ts), for the APIs
-- without request signing (gamma, data, relayer, bridge, perps). The CLOB and Combos RFQ
-- glue (glue/polymarket_clob.lua) has the same settings function plus the signing.
--
-- Each group is all or nothing: none of its values, all of them, or a ConfigError
-- naming the missing variables ("Polymarket CLOB credentials are incomplete: set
-- CLOB_SECRET"), key = the first missing variable. As with CredentialsFromEnv, every
-- API checks every group.
local errors = require("distilled.errors")
local secret = require("distilled.secret")

local glue = {}

local GROUPS = {
  {
    label = "CLOB",
    { "clob_address", "POLY_ADDRESS" },
    { "clob_api_key", "CLOB_API_KEY" },
    { "clob_secret", "CLOB_SECRET" },
    { "clob_passphrase", "CLOB_PASS_PHRASE" },
  },
  {
    label = "relayer",
    { "relayer_address", "RELAYER_API_KEY_ADDRESS" },
    { "relayer_api_key", "RELAYER_API_KEY" },
  },
  {
    label = "Perps",
    { "perps_proxy", "POLYMARKET_PROXY" },
    { "perps_secret", "POLYMARKET_SECRET" },
  },
}

local function present(v)
  if v == nil then
    return false
  end
  local plain = secret.unwrap(v)
  return plain ~= nil and plain ~= ""
end

function glue.settings(s)
  for _, group in ipairs(GROUPS) do
    local missing = {}
    for _, entry in ipairs(group) do
      if not present(s[entry[1]]) then
        missing[#missing + 1] = entry[2]
      end
    end
    if #missing > 0 and #missing < #group then
      return nil,
        errors.new("ConfigError", {
          message = "Polymarket "
            .. group.label
            .. " credentials are incomplete: set "
            .. table.concat(missing, ", "),
          key = missing[1],
        })
    end
  end
  return s
end

return glue
