-- Token sources for an Azure client's `bearer_token` option. Not in Distilled, whose
-- Azure SDK takes a pre-acquired token only (credentials.ts); added because a Lua script
-- has no `az` SDK to get one from. Each returns a credential source (fn(host) -> token
-- | nil, err, see distilled.credentials): the client resolves it on first use, keeps the
-- token, and resolves it again after a 401 that maps to Unauthorized (ARM's
-- ExpiredAuthenticationToken), so an expired token is replaced on the next try.
--
--   local azure_credentials = require("distilled.azure.credentials")
--   Compute.new({ bearer_token = azure_credentials.cli(), host = ... })
--   Compute.new({ bearer_token = azure_credentials.managed_identity({ client_id = id }) })
--
-- Service principals (client_id + client_secret + tenant_id) need no source: the
-- client options do the Entra ID exchange (providers/azure.lua `oauth`).
--
-- Never puts a token in an error: failures name the program, the endpoint and the
-- status only.
local compat = require("distilled.compat")
local credentials = require("distilled.credentials")
local errors = require("distilled.errors")
local json = require("distilled.json")
local url = require("distilled.url")

local azure_credentials = {}

azure_credentials.RESOURCE = "https://management.azure.com/"
azure_credentials.IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token"

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

local function check_opts(where, opts, allowed)
  if opts == nil then
    return {}
  end
  if type(opts) ~= "table" then
    compat.raise(where .. ": expected an options table", 3)
  end
  for k, v in pairs(opts) do
    if not allowed[k] then
      compat.raise(where .. ": unknown option " .. tostring(k), 3)
    end
    if k ~= "timeout" and type(v) ~= "string" then
      compat.raise(where .. ": option " .. k .. " must be a string", 3)
    end
  end
  if opts.timeout ~= nil and type(opts.timeout) ~= "number" then
    compat.raise(where .. ": option timeout must be a number", 3)
  end
  return opts
end

--- azure_credentials.cli{ resource?, tenant?, subscription?, timeout? } -> source
-- `az account get-access-token --resource <resource> --query accessToken --output tsv`
-- through host.exec (the Azure CLI's logged-in account). The token is the command's
-- stdout; it never appears in argv or in an error.
function azure_credentials.cli(opts)
  opts = check_opts(
    "azure.credentials.cli",
    opts,
    { resource = true, tenant = true, subscription = true, timeout = true }
  )
  local argv = {
    "az",
    "account",
    "get-access-token",
    "--resource",
    opts.resource or azure_credentials.RESOURCE,
    "--query",
    "accessToken",
    "--output",
    "tsv",
  }
  if opts.tenant then
    argv[#argv + 1] = "--tenant"
    argv[#argv + 1] = opts.tenant
  end
  if opts.subscription then
    argv[#argv + 1] = "--subscription"
    argv[#argv + 1] = opts.subscription
  end
  return credentials.from_command(argv, { timeout = opts.timeout or 30 })
end

--- azure_credentials.managed_identity{ client_id?, resource?, timeout? } -> source
-- A managed identity's token: App Service / Functions / Container Apps when
-- IDENTITY_ENDPOINT and IDENTITY_HEADER are set (api-version 2019-08-01, header
-- X-IDENTITY-HEADER), else the VM's instance metadata service (IMDS, api-version
-- 2018-02-01, header Metadata: true). `client_id` picks a user-assigned identity.
function azure_credentials.managed_identity(opts)
  opts = check_opts(
    "azure.credentials.managed_identity",
    opts,
    { client_id = true, resource = true, timeout = true }
  )
  local resource = opts.resource or azure_credentials.RESOURCE
  return function(host)
    host = host or {}
    local getenv = host.getenv or os.getenv
    local transport = host.transport
    if transport == nil then
      return nil, config_error("azure managed identity: the host has no transport", "transport")
    end
    local endpoint, headers, where
    local id_endpoint, id_header = getenv("IDENTITY_ENDPOINT"), getenv("IDENTITY_HEADER")
    if id_endpoint and id_endpoint ~= "" and id_header and id_header ~= "" then
      endpoint = id_endpoint
        .. (string.find(id_endpoint, "?", 1, true) and "&" or "?")
        .. "api-version=2019-08-01"
      headers = { ["x-identity-header"] = id_header, accept = "application/json" }
      where = "IDENTITY_ENDPOINT"
    else
      endpoint = azure_credentials.IMDS_URL .. "?api-version=2018-02-01"
      headers = { metadata = "true", accept = "application/json" }
      where = "the instance metadata service"
    end
    endpoint = endpoint .. "&resource=" .. url.encode_component(resource)
    if opts.client_id then
      endpoint = endpoint .. "&client_id=" .. url.encode_component(opts.client_id)
    end
    local ok, res, terr = compat.pcall(transport, {
      method = "GET",
      url = endpoint,
      headers = headers,
      timeout = opts.timeout or 10,
    })
    if not ok then
      return nil,
        errors.new("SdkError", { message = "azure managed identity: the transport raised" })
    end
    if type(res) ~= "table" or type(res.status) ~= "number" then
      local why = errors.is(terr) and terr.message or tostring(terr)
      return nil,
        config_error(
          "azure managed identity: cannot reach " .. where .. ": " .. why,
          "bearer_token"
        )
    end
    local body = json.decode(res.body or "")
    if res.status < 200 or res.status >= 300 then
      -- the OAuth error code only: the body is not echoed
      local code = type(body) == "table" and rawget(body, "error") or nil
      return nil,
        config_error(
          "azure managed identity: "
            .. where
            .. " answered "
            .. res.status
            .. (type(code) == "string" and (" " .. code) or ""),
          "bearer_token"
        )
    end
    local token = type(body) == "table" and rawget(body, "access_token") or nil
    if type(token) ~= "string" or token == "" then
      return nil,
        config_error(
          "azure managed identity: the answer of " .. where .. " has no access_token",
          "bearer_token"
        )
    end
    return token
  end
end

return azure_credentials
