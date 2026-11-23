-- The Azure Resource Manager protocol: a port of Distilled's packages/azure/src/protocol.ts
-- (AzureProtocol) and credentials.ts, on top of the REST protocol.
--
--   local azure = require("distilled.protocol.azure")
--   local protocol = azure.new(service, { provider = <provider-spec runtime data> })
--   -- or azure(service, args): the module is callable (provider spec `protocol` key)
--
-- What is Azure's own (why this is not a plain rest.new):
--
--   request:  `Authorization: Bearer <bearer_token>` and `Accept: application/json`
--             (without it some resource providers negotiate another media type: API
--             Management returns policies as raw XML), base URL `api_base_url` (default
--             https://management.azure.com). Options are resolved on every request (the
--             provider-spec runtime: AZURE_BEARER_TOKEN, AZURE_SUBSCRIPTION_ID,
--             AZURE_TENANT_ID, AZURE_API_BASE_URL; without a token, Entra ID client
--             credentials AZURE_CLIENT_ID / AZURE_CLIENT_SECRET, cached per client class
--             until 5 minutes before expiry). A `{subscriptionId}` the caller left
--             out is filled from `subscription_id` (users set AZURE_SUBSCRIPTION_ID once);
--             an explicit one wins. The operation's `api_version` is appended as
--             `?api-version=` (`&` after other query parameters) unless the URL has one.
--   response: a 2xx body is the payload (no envelope) plus the response headers the
--             output declares (the Azure-AsyncOperation / Location monitor of a 202),
--             decoded by rest. A failure is matched like Distilled (see decode_failure):
--             the ARM envelope's message matchers and code map, a mapped
--             `error.details[].code`, the HTTP status map (Retry-After on retryable
--             statuses), unmapped 5xx -> InternalServerError, else UnknownAzureError.
--
-- Distilled's v0 parity choices kept: no pagination (list operations return
-- `{ value, nextLink }`), no long-running-operation polling (the 202's headers are in
-- the output). Added: the Entra ID client-credentials exchange (rest's provider oauth);
-- distilled.azure.credentials has Azure CLI and managed-identity token sources.
local azure_errors = require("distilled.azure.errors")
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local rest = require("distilled.protocol.rest")
local retry = require("distilled.retry")
local url_lib = require("distilled.url")

local azure = {}

azure.DEFAULT_API_BASE_URL = "https://management.azure.com"

--- azure.PROVIDER: the provider-spec runtime data providers/azure.lua compiles to, for a
-- client defined by hand (`azure.new(service)` with no provider).
azure.PROVIDER = {
  title = "Azure",
  headers = {
    { name = "authorization", values = { { template = "Bearer {bearer_token}" } }, secret = true },
  },
  base_url = { default = azure.DEFAULT_API_BASE_URL, option = "api_base_url" },
  -- Entra ID client credentials when no bearer_token is given (not in Distilled)
  oauth = {
    required = true,
    auth = "form",
    client_id = "client_id",
    client_secret = "client_secret",
    into = "bearer_token",
    label = "Entra ID token request",
    refresh_window_s = 300,
    scope = "scope",
    token_url = "{authority_host}/{tenant_id}/oauth2/v2.0/token",
  },
  options = {
    api_base_url = { env = { "AZURE_API_BASE_URL" } },
    authority_host = {
      default = "https://login.microsoftonline.com",
      env = { "AZURE_AUTHORITY_HOST" },
      trim_slash = true,
    },
    bearer_token = { secret = true, env = { "AZURE_BEARER_TOKEN" } },
    client_id = { env = { "AZURE_CLIENT_ID" } },
    client_secret = { secret = true, env = { "AZURE_CLIENT_SECRET" } },
    scope = { default = "https://management.azure.com/.default" },
    subscription_id = { env = { "AZURE_SUBSCRIPTION_ID" } },
    tenant_id = { env = { "AZURE_TENANT_ID" } },
  },
}

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

local function present(v)
  return v ~= nil and v ~= json.null and v ~= ""
end

-- `{subscriptionId}` in the path with no value in the input: filled from the settings
-- (a copy of the input; the caller's table is not changed). Distilled replaces the
-- placeholder left in the built URL; filling the label first gives the same URL (the
-- value is percent-encoded either way) and keeps request.build's label checks.
local function fill_subscription(op, input, settings)
  if not string.find(op.uri or "", "{subscriptionId}", 1, true) then
    return input
  end
  if type(input) == "table" and present(input.subscriptionId) then
    return input
  end
  local sub = settings.subscription_id
  if not present(sub) then
    return nil,
      errors.new("ConfigError", {
        message = "Azure: "
          .. tostring(op.name)
          .. " needs a subscription id: pass subscriptionId in the input, or the"
          .. " subscription_id option (or set AZURE_SUBSCRIPTION_ID)",
        key = "subscription_id",
      })
  end
  local copy = {}
  for k, v in pairs(type(input) == "table" and input or {}) do
    copy[k] = v
  end
  setmetatable(copy, getmetatable(input))
  copy.subscriptionId = tostring(sub)
  return copy
end

-- ARM requires api-version on every call; an explicit one already in the URL wins.
local function with_api_version(u, version)
  if version == nil then
    return u
  end
  local query = string.match(u, "%?(.*)$")
  if query and (string.find("&" .. query, "&api-version=", 1, true)) then
    return u
  end
  return u .. (query and "&" or "?") .. "api-version=" .. url_lib.encode_component(version)
end

--- azure.new(service, args) -> protocol
-- args: { provider = runtime data (default azure.PROVIDER), unknown_tag, parse_tag,
-- base_url_option } (the provider spec's `protocol` call passes all of them).
function azure.new(service, args)
  args = args or {}
  if type(args) ~= "table" then
    compat.raise("distilled.protocol.azure: expected an options table", 2)
  end
  local provider = args.provider or azure.PROVIDER
  local rt = rest.compile_provider(provider)
  local inner = rest.new({
    base_url = rt.base_url,
    headers = function(settings, route, op_name)
      local h = rt.headers(settings, route, op_name)
      h["accept"] = "application/json"
      return h
    end,
    unknown_tag = args.unknown_tag or "UnknownAzureError",
    parse_tag = args.parse_tag or "AzureParseError",
  })
  local protocol = inner
  local rest_encode, rest_decode = inner.encode, inner.decode

  --- protocol.encode(ctx, op, input [, creds]) -> request | nil, err
  function protocol.encode(ctx, op, input, creds)
    ctx = ctx or {}
    if creds == nil then
      creds = {}
      if ctx.credentials then
        local c, err = ctx.credentials()
        if c == nil then
          return nil, err
        end
        creds = c
      end
    end
    -- the options of every request: given values, then the environment, then defaults
    local settings, serr = rt.resolve(creds, ctx.host, op.name, ctx.timeout)
    if settings == nil then
      return nil, serr
    end
    local filled, ferr = fill_subscription(op, input, settings)
    if filled == nil and ferr then
      return nil, ferr
    end
    local req, err = rest_encode(ctx, op, filled, settings)
    if req == nil then
      return nil, err
    end
    req.url = with_api_version(req.url, op.api_version)
    return req
  end

  -- status >= 400 (protocol.ts decode, steps 1-4)
  local function decode_failure(ctx, res)
    local status, headers = res.status, res.headers or {}
    local text = res.body or ""
    -- read as text and parse tolerantly: error pages are often not JSON
    local value, non_json = nil, false
    if trim(text) ~= "" then
      local v = json.decode(text)
      if v == nil then
        non_json = true
      else
        value = v
      end
    end
    local body = non_json and text or value
    local arm = (not non_json) and azure_errors.parse_arm(value) or nil
    local now = ctx.host and ctx.host.epoch and ctx.host.epoch() or os.time()

    -- 1. the Azure error code (message matchers first) for a richer typed error
    local class = azure_errors.class_for(arm)
    if class then
      return errors.new(class, {
        message = arm.message,
        code = arm.code,
        target = class.fields[1] == "target" and arm.target or nil,
        status = status,
        body = body,
        headers = headers,
      })
    end

    -- 1b. a generic top-level code (`ValidationError`) whose details[].code is mapped
    if arm and arm.details then
      for _, d in ipairs(arm.details) do
        local dclass = d.code ~= nil and azure_errors.codes[d.code]
        if dclass then
          local message = d.message
          if message == nil then
            message = arm.message
          end
          return errors.new(dclass, {
            message = message,
            code = d.code,
            target = dclass.fields[1] == "target" and arm.target or nil,
            status = status,
            body = body,
            headers = headers,
          })
        end
      end
    end

    -- 2. the standard HTTP status classes (Retry-After on retryable statuses)
    local trimmed = trim(text)
    local status_class = errors.STATUS_MAP[status]
    if status_class then
      local message = arm and arm.message
      if message == nil then
        message = (non_json and trimmed ~= "") and trimmed or ""
      end
      return errors.new(status_class, {
        message = message,
        code = arm and arm.code,
        status = status,
        body = body,
        headers = headers,
        retry_after = retry.parse_for_status(status, headers, now),
      })
    end

    -- 3. unmapped 5xx: a retryable server error
    if status >= 500 then
      return errors.new(errors.InternalServerError, {
        message = (arm and arm.message) or ("HTTP " .. tostring(status)),
        code = arm and arm.code,
        status = status,
        body = body,
        headers = headers,
        retry_after = retry.parse_for_status(status, headers, now),
      })
    end

    -- 4. UnknownAzureError
    return errors.new(protocol.unknown_class, {
      status = status,
      code = arm and arm.code,
      message = arm and arm.message,
      target = arm and arm.target,
      body = body,
      headers = headers,
    })
  end

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    ctx = ctx or {}
    if res.status >= 400 then
      return nil, decode_failure(ctx, res)
    end
    return rest_decode(ctx, op, res)
  end

  return protocol
end

return setmetatable(azure, {
  __call = function(_, service, args)
    return azure.new(service, args)
  end,
})
