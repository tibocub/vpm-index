-- GCP credentials providers: what a GCP client authenticates with. Port of Distilled's
-- packages/gcp/src/credentials-service.ts and credential-providers/*.ts.
--
--   local creds = require("distilled.gcp.credentials")
--   local Storage = require("gcp.storage_v1")
--   local client = Storage.new({ host = host, credentials = creds.from_application_default() })
--
-- A provider is a table with `provider:resolve(host) -> config | nil, err`, where
--   config = { access_token = <secret>, project?, region?, quota_project? }
-- The protocol resolves it on every request attempt, so a refreshing provider can mint a
-- new token. creds.custom(fn) makes a provider of a function(host) -> config | nil, err
-- (the client's `credentials` option takes tables only).
--
--   creds.from_access_token{ access_token, project?, region?, quota_project? }
--   creds.from_env()                         GOOGLE_ACCESS_TOKEN, GOOGLE_PROJECT_ID
--   creds.from_authorized_user{ client_id, client_secret, refresh_token, scopes?, token_url? }
--   creds.from_service_account_key{ client_email, private_key, private_key_id?, scopes?,
--                                   token_url? }          (RS256: distilled.crypto.jwt)
--   creds.from_metadata_server{ scopes?, service_account? }
--   creds.from_workload_identity{ audience, subject_token, subject_token_type?,
--                                 service_account_email?, scopes?, token_lifetime_seconds?,
--                                 token_url? }
--   creds.from_application_default{ scopes?, read_file? }  (AIP-4110: the file
--       GOOGLE_APPLICATION_CREDENTIALS names, gcloud's file, then the metadata server)
-- Every token-minting provider also takes the overrides project, region, quota_project
-- (they win over what the source learned) and caches its token until five minutes
-- before it expires (REFRESH_WINDOW_S). Lua runs one call at a time, so there is no
-- lock: Distilled's semaphore only keeps concurrent fibers from minting twice.
--
-- HTTP goes through host.transport, time through host.epoch (seconds), the environment
-- through host.getenv and files through host.read_file or io.open (read_file overrides
-- both). Failures are GCPCredentialsError (distilled.gcp.errors) with Distilled's
-- messages; no message carries a token, a key or a refresh token.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")
local url = require("distilled.url")
local gcp_errors = require("distilled.gcp.errors")

local credentials = {}

credentials.CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
credentials.OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
credentials.STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"
credentials.JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
--- Refresh this long (seconds) before the access token expires.
credentials.REFRESH_WINDOW_S = 5 * 60
--- How long isOnGcp waits for the metadata server (seconds).
credentials.METADATA_PROBE_TIMEOUT_S = 3

local null = json.null
local fail = gcp_errors.credentials

local function is_secret_text(v)
  return type(v) == "string" or secret.is(v)
end

local function epoch(host)
  local f = host and host.epoch or os.time
  return f()
end

local function getenv(host, name)
  local f = (host and host.getenv) or os.getenv
  local v = f(name)
  if v == "" then
    return nil
  end
  return v
end

-- form body in the given order (URLSearchParams, as HttpClientRequest.bodyUrlParams)
local function form(pairs_list)
  local q = url.query()
  for i = 1, #pairs_list, 2 do
    local v = pairs_list[i + 1]
    if v ~= nil then
      q:add(pairs_list[i], tostring(secret.unwrap(v)))
    end
  end
  return q:encode()
end

-- RFC 3339 / ISO 8601 UTC time ("2014-10-02T15:01:23Z", fractions, offsets) -> epoch s
local function days_from_civil(y, m, d)
  if m <= 2 then
    y = y - 1
  end
  local era = math.floor(y / 400)
  local yoe = y - era * 400
  local mp = (m + 9) % 12
  local doy = math.floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

function credentials.parse_time(text)
  if type(text) ~= "string" then
    return nil
  end
  local y, mo, d, hh, mm, ss, frac, zone = string.match(
    text,
    "^(%d%d%d%d)%-(%d%d)%-(%d%d)[Tt ](%d%d):(%d%d):(%d%d)(%.?%d*)([Zz]?[%+%-]?[%d:]*)$"
  )
  if not y then
    return nil
  end
  y, mo, d, hh, mm, ss =
    tonumber(y), tonumber(mo), tonumber(d), tonumber(hh), tonumber(mm), tonumber(ss)
  if mo < 1 or mo > 12 or d < 1 or d > 31 or hh > 23 or mm > 59 or ss > 60 then
    return nil
  end
  local t = days_from_civil(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss
  if frac ~= "" and frac ~= "." then
    t = t + (tonumber("0" .. frac) or 0)
  elseif frac == "." then
    return nil
  end
  if zone == "Z" or zone == "z" then
    return t
  end
  local sign, oh, om = string.match(zone, "^([%+%-])(%d%d):?(%d%d)$")
  if not sign then
    return nil
  end
  local offset = tonumber(oh) * 3600 + tonumber(om) * 60
  return sign == "+" and t - offset or t + offset
end

---------------------------------------------------------------------------------------
-- token endpoint requests (credential-providers/oauth.ts)
---------------------------------------------------------------------------------------

-- OAuth: { error, error_description }; Google APIs: { error: { message } }
local function error_text(body)
  if type(body) ~= "table" or body == null then
    return nil
  end
  local e, desc = rawget(body, "error"), rawget(body, "error_description")
  if type(desc) == "string" then
    return desc
  end
  if type(e) == "string" then
    return e
  end
  if type(e) == "table" and e ~= null and type(rawget(e, "message")) == "string" then
    return rawget(e, "message")
  end
  return nil
end

local function lower_headers(h)
  local out = {}
  for k, v in pairs(h or {}) do
    out[type(k) == "string" and string.lower(k) or k] = v
  end
  return out
end

--- credentials.request_text(host, step, req) -> { text, headers } | nil, GCPCredentialsError
-- Send req through host.transport; a non-2xx answer fails with the endpoint's own error
-- text. `step` names the call in the message.
function credentials.request_text(host, step, req)
  local transport = host and host.transport
  if transport == nil then
    return nil,
      fail(step .. " failed: no transport (" .. require("distilled.host").TRANSPORT_HINT .. ")")
  end
  local ok, res, terr = compat.pcall(transport, req)
  if not ok then
    local message = type(res) == "table" and rawget(res, "message") or res
    return nil, fail(step .. " failed: " .. tostring(message), nil, res)
  end
  if type(res) ~= "table" or type(res.status) ~= "number" then
    local why = errors.is(terr) and terr.message or tostring(terr or "no response")
    return nil, fail(step .. " failed: " .. why, nil, terr)
  end
  local text = res.body or ""
  if res.status < 200 or res.status >= 300 then
    local body = json.decode(text)
    return nil,
      fail(
        step
          .. " failed with status "
          .. tostring(res.status)
          .. ": "
          .. (error_text(body) or string.sub(text, 1, 200)),
        res.status
      )
  end
  return { text = text, headers = lower_headers(res.headers) }
end

--- credentials.request_json(host, step, req) -> object | nil, err
function credentials.request_json(host, step, req)
  local r, err = credentials.request_text(host, step, req)
  if not r then
    return nil, err
  end
  local body = json.decode(r.text)
  if type(body) ~= "table" or body == null then
    return nil, fail(step .. " returned a body that is not JSON.")
  end
  return body
end

--- credentials.oauth_token(step, body, issued_at) -> token | nil, err
-- An OAuth2 token response (access_token, expires_in); issued_at is when the request
-- was sent, so the expiry errs early.
function credentials.oauth_token(step, body, issued_at)
  local access = rawget(body, "access_token")
  if type(access) ~= "string" then
    return nil, fail(step .. " returned no access_token.")
  end
  local expires_in = rawget(body, "expires_in")
  if type(expires_in) ~= "number" then
    expires_in = 3600
  end
  return { access_token = secret.wrap(access), expires_at = issued_at + expires_in }
end

local FORM = "application/x-www-form-urlencoded"

local function post_form(token_url, fields)
  return {
    method = "POST",
    url = token_url,
    headers = { ["content-type"] = FORM },
    body = form(fields),
  }
end

---------------------------------------------------------------------------------------
-- refreshing providers (credentials-service.ts createRefreshingProvider)
---------------------------------------------------------------------------------------

local Provider = {}
Provider.__index = Provider

--- provider:resolve(host) -> config | nil, err
function Provider:resolve(host)
  return self._resolve(host or {})
end

--- provider:clear(): forget a cached token (the next request mints one)
function Provider:clear()
  if self._clear then
    self._clear()
  end
end

local function provider_of(kind, resolve, clear)
  return setmetatable({ kind = kind, _resolve = resolve, _clear = clear }, Provider)
end
credentials.provider_of = provider_of

--- credentials.custom(fn) -> provider: fn(host) -> config | nil, err, called per attempt
function credentials.custom(fn)
  if type(fn) ~= "function" then
    compat.raise("credentials.custom: expected a function(host)", 2)
  end
  return provider_of("custom", fn)
end

--- credentials.is_provider(v) -> v can be a client's `credentials` option
function credentials.is_provider(v)
  if type(v) == "function" then
    return true
  end
  return type(v) == "table" and type(v.resolve) == "function"
end

--- credentials.resolve(provider, host) -> config | nil, err
function credentials.resolve(provider, host)
  local ok, config, err
  if type(provider) == "function" then
    ok, config, err = compat.pcall(provider, host)
  else
    ok, config, err = compat.pcall(provider.resolve, provider, host)
  end
  if not ok then
    if errors.is(config) then
      return nil, config
    end
    local message = type(config) == "table" and rawget(config, "message") or config
    return nil, fail("The credentials provider raised: " .. tostring(message), nil, config)
  end
  if config == nil then
    if errors.is(err) then
      return nil, err
    end
    return nil,
      fail(
        "The credentials provider returned no credentials"
          .. (err and (": " .. tostring(err)) or ".")
      )
  end
  if type(config) ~= "table" or not is_secret_text(config.access_token) then
    return nil, fail("The credentials provider returned no access_token.")
  end
  return config
end

local function check_overrides(where, config)
  for _, k in ipairs({ "project", "region", "quota_project" }) do
    if config[k] ~= nil and type(config[k]) ~= "string" then
      compat.raise(where .. ": " .. k .. " must be a string", 3)
    end
  end
end

--- credentials.refreshing(kind, source, overrides) -> provider
-- source(host) -> token | nil, err, where token = { access_token (secret), expires_at
-- (epoch seconds), project?, quota_project? }. The first request mints a token, later
-- requests reuse it until REFRESH_WINDOW_S before it expires.
function credentials.refreshing(kind, source, overrides)
  overrides = overrides or {}
  local cached
  local function fresh(host)
    return cached ~= nil and epoch(host) < cached.expires_at - credentials.REFRESH_WINDOW_S
  end
  return provider_of(kind, function(host)
    if not fresh(host) then
      local token, err = source(host)
      if not token then
        return nil, err
      end
      cached = token
    end
    return {
      access_token = cached.access_token,
      project = overrides.project or cached.project,
      region = overrides.region,
      quota_project = overrides.quota_project or cached.quota_project,
    }
  end, function()
    cached = nil
  end)
end

---------------------------------------------------------------------------------------
-- from_access_token, from_env
---------------------------------------------------------------------------------------

--- credentials.from_access_token{ access_token, project?, region?, quota_project? }
-- An access token minted outside the SDK (`gcloud auth print-access-token`).
function credentials.from_access_token(config)
  if type(config) ~= "table" or not is_secret_text(config.access_token) then
    compat.raise("from_access_token: access_token must be a string or a secret", 2)
  end
  check_overrides("from_access_token", config)
  local token = secret.wrap(secret.unwrap(config.access_token))
  return provider_of("access_token", function()
    return {
      access_token = token,
      project = config.project,
      region = config.region,
      quota_project = config.quota_project,
    }
  end)
end

--- credentials.from_env() -> GOOGLE_ACCESS_TOKEN (required), GOOGLE_PROJECT_ID (optional)
function credentials.from_env()
  return provider_of("env", function(host)
    local token = getenv(host, "GOOGLE_ACCESS_TOKEN")
    if token == nil then
      return nil, fail("GOOGLE_ACCESS_TOKEN environment variable is required")
    end
    return { access_token = secret.wrap(token), project = getenv(host, "GOOGLE_PROJECT_ID") }
  end)
end

---------------------------------------------------------------------------------------
-- from_authorized_user (AIP-4113)
---------------------------------------------------------------------------------------

local function scopes_list(where, scopes)
  if scopes == nil then
    return nil
  end
  if type(scopes) ~= "table" then
    compat.raise(where .. ": scopes must be a list of strings", 3)
  end
  for _, s in ipairs(scopes) do
    if type(s) ~= "string" then
      compat.raise(where .. ": scopes must be a list of strings", 3)
    end
  end
  return scopes
end

local function join(list, sep)
  return compat.concat(list, sep)
end

--- credentials.authorized_user_source(config) -> source(host)
function credentials.authorized_user_source(config)
  return function(host)
    local step = "Refreshing the user's access token"
    local issued_at = epoch(host)
    local scope = (config.scopes and #config.scopes > 0) and join(config.scopes, " ") or nil
    local body, err = credentials.request_json(
      host,
      step,
      post_form(config.token_url or credentials.OAUTH_TOKEN_URL, {
        "grant_type",
        "refresh_token",
        "client_id",
        config.client_id,
        "client_secret",
        config.client_secret,
        "refresh_token",
        config.refresh_token,
        "scope",
        scope,
      })
    )
    if not body then
      local message = string.gsub(err.message, "%.?$", ".", 1)
      return nil,
        fail(
          message
            .. " Run `gcloud auth application-default login` if the login has expired or"
            .. " needs reauthentication.",
          err.status,
          err.cause
        )
    end
    return credentials.oauth_token(step, body, issued_at)
  end
end

--- credentials.from_authorized_user{ client_id, client_secret, refresh_token, scopes?,
-- token_url?, project?, region?, quota_project? }: a user's OAuth refresh token (what
-- `gcloud auth application-default login` writes), refreshed five minutes early.
function credentials.from_authorized_user(config)
  if type(config) ~= "table" then
    compat.raise("from_authorized_user: expected a table", 2)
  end
  if type(config.client_id) ~= "string" then
    compat.raise("from_authorized_user: client_id must be a string", 2)
  end
  for _, k in ipairs({ "client_secret", "refresh_token" }) do
    if not is_secret_text(config[k]) then
      compat.raise("from_authorized_user: " .. k .. " must be a string or a secret", 2)
    end
  end
  check_overrides("from_authorized_user", config)
  scopes_list("from_authorized_user", config.scopes)
  return credentials.refreshing(
    "authorized_user",
    credentials.authorized_user_source(config),
    config
  )
end

---------------------------------------------------------------------------------------
-- from_service_account_key (AIP-4112): an RS256 JWT assertion for an access token
---------------------------------------------------------------------------------------

-- distilled.crypto.jwt and .pem (task 24); absent, the provider fails with ConfigError
local function jwt_modules()
  local ok_jwt, jwt = compat.pcall(require, "distilled.crypto.jwt")
  local ok_jws, jws = compat.pcall(require, "distilled.crypto.jws")
  local ok_pem, pem = compat.pcall(require, "distilled.crypto.pem")
  if ok_jwt and ok_jws and ok_pem then
    return jwt, jws, pem
  end
  return nil
end

--- credentials.sign_assertion(config, token_url, issued_at) -> jwt text | nil, err
-- Distilled's signAssertion: header { alg: RS256, typ: JWT, kid? }, claims { iss, scope,
-- aud, iat, exp = iat + 3600 }, in that order.
function credentials.sign_assertion(config, token_url, issued_at)
  local jwt, jws, pem = jwt_modules()
  if not jwt then
    return nil,
      errors.new("ConfigError", {
        message = "service account keys need RS256 signing (distilled.crypto.jwt and"
          .. " distilled.crypto.pem, task 24), which this build of distilled-lua does not"
          .. " have; use from_application_default, from_authorized_user,"
          .. " from_workload_identity or an access token",
        key = "credentials",
      })
  end
  local signing_failed = "Could not sign a JWT with the private key of "
    .. tostring(config.client_email)
    .. "; it must be an RSA key in PKCS #8 PEM form."
  local ok, key = compat.pcall(pem.private_key, config.private_key)
  -- the cause can quote key material, so it is not attached
  if not ok or type(key) ~= "table" or key.kind ~= "rsa" then
    return nil, fail(signing_failed)
  end
  local header = config.private_key_id and jws.object("typ", "JWT", "kid", config.private_key_id)
    or jws.object("typ", "JWT")
  local scope = join(config.scopes or { credentials.CLOUD_PLATFORM_SCOPE }, " ")
  local iat = math.floor(issued_at)
  local signed, token = compat.pcall(jwt.encode, {
    key = key,
    alg = "RS256",
    header = header,
    claims = jws.object(
      "iss",
      config.client_email,
      "scope",
      scope,
      "aud",
      token_url,
      "iat",
      iat,
      "exp",
      iat + 3600
    ),
  })
  if not signed or type(token) ~= "string" then
    return nil, fail(signing_failed)
  end
  return token
end

--- credentials.service_account_key_source(config) -> source(host)
function credentials.service_account_key_source(config)
  return function(host)
    local step = "Exchanging the key of " .. tostring(config.client_email) .. " for an access token"
    local token_url = config.token_url or credentials.OAUTH_TOKEN_URL
    local issued_at = epoch(host)
    local assertion, aerr = credentials.sign_assertion(config, token_url, issued_at)
    if not assertion then
      return nil, aerr
    end
    local body, err = credentials.request_json(
      host,
      step,
      post_form(token_url, {
        "grant_type",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion",
        assertion,
      })
    )
    if not body then
      return nil, err
    end
    return credentials.oauth_token(step, body, issued_at)
  end
end

--- credentials.from_service_account_key{ client_email, private_key (PKCS #8 PEM),
-- private_key_id?, scopes?, token_url?, project?, region?, quota_project? }
function credentials.from_service_account_key(config)
  if type(config) ~= "table" or type(config.client_email) ~= "string" then
    compat.raise("from_service_account_key: client_email must be a string", 2)
  end
  if not is_secret_text(config.private_key) then
    compat.raise("from_service_account_key: private_key must be a string or a secret", 2)
  end
  check_overrides("from_service_account_key", config)
  scopes_list("from_service_account_key", config.scopes)
  return credentials.refreshing(
    "service_account",
    credentials.service_account_key_source(config),
    config
  )
end

---------------------------------------------------------------------------------------
-- from_metadata_server (AIP-4115)
---------------------------------------------------------------------------------------

local function metadata_request(host, path, timeout)
  local name = getenv(host, "GCE_METADATA_HOST") or "metadata.google.internal"
  return {
    method = "GET",
    url = "http://" .. name .. "/computeMetadata/v1/" .. path,
    headers = { ["metadata-flavor"] = "Google" },
    timeout = timeout,
  }
end

--- credentials.is_on_gcp(host [, timeout_s]) -> boolean
-- A metadata server answers within the timeout with `Metadata-Flavor: Google`.
function credentials.is_on_gcp(host, timeout)
  local r = credentials.request_text(
    host,
    "Probing the metadata server",
    metadata_request(host, "", timeout or credentials.METADATA_PROBE_TIMEOUT_S)
  )
  return r ~= nil and r.headers["metadata-flavor"] == "Google"
end

--- credentials.metadata_server_source(config) -> source(host)
function credentials.metadata_server_source(config)
  config = config or {}
  return function(host)
    local step = "Fetching an access token from the metadata server"
    local account = url.encode_component(config.service_account or "default")
    local scopes = ""
    if config.scopes and #config.scopes > 0 then
      scopes = "?scopes=" .. url.encode_component(join(config.scopes, ","))
    end
    local issued_at = epoch(host)
    local body, err = credentials.request_json(
      host,
      step,
      metadata_request(host, "instance/service-accounts/" .. account .. "/token" .. scopes)
    )
    if not body then
      return nil, err
    end
    local token, terr = credentials.oauth_token(step, body, issued_at)
    if not token then
      return nil, terr
    end
    if config.project ~= nil then
      return token
    end
    -- no project (404 or an empty answer) is not an error; a failed read is
    local r, perr = credentials.request_text(
      host,
      "Reading the project id from the metadata server",
      metadata_request(host, "project/project-id")
    )
    if r then
      local p = string.gsub(string.gsub(r.text, "^%s+", ""), "%s+$", "")
      token.project = p ~= "" and p or nil
    elseif perr.status ~= 404 then
      return nil, perr
    end
    return token
  end
end

--- credentials.from_metadata_server{ scopes?, service_account?, project?, region?,
-- quota_project? }: the service account of the Google Cloud resource the code runs on.
function credentials.from_metadata_server(config)
  config = config or {}
  if type(config) ~= "table" then
    compat.raise("from_metadata_server: expected a table", 2)
  end
  check_overrides("from_metadata_server", config)
  scopes_list("from_metadata_server", config.scopes)
  return credentials.refreshing(
    "metadata_server",
    credentials.metadata_server_source(config),
    config
  )
end

---------------------------------------------------------------------------------------
-- from_workload_identity (AIP-4117)
---------------------------------------------------------------------------------------

-- RFC 8693 token exchange at Google's Security Token Service
local function exchange_subject_token(host, config, subject_token, scopes)
  local step = "The workload identity token exchange"
  local issued_at = epoch(host)
  local body, err = credentials.request_json(
    host,
    step,
    post_form(config.token_url or credentials.STS_TOKEN_URL, {
      "grant_type",
      "urn:ietf:params:oauth:grant-type:token-exchange",
      "audience",
      config.audience,
      "scope",
      join(scopes, " "),
      "requested_token_type",
      "urn:ietf:params:oauth:token-type:access_token",
      "subject_token",
      subject_token,
      "subject_token_type",
      config.subject_token_type or credentials.JWT_TOKEN_TYPE,
    })
  )
  if not body then
    return nil, err
  end
  return credentials.oauth_token(step, body, issued_at)
end

--- credentials.impersonate_service_account(host, email, source_token, opts) -> token | nil, err
-- IAM Credentials generateAccessToken: trade source_token (cloud-platform or IAM scope)
-- for email's access token. opts = { scopes, lifetime_seconds?, delegates? }.
function credentials.impersonate_service_account(host, email, source, opts)
  local step = "Impersonating " .. email
  local payload = {
    scope = json.array(opts.scopes),
    lifetime = tostring(opts.lifetime_seconds or 3600) .. "s",
  }
  if opts.delegates and #opts.delegates > 0 then
    payload.delegates = json.array(opts.delegates)
  end
  local body, err = credentials.request_json(host, step, {
    method = "POST",
    url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
      .. url.encode_component(email)
      .. ":generateAccessToken",
    headers = {
      authorization = "Bearer " .. tostring(secret.unwrap(source.access_token)),
      ["content-type"] = "application/json",
    },
    body = json.encode(payload),
  })
  if not body then
    return nil, err
  end
  local access = rawget(body, "accessToken")
  local expires_at = credentials.parse_time(rawget(body, "expireTime"))
  if type(access) ~= "string" or expires_at == nil then
    return nil, fail(step .. " returned no accessToken or expireTime.")
  end
  return { access_token = secret.wrap(access), expires_at = expires_at }
end

-- a subject token: a string, a secret, or fn(host) -> string | secret | nil, err
local function subject_token_of(host, v)
  if is_secret_text(v) then
    return v
  end
  local ok, token, err = compat.pcall(v, host)
  if ok and is_secret_text(token) then
    return token
  end
  return nil, fail("Could not resolve the workload identity subject token.", nil, ok and err or nil)
end

--- credentials.workload_identity_source(config) -> source(host)
function credentials.workload_identity_source(config)
  return function(host)
    local scopes = config.scopes or { credentials.CLOUD_PLATFORM_SCOPE }
    local subject, serr = subject_token_of(host, config.subject_token)
    if not subject then
      return nil, serr
    end
    if config.service_account_email == nil then
      return exchange_subject_token(host, config, subject, scopes)
    end
    -- impersonation needs cloud-platform on the federated token; the caller's scopes go
    -- to generateAccessToken
    local federated, ferr =
      exchange_subject_token(host, config, subject, { credentials.CLOUD_PLATFORM_SCOPE })
    if not federated then
      return nil, ferr
    end
    return credentials.impersonate_service_account(host, config.service_account_email, federated, {
      scopes = scopes,
      lifetime_seconds = config.token_lifetime_seconds,
    })
  end
end

--- credentials.from_workload_identity{ audience, subject_token, subject_token_type?,
-- service_account_email?, scopes?, token_lifetime_seconds?, token_url?, project?,
-- region?, quota_project? }: an OIDC or SAML token from another platform exchanged at
-- Google STS (and for a service account's token when service_account_email is set).
-- subject_token may be a function(host) -> token, run again on every exchange.
function credentials.from_workload_identity(config)
  if type(config) ~= "table" or type(config.audience) ~= "string" then
    compat.raise("from_workload_identity: audience must be a string", 2)
  end
  local st = config.subject_token
  if not is_secret_text(st) and type(st) ~= "function" then
    compat.raise(
      "from_workload_identity: subject_token must be a string, a secret or a function",
      2
    )
  end
  check_overrides("from_workload_identity", config)
  scopes_list("from_workload_identity", config.scopes)
  return credentials.refreshing(
    "workload_identity",
    credentials.workload_identity_source(config),
    config
  )
end

---------------------------------------------------------------------------------------
-- from_application_default (AIP-4110)
---------------------------------------------------------------------------------------

local function str(t, key)
  local v = type(t) == "table" and rawget(t, key) or nil
  if type(v) == "string" and v ~= "" then
    return v
  end
  return nil
end

local function obj(t, key)
  local v = type(t) == "table" and rawget(t, key) or nil
  if type(v) == "table" and v ~= null and not json.is_array(v) then
    return v
  end
  return {}
end

local WINDOWS = string.sub(package.config, 1, 1) == "\\"

--- credentials.well_known_path(host) -> gcloud's application_default_credentials.json | nil
function credentials.well_known_path(host)
  local config = getenv(host, "CLOUDSDK_CONFIG")
  if config == nil then
    if WINDOWS then
      local appdata = getenv(host, "APPDATA")
      config = appdata and (appdata .. "\\gcloud")
    else
      local home = getenv(host, "HOME")
      config = home and (home .. "/.config/gcloud")
    end
  end
  return config and (config .. "/application_default_credentials.json")
end

-- read_file(path) -> text | nil (absent) | false, message (unreadable)
local function default_read_file(path)
  local f, message, code = io.open(path, "rb")
  if not f then
    -- ENOENT (errno 2) is "absent", as Distilled's readFile ENOENT; anything else fails
    if code == 2 or string.find(tostring(message), "No such file", 1, true) then
      return nil
    end
    return false, "unreadable"
  end
  local text = f:read("*a")
  f:close()
  if type(text) ~= "string" then
    return false, "unreadable"
  end
  return text
end

local function reader_of(config, host)
  return config.read_file or (host and host.read_file) or default_read_file
end

-- Read and parse a credentials file: object | nil (absent) | false, err
local function read_credentials_file(read, path)
  local ok, text, why = compat.pcall(read, path)
  if not ok or text == false then
    return false, fail("Could not read the credentials file " .. path .. ".")
  end
  if text == nil then
    return nil
  end
  local doc = json.decode(text)
  if type(doc) ~= "table" or doc == null or json.is_array(doc) then
    return false, fail("The credentials file " .. path .. " is not a JSON object.")
  end
  return doc, why
end

local function require_fields(t, keys, what, path)
  local missing = {}
  for _, k in ipairs(keys) do
    if str(t, k) == nil then
      missing[#missing + 1] = k
    end
  end
  if #missing == 0 then
    return true
  end
  return nil, fail("The " .. what .. " in " .. path .. " is missing " .. join(missing, ", ") .. ".")
end

local function authorized_user_token(host, t, path, scopes)
  local ok, err =
    require_fields(t, { "client_id", "client_secret", "refresh_token" }, "user credentials", path)
  if not ok then
    return nil, err
  end
  return credentials.authorized_user_source({
    client_id = str(t, "client_id"),
    client_secret = secret.wrap(str(t, "client_secret")),
    refresh_token = secret.wrap(str(t, "refresh_token")),
    token_url = str(t, "token_uri"),
    scopes = scopes,
  })(host)
end

local function service_account_token(host, t, path, scopes)
  local ok, err = require_fields(t, { "client_email", "private_key" }, "service account key", path)
  if not ok then
    return nil, err
  end
  return credentials.service_account_key_source({
    client_email = str(t, "client_email"),
    private_key = secret.wrap(str(t, "private_key")),
    private_key_id = str(t, "private_key_id"),
    token_url = str(t, "token_uri"),
    scopes = scopes,
  })(host)
end

-- ".../serviceAccounts/<email>:generateAccessToken" -> <email> | nil | false, err
-- (decodeURIComponent: a "%" not followed by two hex digits is malformed)
local function impersonated_email(impersonation_url, path)
  local encoded = string.match(impersonation_url, "/serviceAccounts/([^/:]+):generateAccessToken$")
  if not encoded then
    return nil
  end
  if string.find(string.gsub(encoded, "%%%x%x", ""), "%%") then
    return false,
      fail(
        "The service_account_impersonation_url in "
          .. path
          .. " has a malformed percent-escape: "
          .. impersonation_url
          .. "."
      )
  end
  return (
    string.gsub(encoded, "%%(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end)
  )
end

-- the subject token an external_account file's credential_source points at
local function file_subject_token(host, read, source, path)
  local format = obj(source, "format")
  local field = str(format, "subject_token_field_name")
  local text
  if str(source, "file") then
    local file = str(source, "file")
    local ok, t = compat.pcall(read, file)
    if not ok or type(t) ~= "string" then
      return nil, fail("Could not read the subject token file " .. file .. ".")
    end
    text = t
  elseif str(source, "url") then
    local headers = {}
    for k, v in pairs(obj(source, "headers")) do
      if type(k) == "string" and type(v) == "string" then
        headers[string.lower(k)] = v
      end
    end
    local r, err = credentials.request_text(
      host,
      "Fetching the workload identity subject token",
      { method = "GET", url = str(source, "url"), headers = headers }
    )
    if not r then
      return nil, err
    end
    text = r.text
  else
    return nil,
      fail(
        "The external account in "
          .. path
          .. ' uses a credential_source this SDK does not read (only "file" and "url"). Use'
          .. " from_workload_identity and pass the subject token yourself."
      )
  end
  if str(format, "type") ~= "json" then
    return secret.wrap((string.gsub(string.gsub(text, "^%s+", ""), "%s+$", "")))
  end
  -- no cause: a JSON parse error message could quote the text, which is a secret
  local doc
  if field then
    doc = json.decode(text)
    if doc == nil then
      return nil,
        fail(
          "The subject token for "
            .. path
            .. ' is not valid JSON, but its credential_source format is "json".'
        )
    end
  end
  local token = field and type(doc) == "table" and doc ~= null and rawget(doc, field) or nil
  if type(token) ~= "string" then
    return nil,
      fail(
        "The subject token for " .. path .. " has no string field " .. (field or "(unnamed)") .. "."
      )
  end
  return secret.wrap(token)
end

local function external_account_token(host, read, t, path, scopes)
  local ok, err = require_fields(t, { "audience", "subject_token_type" }, "external account", path)
  if not ok then
    return nil, err
  end
  local source = obj(t, "credential_source")
  if str(source, "environment_id") ~= nil or rawget(source, "executable") ~= nil then
    return nil,
      fail(
        "The external account in "
          .. path
          .. " uses an AWS or executable credential_source, which this SDK does not support."
          .. " Use from_workload_identity and pass the subject token yourself."
      )
  end
  local impersonation_url = str(t, "service_account_impersonation_url")
  local email
  if impersonation_url then
    local e, eerr = impersonated_email(impersonation_url, path)
    if e == false then
      return nil, eerr
    end
    if not e or e == "" then
      return nil, fail("Could not read a service account from " .. impersonation_url .. ".")
    end
    email = e
  end
  local impersonation = obj(t, "service_account_impersonation")
  local lifetime = rawget(impersonation, "token_lifetime_seconds")
  return credentials.workload_identity_source({
    audience = str(t, "audience"),
    subject_token_type = str(t, "subject_token_type"),
    token_url = str(t, "token_url"),
    service_account_email = email,
    token_lifetime_seconds = type(lifetime) == "number" and lifetime or nil,
    scopes = scopes,
    subject_token = function(h)
      return file_subject_token(h, read, source, path)
    end,
  })(host)
end

local function impersonated_token(host, t, path, scopes)
  local impersonation_url = str(t, "service_account_impersonation_url")
  local email
  if impersonation_url then
    local e, eerr = impersonated_email(impersonation_url, path)
    if e == false then
      return nil, eerr
    end
    email = e
  end
  if not email or email == "" then
    return nil,
      fail(
        "The impersonated service account in "
          .. path
          .. " has no valid service_account_impersonation_url."
      )
  end
  local src = obj(t, "source_credentials")
  local source_token, serr
  -- the source token needs cloud-platform to call IAM Credentials; user credentials
  -- already carry it from gcloud
  if rawget(src, "type") == "authorized_user" then
    source_token, serr = authorized_user_token(host, src, path, nil)
  elseif rawget(src, "type") == "service_account" then
    source_token, serr =
      service_account_token(host, src, path, { credentials.CLOUD_PLATFORM_SCOPE })
  else
    return nil,
      fail(
        "The impersonated service account in "
          .. path
          .. " has source_credentials of type "
          .. url.text(rawget(src, "type"))
          .. "; only authorized_user and service_account are supported."
      )
  end
  if not source_token then
    return nil, serr
  end
  local delegates
  local d = rawget(t, "delegates")
  if type(d) == "table" and d ~= null then
    delegates = {}
    for _, v in ipairs(d) do
      if type(v) == "string" then
        delegates[#delegates + 1] = v
      end
    end
  end
  return credentials.impersonate_service_account(host, email, source_token, {
    scopes = scopes or { credentials.CLOUD_PLATFORM_SCOPE },
    delegates = delegates,
  })
end

local function json_type_text(v)
  if v == nil then
    return "undefined"
  end
  local text = json.encode(v)
  return text or url.text(v)
end

-- the token a credentials file describes, plus the project it names
local function file_source(host, read, t, path, scopes)
  local kind = rawget(t, "type")
  local token, err
  if kind == "authorized_user" then
    token, err = authorized_user_token(host, t, path, scopes)
  elseif kind == "service_account" then
    token, err = service_account_token(host, t, path, scopes)
  elseif kind == "external_account" then
    token, err = external_account_token(host, read, t, path, scopes)
  elseif kind == "impersonated_service_account" then
    token, err = impersonated_token(host, t, path, scopes)
  else
    return nil,
      fail(
        "The credentials file "
          .. path
          .. " has type "
          .. json_type_text(kind)
          .. "; expected authorized_user, service_account, external_account or"
          .. " impersonated_service_account."
      )
  end
  if not token then
    return nil, err
  end
  local quota = str(t, "quota_project_id")
  -- gcloud stores its active project as quota_project_id, so for user credentials it is
  -- the best guess at the project too
  token.project = str(t, "project_id") or quota
  token.quota_project = quota
  return token
end

--- credentials.application_default_source(config) -> source(host)
function credentials.application_default_source(config)
  config = config or {}
  local on_gcp = false
  return function(host)
    local read = reader_of(config, host)
    local token, err
    local explicit = getenv(host, "GOOGLE_APPLICATION_CREDENTIALS")
    if explicit ~= nil then
      local t, rerr = read_credentials_file(read, explicit)
      if t == false then
        return nil, rerr
      end
      if t == nil then
        return nil,
          fail("GOOGLE_APPLICATION_CREDENTIALS is set to " .. explicit .. ", which does not exist.")
      end
      token, err = file_source(host, read, t, explicit, config.scopes)
    else
      local path = credentials.well_known_path(host)
      local t, rerr
      if path ~= nil then
        t, rerr = read_credentials_file(read, path)
        if t == false then
          return nil, rerr
        end
      end
      if t ~= nil then
        token, err = file_source(host, read, t, path, config.scopes)
      else
        on_gcp = on_gcp or credentials.is_on_gcp(host)
        if not on_gcp then
          return nil,
            fail(
              "Could not find Application Default Credentials. Run `gcloud auth"
                .. " application-default login`, set GOOGLE_APPLICATION_CREDENTIALS to a"
                .. " credentials file, or run on Google Cloud."
            )
        end
        token, err = credentials.metadata_server_source({
          scopes = config.scopes,
          project = config.project,
        })(host)
      end
    end
    if not token then
      return nil, err
    end
    token.project = getenv(host, "GOOGLE_CLOUD_PROJECT")
      or getenv(host, "GCLOUD_PROJECT")
      or getenv(host, "GOOGLE_PROJECT_ID")
      or token.project
    token.quota_project = getenv(host, "GOOGLE_CLOUD_QUOTA_PROJECT") or token.quota_project
    return token
  end
end

--- credentials.from_application_default{ scopes?, project?, region?, quota_project?,
-- read_file? }: locally the login from `gcloud auth application-default login`, on
-- Google Cloud the attached service account. `project` and `quota_project` set here win
-- over GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_QUOTA_PROJECT and the file. read_file(path) ->
-- text | nil (absent) | false (unreadable) replaces io.open (tests, sandboxes).
function credentials.from_application_default(config)
  config = config or {}
  if type(config) ~= "table" then
    compat.raise("from_application_default: expected a table", 2)
  end
  if config.read_file ~= nil and type(config.read_file) ~= "function" then
    compat.raise("from_application_default: read_file must be a function", 2)
  end
  check_overrides("from_application_default", config)
  scopes_list("from_application_default", config.scopes)
  return credentials.refreshing(
    "application_default",
    credentials.application_default_source(config),
    config
  )
end

return credentials
