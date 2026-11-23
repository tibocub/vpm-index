-- AWS credentials: the default provider chain and its sources.
--
-- Port of Distilled's packages/aws/src/credential-providers/ (from-node-provider-chain,
-- from-env, from-ini, from-process, from-token-file, from-web-token, from-http,
-- from-container-metadata, from-instance-metadata, metadata-credentials, sts, profile),
-- util/parse-ini.ts and util/shared-config.ts, and the SSO part of auth.ts.
--
-- A source is a function `source(host) -> creds | nil, err`, the shape of a client's
-- secret-option source (distilled.credentials): the client caches what it returns, and
-- the AWS protocol re-resolves (through the Unauthorized refresh) once it expires.
--
--   creds = { access_key_id, secret_access_key, session_token?, expiration? (epoch
--             seconds), account_id?, region? (the region the profile names) }
--
--   aws_credentials.chain{ profile? } -> source       -- fromNodeProviderChain's order:
--     env (unless a profile is named) -> shared files (static, assume role, web identity,
--     credential_process, SSO) -> credential_process -> web identity token file ->
--     container (ECS / EKS) or instance metadata (IMDSv2, then v1)
--   aws_credentials.static{ access_key_id, secret_access_key, session_token? } -> source
--   aws_credentials.env(), .profile(name), .process(name), .token_file{...},
--   .web_token{ role_arn, web_identity_token, ... }, .container(), .instance_metadata()
--   aws_credentials.region(host, profile) -> region | nil   -- env, then the profile
--   aws_credentials.parse_ini(text, path) -> sections | nil, err
--
-- Files are read with io.open (like distilled.credentials.from_file); every process
-- runs through host.exec and every request through host.transport. Messages never hold
-- a key, a token or a command's output.
local codec = require("distilled.aws.codec")
local compat = require("distilled.compat")
local crypto = require("distilled.crypto")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")

local M = {}

local find, sub, gsub, match = string.find, string.sub, string.gsub, string.match

-- Distilled's AwsCredentialProviderError: the chain (or a named source) failed.
M.CredentialsError = errors.define({
  tag = "AwsCredentialsError",
  categories = { "AuthError", "ConfigurationError" },
  fields = { "provider", "hints" },
})
-- Distilled's MissingRegion.
M.MissingRegion = errors.define({
  tag = "MissingRegion",
  categories = { "ConfigurationError" },
  fields = { "hints" },
})

local DEFAULT_TIMEOUT_S = 1
-- credentials-service.ts CREDENTIAL_REFRESH_WINDOW_MS: refreshed 5 minutes early
M.REFRESH_WINDOW_S = 5 * 60

-- A source failure: `stop` (Distilled's tryNextLink = false) ends the chain with it.
local function failure(message, stop)
  return { message = message, stop = stop == true }
end

local function getenv(host, name)
  local g = host and host.getenv or os.getenv
  local v = g(name)
  if v == "" then
    return nil
  end
  return v
end

local function now_of(host)
  local f = host and (host.epoch or host.now)
  return f and f() or os.time()
end

local function trim(s)
  return (gsub(gsub(s, "^%s+", ""), "%s+$", ""))
end

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local text = f:read("*a")
  f:close()
  return text or ""
end

local function write_file(path, text)
  local f = io.open(path, "wb")
  if not f then
    return false
  end
  f:write(text)
  f:close()
  return true
end

---------------------------------------------------------------------------------------
-- shared config files (parse-ini.ts, shared-config.ts)
---------------------------------------------------------------------------------------

local SECTION_TYPES = { profile = true, ["sso-session"] = true, services = true }
local BLOCKED_NAMES = { ["__proto__"] = true, ["profile __proto__"] = true }

-- prefixKeyRegex = /^([\w-]+)\s(["'])?([\w-@\+\.%:/]+)\2$/
local function prefixed_section(name)
  local prefix, rest = match(name, "^([%w_%-]+)%s(.+)$")
  if not prefix then
    return nil
  end
  local q = sub(rest, 1, 1)
  if q == '"' or q == "'" then
    if sub(rest, -1) ~= q or #rest < 3 then
      return nil
    end
    rest = sub(rest, 2, -2)
  end
  if not find(rest, "^[%w_%-@%+%.%%:/]+$") then
    return nil
  end
  return prefix, rest
end

-- the text before a comment: `;` or `#` at the start or after whitespace
local function strip_comment(line)
  local at = find(line, "^[;#]")
  if at then
    return ""
  end
  local s = find(line, "%s[;#]")
  if s then
    return sub(line, 1, s - 1)
  end
  return line
end

local function split_lines(text)
  local lines = {}
  for line in string.gmatch(text .. "\n", "([^\n]*)\n") do
    lines[#lines + 1] = (gsub(line, "\r$", ""))
  end
  return lines
end

--- M.parse_ini(text, path) -> { [section] = { key = value } } | nil, err
-- `[profile x]` is "profile.x", `[sso-session s]` "sso-session.s"; a key with an empty
-- value opens a sub-section whose indented keys are "<key>.<name>".
function M.parse_ini(text, path)
  local map = {}
  local section, subsection
  for _, line in ipairs(split_lines(text)) do
    local trimmed = trim(strip_comment(line))
    if sub(trimmed, 1, 1) == "[" and sub(trimmed, -1) == "]" then
      section, subsection = nil, nil
      local name = sub(trimmed, 2, -2)
      local prefix, rest = prefixed_section(name)
      if prefix then
        if SECTION_TYPES[prefix] then
          section = prefix .. "." .. rest
        end
      else
        section = name
      end
      if BLOCKED_NAMES[name] then
        return nil, failure(tostring(path) .. ' has an invalid profile name "' .. name .. '"')
      end
    elseif section then
      local eq = find(trimmed, "=", 1, true)
      if eq and eq > 1 then
        local name = trim(sub(trimmed, 1, eq - 1))
        local value = trim(sub(trimmed, eq + 1))
        if value == "" then
          subsection = name
        else
          if subsection and not find(line, "^%s") then
            subsection = nil
          end
          map[section] = map[section] or {}
          map[section][subsection and (subsection .. "." .. name) or name] = value
        end
      end
    end
  end
  return map
end

local function home_dir(host)
  return getenv(host, "HOME")
    or getenv(host, "USERPROFILE")
    or (getenv(host, "HOMEPATH") and ((getenv(host, "HOMEDRIVE") or "C:\\") .. getenv(
      host,
      "HOMEPATH"
    )))
    or "."
end
M.home_dir = home_dir

local function resolve_home(host, path)
  if sub(path, 1, 2) == "~/" then
    return home_dir(host) .. "/" .. sub(path, 3)
  end
  return path
end

function M.config_path(host)
  return resolve_home(host, getenv(host, "AWS_CONFIG_FILE") or (home_dir(host) .. "/.aws/config"))
end

function M.credentials_path(host)
  return resolve_home(
    host,
    getenv(host, "AWS_SHARED_CREDENTIALS_FILE") or (home_dir(host) .. "/.aws/credentials")
  )
end

local function read_ini(path)
  local text = read_file(path) or "" -- a missing file is an empty one
  return M.parse_ini(text, path)
end

-- configSections: `default` and the prefixed sections, "profile.x" as "x"
local function config_sections(data)
  local out = {}
  if data.default then
    out.default = data.default
  end
  for key, value in pairs(data) do
    local dot = find(key, ".", 1, true)
    if dot then
      local prefix = sub(key, 1, dot - 1)
      if SECTION_TYPES[prefix] then
        out[prefix == "profile" and sub(key, dot + 1) or key] = value
      end
    end
  end
  return out
end

--- M.load_files(host) -> { config_file, credentials_file } | nil, failure
function M.load_files(host)
  local config, err = read_ini(M.config_path(host))
  if not config then
    return nil, err
  end
  local creds, err2 = read_ini(M.credentials_path(host))
  if not creds then
    return nil, err2
  end
  return { config_file = config_sections(config), credentials_file = creds }
end

--- M.load_profiles(host) -> merged profiles (credentials file over config file)
function M.load_profiles(host)
  local files, err = M.load_files(host)
  if not files then
    return nil, err
  end
  local merged = {}
  for name, values in pairs(files.config_file) do
    merged[name] = values
  end
  for name, values in pairs(files.credentials_file) do
    local out = {}
    for k, v in pairs(merged[name] or {}) do
      out[k] = v
    end
    for k, v in pairs(values) do
      out[k] = v
    end
    merged[name] = out
  end
  return merged, nil, files
end

local function profile_name(host, profile)
  return profile or getenv(host, "AWS_PROFILE") or "default"
end

--- M.region(host, profile) -> region | nil: AWS_REGION, AWS_DEFAULT_REGION, then the
-- profile's `region` in the config file (profile.ts profileRegion)
function M.region(host, profile)
  local r = getenv(host, "AWS_REGION") or getenv(host, "AWS_DEFAULT_REGION")
  if r then
    return r
  end
  local files = M.load_files(host)
  if not files then
    return nil
  end
  local name = profile
    or getenv(host, "AWS_PROFILE")
    or getenv(host, "AWS_DEFAULT_PROFILE")
    or "default"
  local section = files.config_file[name]
  return section and section.region or nil
end

---------------------------------------------------------------------------------------
-- HTTP (metadata services, STS, SSO)
---------------------------------------------------------------------------------------

local function send(host, request)
  local transport = host and host.transport
  if transport == nil then
    return nil, failure("no transport to reach " .. request.url)
  end
  local res, err = transport(request)
  if type(res) ~= "table" then
    return nil, failure(tostring(err and err.message or err or "transport failed"))
  end
  return res
end

local function header(res, name)
  local h = res.headers or {}
  return h[name] or h[string.lower(name)]
end

---------------------------------------------------------------------------------------
-- STS (sts.ts): AssumeRole and AssumeRoleWithWebIdentity over awsQuery
---------------------------------------------------------------------------------------

local function sts_region(host, region, profile_region)
  return region
    or getenv(host, "AWS_REGION")
    or getenv(host, "AWS_DEFAULT_REGION")
    or profile_region
    or "us-east-1"
end

local function form(params)
  local url = require("distilled.url")
  local keys = {}
  for k in pairs(params) do
    keys[#keys + 1] = k
  end
  table.sort(keys, function(a, b)
    -- Action and Version first, as the query serializer writes them
    local ra = (a == "Action" and 1) or (a == "Version" and 2) or 3
    local rb = (b == "Action" and 1) or (b == "Version" and 2) or 3
    if ra ~= rb then
      return ra < rb
    end
    return a < b
  end)
  local out = {}
  for _, k in ipairs(keys) do
    out[#out + 1] = url.encode_component(k) .. "=" .. url.encode_component(params[k])
  end
  return table.concat(out, "&")
end

local function sts_call(host, action, params, region, signing_creds)
  local endpoint = require("distilled.aws.endpoint")
  local p = { Action = action, Version = "2011-06-15" }
  for k, v in pairs(params) do
    p[k] = secret.unwrap(v)
  end
  local request = {
    method = "POST",
    url = "https://sts." .. region .. "." .. endpoint.dns_suffix(region) .. "/",
    headers = { ["content-type"] = "application/x-www-form-urlencoded" },
    body = form(p),
    timeout = 10,
  }
  if signing_creds then
    local signed, err = require("distilled.sigv4").sign({
      request = request,
      credentials = signing_creds,
      region = region,
      service = "sts",
      now_epoch = now_of(host),
    })
    if not signed then
      return nil, failure(err.message, true)
    end
    request = signed
  end
  local res, err = send(host, request)
  if not res then
    err.stop = true
    return nil, err
  end
  local xml = require("distilled.xml")
  local tree = xml.decode(res.body or "")
  if res.status < 200 or res.status >= 300 then
    local code, message
    local er = tree and tree.ErrorResponse
    if type(er) == "table" and type(er.Error) == "table" then
      code, message = er.Error.Code, er.Error.Message
    end
    return nil,
      failure(
        "STS "
          .. action
          .. " failed (status "
          .. tostring(res.status)
          .. (type(code) == "string" and (", " .. code) or "")
          .. ")"
          .. (type(message) == "string" and (": " .. message) or ""),
        true
      )
  end
  local result = tree and tree[action .. "Response"]
  result = type(result) == "table" and result[action .. "Result"] or nil
  local c = type(result) == "table" and result.Credentials or nil
  if
    type(c) ~= "table"
    or type(c.AccessKeyId) ~= "string"
    or type(c.SecretAccessKey) ~= "string"
  then
    return nil,
      failure("Invalid response from STS call with role " .. tostring(params.RoleArn), true)
  end
  local arn = type(result.AssumedRoleUser) == "table" and result.AssumedRoleUser.Arn
  local account
  if type(arn) == "string" then
    local parts = require("distilled.aws.endpoint").split(arn, ":")
    if #parts > 4 and parts[5] ~= "" then
      account = parts[5]
    end
  end
  return {
    access_key_id = c.AccessKeyId,
    secret_access_key = c.SecretAccessKey,
    session_token = type(c.SessionToken) == "string" and c.SessionToken or nil,
    expiration = codec.parse_date(c.Expiration),
    account_id = account,
  }
end

local function session_name(host, prefix)
  return prefix .. tostring(math.floor(now_of(host) * 1000))
end

---------------------------------------------------------------------------------------
-- sources
---------------------------------------------------------------------------------------

-- from-env.ts
local function env_source(host)
  local key = getenv(host, "AWS_ACCESS_KEY_ID")
  local secret_key = getenv(host, "AWS_SECRET_ACCESS_KEY")
  if key and secret_key then
    local expiry = getenv(host, "AWS_CREDENTIAL_EXPIRATION")
    return {
      access_key_id = key,
      secret_access_key = secret_key,
      session_token = getenv(host, "AWS_SESSION_TOKEN"),
      expiration = expiry and codec.parse_date(expiry) or nil,
      account_id = getenv(host, "AWS_ACCOUNT_ID"),
    }
  end
  return nil, failure("Unable to find environment variable credentials.")
end

-- metadata-credentials.ts parseImdsCredentials
local function parse_metadata_credentials(text)
  local v = json.decode(text or "")
  if
    type(v) ~= "table"
    or type(v.AccessKeyId) ~= "string"
    or type(v.SecretAccessKey) ~= "string"
    or type(v.Token) ~= "string"
    or type(v.Expiration) ~= "string"
  then
    return nil
  end
  return {
    access_key_id = v.AccessKeyId,
    secret_access_key = v.SecretAccessKey,
    session_token = v.Token,
    expiration = codec.parse_date(v.Expiration),
    account_id = type(v.AccountId) == "string" and v.AccountId or nil,
  }
end

local function http_credentials(host, url, authorization)
  local headers = {}
  if authorization then
    headers.authorization = authorization
  end
  local res, err = send(host, {
    method = "GET",
    url = url,
    headers = headers,
    timeout = DEFAULT_TIMEOUT_S,
  })
  if not res then
    return nil, err
  end
  if res.status == 200 then
    local c = parse_metadata_credentials(res.body)
    if not c then
      return nil,
        failure(
          "HTTP credential provider response not of the required format, an object matching: "
            .. "{ AccessKeyId: string, SecretAccessKey: string, Token: string, Expiration: string(rfc3339) }"
        )
    end
    return c
  end
  local detail = ""
  if res.status >= 400 and res.status < 500 then
    local body = json.decode(res.body or "")
    if
      type(body) == "table" and (type(body.Code) == "string" or type(body.Message) == "string")
    then
      detail = trim(
        " "
          .. (type(body.Code) == "string" and body.Code or "")
          .. " "
          .. (type(body.Message) == "string" and body.Message or "")
      )
      detail = " " .. detail
    end
  end
  return nil, failure("Server responded with status: " .. tostring(res.status) .. detail)
end

local CMDS_IP = "169.254.170.2"

-- from-http.ts checkUrl: https, or a loopback / container host over http
local function accepted_url(url)
  -- an IPv6 host keeps its brackets (and holds colons)
  local scheme, host = match(url, "^(%a[%w+.-]*)://(%[[^%]]*%])")
  if not scheme then
    scheme, host = match(url, "^(%a[%w+.-]*)://([^/:?#]*)")
  end
  if not scheme then
    return false, "not a valid credential provider URL"
  end
  if string.lower(scheme) == "https" then
    return true
  end
  host = string.lower(host or "")
  if host == CMDS_IP or host == "169.254.170.23" or host == "[fd00:ec2::23]" then
    return true
  end
  if host == "[::1]" or host == "[0000:0000:0000:0000:0000:0000:0000:0001]" then
    return true
  end
  if host == "localhost" then
    return true
  end
  local a, b, c, d = match(host, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if a == "127" and tonumber(b) <= 255 and tonumber(c) <= 255 and tonumber(d) <= 255 then
    return true
  end
  return false,
    "URL not accepted. It must either be HTTPS or match one of the following:\n"
      .. "  - loopback CIDR 127.0.0.0/8 or [::1/128]\n"
      .. "  - ECS container host 169.254.170.2\n"
      .. "  - EKS container host 169.254.170.23 or [fd00:ec2::23]"
end

-- from-http.ts httpSource (ECS / EKS container credentials, with the token file)
local function container_source(host)
  local relative = getenv(host, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
  local full = getenv(host, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
  local url = relative and ("http://" .. CMDS_IP .. relative) or full
  if not url then
    return nil,
      failure(
        "No HTTP credential provider host provided.\n"
          .. "Set AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI."
      )
  end
  local ok, why = accepted_url(url)
  if not ok then
    return nil, failure(why)
  end
  local token
  local token_file = getenv(host, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
  if token_file then
    token = read_file(token_file)
    if token == nil then
      return nil,
        failure("Could not read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE " .. token_file .. ".")
    end
    token = trim(token)
  else
    token = getenv(host, "AWS_CONTAINER_AUTHORIZATION_TOKEN")
  end
  if token and find(token, "\r\n", 1, true) then
    return nil, failure("Authorization token contains invalid \\r\\n sequence.")
  end
  -- Distilled retries 3 times, spaced by the timeout
  local c, err
  for attempt = 1, 4 do
    c, err = http_credentials(host, url, token)
    if c then
      return c
    end
    if attempt < 4 and host.sleep then
      host.sleep(DEFAULT_TIMEOUT_S)
    end
  end
  return nil, err
end

-- from-instance-metadata.ts: IMDSv2 (token), falling back to v1 unless disabled
local IMDS_PATH = "/latest/meta-data/iam/security-credentials/"

local function imds_source(host, profile_config)
  profile_config = profile_config or {}
  local endpoint = getenv(host, "AWS_EC2_METADATA_SERVICE_ENDPOINT")
    or profile_config.ec2_metadata_service_endpoint
  if not endpoint then
    local mode = getenv(host, "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE")
      or profile_config.ec2_metadata_service_endpoint_mode
      or "IPv4"
    if mode == "IPv4" then
      endpoint = "http://169.254.169.254"
    elseif mode == "IPv6" then
      endpoint = "http://[fd00:ec2::254]"
    else
      return nil, failure("Unsupported endpoint mode: " .. mode .. ". Select from IPv4, IPv6", true)
    end
  end
  local function request(path, method, headers)
    local res, err = send(host, {
      method = method,
      url = endpoint .. path,
      headers = headers,
      timeout = DEFAULT_TIMEOUT_S,
    })
    if not res then
      err.timeout = true
      return nil, err
    end
    if res.status >= 200 and res.status < 300 then
      return res.body or ""
    end
    local f = failure(
      "Error response received from instance metadata service (status "
        .. tostring(res.status)
        .. ")"
    )
    f.status = res.status
    return nil, f
  end
  local headers = {}
  local token, terr = request("/latest/api/token", "PUT", {
    ["x-aws-ec2-metadata-token-ttl-seconds"] = "21600",
  })
  if token then
    headers["x-aws-ec2-metadata-token"] = token
  elseif terr.status == 400 then
    return nil, failure("EC2 Metadata token request returned error")
  end
  if not token then
    local env_value = getenv(host, "AWS_EC2_METADATA_V1_DISABLED")
    local blocked_env = env_value ~= nil and env_value ~= "false"
    local pv = env_value == nil and profile_config.ec2_metadata_v1_disabled or nil
    local blocked_profile = pv ~= nil and pv ~= "false"
    if blocked_env or blocked_profile then
      local causes = {}
      if blocked_profile then
        causes[#causes + 1] = "config file profile (ec2_metadata_v1_disabled)"
      end
      if blocked_env then
        causes[#causes + 1] = "process environment variable (AWS_EC2_METADATA_V1_DISABLED)"
      end
      return nil,
        failure(
          "AWS EC2 Metadata v1 fallback has been blocked by AWS SDK configuration in the following: ["
            .. table.concat(causes, ", ")
            .. "].",
          true
        )
    end
  end
  local role, rerr = request(IMDS_PATH, "GET", headers)
  if not role then
    return nil, rerr
  end
  local text, cerr = request(IMDS_PATH .. trim(role), "GET", headers)
  if not text then
    return nil, cerr
  end
  local c = parse_metadata_credentials(text)
  if not c then
    return nil, failure("Invalid response received from instance metadata service.")
  end
  local now = now_of(host)
  if c.expiration and c.expiration < now then
    -- static stability: expired credentials are used for 5 to 10 more minutes
    local random = host.random or math.random
    c.expiration = now + 300 + math.floor(random() * 300)
  end
  return c
end

-- from-process.ts
local function process_credentials(host, name, profiles)
  local profile = profiles[name]
  if not profile then
    return nil, failure("Profile " .. name .. " could not be found in shared credentials file.")
  end
  local command = profile.credential_process
  if command == nil then
    return nil, failure("Profile " .. name .. " did not contain credential_process.")
  end
  local function invalid(reason)
    return nil, failure("Profile " .. name .. " credential_process " .. reason .. ".")
  end
  local exec = host and host.exec
  if not exec then
    return nil, failure("Profile " .. name .. " credential_process needs a host with exec.")
  end
  -- exec(command) runs through a shell in Node: so does this
  local res = exec({ "/bin/sh", "-c", command }, { timeout = 60 })
  if type(res) ~= "table" or res.timed_out or res.ok == false or (res.code or 0) ~= 0 then
    return invalid(
      "failed (exit code " .. tostring(type(res) == "table" and res.code or "?") .. ")"
    )
  end
  local data = json.decode(trim(res.stdout or ""))
  if data == nil then
    return invalid("returned invalid JSON")
  end
  if type(data) ~= "table" or data == json.null then
    return invalid("did not return a JSON object")
  end
  if data.Version ~= 1 then
    return invalid("did not return Version 1")
  end
  if data.AccessKeyId == nil or data.SecretAccessKey == nil then
    return invalid("returned invalid credentials")
  end
  local expiration = type(data.Expiration) == "string" and codec.parse_date(data.Expiration) or nil
  if expiration and expiration < now_of(host) then
    return invalid("returned expired credentials")
  end
  local account = data.AccountId or profile.aws_account_id
  return {
    access_key_id = data.AccessKeyId,
    secret_access_key = data.SecretAccessKey,
    session_token = type(data.SessionToken) == "string"
        and data.SessionToken ~= ""
        and data.SessionToken
      or nil,
    expiration = expiration,
    account_id = account,
  }
end

-- from-token-file.ts
local function token_file_credentials(host, opts, profile_region)
  local file = opts.web_identity_token_file or getenv(host, "AWS_WEB_IDENTITY_TOKEN_FILE")
  local role = opts.role_arn or getenv(host, "AWS_ROLE_ARN")
  local session = opts.role_session_name or getenv(host, "AWS_ROLE_SESSION_NAME")
  if not file or not role then
    return nil, failure("Web identity configuration not specified")
  end
  local token = read_file(file)
  if token == nil then
    return nil, failure("Could not read web identity token file " .. file .. ".")
  end
  return sts_call(host, "AssumeRoleWithWebIdentity", {
    RoleArn = role,
    RoleSessionName = session or session_name(host, "aws-sdk-js-session-"),
    WebIdentityToken = token,
  }, sts_region(host, opts.region, profile_region))
end

-- auth.ts loadProfileCredentials (SSO): the role credentials cached by `aws sso login`
-- or this SDK, else the portal with the cached token (refreshed through OIDC when it
-- has a refresh token).
local SSO_REFRESH =
  "To refresh this SSO session run 'aws sso login' with the corresponding profile."

local function sha1_hex(s)
  return crypto.hex.encode(crypto.sha1(s))
end

local function sso_credentials(host, name, profiles, files, region_fallback)
  local profile = {}
  for k, v in pairs(profiles[name] or {}) do
    profile[k] = v
  end
  local endpoint = require("distilled.aws.endpoint")
  if profile.sso_session then
    local session = files.config_file["sso-session." .. profile.sso_session]
    if not session then
      return nil,
        failure(
          "Profile "
            .. name
            .. " sets sso_session = "
            .. profile.sso_session
            .. ", but "
            .. M.config_path(host)
            .. " has no [sso-session "
            .. profile.sso_session
            .. "] section.",
          true
        )
    end
    if profile.sso_start_url and profile.sso_start_url ~= session.sso_start_url then
      return nil, failure("Conflicting SSO start url", true)
    end
    profile.sso_region = session.sso_region
    profile.sso_start_url = session.sso_start_url
  end
  local missing = {}
  for _, f in ipairs({ "sso_start_url", "sso_account_id", "sso_region", "sso_role_name" }) do
    if not profile[f] then
      missing[#missing + 1] = f
    end
  end
  if #missing > 0 then
    return nil,
      failure(
        'Profile is configured with invalid SSO credentials. Required parameters "sso_account_id", '
          .. '"sso_region", "sso_role_name", "sso_start_url". Missing: '
          .. table.concat(missing, ", "),
        true
      )
  end
  local region = profile.region or profile.sso_region or region_fallback
  local cache = home_dir(host) .. "/.aws/sso/cache/"
  local key = profile.sso_session or profile.sso_start_url
  local token_path = cache .. sha1_hex(key) .. ".json"
  local creds_path = cache
    .. sha1_hex(
      (profile.sso_session or profile.sso_start_url or "")
        .. "\n"
        .. (profile.sso_account_id or "")
        .. "\n"
        .. (profile.sso_role_name or "")
    )
    .. ".credentials.json"
  local now = now_of(host)
  local function expired(expiry)
    local at = type(expiry) == "number" and expiry / 1000 or codec.parse_date(expiry)
    return at == nil or at - now <= M.REFRESH_WINDOW_S
  end
  local cached = json.decode(read_file(creds_path) or "")
  if
    type(cached) == "table"
    and type(cached.accessKeyId) == "string"
    and type(cached.secretAccessKey) == "string"
    and type(cached.expiry) == "number"
    and cached.sso_account_id == profile.sso_account_id
    and cached.sso_role_name == profile.sso_role_name
    and not expired(cached.expiry)
  then
    return {
      access_key_id = cached.accessKeyId,
      secret_access_key = cached.secretAccessKey,
      session_token = type(cached.sessionToken) == "string" and cached.sessionToken or nil,
      expiration = cached.expiry / 1000,
      region = region,
    }
  end
  local invalid_token = "The SSO session token associated with profile="
    .. name
    .. " was not found or is invalid. "
    .. SSO_REFRESH
  local token = json.decode(read_file(token_path) or "")
  if type(token) ~= "table" or token == json.null then
    return nil, failure(invalid_token, true)
  end
  local access = token.accessToken
  if expired(token.expiresAt) then
    local still_valid = (codec.parse_date(token.expiresAt) or 0) > now
    local refreshed
    if
      type(token.refreshToken) == "string"
      and type(token.clientId) == "string"
      and type(token.clientSecret) == "string"
      and not (
        token.registrationExpiresAt
        and (codec.parse_date(token.registrationExpiresAt) or 0) <= now
      )
    then
      local sr = profile.sso_region
      local res = send(host, {
        method = "POST",
        url = "https://oidc." .. sr .. "." .. endpoint.dns_suffix(sr) .. "/token",
        headers = { ["content-type"] = "application/json", ["user-agent"] = "distilled-lua" },
        body = json.encode(json.object({
          clientId = token.clientId,
          clientSecret = token.clientSecret,
          grantType = "refresh_token",
          refreshToken = token.refreshToken,
        })),
        timeout = 10,
      })
      local body = res and json.decode(res.body or "")
      if
        res
        and res.status >= 200
        and res.status < 300
        and type(body) == "table"
        and type(body.accessToken) == "string"
      then
        refreshed = body.accessToken
        local updated = {}
        for k, v in pairs(token) do
          updated[k] = v
        end
        updated.accessToken = refreshed
        updated.expiresAt = codec.iso8601(now + (tonumber(body.expiresIn) or 3600))
        if type(body.refreshToken) == "string" then
          updated.refreshToken = body.refreshToken
        end
        write_file(token_path, json.encode(json.object(updated)))
      end
    end
    if refreshed then
      access = refreshed
    elseif not still_valid then
      return nil, failure(invalid_token, true)
    end
  end
  if type(access) ~= "string" then
    return nil, failure(invalid_token, true)
  end
  local url = require("distilled.url")
  local sr = profile.sso_region
  local res, err = send(host, {
    method = "GET",
    url = "https://portal.sso."
      .. sr
      .. "."
      .. endpoint.dns_suffix(sr)
      .. "/federation/credentials?account_id="
      .. url.encode_component(profile.sso_account_id)
      .. "&role_name="
      .. url.encode_component(profile.sso_role_name),
    headers = {
      ["user-agent"] = "distilled-lua",
      ["content-type"] = "application/json",
      ["x-amz-sso_bearer_token"] = access,
    },
    timeout = 10,
  })
  if not res then
    err.stop = true
    return nil, err
  end
  local body = json.decode(res.body or "")
  local rc = type(body) == "table" and body.roleCredentials or nil
  if type(rc) ~= "table" then
    return nil,
      failure(
        "AWS SSO portal did not return roleCredentials for profile="
          .. name
          .. " (account="
          .. profile.sso_account_id
          .. " role="
          .. profile.sso_role_name
          .. ", status="
          .. tostring(res.status)
          .. (type(body) == "table" and type(body.message) == "string" and (", " .. body.message) or "")
          .. "). "
          .. SSO_REFRESH,
        true
      )
  end
  write_file(
    creds_path,
    json.encode(json.object({
      accessKeyId = rc.accessKeyId,
      secretAccessKey = rc.secretAccessKey,
      sessionToken = rc.sessionToken,
      expiry = rc.expiration,
      sso_account_id = profile.sso_account_id,
      sso_role_name = profile.sso_role_name,
    }))
  )
  return {
    access_key_id = rc.accessKeyId,
    secret_access_key = rc.secretAccessKey,
    session_token = rc.sessionToken,
    expiration = type(rc.expiration) == "number" and rc.expiration / 1000 or nil,
    region = region,
  }
end

-- from-ini.ts
local function is_string(v)
  return type(v) == "string"
end

local function static_profile(p)
  return is_string(p.aws_access_key_id) and is_string(p.aws_secret_access_key)
end

local function assume_role_profile(p)
  return is_string(p.role_arn)
    and (
      (is_string(p.source_profile) and p.credential_source == nil)
      or (is_string(p.credential_source) and p.source_profile == nil)
    )
end

local function source_without_role(p)
  return not p.role_arn and p.credential_source ~= nil
end

local function static_credentials(p)
  return {
    access_key_id = p.aws_access_key_id,
    secret_access_key = p.aws_secret_access_key,
    session_token = p.aws_session_token,
    account_id = p.aws_account_id,
  }
end

local MAX_PROFILE_DEPTH = 16

local resolve_profile

local function credential_source(host, source, name)
  if source == "EcsContainer" then
    return container_source(host)
  elseif source == "Ec2InstanceMetadata" then
    return imds_source(host)
  elseif source == "Environment" then
    return env_source(host)
  end
  return nil,
    failure(
      "Unsupported credential source in profile "
        .. name
        .. ". Got "
        .. tostring(source)
        .. ", expected EcsContainer or Ec2InstanceMetadata or Environment."
    )
end

local function assume_role(host, name, ctx, visited, depth)
  local profile = ctx.profiles[name]
  local source_name = profile.source_profile
  if source_name and visited[source_name] then
    local list = {}
    for k in pairs(visited) do
      list[#list + 1] = k
    end
    table.sort(list)
    return nil,
      failure(
        "Detected a cycle attempting to resolve credentials for profile "
          .. ctx.root
          .. ". Profiles visited: "
          .. table.concat(list, ", ")
      )
  end
  local source, err
  if source_name then
    local next_visited = { [source_name] = true }
    for k in pairs(visited) do
      next_visited[k] = true
    end
    source, err = resolve_profile(
      host,
      source_name,
      ctx,
      next_visited,
      source_without_role(ctx.profiles[source_name] or {}),
      depth + 1
    )
  else
    source, err = credential_source(host, profile.credential_source, name)
  end
  if not source then
    return nil, err
  end
  if source_without_role(profile) then
    return source
  end
  if profile.mfa_serial then
    if not ctx.mfa_code then
      return nil,
        failure(
          "Profile "
            .. name
            .. " requires multi-factor authentication, but no MFA code callback was provided.",
          true
        )
    end
  end
  local params = {
    RoleArn = profile.role_arn,
    RoleSessionName = profile.role_session_name or session_name(host, "aws-sdk-js-"),
    ExternalId = profile.external_id,
    DurationSeconds = tostring(math.floor(tonumber(profile.duration_seconds or "3600") or 3600)),
  }
  if profile.mfa_serial then
    params.SerialNumber = profile.mfa_serial
    local code, cerr = ctx.mfa_code(profile.mfa_serial)
    if not code then
      return nil,
        failure("Profile " .. name .. ": MFA code provider failed: " .. tostring(cerr), true)
    end
    params.TokenCode = code
  end
  local root_config = ctx.files.config_file[ctx.root] or {}
  local region = sts_region(host, profile.region, root_config.region)
  return sts_call(host, "AssumeRole", params, region, {
    access_key_id = source.access_key_id,
    secret_access_key = source.secret_access_key,
    session_token = source.session_token,
  })
end

resolve_profile = function(host, name, ctx, visited, recursive_assume, depth)
  if depth > MAX_PROFILE_DEPTH then
    return nil, failure("Profile " .. name .. ": source_profile chain is too long")
  end
  local profile = ctx.profiles[name]
  if not profile then
    return nil,
      failure(
        "Could not resolve credentials using profile: ["
          .. name
          .. "] in configuration/credentials file(s)."
      )
  end
  if next(visited) ~= nil and static_profile(profile) then
    return static_credentials(profile)
  end
  if recursive_assume or assume_role_profile(profile) then
    return assume_role(host, name, ctx, visited, depth)
  end
  if static_profile(profile) then
    return static_credentials(profile)
  end
  if is_string(profile.web_identity_token_file) and is_string(profile.role_arn) then
    local root_config = ctx.files.config_file[ctx.root] or {}
    return token_file_credentials(host, {
      web_identity_token_file = profile.web_identity_token_file,
      role_arn = profile.role_arn,
      role_session_name = profile.role_session_name,
    }, root_config.region)
  end
  if is_string(profile.credential_process) then
    return process_credentials(host, name, ctx.profiles)
  end
  if is_string(profile.login_session) then
    return nil,
      failure(
        "Profile "
          .. name
          .. " uses login_session (`aws login`), which distilled-lua does not support yet.",
        true
      )
  end
  if
    is_string(profile.sso_start_url)
    or is_string(profile.sso_account_id)
    or is_string(profile.sso_session)
    or is_string(profile.sso_region)
    or is_string(profile.sso_role_name)
  then
    return sso_credentials(host, name, ctx.profiles, ctx.files, M.region(host, ctx.root))
  end
  return nil,
    failure(
      "Could not resolve credentials using profile: ["
        .. name
        .. "] in configuration/credentials file(s)."
    )
end

local function ini_source(host, opts)
  local profiles, err, files = M.load_profiles(host)
  if not profiles then
    return nil, err
  end
  local root = profile_name(host, opts.profile)
  return resolve_profile(host, root, {
    profiles = profiles,
    files = files,
    root = root,
    mfa_code = opts.mfa_code,
  }, {}, false, 0)
end

local function process_source(host, opts)
  local profiles, err = M.load_profiles(host)
  if not profiles then
    return nil, err
  end
  return process_credentials(host, profile_name(host, opts.profile), profiles)
end

local function remote_source(host, opts)
  if
    getenv(host, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    or getenv(host, "AWS_CONTAINER_CREDENTIALS_FULL_URI")
  then
    return container_source(host)
  end
  local disabled = getenv(host, "AWS_EC2_METADATA_DISABLED")
  if disabled and disabled ~= "false" then
    return nil, failure("EC2 Instance Metadata Service access disabled")
  end
  local files = M.load_files(host)
  local config = files and files.config_file[profile_name(host, opts.profile)] or nil
  return imds_source(host, config)
end

---------------------------------------------------------------------------------------
-- providers (createLazyProvider): a source plus the region and the error shape
---------------------------------------------------------------------------------------

local function finish(host, creds, region_profile, provider, hints)
  if type(creds) ~= "table" then
    return nil
  end
  local out = {}
  for k, v in pairs(creds) do
    out[k] = secret.unwrap(v)
  end
  if out.region == nil then
    out.region = M.region(host, region_profile)
  end
  out.provider = provider
  return out
end

local function credentials_error(provider, err, hints)
  return errors.new(M.CredentialsError, {
    message = "Failed to resolve credentials from " .. provider .. ": " .. tostring(
      err and err.message or "no credentials"
    ),
    provider = provider,
    hints = hints,
  })
end

local function provider(name, hints, run, region_profile)
  return function(host)
    local creds, err = run(host)
    if not creds then
      return nil, credentials_error(name, err, hints)
    end
    return finish(host, creds, region_profile, name, hints)
  end
end

--- M.chain{ profile?, mfa_code? } -> source: the default chain (fromNodeProviderChain)
function M.chain(opts)
  opts = opts or {}
  local links = {
    -- envUnlessProfile: a named profile (option or AWS_PROFILE) skips the environment
    function(host)
      if opts.profile or getenv(host, "AWS_PROFILE") then
        return nil, failure("AWS_PROFILE is set, skipping fromEnv provider.")
      end
      return env_source(host)
    end,
    function(host)
      return ini_source(host, opts)
    end,
    function(host)
      return process_source(host, opts)
    end,
    function(host)
      return token_file_credentials(host, {})
    end,
    function(host)
      return remote_source(host, opts)
    end,
  }
  return provider("chain", {
    "Configure at least one credential source for the default chain.",
    "If using SSO, run `aws sso login` for the profile.",
  }, function(host)
    local last
    for _, link in ipairs(links) do
      local creds, err = link(host)
      if creds then
        return creds
      end
      last = err
      if err and err.stop then
        return nil, err
      end
    end
    return nil,
      failure("Could not load credentials from any providers: " .. tostring(last and last.message))
  end, opts.profile)
end

--- M.default: the chain with no options (the generated clients' default source)
M.default = M.chain()

--- M.static{ access_key_id, secret_access_key, session_token?, region? } -> source
function M.static(c)
  if type(c) ~= "table" then
    compat.raise("aws.credentials.static: expected { access_key_id, secret_access_key }", 2)
  end
  return function(host)
    local out = {}
    for k, v in pairs(c) do
      out[k] = v
    end
    if out.access_key_id == nil or out.secret_access_key == nil then
      return nil,
        credentials_error("static", failure("access_key_id and secret_access_key are required"))
    end
    return finish(host, out, nil, "static")
  end
end

function M.env()
  return provider("env", {
    "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN if needed).",
  }, env_source)
end

--- M.profile(name | { profile, mfa_code }) -> source: the shared files only (fromIni)
function M.profile(opts)
  if type(opts) ~= "table" then
    opts = { profile = opts }
  end
  return provider(
    "ini",
    { "Check ~/.aws/credentials and ~/.aws/config for the profile." },
    function(host)
      return ini_source(host, opts)
    end,
    opts.profile
  )
end

function M.process(name)
  return provider("process", {
    "Set credential_process in the profile to a command that prints Version 1 JSON.",
  }, function(host)
    return process_source(host, { profile = name })
  end, name)
end

--- M.token_file{ web_identity_token_file?, role_arn?, role_session_name?, region? }
function M.token_file(opts)
  opts = opts or {}
  return provider("token-file", {
    "Set AWS_WEB_IDENTITY_TOKEN_FILE and ensure the file is readable.",
  }, function(host)
    return token_file_credentials(host, opts)
  end)
end

--- M.web_token{ role_arn, web_identity_token (string, secret or fn(host)),
-- role_session_name?, provider_id?, policy?, duration_seconds?, region? }
function M.web_token(opts)
  if type(opts) ~= "table" or type(opts.role_arn) ~= "string" then
    compat.raise("aws.credentials.web_token: expected { role_arn, web_identity_token }", 2)
  end
  return provider("web-token", {
    "Check that the web identity token is valid and trusted by the role's trust policy.",
  }, function(host)
    local token, err = require("distilled.credentials").resolve(opts.web_identity_token, host)
    if not token then
      return nil,
        failure("Could not resolve the web identity token: " .. tostring(err.message), true)
    end
    local params = {
      RoleArn = opts.role_arn,
      RoleSessionName = opts.role_session_name or session_name(host, "aws-sdk-js-session-"),
      WebIdentityToken = token,
      ProviderId = opts.provider_id,
      Policy = opts.policy,
      DurationSeconds = opts.duration_seconds and tostring(opts.duration_seconds) or nil,
    }
    return sts_call(host, "AssumeRoleWithWebIdentity", params, sts_region(host, opts.region))
  end)
end

function M.container()
  return provider(
    "container",
    { "Ensure a container credential endpoint is available." },
    container_source
  )
end

function M.instance_metadata()
  return provider("instance-metadata", {
    "Ensure the EC2 instance metadata service is reachable and the instance has a role.",
  }, function(host)
    return imds_source(host)
  end)
end

--- M.expired(creds, now) -> true when the credentials expire within the refresh window
function M.expired(creds, now)
  return type(creds) == "table"
    and type(creds.expiration) == "number"
    and now >= creds.expiration - M.REFRESH_WINDOW_S
end

-- internals, for the specs
M._sts_call = sts_call
M._accepted_url = accepted_url

return M
