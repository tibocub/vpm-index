-- Fly.io Sprites glue (packages/fly-io/src/protocol.ts SpritesProtocol, errors.ts
-- SpritesNotEnabled).
--
-- Sprites calls carry a bearer token minted from the Fly API token, never the Fly token
-- itself:
--   1. the organization slug: GET <machines>/v1/tokens/current (tokens[1].org_slug or
--      .organization), else POST https://api.fly.io/graphql (viewer's personal
--      organization, else the first organization);
--   2. POST https://api.sprites.dev/v1/organizations/<slug>/tokens with
--      `Authorization: FlyV1 <macaroon>` -> { token }.
-- The minted token is cached per Fly token for the life of the process (Distilled's
-- mintedTokens map; the cache key is the SHA-256 of the Fly token, not the token). The
-- mint operation itself (POST /organizations/{org}/tokens) authenticates with FlyV1.
-- Answers: a body that is exec frames (first byte 0-3: stdout, stderr, exit code) or
-- NDJSON becomes { stdout, stderr, exit_code } or a list. A 401 saying "sprites not
-- enabled" is SpritesNotEnabled.
local crypto = require("distilled.crypto")
local errors = require("distilled.errors")
local json = require("distilled.json")
local retry = require("distilled.retry")
local secret = require("distilled.secret")
local url = require("distilled.url")

local SPRITES_API = "https://api.sprites.dev/v1"
local FLY_API = "https://api.fly.io"

local SpritesNotEnabled = errors.define({
  tag = "SpritesNotEnabled",
  categories = { "AuthError" },
})
local UnknownFlyIoError = errors.define({ tag = "UnknownFlyIoError" })
local FlyIoParseError = errors.define({ tag = "FlyIoParseError", categories = { "ParseError" } })

local glue = {}

local minted = {} -- sha256(fly token) -> secret(minted token)

local function is_object(v)
  return type(v) == "table" and v ~= json.null and not json.is_array(v)
end

local function str(v)
  return type(v) == "string" and v ~= "" and v or nil
end

-- stripFlyAuthScheme: "FlyV1 fm2_..." or "Bearer fm2_..." -> the macaroon
local function strip_scheme(token)
  local t = string.gsub(string.gsub(token, "^%s+", ""), "%s+$", "")
  local scheme, rest = string.match(t, "^(%S+)%s+(.*)$")
  if scheme and (string.lower(scheme) == "flyv1" or string.lower(scheme) == "bearer") then
    return (string.gsub(rest, "^%s+", ""))
  end
  return t
end

local function is_mint(route)
  return route ~= nil
    and route.method == "POST"
    and type(route.uri) == "string"
    and string.find(route.uri, "/organizations/{[^}]+}/tokens$") ~= nil
end

-- errorEnv: the Sprites envelope (message | error, code = error next to a message), else
-- Fly's (error | message | errors.detail)
function glue.error_envelope(body)
  if not is_object(body) then
    return nil
  end
  local message = str(rawget(body, "message")) or str(rawget(body, "error"))
  local code = (
    type(rawget(body, "error")) == "string" and type(rawget(body, "message")) == "string"
  )
      and rawget(body, "error")
    or nil
  if message == nil then
    local e = rawget(body, "errors")
    if is_object(e) then
      message = str(rawget(e, "detail"))
    end
  end
  return { message = message, code = code }
end

local function haystack(body, message)
  local parts = { type(body) == "string" and body or "", message or "" }
  if is_object(body) then
    parts[#parts + 1] = str(rawget(body, "message")) or ""
    parts[#parts + 1] = str(rawget(body, "error")) or ""
  end
  return string.lower(table.concat(parts, " "))
end

local function not_enabled(status, body, message)
  return status == 401 and string.find(haystack(body, message), "sprites not enabled", 1, true)
end

function glue.classify_error(info)
  if not_enabled(info.status, info.body, info.message) then
    return errors.new(SpritesNotEnabled, { message = info.message })
  end
  return nil
end

-- failHttp for the token mint's own requests
local function http_failure(res, body)
  local env = glue.error_envelope(body) or {}
  local text = string.gsub(string.gsub(res.body or "", "^%s+", ""), "%s+$", "")
  local message = env.message or (text ~= "" and text or ("HTTP " .. tostring(res.status)))
  if not_enabled(res.status, body or text, message) then
    return errors.new(SpritesNotEnabled, { message = message })
  end
  local class = errors.STATUS_MAP[res.status]
  if class == nil and res.status >= 500 then
    class = errors.InternalServerError
  end
  if class then
    return errors.new(class, {
      message = message,
      status = res.status,
      retry_after = retry.parse_for_status(res.status, res.headers or {}, os.time()),
    })
  end
  return errors.new(UnknownFlyIoError, { status = res.status, code = env.code, message = message })
end

local function send(host, req)
  local transport = host and host.transport
  if transport == nil then
    return nil,
      errors.new("ConfigError", {
        message = "no transport; " .. require("distilled.host").TRANSPORT_HINT,
        key = "transport",
      })
  end
  local res, err = transport(req)
  if type(res) ~= "table" or type(res.status) ~= "number" then
    if errors.is(err) then
      return nil, err
    end
    return nil, errors.new("TransportError", { message = "Sprites token mint: transport failed" })
  end
  local headers = {}
  for k, v in pairs(res.headers or {}) do
    headers[string.lower(k)] = v
  end
  res.headers = headers
  return res, json.decode(res.body or "")
end

local function org_from_tokens(body)
  local tokens = is_object(body) and rawget(body, "tokens")
  if type(tokens) ~= "table" or not json.is_array(tokens) or #tokens == 0 then
    return nil
  end
  local first = tokens[1]
  if not is_object(first) then
    return nil
  end
  return str(rawget(first, "org_slug")) or str(rawget(first, "organization"))
end

local function org_from_graphql(body)
  local data = is_object(body) and rawget(body, "data")
  if not is_object(data) then
    return nil
  end
  local viewer = rawget(data, "viewer")
  local root = is_object(viewer) and viewer or data
  local personal = rawget(root, "personalOrganization")
  if is_object(personal) and str(rawget(personal, "slug")) then
    return rawget(personal, "slug")
  end
  local orgs = rawget(root, "organizations")
  local nodes = is_object(orgs) and rawget(orgs, "nodes")
  if type(nodes) == "table" and json.is_array(nodes) then
    for _, node in ipairs(nodes) do
      if is_object(node) and str(rawget(node, "slug")) then
        return rawget(node, "slug")
      end
    end
  end
  return nil
end

local function discover_org(host, s, fly_token)
  local machines = string.gsub(tostring(s.machines_base_url), "/+$", "")
  local res, body = send(host, {
    method = "GET",
    url = machines .. "/v1/tokens/current",
    headers = { authorization = "Bearer " .. fly_token, accept = "application/json" },
  })
  if res == nil then
    return nil, body
  end
  if res.status < 400 then
    local slug = org_from_tokens(body)
    if slug then
      return slug
    end
  end
  res, body = send(host, {
    method = "POST",
    url = FLY_API .. "/graphql",
    headers = {
      authorization = "Bearer " .. fly_token,
      accept = "application/json",
      ["content-type"] = "application/json",
    },
    body = json.encode({
      query = "{ viewer { personalOrganization { slug } organizations { nodes { slug } } } }",
    }),
  })
  if res == nil then
    return nil, body
  end
  if res.status < 400 then
    local slug = org_from_graphql(body)
    if slug then
      return slug
    end
  end
  return nil,
    errors.new("ConfigError", {
      message = "Could not discover a Fly organization slug from /tokens/current or GraphQL",
      key = "api_key",
    })
end

local function mint(host, s, fly_token)
  local slug, err = discover_org(host, s, fly_token)
  if not slug then
    return nil, err
  end
  local res, body = send(host, {
    method = "POST",
    url = SPRITES_API .. "/organizations/" .. url.encode_component(slug) .. "/tokens",
    headers = {
      authorization = "FlyV1 " .. strip_scheme(fly_token),
      accept = "application/json",
      ["content-type"] = "application/json",
    },
    body = json.encode({ description = "Alchemy Sprites token" }),
  })
  if res == nil then
    return nil, body
  end
  if res.status >= 400 then
    return nil, http_failure(res, body)
  end
  local token = is_object(body) and rawget(body, "token")
  if type(token) ~= "string" or token == "" then
    return nil,
      errors.new(FlyIoParseError, {
        body = "[REDACTED]",
        cause = "mint response missing token",
        message = "mint response missing token",
      })
  end
  return secret.wrap(token)
end

-- every call but the mint gets a minted Sprites token (settings.sprites_token)
function glue.settings(s, host, route)
  if is_mint(route) or s.api_key == nil then
    return s
  end
  local fly_token = tostring(secret.unwrap(s.api_key))
  local key = crypto.hex.encode(crypto.sha256(fly_token))
  local token = minted[key]
  if token == nil then
    local err
    token, err = mint(host, s, fly_token)
    if token == nil then
      return nil, err
    end
    minted[key] = token
  end
  s.sprites_token = token
  return s
end

function glue.headers(s, route, headers)
  local out = {}
  for k, v in pairs(headers) do
    out[k] = v
  end
  if is_mint(route) then
    out.authorization = "FlyV1 " .. strip_scheme(tostring(secret.unwrap(s.api_key)))
  elseif s.sprites_token ~= nil then
    out.authorization = "Bearer " .. tostring(secret.unwrap(s.sprites_token))
  end
  out.accept = "application/json"
  return out
end

-- parseSpritesExecFrames: [id][payload]...[3][exit code]; id 2 is stderr
local function exec_frames(text)
  if #text == 0 then
    return nil
  end
  local first = string.byte(text, 1)
  if first > 3 then
    return nil
  end
  local stop = #text
  local exit_code = 0
  if stop >= 2 and string.byte(text, stop - 1) == 3 then
    exit_code = string.byte(text, stop)
    stop = stop - 2
  end
  local stdout, stderr = "", ""
  if stop > 0 then
    local payload = string.sub(text, 2, stop)
    if first == 2 then
      stderr = payload
    else
      stdout = payload
    end
  end
  return json.object({ stdout = stdout, stderr = stderr, exit_code = exit_code })
end

-- parseMaybeNdjson: a text body of JSON lines -> the list of values
local function ndjson(text)
  local list = {}
  for line in string.gmatch(text, "[^\r\n]+") do
    local l = string.gsub(string.gsub(line, "^%s+", ""), "%s+$", "")
    if l ~= "" then
      local v = json.decode(l)
      if v == nil then
        return nil
      end
      list[#list + 1] = v
    end
  end
  if #list == 0 then
    return nil
  end
  return json.array(list)
end

function glue.transform_response(body)
  if type(body) ~= "string" then
    return body
  end
  return exec_frames(body) or ndjson(body) or body
end

return glue
