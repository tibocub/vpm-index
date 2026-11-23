-- Questrade's credentials (packages/questrade/src/credentials.ts).
--
-- Every call carries an OAuth access token and goes to the API server the token was
-- issued for. Either the caller holds both (access_token + api_server, or
-- QUESTRADE_ACCESS_TOKEN + QUESTRADE_API_SERVER), or a refresh token is redeemed:
--   GET <login origin>/oauth2/token?grant_type=refresh_token&refresh_token=<token>
--   -> { access_token, refresh_token, api_server, expires_in }
-- Each refresh token redeems ONCE; the answer carries the next one. The access token is
-- reused until 60 s before it expires (at least 60 s), then the refresh token the last
-- redemption returned is redeemed. The cache lives in this module for the life of the
-- process, keyed by the SHA-256 of the refresh token first given and the login URL (so
-- the plain token is never a table key). The rotated refresh tokens are kept in memory
-- only, as with Distilled's CredentialsFromEnv: a program that must restart later has to
-- read the latest one itself (`glue` has no onRefresh hook yet; see STATUS 27).
--
-- The refresh token travels in the URL query. The curl transports put the URL in curl's
-- config text (stdin for exec_curl, a 0600 temp file for popen_curl), never in a process
-- argument, and scrub the query from their error messages; the errors below never name
-- the URL.
local crypto = require("distilled.crypto")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")
local url = require("distilled.url")

local glue = {}

local REFRESH_WINDOW_S = 60
local MISSING =
  "QUESTRADE_REFRESH_TOKEN, or QUESTRADE_ACCESS_TOKEN with QUESTRADE_API_SERVER, is required"

local cache = {} -- sha256(first refresh token) .. "\0" .. login URL -> tokens

local function present(v)
  if v == nil then
    return false
  end
  local plain = secret.unwrap(v)
  return plain ~= nil and plain ~= ""
end

-- normalizeApiServer: "https://api01.iq.questrade.com/" and ".../v1" -> the server root
local function normalize_api_server(v)
  v = string.gsub(tostring(v), "/+$", "")
  if string.sub(v, -3) == "/v1" then
    v = string.sub(v, 1, -4)
  end
  return v
end

local function token_error(message)
  return errors.new("ConfigError", {
    message = "Questrade refresh token redemption failed: " .. message,
    key = "refresh_token",
  })
end

-- plain split on a literal separator (no patterns: a token may hold `%` or `-`)
local function split_plain(text, sep)
  local parts, start = {}, 1
  if sep == nil or sep == "" then
    return { text }
  end
  while true do
    local i, j = string.find(text, sep, start, true)
    if not i then
      parts[#parts + 1] = string.sub(text, start)
      return parts
    end
    parts[#parts + 1] = string.sub(text, start, i - 1)
    start = j + 1
  end
end

-- redeemRefreshToken. Returns { access, refresh, api_server, expires_in } | nil, err.
local function redeem(host, refresh, login_url)
  local origin = string.match(login_url, "^(%a[%w+.-]*://[^/?#]+)")
  if origin == nil then
    return nil, token_error("the login URL " .. login_url .. " is not a URL")
  end
  local transport = host and host.transport
  if transport == nil then
    return nil,
      errors.new("ConfigError", {
        message = "no transport; " .. require("distilled.host").TRANSPORT_HINT,
        key = "transport",
      })
  end
  local plain = tostring(secret.unwrap(refresh))
  local res, terr = transport({
    method = "GET",
    url = origin .. "/oauth2/token?grant_type=refresh_token&refresh_token=" .. url.encode_form(
      plain
    ),
    headers = { accept = "application/json" },
  })
  if type(res) ~= "table" or type(res.status) ~= "number" then
    local why = errors.is(terr) and terr.message or tostring(terr)
    -- the transports scrub the query already; this is the second line of defence
    why = table.concat(split_plain(why, plain), "<redacted>")
    return nil, token_error("request to " .. login_url .. " failed: " .. why)
  end
  if res.status < 200 or res.status >= 300 then
    -- the body of a refused redemption is an HTML page or a bare message: not echoed
    return nil,
      token_error(
        login_url
          .. " answered "
          .. res.status
          .. " (a refresh token redeems once -- use the one the last redemption returned)"
      )
  end
  local body = json.decode(res.body or "")
  if type(body) ~= "table" or body == json.null then
    return nil, token_error(login_url .. " answered with a body that is not JSON")
  end
  local access, next_refresh, api_server =
    rawget(body, "access_token"), rawget(body, "refresh_token"), rawget(body, "api_server")
  if type(access) ~= "string" or type(next_refresh) ~= "string" or type(api_server) ~= "string" then
    return nil, token_error("the answer has no access_token, refresh_token or api_server")
  end
  local expires_in = rawget(body, "expires_in")
  if type(expires_in) ~= "number" or expires_in <= 0 then
    expires_in = 1800
  end
  return {
    access = secret.wrap(access),
    refresh = secret.wrap(next_refresh),
    api_server = normalize_api_server(api_server),
    expires_in = expires_in,
  }
end

function glue.settings(s, host)
  if present(s.access_token) and present(s.api_server) then
    s.api_server = normalize_api_server(secret.unwrap(s.api_server))
    return s
  end
  if not present(s.refresh_token) then
    return nil, errors.new("ConfigError", { message = MISSING, key = "refresh_token" })
  end
  local login_url = tostring(s.login_url or "https://login.questrade.com")
  local first = tostring(secret.unwrap(s.refresh_token))
  local key = crypto.hex.encode(crypto.sha256(first)) .. "\0" .. login_url
  local now = (host and host.epoch or os.time)()
  local entry = cache[key]
  if entry == nil or now >= entry.refresh_at then
    local tokens, err = redeem(host, entry and entry.next or s.refresh_token, login_url)
    if not tokens then
      return nil, err
    end
    entry = {
      next = tokens.refresh,
      access = tokens.access,
      api_server = tokens.api_server,
      refresh_at = now + math.max(tokens.expires_in - REFRESH_WINDOW_S, REFRESH_WINDOW_S),
    }
    cache[key] = entry
  end
  s.access_token = entry.access
  s.api_server = entry.api_server
  return s
end

function glue.base_url(s)
  if present(s.base_url) then
    return (string.gsub(tostring(s.base_url), "/+$", ""))
  end
  return s.api_server
end

return glue
