-- The REST protocol for bearer/header-auth JSON APIs. Port of Distilled's
-- makeRestProtocol (protocol-rest.ts: requestFor, decodeText, decodeSuccess,
-- checkSuccess) on top of the layer-2 algorithms.
--
--   local protocol = rest.new{
--     base_url = fn(creds, { uri, method, server, base_url }) | "https://...",
--                -- route.server / route.base_url: the op's own host (op.server, op.base_url);
--                -- rest.route_base_url(option, opts) is the generated default
--     headers = fn(creds) -> { authorization = ... },        -- rest.bearer("api_key")
--     error_envelope = fn(body) -> { code, message } | nil,  -- default: code, message | error
--     error_fields_at = "/error",       -- where a typed error's declared fields live
--     status_map = { [404] = class, ... },                    -- default errors.STATUS_MAP
--     classify_error = fn(info) -> err | nil,                 -- consulted first
--     unknown_tag = "UnknownNeonError", parse_tag = "NeonParseError",
--     unknown_error = fn(info) -> err, parse_error = fn(info) -> err,   -- optional
--     transform_response = fn(body, op, { status, headers }) -> body,  -- rest.transforms{}
--     map_member_header, unknown_key_to_wire, empty_json_body, query_style,  -- request.build
--     user_agent = "...",
--     -- provider-spec features (task 13; see "Provider-spec features" below):
--     provider = { title, options, headers, base_url, require_one_of, anonymous, oauth,
--                  user_agent },
--     unknown_fields = { reason = "/reason" },   -- extra fields of the unknown error
--     transform_input = fn(input, op, settings, service) -> input,
--     classify_success = fn{ status, headers, body, non_json, op } -> err | true | nil,
--                        -- true: read the 2xx answer as a failure (envelope, matchers, ...)
--     glue = <module>,   -- a provider's hand-written functions, by these names: settings
--                        -- (settings, host, route) -> settings | nil, err; base_url;
--                        -- headers (settings, route, headers) -> headers; transform_input;
--                        -- error_envelope; classify_error; classify_success;
--                        -- transform_response; unknown_error;
--                        -- sign (request, settings, { host, op, base_url }) -> request
--                        --   | nil, err: after the request is built (task 28: Coinbase's
--                        --   per-request JWT, Polymarket's L1/L2 headers);
--                        -- accept_failure { status, headers, body, op } -> true: decode a
--                        --   >= 400 answer as the success value (Coinbase's isValid bodies)
--   }
--   With `provider`, base_url and headers default to the provider's; `creds` they see
--   are the resolved settings.
--   protocol.call(ctx, op, input) -> value, nil, meta | nil, err, meta
--   protocol.encode(ctx, op, input [, creds]) -> request | nil, err   (no send)
--   protocol.decode(ctx, op, response) -> value | nil, err
--
-- ctx = { service, credentials = fn() -> creds | nil, err, host, tracer, span,
--         validation = "lenient" | "additional" | "strict", timeout, attempt, user_agent }.
-- meta = { status, headers } whenever a response arrived.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local keys = require("distilled.keys")
local noop = require("distilled.trace.noop")
local redact = require("distilled.redact")
local request = require("distilled.request")
local retry = require("distilled.retry")
local schema = require("distilled.schema")
local secret = require("distilled.secret")
local url_lib = require("distilled.url")
local validate = require("distilled.validate")

-- A transport returned something that is neither a response table nor `nil, err`. The
-- usual cause is a transport constructor passed as the transport (popen_curl.new, or a
-- custom factory): called with the request it returns a transport function. Not
-- retryable: the next try would do the same.
local TRANSPORT_HINT = require("distilled.host").TRANSPORT_HINT
local function contract_error(res)
  local what
  if res == nil then
    what = "returned nothing (neither a response table nor nil, err)"
  elseif type(res) == "function" or type(res) == "table" then
    -- a callable table: popen_curl(opts) / exec_curl(exec) return one (task 29)
    what = "returned a function, so it is probably a transport constructor, not a transport"
  else
    what = "returned a " .. type(res) .. " instead of a response table or nil, err"
  end
  return errors.new("ConfigError", {
    message = "the transport " .. what .. "; " .. TRANSPORT_HINT,
    key = "transport",
  })
end

local rest = {}

rest.VERSION = "0.1.0"
rest.USER_AGENT = "distilled-lua/" .. rest.VERSION

local null = json.null

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end

-- a raise inside a provider callback becomes an SdkError; a raised error table is the
-- error itself (Distilled: a baseUrl that throws fails the call with what it threw)
local function callback_error(what, raised)
  if errors.is(raised) then
    return raised
  end
  local message = type(raised) == "table" and rawget(raised, "message") or raised
  return errors.new(
    "SdkError",
    { message = what .. " raised: " .. tostring(message), cause = raised }
  )
end

-- fn(...) -> its results, or nil, SdkError when it raised
local function protect(what, fn, ...)
  local r = compat.pack(compat.pcall(fn, ...))
  if not r[1] then
    return false, callback_error(what, r[2])
  end
  return true, compat.unpack(r, 2, r.n)
end

--- rest.bearer(option) -> headers function: authorization = "Bearer <creds[option]>"
-- (no header when the option has no value)
function rest.bearer(option)
  return function(creds)
    local v = creds and creds[option]
    if v == nil then
      return {}
    end
    return { authorization = "Bearer " .. tostring(secret.unwrap(v)) }
  end
end

-- a template value goes into a host name: letters, digits, dot, dash, underscore only
local function template_value(v)
  if type(v) == "number" then
    v = tostring(v)
  end
  if type(v) ~= "string" or not string.find(v, "^[%w._%-]*$") then
    return nil
  end
  return v
end

--- rest.route_base_url(option [, opts]) -> base_url function(creds, route)
-- The base URL for operations that name their own host (smithy.api#http server and
-- baseUrl, see gen/ops.lua):
--   route.server   -> creds[opts.servers[server] or server .. "_base_url"]; unset is a
--                     ConfigError, never a fallback to the main host (Distilled's
--                     DigitalOcean baseUrlFor refuses an unknown server the same way)
--   route.base_url -> creds[option] when it equals opts.default (the base URL option
--                     still moves the main host: ScalewayProtocol's baseUrlFor rule),
--                     else the URL with each {name} filled from creds[name] (an unset or
--                     non-host value is a ConfigError naming the option)
--   neither        -> creds[option]
-- A provider whose hosts follow another rule passes its own base_url function.
function rest.route_base_url(option, opts)
  if type(option) ~= "string" then
    compat.raise("rest.route_base_url: option must be the base URL option's name", 2)
  end
  opts = opts or {}
  local servers = opts.servers or {}
  return function(creds, route)
    creds = creds or {}
    route = route or {}
    if route.server ~= nil then
      local name = servers[route.server] or (tostring(route.server) .. "_base_url")
      local v = creds[name]
      if type(v) ~= "string" or v == "" then
        return nil,
          errors.new("ConfigError", {
            message = "the operation runs on server "
              .. tostring(route.server)
              .. ", which has no base URL: set the client option "
              .. name,
            key = name,
          })
      end
      return v
    end
    local own = route.base_url
    if own == nil or own == opts.default then
      return creds[option]
    end
    local missing
    local filled = string.gsub(own, "{([%w_]+)}", function(name)
      local v = template_value(secret.unwrap(creds[name]))
      if v == nil then
        missing = missing or name
        return ""
      end
      return v
    end)
    if missing then
      return nil,
        errors.new("ConfigError", {
          message = "the operation's base URL "
            .. own
            .. " needs the client option "
            .. missing
            .. " (letters, digits, '.', '-' or '_')",
          key = missing,
        })
    end
    return filled
  end
end

--- rest.header(header_name, option) -> headers function: header_name = creds[option]
function rest.header(header_name, option)
  local name = string.lower(header_name)
  return function(creds)
    local v = creds and creds[option]
    if v == nil then
      return {}
    end
    return { [name] = tostring(secret.unwrap(v)) }
  end
end

-- defaultErrorEnvelope: code (string or number) and message, else a string `error`
local function default_envelope(body)
  if type(body) ~= "table" or body == null or json.is_array(body) then
    return nil
  end
  local code = rawget(body, "code")
  if type(code) ~= "string" and type(code) ~= "number" then
    code = nil
  end
  local message = rawget(body, "message")
  if type(message) ~= "string" then
    message = rawget(body, "error")
    if type(message) ~= "string" then
      message = nil
    end
  end
  return { code = code, message = message }
end
rest.default_error_envelope = default_envelope

---------------------------------------------------------------------------------------
-- Provider-spec features (task 13). What each Distilled package hand-writes in
-- credentials.ts and protocol.ts (env fallbacks, versions in headers, base URLs from a
-- site or a region, error envelopes with fallbacks), as plain data the generator
-- writes into a client's init.lua: `rest.new{ provider = { ... } }`. The data is
-- validated by the generator (gen/provider.lua); here it is only interpreted.
--
--   provider = {
--     title = "Datadog",                         -- names the client in ConfigErrors
--     options = { [name] = {
--       secret = true, env = { "A", "B" },      -- first variable that is set and not empty
--       default = "text", required = true,
--       choices = { "x", "y" } | { x = "text" },  -- a map resolves to the mapped text
--       ignore_case = true, invalid = "error" | "default",
--       trim_slash = true, strip_scheme = true,
--     } },
--     require_one_of = { "api_key", "access_token" },
--     headers = { { name = "authorization", values = { { template = "Bearer {api_key}" },
--                   { template = "{id}:{secret}", basic = true } }, secret = true }, ... },
--     base_url = { option = "base_url", default = "https://api.{site}", trim_slash = true,
--                  ensure_suffix = "/api", origin = { label, example } },
--     anonymous = { OpName = true },             -- no secret header, no required check
--     oauth = { ... },                           -- see oauth_token below
--   }
--
-- `{name}` in a template is the option's resolved value; a template naming an option
-- without a value yields nothing (the header is left out, the next alternative is tried).
---------------------------------------------------------------------------------------

-- base64 for basic auth (RFC 4648, with padding). Kept local and small; arithmetic only
-- (Lua 5.1 has no bitwise operators).
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function base64(s)
  local out = {}
  for i = 1, #s, 3 do
    local a, b, c = string.byte(s, i, i + 2)
    local n = a * 65536 + (b or 0) * 256 + (c or 0)
    local c1 = math.floor(n / 262144) % 64
    local c2 = math.floor(n / 4096) % 64
    local c3 = math.floor(n / 64) % 64
    local c4 = n % 64
    out[#out + 1] = string.sub(B64, c1 + 1, c1 + 1)
      .. string.sub(B64, c2 + 1, c2 + 1)
      .. (b and string.sub(B64, c3 + 1, c3 + 1) or "=")
      .. (c and string.sub(B64, c4 + 1, c4 + 1) or "=")
  end
  return compat.concat(out)
end
rest._base64 = base64

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

local function as_list(v)
  if v == nil then
    return {}
  end
  if type(v) == "table" then
    return v
  end
  return { v }
end

local function present(v)
  if v == nil then
    return false
  end
  local plain = secret.unwrap(v)
  return plain ~= "" and plain ~= nil
end

-- render(template, settings) -> text | nil, missing option name
local function render(template, settings)
  local missing
  local text = string.gsub(template, "{([%w_]+)}", function(name)
    local v = settings[name]
    if not present(v) then
      missing = missing or name
      return ""
    end
    return tostring(secret.unwrap(v))
  end)
  if missing then
    return nil, missing
  end
  return text
end
rest.render = render

local function env_hint(names)
  if #names == 0 then
    return ""
  end
  if #names == 1 then
    return " or set " .. names[1]
  end
  local others = {}
  for i = 2, #names do
    others[#others + 1] = names[i]
  end
  return " or set " .. names[1] .. " (or " .. compat.concat(others, ", ") .. ")"
end

-- one option's value: the user's, else the first environment variable set, else the
-- default; then choices and the text clean-ups. Returns value | nil, err.
local function resolve_option(title, name, o, given, getenv)
  local value = given
  if not present(value) then
    value = nil
    for _, var in ipairs(as_list(o.env)) do
      local e = getenv(var)
      if e ~= nil and e ~= "" then
        value = o.secret and secret.wrap(e) or e
        break
      end
    end
  end
  if value == nil then
    value = o.default
  end
  if value ~= nil and o.choices ~= nil then
    local text = tostring(secret.unwrap(value))
    local is_map = o.choices[1] == nil
    local found
    for k, v in pairs(o.choices) do
      local key = is_map and k or v
      if key == text or (o.ignore_case and string.lower(key) == string.lower(text)) then
        found = is_map and v or key
        break
      end
    end
    if found == nil and o.invalid == "default" and o.default ~= nil then
      return resolve_option(title, name, { default = o.default, choices = o.choices }, nil, getenv)
    end
    if found == nil then
      local names = {}
      for k, v in pairs(o.choices) do
        names[#names + 1] = is_map and k or v
      end
      table.sort(names)
      -- choices are never secret (the generator refuses it), so the value may be named
      return nil,
        config_error(
          title
            .. ": option "
            .. name
            .. " must be one of "
            .. compat.concat(names, ", ")
            .. ", got "
            .. text,
          name
        )
    end
    value = found
  end
  if type(value) == "string" then
    if o.strip_scheme then
      value = string.gsub(value, "^[Hh][Tt][Tt][Pp][Ss]?://", "")
    end
    if o.trim_slash then
      value = string.gsub(value, "/+$", "")
    end
  end
  return value
end

local LOOPBACK = { ["127.0.0.1"] = true, localhost = true, ["[::1]"] = true }

-- the origin of a URL that must be one (NetBird, Technitium, Starburst Galaxy:
-- `new URL(v)` with no userinfo, path, query or fragment; https unless loopback http)
local function origin_of(value, label, example)
  local scheme, rest_of = string.match(value, "^(%a[%w+.-]*)://(.*)$")
  if not scheme then
    return nil, label .. " is not a URL"
  end
  scheme = string.lower(scheme)
  local authority, tail = string.match(rest_of, "^([^/?#]*)(.*)$")
  if authority == "" then
    return nil, label .. " is not a URL"
  end
  if string.find(authority, "@", 1, true) or (tail ~= "" and tail ~= "/") then
    return nil, label .. " must be an origin such as " .. example .. ", without a path"
  end
  local hostname, port = string.match(authority, "^(.-):(%d+)$")
  hostname = string.lower(hostname or authority)
  if scheme ~= "https" and not (scheme == "http" and LOOPBACK[hostname]) then
    return nil, label .. " must use HTTPS"
  end
  if port == (scheme == "https" and "443" or "80") then
    port = nil
  end
  return scheme .. "://" .. hostname .. (port and (":" .. port) or "")
end
rest._origin_of = origin_of

-- form encoding for token requests (application/x-www-form-urlencoded)
local function form_body(fields)
  local names = {}
  for k in pairs(fields) do
    names[#names + 1] = k
  end
  table.sort(names)
  local parts = {}
  for _, k in ipairs(names) do
    parts[#parts + 1] = url_lib.encode_form(k) .. "=" .. url_lib.encode_form(fields[k])
  end
  return compat.concat(parts, "&")
end

-- OAuth 2.0 client credentials (MongoDB Atlas, 1Password Users, Starburst Galaxy,
-- Tailscale): exchange client_id/client_secret for an access token at token_url, cache
-- it until `refresh_window_s` before it expires. oauth = { token_url (template),
-- client_id, client_secret (option names), into (option the token fills),
-- auth = "basic" | "form" (where the client credentials go), scope, extra = { field =
-- option }, default_ttl_s, refresh_window_s, reuse = "window" | "half", required,
-- label }. The cache lives in the protocol, keyed by URL and client id; an entry is
-- used only while its client secret is the same.
local function oauth_token(cache, title, o, settings, host, timeout)
  local token_url, missing = render(o.token_url, settings)
  if not token_url then
    return nil, config_error(title .. ": option " .. missing .. " is required", missing)
  end
  local id = tostring(secret.unwrap(settings[o.client_id]))
  local client_secret = tostring(secret.unwrap(settings[o.client_secret]))
  local key = token_url .. "\0" .. id
  local now = (host.epoch or os.time)()
  local hit = cache[key]
  if hit and hit.client_secret == client_secret and now < hit.refresh_at then
    return hit.token
  end
  local fields = { grant_type = "client_credentials" }
  local headers = {
    ["content-type"] = "application/x-www-form-urlencoded",
    accept = "application/json",
  }
  if o.auth == "form" then
    fields.client_id = id
    fields.client_secret = client_secret
  else
    headers.authorization = "Basic " .. base64(id .. ":" .. client_secret)
  end
  if o.scope and present(settings[o.scope]) then
    fields.scope = tostring(secret.unwrap(settings[o.scope]))
  end
  for field, option in pairs(o.extra or {}) do
    if present(settings[option]) then
      fields[field] = tostring(secret.unwrap(settings[option]))
    end
  end
  local label = (o.label or (title .. " OAuth token request")) .. " failed"
  local transport = host.transport
  if transport == nil then
    return nil, config_error("no transport; " .. TRANSPORT_HINT, "transport")
  end
  local ok, res, terr = protect("the transport", transport, {
    method = "POST",
    url = token_url,
    headers = headers,
    body = form_body(fields),
    timeout = timeout,
  })
  if not ok then
    return nil, res
  end
  if type(res) ~= "table" or type(res.status) ~= "number" then
    local why = errors.is(terr) and terr.message or tostring(terr)
    return nil, config_error(label .. ": " .. why, o.client_id)
  end
  local body = json.decode(res.body or "")
  if res.status < 200 or res.status >= 300 then
    -- the OAuth error fields only: a token endpoint's body is not echoed
    local code = type(body) == "table" and rawget(body, "error") or nil
    local desc = type(body) == "table" and rawget(body, "error_description") or nil
    return nil,
      config_error(
        label
          .. " with "
          .. res.status
          .. (type(code) == "string" and (" " .. code) or "")
          .. (type(desc) == "string" and (": " .. desc) or ""),
        o.client_id
      )
  end
  local access = type(body) == "table" and rawget(body, "access_token") or nil
  if type(access) ~= "string" or access == "" then
    return nil, config_error(label .. ": the answer has no access_token", o.client_id)
  end
  local ttl = type(body) == "table" and rawget(body, "expires_in") or nil
  if type(ttl) ~= "number" or ttl <= 0 then
    ttl = o.default_ttl_s or 3600
  end
  local window = o.refresh_window_s or 60
  local reuse
  if o.reuse == "half" then
    reuse = math.max(ttl - window, ttl / 2)
  else
    reuse = math.max(ttl - window, window)
  end
  local token = secret.wrap(access)
  cache[key] = { token = token, client_secret = client_secret, refresh_at = now + reuse }
  return token
end

--- rest.compile_provider(p) -> { resolve, base_url, headers }
-- resolve(creds, host, op_name [, timeout]) -> settings | nil, err
-- base_url(settings, route) -> url | nil, err ; headers(settings, route, op_name) -> headers
function rest.compile_provider(p)
  local title = p.title or "client"
  local options = p.options or {}
  local names = {}
  for name in pairs(options) do
    names[#names + 1] = name
  end
  table.sort(names)
  local anonymous = p.anonymous or {}
  local oauth_cache = {}
  local compiled = {}

  function compiled.resolve(creds, host, op_name, timeout)
    host = host or {}
    local getenv = host.getenv or os.getenv
    local is_anon = op_name ~= nil and anonymous[op_name] == true
    local settings = {}
    for k, v in pairs(creds or {}) do
      settings[k] = v
    end
    for _, name in ipairs(names) do
      local o = options[name]
      local v, err = resolve_option(title, name, o, settings[name], getenv)
      if err then
        return nil, err
      end
      settings[name] = v
    end
    local oauth = p.oauth
    -- oauth.exclusive (Tailscale BOTH_METHODS): a token and client credentials together
    -- are a ConfigError, not a silent choice
    if
      oauth
      and oauth.exclusive
      and present(settings[oauth.into])
      and (present(settings[oauth.client_id]) or present(settings[oauth.client_secret]))
    then
      return nil,
        config_error(
          title
            .. ": pass "
            .. oauth.into
            .. " or "
            .. oauth.client_id
            .. " and "
            .. oauth.client_secret
            .. ", not both",
          oauth.into
        )
    end
    if
      oauth
      and not present(settings[oauth.into])
      and present(settings[oauth.client_id])
      and present(settings[oauth.client_secret])
      and not is_anon
    then
      -- the token URL may name the base URL option ({base_url}/oauth/token): it sees the
      -- resolved base URL (default, template, suffix and origin rules applied)
      local ctx = settings
      local bopt = p.base_url and p.base_url.option
      if bopt and string.find(oauth.token_url, "{" .. bopt .. "}", 1, true) then
        local base, berr = compiled.base_url(settings)
        if not base then
          return nil, berr
        end
        ctx = {}
        for k, v in pairs(settings) do
          ctx[k] = v
        end
        ctx[bopt] = base
      end
      local token, err = oauth_token(oauth_cache, title, oauth, ctx, host, timeout)
      if not token then
        return nil, err
      end
      settings[oauth.into] = token
    end
    if is_anon then
      return settings
    end
    for _, name in ipairs(names) do
      local o = options[name]
      if o.required and not present(settings[name]) then
        return nil,
          config_error(
            title
              .. ": option "
              .. name
              .. " is required: pass "
              .. name
              .. " = ..."
              .. env_hint(as_list(o.env)),
            name
          )
      end
    end
    if oauth and oauth.required and not present(settings[oauth.into]) then
      return nil,
        config_error(
          title
            .. ": pass "
            .. oauth.into
            .. ", or "
            .. oauth.client_id
            .. " and "
            .. oauth.client_secret,
          oauth.into
        )
    end
    if p.require_one_of then
      local any = false
      local vars = {}
      for _, name in ipairs(p.require_one_of) do
        any = any or present(settings[name])
        for _, var in ipairs(as_list(options[name] and options[name].env)) do
          vars[#vars + 1] = var
        end
      end
      if not any then
        return nil,
          config_error(
            title
              .. ": one of "
              .. compat.concat(p.require_one_of, ", ")
              .. " is required"
              .. (#vars > 0 and (" (or set " .. compat.concat(vars, ", ") .. ")") or ""),
            p.require_one_of[1]
          )
      end
    end
    return settings
  end

  local b = p.base_url or {}
  -- an operation on its own host (task 12: route.server, or a route.base_url other than
  -- the provider's default) follows rest.route_base_url's rule
  local route_rule = rest.route_base_url(b.option or "base_url", { default = b.default })
  function compiled.base_url(settings, route)
    if
      route
      and (route.server ~= nil or (route.base_url ~= nil and route.base_url ~= b.default))
    then
      return route_rule(settings, route)
    end
    local value = b.option and settings[b.option]
    if not present(value) then
      if b.default == nil then
        local o = b.option and options[b.option] or {}
        return nil,
          config_error(
            title
              .. ": option "
              .. tostring(b.option)
              .. " is required: pass "
              .. tostring(b.option)
              .. " = ..."
              .. env_hint(as_list(o.env)),
            b.option
          )
      end
      local text, missing = render(b.default, settings)
      if not text then
        local o = options[missing] or {}
        return nil,
          config_error(
            title
              .. ": option "
              .. missing
              .. " is required (it is part of the base URL): pass "
              .. missing
              .. " = ..."
              .. env_hint(as_list(o.env)),
            missing
          )
      end
      value = text
    end
    value = tostring(secret.unwrap(value))
    if b.trim_slash or b.ensure_suffix then
      value = string.gsub(value, "/+$", "")
    end
    if b.ensure_suffix then
      local suffix = b.ensure_suffix
      if string.sub(value, -#suffix) ~= suffix then
        value = value .. suffix
      end
    end
    if b.origin then
      -- origin.bare_host (Starburst Galaxy apiBaseUrlFor): a host without a scheme is https
      if b.origin.bare_host and not string.find(value, "^[%a][%w+.-]*://") then
        value = "https://" .. value
      end
      local origin, why = origin_of(
        value,
        b.origin.label or (title .. " base URL"),
        b.origin.example or "https://api.example.com"
      )
      if not origin then
        return nil, config_error(why, b.option)
      end
      value = origin
    end
    return value
  end

  local header_list = p.headers or {}
  function compiled.headers(settings, _, op_name)
    local is_anon = op_name ~= nil and anonymous[op_name] == true
    local out = {}
    for _, h in ipairs(header_list) do
      if not (is_anon and h.secret) then
        for _, alt in ipairs(h.values) do
          local text = render(alt.template, settings)
          if text then
            out[h.name] = alt.basic and ("Basic " .. base64(text)) or text
            break
          end
        end
      end
    end
    return out
  end

  -- user_agent = { default, env }: the provider's User-Agent (GitHub, Modrinth,
  -- Squarespace), used when the caller sets no user_agent client option
  function compiled.user_agent(host)
    local ua = p.user_agent
    if not ua then
      return nil
    end
    local getenv = (host and host.getenv) or os.getenv
    for _, var in ipairs(as_list(ua.env)) do
      local e = getenv(var)
      if e ~= nil and e ~= "" then
        return e
      end
    end
    return ua.default
  end

  return compiled
end

--- rest.envelope{ code = { pointers }, message = { pointers }, non_empty } -> fn(body)
-- The first pointer whose value is text (code: text or a number) wins, like the
-- `typeof x === "string" ? x : typeof y === "string" ? y : ...` chains of each
-- package's errorEnvelope.
function rest.envelope(spec)
  local codes, messages = as_list(spec.code), as_list(spec.message)
  local non_empty = spec.non_empty == true
  local function first(body, pointers, numbers)
    for _, p in ipairs(pointers) do
      local v = errors.at_pointer(body, p)
      if type(v) == "string" and not (non_empty and v == "") then
        return v
      end
      if numbers and type(v) == "number" then
        return v
      end
    end
    return nil
  end
  return function(body)
    if type(body) ~= "table" or body == null then
      return nil
    end
    return { code = first(body, codes, true), message = first(body, messages, false) }
  end
end

-- Distilled's stripNulls (Axiom, Daytona): drop object members that are null, at every
-- depth. An explicit stack: no recursion over data depth (gopher-lua's call stack).
local function strip_nulls(value)
  if type(value) ~= "table" or value == null then
    return value
  end
  local root = { v = value }
  local stack = { { src = value, parent = root, key = "v" } }
  while #stack > 0 do
    local item = table.remove(stack)
    local src = item.src
    local copy = setmetatable({}, getmetatable(src))
    item.parent[item.key] = copy
    local array = json.is_array(src)
    for k, v in pairs(src) do
      if v == null and not array then
        -- dropped
      elseif type(v) == "table" and v ~= null then
        stack[#stack + 1] = { src = v, parent = copy, key = k }
      else
        copy[k] = v
      end
    end
  end
  return root.v
end
rest.strip_nulls = strip_nulls

--- rest.transforms(list) -> fn(body, op) applying each transform in order:
-- "strip_nulls", or { unwrap = "key", skip_paginated = bool } (an object holding `key`
-- is replaced by that member: ClickHouse `result`, Proxmox `data`).
function rest.transforms(list)
  return function(body, op)
    for _, tr in ipairs(list) do
      if tr == "strip_nulls" then
        body = strip_nulls(body)
      elseif type(tr) == "table" and tr.unwrap then
        local skip = tr.skip_paginated and op and op.pagination ~= nil
        if
          not skip
          and type(body) == "table"
          and body ~= null
          and not json.is_array(body)
          and rawget(body, tr.unwrap) ~= nil
        then
          body = rawget(body, tr.unwrap)
        end
      end
    end
    return body
  end
end

local function lower_headers(h)
  if type(h) ~= "table" then
    return {}
  end
  for k in pairs(h) do
    if type(k) == "string" and string.find(k, "%u") then
      local out = {}
      for k2, v in pairs(h) do
        out[type(k2) == "string" and string.lower(k2) or k2] = v
      end
      return out
    end
  end
  return h
end

-- the authority of a URL: host and port (server.address / server.port)
local function host_and_port(target)
  local host = retry.host_of(target)
  local authority = string.match(target, "^%a[%w+.-]*://([^/?#]*)") or ""
  authority = string.gsub(authority, "^.*@", "")
  local port = string.match(authority, ":(%d+)$")
  if port then
    return host, tonumber(port)
  end
  return host, string.find(target, "^https") and 443 or 80
end

-- numbers in response headers: Number(raw) unless blank; text that is not a number is
-- kept as sent, so strict validation reports it (withResponseHeaders)
local function header_value(member, raw, registry)
  local node = schema.resolve(member.schema, registry)
  if node and node.t == "number" and trim(raw) ~= "" then
    local n = retry._js_number(raw)
    if n ~= nil then
      return n
    end
  end
  return raw
end

--- rest.new(opts) -> protocol
function rest.new(opts)
  opts = opts or {}
  if type(opts) ~= "table" then
    compat.raise("rest.new: expected an options table", 2)
  end
  -- provider-spec data (task 13) and a provider's hand-written glue module: a glue
  -- function wins over the option of the same name (the generator allows only one)
  local glue = opts.glue or {}
  if type(glue) ~= "table" then
    compat.raise("rest.new: glue must be a module table", 2)
  end
  local function pick(name)
    local v = glue[name]
    if v == nil then
      v = opts[name]
    end
    return v
  end
  local provider_rt = opts.provider and rest.compile_provider(opts.provider)
  local base_url = pick("base_url") or (provider_rt and provider_rt.base_url)
  if type(base_url) ~= "string" and type(base_url) ~= "function" then
    compat.raise("rest.new: base_url must be a string or a function(creds, route)", 2)
  end
  local headers_fn = opts.headers or (provider_rt and provider_rt.headers)
  if headers_fn ~= nil and type(headers_fn) ~= "function" then
    compat.raise("rest.new: headers must be a function(creds) -> table", 2)
  end
  local settings_hook = glue.settings
  local headers_hook = glue.headers
  local transform_input = pick("transform_input")
  local classify_success = pick("classify_success")
  local classify_error = pick("classify_error")
  local unknown_hook = pick("unknown_error")
  local transform_response = pick("transform_response")
  local sign_hook = glue.sign
  local accept_failure = glue.accept_failure
  local unknown_fields = opts.unknown_fields
  local envelope = pick("error_envelope") or default_envelope
  local status_map = opts.status_map or errors.STATUS_MAP
  local unknown_class = errors.define({ tag = opts.unknown_tag or "UnknownError" })
  local parse_class =
    errors.define({ tag = opts.parse_tag or "ParseError", categories = { "ParseError" } })
  local user_agent = opts.user_agent or rest.USER_AGENT

  local protocol = {
    options = opts,
    unknown_class = unknown_class,
    parse_class = parse_class,
  }

  -- the operation's declared error classes, resolved once per op table (long-lived)
  local class_cache = {}
  local function classes_of(service, op)
    local list = class_cache[op]
    if list then
      return list
    end
    list = {}
    local declared = (service and service.errors) or {}
    for _, name in ipairs(op.errors or {}) do
      local class = declared[name] or errors.classes[name]
      if errors.is_class(class) then
        list[#list + 1] = class
      end
    end
    class_cache[op] = list
    return list
  end

  local function unknown_error(info)
    if unknown_hook then
      local ok, err = protect("the protocol's unknown_error", unknown_hook, info)
      if not ok then
        return err
      end
      if errors.is(err) then
        return err
      end
    end
    local fields = {
      status = info.status,
      code = info.code ~= nil and tostring(info.code) or nil,
      message = info.message,
      body = info.body,
      headers = info.headers,
    }
    -- provider spec unknown_fields: extra members of the unknown error read from the
    -- body (Hetzner `details`, Kubernetes `reason`, Prisma `hint`)
    for name, pointer in pairs(unknown_fields or {}) do
      if fields[name] == nil then
        local v = errors.at_pointer(info.body, pointer)
        if v ~= nil and v ~= null then
          fields[name] = v
        end
      end
    end
    return errors.new(unknown_class, fields)
  end

  local function parse_error(op, info)
    if opts.parse_error then
      local ok, err = protect("the protocol's parse_error", opts.parse_error, info)
      if not ok then
        return err
      end
      if errors.is(err) then
        return err
      end
    end
    local cause = info.cause
    local why = type(cause) == "table" and cause.message or tostring(cause)
    return errors.new(parse_class, {
      message = "cannot decode the response of " .. tostring(op.name) .. ": " .. tostring(why),
      body = info.body,
      cause = cause,
    })
  end

  -----------------------------------------------------------------------------------
  -- request
  -----------------------------------------------------------------------------------

  --- protocol.encode(ctx, op, input [, creds]) -> request | nil, err
  function protocol.encode(ctx, op, input, creds)
    ctx = ctx or {}
    if creds == nil then
      if ctx.credentials then
        local c, err = ctx.credentials()
        if c == nil then
          return nil, err
        end
        creds = c
      else
        creds = {}
      end
    end
    local route = { uri = op.uri, method = op.method, server = op.server, base_url = op.base_url }
    -- provider settings (task 13): env fallbacks, defaults, choices, OAuth tokens, then
    -- the glue's settings hook; base_url and headers then see the settings
    if provider_rt then
      local settings, serr = provider_rt.resolve(creds, ctx.host, op.name, ctx.timeout)
      if settings == nil then
        return nil, serr
      end
      creds = settings
    end
    if settings_hook then
      local ok, v, err = protect("the glue's settings", settings_hook, creds, ctx.host or {}, route)
      if not ok then
        return nil, v
      end
      if type(v) ~= "table" then
        return nil,
          errors.is(err) and err or errors.new(
            "SdkError",
            { message = "the glue's settings returned no table" }
          )
      end
      creds = v
    end
    local url = base_url
    if type(base_url) == "function" then
      local ok, v, err = protect("the protocol's base_url", base_url, creds, route)
      if not ok then
        return nil, v
      end
      if type(v) ~= "string" then
        return nil,
          errors.is(err) and err or errors.new(
            "ConfigError",
            { message = "no base URL for " .. tostring(op.name), key = "base_url" }
          )
      end
      url = v
    end
    local headers
    if headers_fn then
      local ok, h, err = protect("the protocol's headers", headers_fn, creds, route, op.name)
      if not ok then
        return nil, h
      end
      if type(h) ~= "table" then
        return nil,
          errors.is(err) and err or errors.new(
            "SdkError",
            { message = "the protocol's headers returned no table" }
          )
      end
      headers = h
    end
    if provider_rt and ctx.user_agent == nil then
      local ua = provider_rt.user_agent(ctx.host)
      if ua ~= nil then
        headers = headers or {}
        headers["user-agent"] = ua
      end
    end
    if headers_hook then
      local ok, h = protect("the glue's headers", headers_hook, creds, route, headers or {})
      if not ok then
        return nil, h
      end
      if type(h) ~= "table" then
        return nil, errors.new("SdkError", { message = "the glue's headers returned no table" })
      end
      headers = h
    end
    if transform_input then
      -- settings (task 27): the resolved options, for inputs that carry a credential
      -- (Mailchimp Transactional's `key`) or a default (Scaleway's region and zone)
      local ok, v = protect(
        "the protocol's transform_input",
        transform_input,
        input,
        op,
        creds,
        ctx.service or {}
      )
      if not ok then
        return nil, v
      end
      input = v
    end
    local service = ctx.service or {}
    local req, berr = request.build({
      op = op,
      input = input,
      registry = service.shapes,
      base_url = url,
      headers = headers,
      map_member_header = opts.map_member_header,
      unknown_key_to_wire = opts.unknown_key_to_wire,
      empty_json_body = opts.empty_json_body,
      query_style = opts.query_style,
      -- the multipart boundary comes from host.random (deterministic under a test host)
      host = ctx.host,
    })
    if req and op.raw_download then
      -- a `...Raw` file download (Scaleway, task 12's op.raw_download) asks for the file
      -- itself, not its JSON description: ScalewayProtocol appends dl=1
      req.url = req.url .. (string.find(req.url, "?", 1, true) and "&" or "?") .. "dl=1"
    end
    if req and sign_hook then
      -- the glue signs the final request (method, URL, headers, body): Coinbase's JWT
      -- covers the label-filled path, Polymarket's HMAC the path and the exact body
      local ok, signed, err = protect(
        "the glue's sign",
        sign_hook,
        req,
        creds,
        { host = ctx.host or {}, op = op, base_url = url }
      )
      if not ok then
        return nil, signed
      end
      if type(signed) ~= "table" then
        return nil,
          errors.is(err) and err or errors.new(
            "SdkError",
            { message = "the glue's sign returned no request" }
          )
      end
      req = signed
    end
    return req, berr
  end

  -----------------------------------------------------------------------------------
  -- response
  -----------------------------------------------------------------------------------

  -- status >= 400: classify_error, typed matchers, status map, unmapped 5xx, unknown
  local function decode_failure(ctx, op, status, headers, text, value, non_json)
    local env = {}
    if not non_json then
      local ok, e = protect("the protocol's error_envelope", envelope, value)
      if not ok then
        return e
      end
      if type(e) == "table" then
        env = e
      end
    end
    local trimmed = trim(text)
    local message = env.message
    if message == nil then
      message = (non_json and trimmed ~= "") and trimmed or ("HTTP " .. tostring(status))
    end
    local body = non_json and text or value
    local now = ctx.host and ctx.host.epoch and ctx.host.epoch() or os.time()

    -- 0. the provider's own reading
    if classify_error then
      local ok, classified = protect("the protocol's classify_error", classify_error, {
        status = status,
        code = env.code,
        message = message,
        body = body,
        headers = headers,
        now = now, -- the host's epoch seconds (a glue computes retry hints from it)
      })
      if not ok then
        return classified
      end
      if classified ~= nil then
        if errors.is(classified) then
          return classified
        end
        return errors.new(
          "SdkError",
          { message = "classify_error returned a value that is not an error" }
        )
      end
    end

    -- 1. the operation's declared errors; a string envelope code never satisfies a
    -- numeric code matcher, so only number codes take part (Distilled's rule)
    local typed = errors.match(classes_of(ctx.service, op), {
      status = status,
      code = type(env.code) == "number" and env.code or nil,
      message = message,
      body = body,
      headers = headers,
      fields_at = opts.error_fields_at,
      retry_after = retry.parse_server_hint(headers, now),
    })
    if typed then
      if typed.code == nil and env.code ~= nil then
        typed.code = env.code
      end
      return typed
    end

    -- 2. the status map; retry_after only on retryable statuses
    local class = status_map[status]
    if class == nil and status >= 500 then
      -- 3. unmapped 5xx (proxy statuses) is a retryable server error
      class = errors.InternalServerError
    end
    if class then
      return errors.new(class, {
        message = message,
        status = status,
        code = env.code,
        body = body,
        headers = headers,
        retry_after = retry.parse_for_status(status, headers, now),
      })
    end

    -- 4. the provider's fallback; only non-5xx reach it, so it is never retried
    return unknown_error({
      status = status,
      code = env.code,
      message = message,
      body = body,
      headers = headers,
    })
  end

  -- a 2xx body (decodeSuccess + checkSuccess)
  local function decode_success(ctx, op, status, headers, text, value, non_json)
    local service = ctx.service or {}
    local registry = service.shapes
    local output = op.output
    local node
    if output ~= nil then
      local resolved, err = schema.resolve(output, registry)
      if not resolved then
        return nil, errors.new("SdkError", { message = err.message })
      end
      node = resolved
    end
    local body
    if non_json then
      body = text
    elseif value == nil then
      -- an empty body (204, or 200 with nothing): "" for a string output, else {}
      body = (node and node.t == "string") and "" or json.object({})
    else
      body = value
    end
    if transform_response then
      -- meta (task 27): the response's status and headers (Scaleway's X-Total-Count)
      local ok, transformed = protect(
        "the protocol's transform_response",
        transform_response,
        body,
        op,
        { status = status, headers = headers }
      )
      if not ok then
        return nil, transformed
      end
      body = transformed
    end

    local mapped = body
    local plan
    if node and node.t == "struct" then
      plan = schema.plan(node)
    end
    local payload = plan and plan.payload
    if payload then
      -- a member that receives the whole body (RawResponse) next to header members
      mapped = json.object({ [payload.name] = keys.decode(payload.schema, body, registry) })
    elseif output ~= nil then
      mapped = keys.decode(output, body, registry)
    end
    if plan and schema.is_record_value(mapped) then
      local copied = false
      local function own()
        if not copied then
          local c = {}
          for k, v in pairs(mapped) do
            c[k] = v
          end
          mapped = setmetatable(c, getmetatable(mapped))
          copied = true
        end
      end
      for _, m in ipairs(plan.by_bind.header or {}) do
        local raw = headers[string.lower(m.wire or m.name)]
        if raw ~= nil then
          own()
          mapped[m.name] = header_value(m, raw, registry)
        end
      end
      for _, m in ipairs(plan.by_bind.status or {}) do
        own()
        mapped[m.name] = status
      end
    end

    if output == nil then
      return mapped
    end
    local sensitive = redact.holds_sensitive(output, registry)
    if non_json and sensitive then
      -- a non-JSON body for an output that can hold a secret fails in every mode
      return nil, parse_error(op, { body = "[REDACTED]", cause = "Invalid JSON response" })
    end
    local mode = ctx.validation or "lenient"
    if mode ~= "lenient" then
      local ok, mismatch = validate.check(output, mapped, registry, { exact = mode == "strict" })
      if not ok then
        if sensitive then
          return nil, parse_error(op, { body = "[REDACTED]", cause = validate.withhold(mismatch) })
        end
        return nil, parse_error(op, { body = non_json and text or value, cause = mismatch })
      end
    end
    if sensitive then
      return redact.wrap(output, mapped, registry)
    end
    return mapped
  end

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    ctx = ctx or {}
    local status = res.status
    local headers = res.headers
    local text = res.body or ""
    if type(text) ~= "string" then
      text = tostring(text)
    end
    local service = ctx.service or {}
    if status >= 200 and status < 300 and op.output ~= nil then
      -- binary outputs return the body bytes untouched
      local node = schema.resolve(op.output, service.shapes)
      if node and node.t == "blob" then
        return text
      end
    end
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
    if status >= 400 and accept_failure then
      -- a provider whose API delivers some success values with an error status
      -- (Coinbase's policy-validation results: isValid / success keys, matchError)
      local ok, accepted = protect("the glue's accept_failure", accept_failure, {
        status = status,
        headers = headers,
        body = non_json and text or value,
        non_json = non_json,
        op = op,
      })
      if not ok then
        return nil, accepted
      end
      if accepted == true then
        return decode_success(ctx, op, status, headers, text, value, non_json)
      end
    end
    if status >= 400 then
      return nil, decode_failure(ctx, op, status, headers, text, value, non_json)
    end
    if classify_success then
      -- APIs that report failures in a 2xx body (Slack `ok: false`, ZeroSSL, Technitium)
      local ok, failed = protect("the protocol's classify_success", classify_success, {
        status = status,
        headers = headers,
        body = non_json and text or value,
        non_json = non_json,
        op = op,
      })
      if not ok then
        return nil, failed
      end
      if failed == true then
        -- a failure the protocol reads like any other (envelope, classify_error, the
        -- operation's errors, the status map, the unknown error): ZeroSSL success = 0
        return nil, decode_failure(ctx, op, status, headers, text, value, non_json)
      end
      if failed ~= nil and failed ~= false then
        if errors.is(failed) then
          return nil, failed
        end
        return nil,
          errors.new(
            "SdkError",
            { message = "classify_success returned a value that is not an error" }
          )
      end
    end
    if op.stream and op.stream.framing == "ndjson" then
      -- a framed body that a plain call collects: its lines are the output's items
      -- (ndjson.ts collect; only when the reply is NDJSON)
      local collected =
        require("distilled.stream.ndjson").collect(text, headers and headers["content-type"])
      if collected then
        return decode_success(ctx, op, status, headers, text, collected.json, collected.non_json)
      end
    end
    return decode_success(ctx, op, status, headers, text, value, non_json)
  end

  -----------------------------------------------------------------------------------
  -- the whole call
  -----------------------------------------------------------------------------------

  -- credentials, the request, the common headers and span facts: what a call and a
  -- stream share. Returns req, transport | nil, err
  local function prepare(ctx, op, input, accept)
    local tracer = ctx.tracer or noop
    local span = ctx.span or noop.NOOP_SPAN
    local host = ctx.host or {}
    local attempt = ctx.attempt or {}

    local creds, cerr
    if ctx.credentials then
      creds, cerr = tracer:with("distilled.credentials", { debug = true }, function()
        return ctx.credentials()
      end)
      if creds == nil then
        return nil, cerr
      end
    else
      creds = {}
    end

    local req, berr = tracer:with("distilled.request.build", { debug = true }, function()
      return protocol.encode(ctx, op, input, creds)
    end)
    if req == nil then
      return nil, berr
    end

    local h = req.headers
    local traceparent = tracer:traceparent()
    if
      traceparent
      and not (ctx.service and ctx.service.telemetry and ctx.service.telemetry.propagate == false)
    then
      h["traceparent"] = traceparent
    end
    if h["accept"] == nil then
      h["accept"] = accept or "application/json"
    end
    if h["user-agent"] == nil then
      h["user-agent"] = ctx.user_agent or user_agent
    end
    req.timeout = ctx.timeout

    local server, port = host_and_port(req.url)
    span:set("http.request.method", req.method)
    span:set("server.address", server)
    span:set("server.port", port)
    attempt.host = server

    local transport = host.transport
    if transport == nil then
      return nil,
        errors.new("ConfigError", {
          message = "no transport; " .. TRANSPORT_HINT,
          key = "transport",
        })
    end
    return req, transport, server
  end

  --- protocol.call(ctx, op, input) -> value, nil, meta | nil, err, meta
  function protocol.call(ctx, op, input)
    local tracer = ctx.tracer or noop
    local span = ctx.span or noop.NOOP_SPAN
    local attempt = ctx.attempt or {}
    local req, transport, server = prepare(ctx, op, input)
    if req == nil then
      return nil, transport
    end
    local res, terr = tracer:with("distilled.transport", {
      debug = true,
      attributes = { ["http.request.method"] = req.method, ["server.address"] = server },
    }, function(s)
      local r, e = transport(req)
      if type(r) == "table" then
        s:set("http.response.status_code", r.status)
      end
      return r, e
    end)
    if
      (type(res) ~= "table" and (res ~= nil or terr == nil))
      or (
        type(res) == "table"
        and res.status == nil
        and getmetatable(res) ~= nil
        and type(getmetatable(res).__call) == "function"
      )
    then
      return nil, contract_error(res)
    end
    if type(res) ~= "table" then
      if not errors.is(terr) then
        terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
      end
      return nil, terr
    end
    if type(res.status) ~= "number" then
      return nil, errors.new("TransportError", { message = "the transport returned no status" })
    end
    local headers = lower_headers(res.headers)
    res = { status = res.status, headers = headers, body = res.body or "" }
    local meta = { status = res.status, headers = headers }
    attempt.status = res.status
    if res.status >= 300 then
      attempt.hint_ms = retry.bounded_hint_ms(headers)
    end
    span:set("http.response.status_code", res.status)
    -- the debug attempt span gets the facts of its own try (telemetry.ts annotate)
    local current = tracer:current()
    if current and current ~= span then
      current:set("http.response.status_code", res.status)
    end

    local value, derr = tracer:with("distilled.decode", { debug = true }, function()
      return protocol.decode(ctx, op, res)
    end)
    if value == nil and derr ~= nil then
      return nil, derr, meta
    end
    return value, nil, meta
  end

  -----------------------------------------------------------------------------------
  -- streams (task 29): protocol-rest.ts `stream` / openFramed
  -----------------------------------------------------------------------------------

  local STREAM_ACCEPT = {
    ndjson = "application/x-ndjson, application/json",
    sse = "text/event-stream, application/json",
  }

  -- one frame's item decoder: a frame schema of its own (op.stream.item), as a 2xx body
  -- decodes (keys, validation, redaction)
  local item_ops = {}
  local function item_op(op)
    local o = item_ops[op]
    if o == nil then
      o = { name = op.name, output = op.stream.item }
      item_ops[op] = o
    end
    return o
  end

  --- protocol.stream(ctx, op, input) -> parts, nil, meta | nil, err, meta
  -- parts = { status, headers, next = fn() -> item | nil, nil | nil, err, close = fn() }.
  -- A status >= 400 is read whole and decoded as the call's typed error.
  function protocol.stream(ctx, op, input)
    ctx = ctx or {}
    local framing_name = op.stream and op.stream.framing
    local stream_lib = require("distilled.stream")
    local framing = framing_name and stream_lib.framing(framing_name)
    if framing == nil then
      return nil,
        errors.new("SdkError", {
          message = tostring(op.name) .. ": its protocol can't stream " .. tostring(framing_name),
        })
    end
    local span = ctx.span or noop.NOOP_SPAN
    local attempt = ctx.attempt or {}
    local req, transport = prepare(ctx, op, input, STREAM_ACCEPT[framing_name])
    if req == nil then
      return nil, transport
    end
    local open = type(transport) == "table" and rawget(transport, "stream")
    if type(open) ~= "function" then
      return nil,
        errors.new("ConfigError", {
          message = "the transport cannot stream (it has no transport.stream entry point); "
            .. "use distilled.host.popen or distilled.host.rex",
          key = "transport",
        })
    end
    local res, terr = open(req)
    if type(res) ~= "table" then
      if not errors.is(terr) then
        terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
      end
      return nil, terr
    end
    local reader = res.body
    local closed = false
    local function close()
      if not closed then
        closed = true
        if type(reader) == "table" and reader.close then
          reader:close()
        end
      end
    end
    if type(res.status) ~= "number" or type(reader) ~= "table" then
      close()
      return nil,
        errors.new("TransportError", { message = "the stream entry point returned no response" })
    end
    local headers = lower_headers(res.headers)
    local meta = { status = res.status, headers = headers }
    attempt.status = res.status
    span:set("http.response.status_code", res.status)
    if res.status >= 300 then
      attempt.hint_ms = retry.bounded_hint_ms(headers)
    end
    if res.status >= 400 then
      local body, rerr = reader:read_all()
      close()
      if body == nil then
        return nil, rerr, meta
      end
      local value, derr =
        protocol.decode(ctx, op, { status = res.status, headers = headers, body = body })
      if value ~= nil then
        -- an accept_failure glue read the failure as a value: one item
        local given = false
        return {
          status = res.status,
          headers = headers,
          next = function()
            if given then
              return nil, nil
            end
            given = true
            return value
          end,
          close = close,
        },
          nil,
          meta
      end
      return nil, derr, meta
    end
    local frames = framing(reader)
    local iop = item_op(op)
    local registry = (ctx.service or {}).shapes
    local function next_item()
      if closed then
        return nil, nil
      end
      local frame, ferr = frames.next()
      if frame == nil then
        close()
        return nil, ferr
      end
      local text = type(frame) == "table" and frame.data or frame
      local value = json.decode(text)
      local non_json = value == nil
      if non_json and framing_name == "ndjson" then
        close()
        local sensitive = iop.output ~= nil and redact.holds_sensitive(iop.output, registry)
        return nil,
          parse_error(
            op,
            { body = sensitive and "[REDACTED]" or text, cause = "Invalid JSON frame" }
          )
      end
      local item, derr = decode_success(ctx, iop, res.status, headers, text, value, non_json)
      if item == nil and derr ~= nil then
        close()
        return nil, derr
      end
      return item
    end
    return { status = res.status, headers = headers, next = next_item, close = close }, nil, meta
  end

  return protocol
end

return rest
