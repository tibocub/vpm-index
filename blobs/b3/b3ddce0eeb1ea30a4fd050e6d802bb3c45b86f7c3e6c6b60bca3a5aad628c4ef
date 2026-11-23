-- What the generated clients of proto-sourced providers share (task 23): the provider
-- spec's `rpc` section as runtime data, read by distilled.protocol.grpc and
-- distilled.protocol.connect. Everything here is plain data in, functions out, so the
-- generated init.lua stays declarative:
--
--   local settings = {                        -- provider spec rpc.options
--     token_id = { secret = true, env = { "MODAL_TOKEN_ID" }, required = true },
--     base_url = { env = { "MODAL_SERVER_URL", "MODAL_API_URL" }, default = "https://api.modal.com" },
--     compute_base_url = { env = { "NSC_COMPUTE_URL", "NSC_ENDPOINT" },
--                          default = "https://{region}.compute.namespaceapis.com" },
--   }
--   rpc.client_options(settings) -> Client.define options (the first env of each)
--   rpc.prepare(settings, { require_one_of = { "api_key", "access_token" } })
--     -> fn(creds, host) -> settings | nil, err: the other env variables in order, then
--        the default (whose {name}s are other settings), then the required checks
--   rpc.base_url("{base_url}" | { by_prefix = { { "/pkg.", "{other_url}" } }, default }
--                | { when = "domain", cases = { ["e2b.app"] = "..." }, default })
--     -> fn(settings, route) -> url | nil, ConfigError
--   rpc.headers({ { "authorization", "Bearer {bearer_token}" },
--                 { "x-modal-token-id", "{token_id}", unless = "bearer_token" } })
--     -> fn(settings) -> headers: a rule whose {name} is unset or "" is skipped, and so is
--        one whose `unless` setting is set
--   rpc.when_set(name) -> fn(settings) -> boolean (grpc's http2 = ...)
--   rpc.envelope({ code = "/code", message = { "/message", "/details" } }) -> error_envelope
--   rpc.unknown_error(tag, { details = "/details" }) -> unknown_error with extra fields
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")

local rpc = {}

local function sorted_keys(t)
  local list = {}
  for k in pairs(t) do
    list[#list + 1] = k
  end
  table.sort(list)
  return list
end

local function envs_of(spec)
  local e = spec.env
  if e == nil then
    return {}
  end
  if type(e) == "string" then
    return { e }
  end
  return e
end

local function is_set(v)
  if v == nil or v == json.null then
    return false
  end
  local plain = secret.unwrap(v)
  return plain ~= nil and plain ~= ""
end

--- rpc.client_options(settings) -> options for Client.define
-- Defaults and required checks are rpc.prepare's (a default can name another setting).
function rpc.client_options(settings)
  local out = {}
  for name, spec in pairs(settings) do
    local o = {}
    if spec.secret then
      o.secret = true
    end
    local envs = envs_of(spec)
    if envs[1] then
      o.env = envs[1]
    end
    out[name] = o
  end
  return out
end

-- fill each {name} of text from values; returns text | nil, missing name
local function fill(text, values, raw_whole)
  local missing
  if raw_whole then
    local whole = string.match(text, "^{([%w_]+)}$")
    if whole then
      local v = values[whole]
      if not is_set(v) then
        return nil, whole
      end
      return tostring(secret.unwrap(v))
    end
  end
  local out = string.gsub(text, "{([%w_]+)}", function(name)
    local v = values[name]
    if not is_set(v) then
      missing = missing or name
      return ""
    end
    return tostring(secret.unwrap(v))
  end)
  if missing then
    return nil, missing
  end
  return out
end
rpc.fill = fill

--- rpc.prepare(settings [, opts]) -> fn(creds, host) -> settings | nil, err
function rpc.prepare(settings, opts)
  opts = opts or {}
  local names = sorted_keys(settings)
  return function(creds, host)
    local out = {}
    for k, v in pairs(creds or {}) do
      out[k] = v
    end
    local getenv = (host and host.getenv) or os.getenv
    local pending = {}
    for _, name in ipairs(names) do
      local spec = settings[name]
      if out[name] == nil then
        local envs = envs_of(spec)
        for i = 2, #envs do
          local e = getenv(envs[i])
          if e ~= nil and e ~= "" then
            out[name] = spec.secret and secret.wrap(e) or e
            break
          end
        end
      end
      if out[name] == nil and spec.default ~= nil then
        pending[#pending + 1] = name
      end
    end
    -- defaults, which may name other settings: resolved in as many passes as needed
    local progress = true
    while #pending > 0 and progress do
      progress = false
      local left = {}
      for _, name in ipairs(pending) do
        local d = settings[name].default
        local v = d
        if type(d) == "string" and string.find(d, "{", 1, true) then
          local waiting = false
          for ref in string.gmatch(d, "{([%w_]+)}") do
            for _, p in ipairs(pending) do
              waiting = waiting or (p == ref and p ~= name)
            end
          end
          if waiting then
            v = nil
          else
            v = fill(d, out)
          end
        end
        if v ~= nil then
          out[name] = settings[name].secret and secret.wrap(v) or v
          progress = true
        else
          left[#left + 1] = name
        end
      end
      pending = left
    end
    for _, name in ipairs(names) do
      local spec = settings[name]
      if spec.required and out[name] == nil then
        local envs = envs_of(spec)
        local hint = #envs > 0 and (" or set " .. compat.concat(envs, " or ")) or ""
        return nil,
          errors.new("ConfigError", {
            message = "option " .. name .. " is required: pass " .. name .. " = ..." .. hint,
            key = name,
          })
      end
    end
    if opts.require_one_of then
      local any = false
      local hints = {}
      for _, name in ipairs(opts.require_one_of) do
        any = any or is_set(out[name])
        for _, e in ipairs(envs_of(settings[name] or {})) do
          hints[#hints + 1] = e
        end
      end
      if not any then
        return nil,
          errors.new("ConfigError", {
            message = "one of the options "
              .. compat.concat(opts.require_one_of, ", ")
              .. " is required"
              .. (#hints > 0 and (" (or set " .. compat.concat(hints, " or ") .. ")") or ""),
            key = opts.require_one_of[1],
          })
      end
    end
    return out
  end
end

-- a value placed inside a URL (not the whole URL): host-safe characters only
local function url_fill(template, values)
  local whole = string.match(template, "^{([%w_]+)}$")
  if whole then
    return fill(template, values, true)
  end
  local missing
  local out = string.gsub(template, "{([%w_]+)}", function(name)
    local v = values[name]
    if not is_set(v) then
      missing = missing or name
      return ""
    end
    local s = tostring(secret.unwrap(v))
    if not string.find(s, "^[%w._%-]*$") then
      missing = missing or name
      return ""
    end
    return s
  end)
  if missing then
    return nil, missing
  end
  return out
end

--- rpc.base_url(spec) -> fn(settings, route) -> url | nil, err
function rpc.base_url(spec)
  local function resolve(template, settings)
    local url, missing = url_fill(template, settings)
    if not url then
      return nil,
        errors.new("ConfigError", {
          message = "the base URL "
            .. template
            .. " needs the option "
            .. tostring(missing)
            .. " (as a host part: letters, digits, '.', '-' or '_')",
          key = missing,
        })
    end
    return (string.gsub(url, "/+$", ""))
  end
  if type(spec) == "string" then
    return function(settings)
      return resolve(spec, settings or {})
    end
  end
  if type(spec) ~= "table" then
    compat.raise("rpc.base_url: expected a template or a table", 2)
  end
  return function(settings, route)
    settings = settings or {}
    local uri = route and route.uri or ""
    for _, entry in ipairs(spec.by_prefix or {}) do
      if string.sub(uri, 1, #entry[1]) == entry[1] then
        return resolve(entry[2], settings)
      end
    end
    if spec.when then
      local v = settings[spec.when]
      local case = spec.cases and v ~= nil and spec.cases[tostring(secret.unwrap(v))]
      if case then
        return resolve(case, settings)
      end
    end
    return resolve(spec.default, settings)
  end
end

--- rpc.headers(rules) -> fn(settings) -> headers
function rpc.headers(rules)
  return function(settings)
    settings = settings or {}
    local out = {}
    for _, rule in ipairs(rules) do
      if not (rule.unless and is_set(settings[rule.unless])) then
        local value = fill(rule[2], settings)
        if value ~= nil then
          out[string.lower(rule[1])] = value
        end
      end
    end
    return out
  end
end

--- rpc.when_set(name) -> fn(settings) -> boolean
function rpc.when_set(name)
  return function(settings)
    return is_set(settings and settings[name])
  end
end

local function text_at(body, pointer)
  local v = errors.at_pointer(body, pointer)
  if type(v) == "string" or type(v) == "number" then
    return v
  end
  return nil
end

local function first_text(body, pointers)
  if type(pointers) == "string" then
    return text_at(body, pointers)
  end
  for _, p in ipairs(pointers or {}) do
    local v = text_at(body, p)
    if v ~= nil then
      return v
    end
  end
  return nil
end

--- rpc.envelope{ code = pointer | { ... }, message = pointer | { ... } } -> error_envelope
-- text or numbers only, like Distilled's default envelope; the first pointer with one wins
function rpc.envelope(spec)
  return function(body)
    if type(body) ~= "table" or body == json.null then
      return nil
    end
    local message = first_text(body, spec.message)
    return {
      code = first_text(body, spec.code),
      message = message ~= nil and tostring(message) or nil,
    }
  end
end

--- rpc.unknown_error(tag, fields) -> fn(info) -> err: the unknown error with extra fields
-- read from the body (UnknownNamespaceLabsError's `details`)
function rpc.unknown_error(tag, fields)
  local class = errors.define({ tag = tag })
  return function(info)
    local e = errors.new(class, {
      status = info.status,
      code = info.code ~= nil and tostring(info.code) or nil,
      message = info.message,
      body = info.body,
      headers = info.headers,
    })
    for name, pointer in pairs(fields or {}) do
      if type(info.body) == "table" then
        e[name] = errors.at_pointer(info.body, pointer)
      end
    end
    return e
  end
end

return rpc
