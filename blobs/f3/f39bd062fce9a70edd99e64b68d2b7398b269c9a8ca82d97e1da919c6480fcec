-- Error values: classes, instances, predicates, and typed error matching.
--
-- Ported from Distilled: core/src/errors.ts (built-in classes, HTTP_STATUS_MAP),
-- category.ts (categories, isTransientError, isThrottling), trait.ts (ErrorMatcher)
-- and protocol-http.ts (matchTypedError, matchesExpression, atPointer,
-- matcherSpecificity). Errors are returned as `nil, err`, never raised.
local errors = {}

-- The sixteen category names from Distilled's category.ts, in its order.
errors.CATEGORIES = {
  "AuthError",
  "BadRequestError",
  "ConflictError",
  "NotFoundError",
  "QuotaError",
  "ServerError",
  "ThrottlingError",
  "NetworkError",
  "ParseError",
  "ConfigurationError",
  "TimeoutError",
  "RetryableError",
  "LockedError",
  "AbortedError",
  "AlreadyExistsError",
  "DependencyViolationError",
}

local KNOWN_CATEGORY = {}
for _, name in ipairs(errors.CATEGORIES) do
  KNOWN_CATEGORY[name] = true
end

-- Field names every error instance owns. A class's declared `fields` with one of these
-- names is never filled from a response body (in Distilled a body field could shadow
-- them; here `status` is always the HTTP status, `code` the matched provider code).
local RESERVED_FIELD = {
  tag = true,
  message = true,
  categories = true,
  retryable = true,
  throttling = true,
  status = true,
  code = true,
  body = true,
  headers = true,
  retry_after = true,
  trace_id = true,
  cause = true,
}

local CLASS_MT = {}
CLASS_MT.__index = CLASS_MT
CLASS_MT.__tostring = function(class)
  return "error class " .. class.tag
end

local ERROR_MT = {}
ERROR_MT.__tostring = function(err)
  local text = tostring(err.tag) .. ": " .. tostring(err.message)
  if err.trace_id then
    text = text .. " [trace " .. tostring(err.trace_id) .. "]"
  end
  return text
end

local function copy_set(set)
  local out = {}
  for k, v in pairs(set) do
    out[k] = v
  end
  return out
end

--- errors.define{ tag, categories, retryable, throttling, matchers, fields } -> class
function errors.define(spec)
  if type(spec) ~= "table" then
    error("errors.define: expected a table", 2)
  end
  if type(spec.tag) ~= "string" or spec.tag == "" then
    error("errors.define: tag must be a non-empty string", 2)
  end
  local categories = {}
  for _, name in ipairs(spec.categories or {}) do
    if not KNOWN_CATEGORY[name] then
      error("errors.define: unknown category " .. tostring(name) .. " on " .. spec.tag, 2)
    end
    categories[name] = true
  end
  local retryable = spec.retryable == true
  -- Distilled's isThrottling: a retryable class is throttling only when marked so;
  -- otherwise the ThrottlingError category decides.
  local throttling
  if retryable then
    throttling = spec.throttling == true
  else
    throttling = categories.ThrottlingError == true
  end
  local class = {
    tag = spec.tag,
    categories = categories,
    retryable = retryable,
    throttling = throttling,
    matchers = spec.matchers,
    fields = spec.fields or {},
  }
  return setmetatable(class, CLASS_MT)
end

function errors.is_class(v)
  return type(v) == "table" and getmetatable(v) == CLASS_MT
end

-- Built-in classes, keyed by tag. Filled below.
errors.classes = {}

local function class_for(class_or_tag)
  if errors.is_class(class_or_tag) then
    return class_or_tag
  end
  if type(class_or_tag) == "string" then
    return errors.classes[class_or_tag] or errors.define({ tag = class_or_tag })
  end
  return nil
end

--- errors.new(class_or_tag, fields) -> err
-- Every field given is copied onto the instance; `message` defaults to "HTTP <status>"
-- when a status is given, otherwise to the tag.
function errors.new(class_or_tag, fields)
  local class = class_for(class_or_tag)
  if not class then
    error("errors.new: expected an error class or a tag string", 2)
  end
  if fields ~= nil and type(fields) ~= "table" then
    error("errors.new: fields must be a table", 2)
  end
  local err = {}
  for k, v in pairs(fields or {}) do
    err[k] = v
  end
  err.tag = class.tag
  err.categories = copy_set(class.categories)
  err.retryable = class.retryable
  err.throttling = class.throttling
  if err.message == nil then
    err.message = err.status and ("HTTP " .. tostring(err.status)) or class.tag
  else
    err.message = tostring(err.message)
  end
  return setmetatable(err, ERROR_MT)
end

function errors.is(v)
  return type(v) == "table" and getmetatable(v) == ERROR_MT
end

function errors.is_tag(err, tag)
  return errors.is(err) and err.tag == tag
end

function errors.has_category(err, category)
  return type(err) == "table"
    and type(err.categories) == "table"
    and err.categories[category] == true
end

-- Distilled's isThrottling.
function errors.is_throttling(err)
  if type(err) ~= "table" then
    return false
  end
  if err.retryable then
    return err.throttling == true
  end
  return errors.has_category(err, "ThrottlingError")
end

-- Distilled's isTransientError: only errors that say so are retried. ServerError,
-- TimeoutError and LockedError describe an error; they do not make it retryable.
function errors.is_transient(err)
  if type(err) ~= "table" then
    return false
  end
  return err.retryable == true
    or errors.has_category(err, "RetryableError")
    or errors.has_category(err, "ThrottlingError")
    or errors.has_category(err, "NetworkError")
end

-- Built-in classes (core/src/errors.ts). The retryable ones declare `retry_after`,
-- like Distilled's classes that declare `retryAfter`.
local function builtin(spec)
  local class = errors.define(spec)
  errors.classes[spec.tag] = class
  errors[spec.tag] = class
  return class
end

local RETRY_FIELDS = { "retry_after" }

builtin({ tag = "BadRequest", categories = { "BadRequestError" } })
builtin({ tag = "Unauthorized", categories = { "AuthError" } })
builtin({ tag = "Forbidden", categories = { "AuthError" } })
builtin({ tag = "NotFound", categories = { "NotFoundError" } })
builtin({ tag = "Conflict", categories = { "ConflictError" } })
builtin({ tag = "UnprocessableEntity", categories = { "BadRequestError" } })
builtin({ tag = "Locked", categories = { "LockedError" }, retryable = true, fields = RETRY_FIELDS })
builtin({
  tag = "TooManyRequests",
  categories = { "ThrottlingError" },
  retryable = true,
  throttling = true,
  fields = RETRY_FIELDS,
})
builtin({
  tag = "InternalServerError",
  categories = { "ServerError" },
  retryable = true,
  fields = RETRY_FIELDS,
})
builtin({
  tag = "BadGateway",
  categories = { "ServerError" },
  retryable = true,
  fields = RETRY_FIELDS,
})
builtin({
  tag = "ServiceUnavailable",
  categories = { "ServerError" },
  retryable = true,
  fields = RETRY_FIELDS,
})
builtin({
  tag = "GatewayTimeout",
  categories = { "ServerError" },
  retryable = true,
  fields = RETRY_FIELDS,
})
builtin({ tag = "ConfigError", categories = { "ConfigurationError" }, fields = { "key" } })
builtin({ tag = "InvalidInput", categories = { "BadRequestError" }, fields = { "member" } })
builtin({ tag = "SdkError" })
builtin({ tag = "ParseError", categories = { "ParseError" } })
builtin({ tag = "TransportError", categories = { "NetworkError" } })
builtin({ tag = "UnknownError" })

-- HTTP_STATUS_MAP from errors.ts.
errors.STATUS_MAP = {
  [400] = errors.BadRequest,
  [401] = errors.Unauthorized,
  [403] = errors.Forbidden,
  [404] = errors.NotFound,
  [408] = errors.GatewayTimeout,
  [409] = errors.Conflict,
  [422] = errors.UnprocessableEntity,
  [423] = errors.Locked,
  [429] = errors.TooManyRequests,
  [500] = errors.InternalServerError,
  [502] = errors.BadGateway,
  [503] = errors.ServiceUnavailable,
  [504] = errors.GatewayTimeout,
}

-- RETRYABLE_HTTP_STATUSES and DEFAULT_ERROR_STATUSES from errors.ts.
errors.RETRYABLE_STATUSES = {
  [408] = true,
  [423] = true,
  [429] = true,
  [500] = true,
  [502] = true,
  [503] = true,
  [504] = true,
}
errors.DEFAULT_STATUSES =
  { [401] = true, [429] = true, [500] = true, [502] = true, [503] = true, [504] = true }

---------------------------------------------------------------------------------------
-- Typed error matching (protocol-http.ts)
---------------------------------------------------------------------------------------

-- json is required lazily: json.lua requires this module at load time.
local json_module
local function json()
  json_module = json_module or require("distilled.json")
  return json_module
end

-- REGEX HOOK (task 03): test a matcher's `matches` (a JavaScript regular expression
-- source, as the model carries it) against `value` with distilled.regex. Each source
-- is compiled once and cached by its string (sources come from the model, so the cache
-- is bounded). A source that does not compile never matches; the generator refuses
-- such patterns, so this only happens with hand-written matchers.
local regex_cache = {}
local function regex_test(source, value)
  if type(source) ~= "string" then
    return false
  end
  local matcher = regex_cache[source]
  if matcher == nil then
    matcher = require("distilled.regex").compile(source) or false
    regex_cache[source] = matcher
  end
  return matcher ~= false and matcher:test(value)
end
errors._regex_cache = regex_cache

-- matchesText: exact string, or the conjunction of `includes` and `matches`.
-- Non-string values (numbers, json.null, absent) never match a text matcher.
local function matches_text(matcher, value)
  if type(value) ~= "string" then
    return false
  end
  if type(matcher) == "string" then
    return matcher == value
  end
  if type(matcher) ~= "table" then
    return false
  end
  local includes, matches = matcher.includes, matcher.matches
  return (includes ~= nil or matches ~= nil)
    and (includes == nil or string.find(value, includes, 1, true) ~= nil)
    and (matches == nil or regex_test(matches, value) == true)
end

-- RFC 6901 pointer lookup. Returns nil for a missing member; a JSON null that is present
-- is returned as json.null. Arrays (marked by json) take 0-based decimal indices.
-- rawget keeps inherited (metatable) values out, like Distilled's own-properties rule.
local function at_pointer(body, pointer)
  if pointer == "" then
    return body
  end
  if
    string.sub(pointer, 1, 1) ~= "/"
    or string.find(pointer, "~[^01]")
    or string.find(pointer, "~$")
  then
    return nil
  end
  local J = json()
  local value = body
  local rest = string.sub(pointer, 2)
  local start = 1
  while true do
    local stop = string.find(rest, "/", start, true)
    local segment = string.sub(rest, start, (stop or 0) - 1)
    local key = string.gsub(string.gsub(segment, "~1", "/"), "~0", "~")
    if type(value) ~= "table" or value == J.null then
      return nil
    end
    if J.is_array(value) then
      if not (key == "0" or string.find(key, "^[1-9][0-9]*$")) then
        return nil
      end
      value = rawget(value, tonumber(key) + 1)
    else
      value = rawget(value, key)
    end
    if value == nil then
      return nil
    end
    if not stop then
      return value
    end
    start = stop + 1
  end
end
errors.at_pointer = at_pointer

local function count_keys(t)
  local n = 0
  if type(t) == "table" then
    for _ in pairs(t) do
      n = n + 1
    end
  end
  return n
end

-- matcherSpecificity: one point per code/status/message, body pointer and header.
local function matcher_specificity(m)
  return (m.code ~= nil and 1 or 0)
    + (m.status ~= nil and 1 or 0)
    + (m.message ~= nil and 1 or 0)
    + count_keys(m.body)
    + count_keys(m.headers)
end
errors.matcher_specificity = matcher_specificity

-- matchesExpression: every supplied constraint must match; an unconstrained matcher
-- matches nothing. `code` comparison is type-strict, so a string "4001" never satisfies
-- a numeric code matcher.
local function matches_expression(m, code, status, message, response)
  response = response or {}
  if matcher_specificity(m) == 0 then
    return false
  end
  if m.code ~= nil and m.code ~= code then
    return false
  end
  if m.status ~= nil and m.status ~= status then
    return false
  end
  if m.message ~= nil and not matches_text(m.message, message) then
    return false
  end
  if m.body ~= nil then
    local null = json().null
    for pointer, expected in pairs(m.body) do
      local actual = at_pointer(response.body, pointer)
      if type(expected) == "string" or (type(expected) == "table" and expected ~= null) then
        if not matches_text(expected, actual) then
          return false
        end
      elseif actual ~= expected then
        -- numbers, booleans and json.null compare by value; a missing member (nil)
        -- never equals json.null
        return false
      end
    end
  end
  if m.headers ~= nil then
    for name, expected in pairs(m.headers) do
      if response.headers == nil then
        return false
      end
      local wanted = string.lower(name)
      local actual
      for key, value in pairs(response.headers) do
        if type(key) == "string" and string.lower(key) == wanted then
          actual = value
          break
        end
      end
      if not matches_text(expected, actual) then
        return false
      end
    end
  end
  return true
end
errors.matches_expression = matches_expression

local function is_record(v)
  local J = json()
  return type(v) == "table" and v ~= J.null and not J.is_array(v) and getmetatable(v) ~= ERROR_MT
end

--- errors.match(classes, response_info) -> err | nil
-- response_info = { status, code, message, body, headers, fields_at, retry_after, errors }
-- `errors` (optional) is a list of { code, message } wire errors, for envelopes that
-- carry several; otherwise `code`/`message` form the single wire error. With neither a
-- code nor a message, the message is "HTTP <status>" so body/header matchers still work.
-- `retry_after` (seconds, parsed by the caller) is set only on classes declaring it.
function errors.match(classes, info)
  if type(classes) ~= "table" then
    error("errors.match: classes must be a list", 2)
  end
  info = info or {}
  local status = info.status
  local wire = info.errors
  if wire == nil or #wire == 0 then
    if info.code == nil and info.message == nil then
      wire = { { message = "HTTP " .. tostring(status) } }
    else
      wire = { { code = info.code, message = info.message or ("HTTP " .. tostring(status)) } }
    end
  end
  local best
  for _, class in ipairs(classes) do
    if not errors.is_class(class) then
      error("errors.match: classes must hold error classes", 2)
    end
    if class.matchers then
      for _, m in ipairs(class.matchers) do
        for _, e in ipairs(wire) do
          if matches_expression(m, e.code, status, e.message, info) then
            local specificity = matcher_specificity(m)
            -- strictly greater: ties keep the first declared class
            if not best or specificity > best.specificity then
              best =
                { class = class, specificity = specificity, code = e.code, message = e.message }
            end
          end
        end
      end
    end
  end
  if not best then
    return nil
  end
  local class = best.class
  local fields = {}
  -- declaredBodyFields: from the object at fields_at first, then the top level
  local nested = info.fields_at and at_pointer(info.body, info.fields_at) or nil
  local declares_retry_after = false
  for _, name in ipairs(class.fields) do
    if name == "retry_after" then
      declares_retry_after = true
    elseif not RESERVED_FIELD[name] then
      local value
      if is_record(nested) then
        value = rawget(nested, name)
      end
      if value == nil and is_record(info.body) then
        value = rawget(info.body, name)
      end
      fields[name] = value
    end
  end
  -- the matched code and message always win over the body's
  fields.code = best.code
  fields.message = best.message
  fields.status = status
  fields.body = info.body
  fields.headers = info.headers
  if declares_retry_after then
    fields.retry_after = info.retry_after
  end
  return errors.new(class, fields)
end

return errors
