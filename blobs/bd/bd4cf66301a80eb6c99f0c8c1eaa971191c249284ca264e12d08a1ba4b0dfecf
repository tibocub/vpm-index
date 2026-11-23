-- Scaleway's protocol glue (packages/scaleway/src/protocol.ts ScalewayProtocol and
-- errors.ts; scaleway-sdk-js error-parser.ts).
--
-- Requests: a `{region}` / `{zone}` path label the caller leaves out (absent, null or "")
-- is filled from the region / zone option (SCW_DEFAULT_REGION / SCW_DEFAULT_ZONE,
-- default fr-par / fr-par-1), as the official SDKs do. Generative APIs
-- (https://api.scaleway.ai) take the key as `Authorization: Bearer` too.
-- Answers: `null` members are dropped (proto3 JSON writes unset fields as null where the
-- specs declare plain optional members), and Instance v1's X-Total-Count header is folded
-- into the body as total_count. Failures `{ type, message, ... }` map by type to
-- Scaleway's classes; a body without a known type falls to the status classes, then
-- UnknownScalewayError (code = type).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local rest = require("distilled.protocol.rest")
local retry = require("distilled.retry")
local secret = require("distilled.secret")

local GENERATIVE_APIS_HOST = "https://api.scaleway.ai"

local glue = {}

-- errors.ts, long-lived classes: categories as Distilled's Category.with* pipes
local function class(tag, categories, fields, retryable)
  return errors.define({
    tag = tag,
    categories = categories,
    fields = fields,
    retryable = retryable,
  })
end
local RESOURCE = { "resource", "resource_id" }
local InvalidArgumentsError = class("InvalidArgumentsError", { "BadRequestError" }, { "details" })
local DeniedAuthenticationError = class(
  "DeniedAuthenticationError",
  { "AuthError" },
  { "method", "reason" }
)
local PermissionsDeniedError = class("PermissionsDeniedError", { "AuthError" }, { "details" })
local QuotasExceededError = class("QuotasExceededError", { "QuotaError" }, { "details" })
local ResourceNotFoundError = class("ResourceNotFoundError", { "NotFoundError" }, RESOURCE)
local ResourceExpiredError = class(
  "ResourceExpiredError",
  { "NotFoundError" },
  { "resource", "resource_id", "expired_since" }
)
local ResourceLockedError = class("ResourceLockedError", { "LockedError" }, RESOURCE)
local TransientStateError = class(
  "TransientStateError",
  { "ConflictError", "RetryableError" },
  { "resource", "resource_id", "current_state" },
  true
)
local AlreadyExistsError = class(
  "AlreadyExistsError",
  { "AlreadyExistsError" },
  { "resource", "resource_id", "help_message" }
)
local PreconditionFailedError = class(
  "PreconditionFailedError",
  { "ConflictError" },
  { "precondition", "help_message" }
)
local OutOfStockError = class("OutOfStockError", { "QuotaError" }, { "resource" })
local UnknownScalewayError = class("UnknownScalewayError", { "ServerError" }, {})

local function is_object(v)
  return type(v) == "table" and v ~= json.null and not json.is_array(v) and not secret.is(v)
end

local function str(v)
  return type(v) == "string" and v or nil
end

local function records(v)
  local out = {}
  if type(v) == "table" and v ~= json.null and json.is_array(v) then
    for _, item in ipairs(v) do
      if is_object(item) then
        out[#out + 1] = item
      end
    end
  end
  return out
end

local function missing(v)
  return v == nil or v == json.null or v == ""
end

-- withLocality: region / zone labels the caller left out, from the options
function glue.transform_input(input, op, settings)
  local uri = op.uri or ""
  local need_region = string.find(uri, "{region}", 1, true) and missing(rawget(input, "region"))
  local need_zone = string.find(uri, "{zone}", 1, true) and missing(rawget(input, "zone"))
  if not need_region and not need_zone then
    return input
  end
  local out = {}
  for k, v in pairs(input) do
    out[k] = v
  end
  if need_region then
    out.region = settings.region
  end
  if need_zone then
    out.zone = settings.zone
  end
  return out
end

function glue.headers(settings, route, headers)
  if route and route.base_url == GENERATIVE_APIS_HOST and settings.secret_key ~= nil then
    local out = {}
    for k, v in pairs(headers) do
      out[k] = v
    end
    out.authorization = "Bearer " .. tostring(secret.unwrap(settings.secret_key))
    return out
  end
  return headers
end

-- failureMessage: message | help_message | type, plus each argument's help
function glue.error_envelope(body)
  if not is_object(body) then
    return nil
  end
  local base = str(rawget(body, "message"))
    or str(rawget(body, "help_message"))
    or str(rawget(body, "type"))
  if base == nil then
    return nil -- "HTTP <status>"
  end
  local help = {}
  for _, d in ipairs(records(rawget(body, "details"))) do
    local name = rawget(d, "argument_name")
    if type(name) == "string" then
      help[#help + 1] = name
        .. ": "
        .. (str(rawget(d, "help_message")) or str(rawget(d, "reason")) or "invalid")
    end
  end
  if #help > 0 then
    base = base .. " (" .. compat.concat(help, "; ") .. ")"
  end
  return { message = base }
end

local UUID = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

-- JavaScript's "a b".split(/["']/)
local function split_quotes(s)
  local parts, start = {}, 1
  while true do
    local i = string.find(s, "[\"']", start)
    if not i then
      parts[#parts + 1] = string.sub(s, start)
      return parts
    end
    parts[#parts + 1] = string.sub(s, start, i - 1)
    start = i + 1
  end
end

-- scalewayError: the class for a failure body's type, or nil (then the status decides)
function glue.classify_error(info)
  local body = info.body
  if not is_object(body) or type(rawget(body, "type")) ~= "string" then
    return nil
  end
  local message, status = info.message, info.status
  local base = { message = message, status = status, body = body }
  local function with(fields)
    local out = {}
    for k, v in pairs(base) do
      out[k] = v
    end
    for k, v in pairs(fields) do
      out[k] = v
    end
    return out
  end
  local resource, resource_id = str(rawget(body, "resource")), str(rawget(body, "resource_id"))
  local kind = rawget(body, "type")
  if kind == "invalid_arguments" then
    local details = {}
    for _, d in ipairs(records(rawget(body, "details"))) do
      local name, reason = rawget(d, "argument_name"), rawget(d, "reason")
      if type(name) == "string" and type(reason) == "string" then
        details[#details + 1] = json.object({
          argument_name = name,
          reason = reason,
          help_message = str(rawget(d, "help_message")),
        })
      end
    end
    return errors.new(InvalidArgumentsError, with({ details = json.array(details) }))
  elseif kind == "denied_authentication" then
    return errors.new(
      DeniedAuthenticationError,
      with({ method = str(rawget(body, "method")), reason = str(rawget(body, "reason")) })
    )
  elseif kind == "permissions_denied" then
    local details = {}
    for _, d in ipairs(records(rawget(body, "details"))) do
      local r, a = rawget(d, "resource"), rawget(d, "action")
      if type(r) == "string" and type(a) == "string" then
        details[#details + 1] = json.object({ resource = r, action = a })
      end
    end
    return errors.new(PermissionsDeniedError, with({ details = json.array(details) }))
  elseif kind == "quotas_exceeded" then
    local details = {}
    for _, d in ipairs(records(rawget(body, "details"))) do
      local r, q, c = rawget(d, "resource"), rawget(d, "quota"), rawget(d, "current")
      if type(r) == "string" and type(q) == "number" and type(c) == "number" then
        details[#details + 1] = json.object({ resource = r, quota = q, current = c })
      end
    end
    return errors.new(QuotasExceededError, with({ details = json.array(details) }))
  elseif kind == "not_found" then
    return errors.new(
      ResourceNotFoundError,
      with({ resource = resource, resource_id = resource_id })
    )
  elseif kind == "expired" then
    return errors.new(
      ResourceExpiredError,
      with({
        resource = resource,
        resource_id = resource_id,
        expired_since = str(rawget(body, "expired_since")),
      })
    )
  elseif kind == "locked" then
    return errors.new(ResourceLockedError, with({ resource = resource, resource_id = resource_id }))
  elseif kind == "transient_state" then
    return errors.new(
      TransientStateError,
      with({
        resource = resource,
        resource_id = resource_id,
        current_state = str(rawget(body, "current_state")),
      })
    )
  elseif kind == "already_exists" then
    return errors.new(
      AlreadyExistsError,
      with({
        resource = resource,
        resource_id = resource_id,
        help_message = str(rawget(body, "help_message")),
      })
    )
  elseif kind == "precondition_failed" then
    return errors.new(
      PreconditionFailedError,
      with({
        precondition = str(rawget(body, "precondition")),
        help_message = str(rawget(body, "help_message")),
      })
    )
  elseif kind == "out_of_stock" then
    return errors.new(OutOfStockError, with({ resource = resource }))
  elseif kind == "too_many_requests" then
    -- reset_seconds is the server's own wait hint when no Retry-After came with it
    local hint = retry.parse_for_status(429, info.headers or {}, info.now)
    local reset = rawget(body, "reset_seconds")
    if hint == nil and type(reset) == "number" then
      hint = reset
    end
    return errors.new(
      errors.TooManyRequests,
      { message = message, status = status, retry_after = hint }
    )
  elseif kind == "unknown_resource" then
    -- legacy Instance v1: `"<uuid>" not found` / `Security group '<uuid>' not found`
    local parts = split_quotes(str(rawget(body, "message")) or "")
    if #parts == 3 and string.find(parts[2], UUID) then
      local name = string.lower(string.gsub(string.gsub(parts[1], "^%s+", ""), "%s+$", ""))
      name = string.gsub(name, " ", "_")
      return errors.new(
        ResourceNotFoundError,
        with({
          resource = name ~= "" and name or nil,
          resource_id = parts[2],
        })
      )
    end
    if status == 404 then
      return errors.new(ResourceNotFoundError, base)
    end
    return nil
  elseif kind == "invalid_request_error" then
    -- legacy Instance v1: quota failures and per-field validation messages
    local text = string.lower(str(rawget(body, "message")) or "")
    if string.find(text, "quota exceeded for this resource", 1, true) then
      return errors.new(
        QuotasExceededError,
        with({
          details = json.array({
            json.object({ resource = resource or "", quota = 0, current = 0 }),
          }),
        })
      )
    end
    local fields = rawget(body, "fields")
    local details = {}
    if is_object(fields) then
      local names = {}
      for k in pairs(fields) do
        names[#names + 1] = k
      end
      table.sort(names)
      for _, name in ipairs(names) do
        local list = rawget(fields, name)
        if type(list) == "table" and json.is_array(list) then
          for _, m in ipairs(list) do
            if type(m) == "string" then
              details[#details + 1] =
                json.object({ argument_name = name, reason = "constraint", help_message = m })
            end
          end
        end
      end
    end
    if #details > 0 then
      return errors.new(InvalidArgumentsError, with({ details = json.array(details) }))
    end
    return nil
  end
  return nil
end

-- the fallback: UnknownScalewayError with the envelope's type as its code
function glue.unknown_error(info)
  local body = info.body
  return errors.new(UnknownScalewayError, {
    status = info.status,
    code = is_object(body) and str(rawget(body, "type")) or nil,
    message = info.message,
    body = body,
    headers = info.headers,
  })
end

-- stripNulls, then fixLegacyTotalCount (X-Total-Count -> total_count)
function glue.transform_response(body, _, meta)
  if type(body) ~= "table" then
    return body
  end
  body = rest.strip_nulls(body)
  local header = meta and meta.headers and meta.headers["x-total-count"]
  if is_object(body) and rawget(body, "total_count") == nil and type(header) == "string" then
    local n = json.decode(header)
    if type(n) == "number" then
      local copy = {}
      for k, v in pairs(body) do
        copy[k] = v
      end
      copy.total_count = n < 0 and math.ceil(n) or math.floor(n)
      body = setmetatable(copy, getmetatable(body))
    end
  end
  return body
end

return glue
