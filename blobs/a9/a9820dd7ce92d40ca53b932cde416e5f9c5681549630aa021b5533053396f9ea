-- Slack's Web API conventions (packages/slack/src/protocol.ts SlackProtocol and
-- errors.ts).
--
-- Requests (serializeForWire): a list in a QUERY member is one comma-joined parameter
-- (`channel_ids=C1,C2`) when its items are scalars, else its JSON; on a form-urlencoded
-- operation every non-scalar BODY member is sent as one field, comma-joined (a list of
-- scalars) or JSON (blocks, attachments, objects). request.build's own spelling would
-- repeat the query key and bracket the form fields (`a[0]=x`), which Slack does not read.
--
-- Responses: `{ ok = false, error = "<slug>" }`, usually with HTTP 200, is a failure
-- (classify_success). Failures are read in Distilled's order: per-operation matchers
-- (none are generated), throttling (429 or rate_limited/ratelimited -> SlackRateLimited),
-- credential slugs (-> Unauthorized), Slack-side hiccups (-> retryable 5xx classes), any
-- other slug (-> SlackError with the slug as code), then the status classes, then
-- SlackHttpError. A message is the first response_metadata.messages / errors entry, else
-- the slug, else the non-JSON text, else "HTTP <status>".
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local retry = require("distilled.retry")
local schema = require("distilled.schema")
local secret = require("distilled.secret")
local url = require("distilled.url")

local glue = {}

-- long-lived classes (errors.ts)
local SlackError =
  errors.define({ tag = "SlackError", fields = { "needed", "provided", "messages" } })
local SlackRateLimited = errors.define({
  tag = "SlackRateLimited",
  categories = { "ThrottlingError" },
  retryable = true,
  throttling = true,
  fields = { "retry_after" },
})
local SlackHttpError = errors.define({ tag = "SlackHttpError" })

-- slugs that mean "the token is no good" on any method
local AUTH_SLUGS = {
  not_authed = true,
  invalid_auth = true,
  account_inactive = true,
  token_revoked = true,
  token_expired = true,
}

-- slugs that are Slack-side hiccups: retryable server errors
local SERVER_SLUGS = {
  internal_error = errors.InternalServerError,
  fatal_error = errors.InternalServerError,
  service_unavailable = errors.ServiceUnavailable,
  request_timeout = errors.GatewayTimeout,
}

local function is_object(v)
  return type(v) == "table" and v ~= json.null and not json.is_array(v) and not secret.is(v)
end

local function is_scalar(v)
  return type(v) ~= "table" or v == json.null or secret.is(v)
end

-- Array.prototype.join: null and undefined items are empty strings
local function join(list)
  local parts = {}
  for i = 1, #list do
    local v = list[i]
    if v == json.null then
      parts[i] = ""
    else
      parts[i] = url.text(secret.unwrap(v))
    end
  end
  return compat.concat(parts, ",")
end

local function to_json(v)
  local text, err = json.encode(secret.unwrap_deep(v))
  if text == nil then
    return nil, err
  end
  return text
end

-- serializeForWire: input members as Slack's wire wants them, before request.build
function glue.transform_input(input, op, _, service)
  if type(input) ~= "table" or op.input == nil then
    return input
  end
  local node = schema.resolve(op.input, service and service.shapes)
  if node == nil or node.t ~= "struct" then
    return input
  end
  local is_form = op.content_type == "form-urlencoded"
  local out
  for _, m in ipairs(schema.plan(node).members) do
    local value = rawget(input, m.name)
    if not is_scalar(value) then
      local is_query = m.bind == "query"
      local wire
      if schema.is_array_value(value) and (is_query or is_form) then
        local all_scalar = true
        for i = 1, #value do
          if not is_scalar(value[i]) then
            all_scalar = false
            break
          end
        end
        -- a value json cannot encode (a cycle) is left for request.build to report
        wire = all_scalar and join(value) or to_json(value)
      elseif is_form and not is_query and (m.bind == nil or m.bind == "body") then
        wire = to_json(value)
      end
      if wire ~= nil then
        if out == nil then
          out = {}
          for k, v in pairs(input) do
            out[k] = v
          end
        end
        out[m.name] = wire
      end
    end
  end
  return out or input
end

-- `ok: false` in a 2xx answer is a failure, read like any other (classify_error below)
function glue.classify_success(info)
  if is_object(info.body) and rawget(info.body, "ok") == false then
    return true
  end
  return nil
end

local function detail_messages(body)
  local list = {}
  if not is_object(body) then
    return list
  end
  local meta = rawget(body, "response_metadata")
  local sources = {}
  if is_object(meta) then
    sources[#sources + 1] = rawget(meta, "messages")
  end
  sources[#sources + 1] = rawget(body, "errors")
  for _, src in ipairs(sources) do
    if type(src) == "table" and json.is_array(src) then
      for _, m in ipairs(src) do
        if type(m) == "string" then
          list[#list + 1] = m
        end
      end
    end
  end
  return list
end

local function slug_of(body)
  local slug = is_object(body) and rawget(body, "error") or nil
  return type(slug) == "string" and slug or nil
end

-- the message every Slack failure carries (see the header comment)
function glue.error_envelope(body)
  local message = detail_messages(body)[1] or slug_of(body)
  return { code = slug_of(body), message = message }
end

function glue.classify_error(info)
  local body = info.body
  local slug = slug_of(body)
  local message = info.message
  local status = info.status
  -- a 2xx ok:false carries no Retry-After; a 429 does
  if status == 429 or slug == "rate_limited" or slug == "ratelimited" then
    return errors.new(SlackRateLimited, {
      code = slug or "rate_limited",
      message = message,
      status = status,
      retry_after = retry.parse_server_hint(info.headers or {}, info.now),
    })
  end
  if slug ~= nil and AUTH_SLUGS[slug] then
    return errors.new(errors.Unauthorized, { message = slug, status = status })
  end
  if slug ~= nil and SERVER_SLUGS[slug] then
    return errors.new(SERVER_SLUGS[slug], { message = message, status = status })
  end
  if slug ~= nil then
    local messages = detail_messages(body)
    local needed, provided = rawget(body, "needed"), rawget(body, "provided")
    return errors.new(SlackError, {
      code = slug,
      message = message,
      status = status,
      needed = type(needed) == "string" and needed or nil,
      provided = type(provided) == "string" and provided or nil,
      messages = #messages > 0 and messages or nil,
    })
  end
  return nil -- no envelope: the status classes, 5xx, then SlackHttpError
end

-- SlackHttpError: a failure without a Slack envelope (proxy pages, HTML 5xx bodies); the
-- body is the text, cut to 2,000 characters
function glue.unknown_error(info)
  local body = info.body
  if type(body) == "table" then
    body = json.encode(body) or nil
  end
  if type(body) == "string" and #body > 2000 then
    body = string.sub(body, 1, 2000)
  end
  return errors.new(SlackHttpError, { status = info.status, message = info.message, body = body })
end

return glue
