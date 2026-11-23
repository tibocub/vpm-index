-- AWS errors: the classes every service shares and the wire-code matching.
--
-- Port of Distilled's packages/s3/src/errors.ts (COMMON_ERRORS, UnknownAwsError,
-- InternalError, EndpointError) and the error half of client/response-parser.ts
-- (registerError, synthetic errors, the status fallback, the Message -> message fold,
-- header members, the lower-case first-letter fallback for member keys).
local errors = require("distilled.errors")

local M = {}

local function class(tag, categories, retryable, fields)
  return errors.define({
    tag = tag,
    categories = categories,
    retryable = retryable,
    fields = fields,
  })
end

-- COMMON_ERRORS, in Distilled's order
-- s3/src/errors.ts COMMON_ERRORS, same categories; `withRetryable()` is the class's
-- retryable flag, not the RetryableError category
M.COMMON = {
  class("AccessDeniedException", { "AuthError" }),
  class("ExpiredTokenException", { "AuthError" }),
  class("IncompleteSignature", { "AuthError" }),
  class("InternalError", { "ServerError" }, true),
  class("InternalFailure", { "ServerError" }, true),
  class("MalformedHttpRequestException", { "BadRequestError" }),
  class("NotAuthorized", { "AuthError" }),
  class("OperationAborted", { "AbortedError" }),
  class("OptInRequired", { "AuthError" }),
  class("RequestAbortedException", { "AbortedError" }),
  class("RequestEntityTooLargeException", { "BadRequestError" }),
  class("RequestExpired", { "BadRequestError", "TimeoutError" }),
  class("RequestTimeoutException", { "TimeoutError" }, true),
  class("ServiceUnavailable", { "ServerError" }, true),
  class("ThrottlingException", { "ThrottlingError" }),
  class("UnknownOperationException", { "BadRequestError" }),
  class("UnrecognizedClientException", { "AuthError" }),
  class("ValidationError", { "BadRequestError" }),
  class("ValidationException", { "BadRequestError" }, false, { "reason", "fieldList" }),
}
M.classes = {}
for _, c in ipairs(M.COMMON) do
  M.classes[c.tag] = c
end

M.UnknownAwsError = class("UnknownAwsError", {}, false, { "service", "operation" })
M.EndpointError = class("EndpointError", { "ConfigurationError" })
M.InternalError = M.classes.InternalError

-- stripErrorSuffix
local function strip_suffix(code)
  for _, suffix in ipairs({ "Exception", "Error" }) do
    if #code > #suffix and string.sub(code, -#suffix) == suffix then
      return string.sub(code, 1, -#suffix - 1)
    end
  end
  return code
end
M.strip_suffix = strip_suffix

local function register(map, tag, cls, query_code)
  map[tag] = cls
  local short = strip_suffix(tag)
  if short ~= tag then
    map[short] = cls
  end
  if query_code then
    map[query_code] = cls
  end
end

--- M.table_for(op, service, facts) -> { codes, synthetic, by_status } for one operation
-- (cached on the op descriptor, a long-lived table). facts = the client's per-tag wire
-- facts ({ query_code, status, synthetic, headers }).
function M.table_for(op, service, facts)
  local cached = op._aws_errors
  if cached then
    return cached
  end
  local codes, synthetic, declared = {}, {}, {}
  for _, c in ipairs(M.COMMON) do
    register(codes, c.tag, c)
  end
  for _, tag in ipairs(op.errors or {}) do
    local cls = service.errors and service.errors[tag]
    if cls then
      local f = facts[tag] or {}
      declared[#declared + 1] = { class = cls, status = f.status, headers = f.headers }
      if f.synthetic then
        synthetic[#synthetic + 1] = { class = cls, trait = f.synthetic, headers = f.headers }
      else
        register(codes, tag, cls, f.query_code)
      end
    end
  end
  cached = { codes = codes, synthetic = synthetic, declared = declared, facts = facts }
  op._aws_errors = cached
  return cached
end

local function wire_code_matches(from, code)
  return from == code or strip_suffix(from) == strip_suffix(code)
end

local function matches_message(matcher, message)
  if type(matcher) == "string" then
    return matcher == message
  end
  if type(matcher) ~= "table" then
    return false
  end
  if matcher.includes == nil and matcher.matches == nil then
    return false
  end
  if matcher.includes ~= nil and not string.find(message, matcher.includes, 1, true) then
    return false
  end
  if matcher.matches ~= nil then
    local re = require("distilled.regex").compile(matcher.matches)
    if not re or not re:test(message) then
      return false
    end
  end
  return true
end

--- M.match(tbl, code, status, message) -> class | nil, fallback
-- fallback: "internal" (no code, 5xx), "parse" (no code, no single status match)
function M.match(tbl, code, status, message)
  local best, best_score = nil, 0
  for _, s in ipairs(tbl.synthetic) do
    if wire_code_matches(s.trait.from, code) and matches_message(s.trait.message, message) then
      local score = type(s.trait.message) == "string" and 2 or 1
      if score > best_score then
        best, best_score = s.class, score
      end
    end
  end
  if best then
    return best
  end
  local cls = tbl.codes[code]
  if cls then
    return cls
  end
  if code == "" then
    local hits = {}
    for _, d in ipairs(tbl.declared) do
      if d.status == status then
        hits[#hits + 1] = d.class
      end
    end
    if #hits == 1 then
      return hits[1]
    end
    if status >= 500 then
      return nil, "internal", 0
    end
    return nil, "parse", #hits
  end
  return nil
end

return M
