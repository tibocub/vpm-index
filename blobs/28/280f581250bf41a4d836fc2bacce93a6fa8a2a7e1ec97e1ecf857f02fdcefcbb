-- Tencent Cloud error classes. Port of Distilled's packages/tencentcloud/src/errors.ts.
--
-- A failed API 3.0 call answers HTTP 200 with an error envelope:
--
--   { "Response": { "Error": { "Code": "AuthFailure.SignatureFailure", "Message": "..." },
--                   "RequestId": "ed93f3cb-..." } }
--
-- `Code` is `<CommonCode>` or `<CommonCode>.<Detail>`. Each common code Tencent documents
-- for every product (https://www.tencentcloud.com/document/api/213/33281) has a class,
-- matched on the code's first segment: `ResourceNotFound.InstanceNotExist` is a
-- ResourceNotFound whose `code` keeps the full value. `ServiceUnavailable` is the core
-- built-in ServiceUnavailable. A code outside the table is UnknownTencentCloudError
-- carrying the code. Every envelope error has `code`, `message` and `request_id`
-- (Distilled's `requestId`).
--
--   local tc_errors = require("distilled.tencentcloud.errors")
--   tc_errors.classes.AuthFailure, tc_errors.COMMON (first segment -> class)
--   tc_errors.envelope_error({ code, message, request_id }, status, body, unknown_class)
local errors = require("distilled.errors")

local tc_errors = {}

local ENVELOPE_FIELDS = { "request_id" }

-- { tag, categories, retryable, throttling } in errors.ts's order. Categories are
-- Distilled's Category.with* pipes; withRetryable() is `retryable`.
local COMMON_SPECS = {
  { "ActionOffline", { "BadRequestError" } },
  { "AuthFailure", { "AuthError" } },
  { "DryRunOperation", {} },
  { "FailedOperation", {} },
  { "InternalError", { "ServerError" }, true },
  { "InvalidAction", { "BadRequestError" } },
  { "InvalidParameter", { "BadRequestError" } },
  { "InvalidParameterValue", { "BadRequestError" } },
  { "InvalidRequest", { "BadRequestError" } },
  { "IpInBlacklist", { "AuthError" } },
  { "IpNotInWhitelist", { "AuthError" } },
  { "LimitExceeded", { "QuotaError" } },
  { "MissingParameter", { "BadRequestError" } },
  { "NoSuchProduct", { "BadRequestError" } },
  { "NoSuchVersion", { "BadRequestError" } },
  { "RequestLimitExceeded", { "ThrottlingError" }, true, true },
  { "RequestSizeLimitExceeded", { "BadRequestError" } },
  { "ResourceInUse", { "ConflictError" } },
  { "ResourceInsufficient", { "QuotaError" } },
  { "ResourceNotFound", { "NotFoundError" } },
  { "ResourceUnavailable", { "ConflictError" } },
  { "ResponseSizeLimitExceeded", { "BadRequestError" } },
  { "UnauthorizedOperation", { "AuthError" } },
  { "UnknownParameter", { "BadRequestError" } },
  { "UnsupportedOperation", { "BadRequestError" } },
  { "UnsupportedProtocol", { "BadRequestError" } },
  { "UnsupportedRegion", { "BadRequestError" } },
}

--- tc_errors.classes[tag]: every common class; tc_errors.COMMON[first segment] -> class
tc_errors.classes = {}
tc_errors.COMMON = {}
tc_errors.TAGS = {}
for i, s in ipairs(COMMON_SPECS) do
  local class = errors.define({
    tag = s[1],
    categories = s[2],
    retryable = s[3] == true,
    throttling = s[4] == true,
    fields = ENVELOPE_FIELDS,
  })
  tc_errors.classes[s[1]] = class
  tc_errors.COMMON[s[1]] = class
  tc_errors.TAGS[i] = s[1]
end

tc_errors.UNKNOWN_TAG = "UnknownTencentCloudError"
tc_errors.PARSE_TAG = "TencentCloudParseError"

--- tc_errors.unknown_class(tag) / tc_errors.parse_class(tag): the provider's fallback
-- classes (the generated client passes its spec's unknown_tag / parse_tag).
function tc_errors.unknown_class(tag)
  return errors.define({ tag = tag or tc_errors.UNKNOWN_TAG, fields = ENVELOPE_FIELDS })
end

function tc_errors.parse_class(tag)
  return errors.define({ tag = tag or tc_errors.PARSE_TAG, categories = { "ParseError" } })
end

--- tc_errors.envelope_error(e, status, body, unknown_class, headers) -> err
-- The error for an envelope's `Code` (Distilled's envelopeError): its common class, the
-- core ServiceUnavailable, or the unknown class with status and body. `e` is
-- { code, message, request_id }.
function tc_errors.envelope_error(e, status, body, unknown_class, headers)
  local code = e.code or ""
  local root = string.match(code, "^([^.]*)")
  if root == "ServiceUnavailable" then
    -- Distilled builds core's ServiceUnavailable with the message only
    return errors.new(errors.ServiceUnavailable, {
      message = e.message,
      code = code,
      request_id = e.request_id,
      status = status,
    })
  end
  local class = tc_errors.COMMON[root]
  if class ~= nil then
    return errors.new(class, {
      code = code,
      message = e.message,
      request_id = e.request_id,
      status = status,
    })
  end
  return errors.new(unknown_class or tc_errors.unknown_class(), {
    code = code,
    message = e.message,
    request_id = e.request_id,
    status = status,
    body = body,
    headers = headers,
  })
end

return tc_errors
