-- How an AWS request's payload is signed: the `x-amz-content-sha256` rules.
--
-- Port of the payload part of Distilled's packages/s3/src/protocol.ts (toHttpRequest),
-- shared by every AWS service. Lua bodies are whole strings, never streams, so the
-- "streaming body" branches of the original are always false here.
--
--   local payload = require("distilled.s3.payload")
--   local plan = payload.plan{ headers = request.headers, body = request.body,
--                              streaming_input = request.streaming_input,
--                              service_sdk_id = "S3" }
--   -- plan = { headers = <headers to sign>, body = <body to sign or nil>,
--   --          hash_payload = boolean, unsigned = boolean }
--   sigv4.sign{ request = { ..., headers = plan.headers, body = plan.body },
--               hash_payload = plan.hash_payload, ... }
--
-- Rules:
-- - An operation with a `@streaming` input payload (S3 PutObject, UploadPart) signs
--   `UNSIGNED-PAYLOAD`, even for a buffered body, except on the services that rebuild the
--   canonical request from the body (Glacier, SageMaker Runtime, AppConfig,
--   ApiGatewayManagementApi, Bedrock Runtime, IoT Data Plane, IoT Wireless, Lambda).
-- - So does a request with a body and an `x-amz-checksum` header (EBS).
-- - Neither applies when the request already sets `x-amz-content-sha256`.
-- - S3 Control and Glacier sign the real payload hash (`hash_payload`): the signer would
--   otherwise put UNSIGNED-PAYLOAD on anything signed as "s3", and S3 Control refuses it
--   on several routes ("Request body cannot be unsigned"); Glacier requires the header.
-- - Otherwise the signer decides: for the signing name "s3" it sends UNSIGNED-PAYLOAD
--   (aws4fetch's default, distilled.sigv4 keeps it), elsewhere it hashes the body.
local payload = {}

local lower = string.lower

-- services whose streaming-input operations must sign the payload hash
payload.HASH_STREAMING_INPUT = {
  ["Glacier"] = true,
  ["SageMaker Runtime"] = true,
  ["AppConfig"] = true,
  ["ApiGatewayManagementApi"] = true,
  ["Bedrock Runtime"] = true,
  ["IoT Data Plane"] = true,
  ["IoT Wireless"] = true,
  ["Lambda"] = true,
}

-- services that always sign the payload hash when it is not unsigned
payload.HASH_PAYLOAD = {
  ["S3 Control"] = true,
  ["Glacier"] = true,
}

payload.UNSIGNED = "UNSIGNED-PAYLOAD"

local function has_header(headers, name)
  for k in pairs(headers) do
    if lower(k) == name then
      return true
    end
  end
  return false
end
payload.has_header = has_header

--- payload.plan{ headers, body, streaming_input, service_sdk_id } -> plan (see above)
function payload.plan(args)
  local headers = args.headers or {}
  local body = args.body
  local sdk = args.service_sdk_id
  local has_content_sha256 = has_header(headers, "x-amz-content-sha256")
  local has_service_checksum = has_header(headers, "x-amz-checksum")
  local has_body = body ~= nil
  local streaming_input = args.streaming_input == true and not payload.HASH_STREAMING_INPUT[sdk]
  local unsigned = (streaming_input or (has_service_checksum and has_body))
    and not has_content_sha256
  local signing_headers = headers
  if unsigned then
    signing_headers = {}
    for k, v in pairs(headers) do
      signing_headers[k] = v
    end
    signing_headers["X-Amz-Content-Sha256"] = payload.UNSIGNED
  end
  return {
    headers = signing_headers,
    body = (not unsigned) and body or nil,
    hash_payload = (payload.HASH_PAYLOAD[sdk] and not unsigned and not has_content_sha256) or false,
    unsigned = unsigned and true or false,
  }
end

return payload
