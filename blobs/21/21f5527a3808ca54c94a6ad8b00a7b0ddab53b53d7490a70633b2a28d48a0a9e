-- The `aws.protocols#httpChecksum` request middleware: a checksum header for the body.
--
-- Port of Distilled's packages/s3/src/middleware/checksum.ts (applyHttpChecksum), which
-- the AWS protocol runs for every operation carrying the trait (S3's DeleteObjects,
-- PutBucket*, PutObject, UploadPart, ...; a few other services too).
--
--   local checksum = require("distilled.s3.checksum")
--   request = checksum.apply(op.http_checksum, request)
--
-- `trait` is the operation's trait in snake_case: { request_algorithm_member?,
-- request_checksum_required? } (nil: no trait, the request is returned as is).
-- `request` is the protocol's serialized request { method, path, query, headers =
-- { [Name] = value }, body, ... }; the result is a copy with the header added.
--
-- Rules (Distilled's, in order):
--   no body (nil or "")                               -> unchanged
--   the trait names an algorithm member: the algorithm is the `x-amz-sdk-checksum-algorithm`
--     header the serializer wrote (lower-cased)
--   not required and no algorithm                     -> unchanged
--   algorithm: the one given, else md5 (bodies here are whole strings, never streams, so
--     Distilled's crc32 default for streams and its aws-chunked trailer never apply)
--   header: `Content-MD5` for md5, else `x-amz-checksum-<algorithm>`; already set (either
--     case) -> unchanged
--   value: base64 of the digest (CRC32 big-endian)
--
-- Intended difference: Distilled computes only crc32 and md5 and leaves the request
-- unchecksummed for any other algorithm (S3 then refuses it: the algorithm header names a
-- checksum that is not there). We also compute crc32c, sha1 and sha256 (distilled.crypto
-- has them). crc64nvme and the xxhash family are still left unchecksummed, as Distilled.
local crypto = require("distilled.crypto")

local checksum = {}

local char, floor, lower = string.char, math.floor, string.lower

checksum.ALGORITHM_HEADER = "x-amz-sdk-checksum-algorithm"

-- a 32-bit number as 4 big-endian bytes
local function be32(n)
  local b1 = floor(n / 16777216) % 256
  local b2 = floor(n / 65536) % 256
  local b3 = floor(n / 256) % 256
  local b4 = n % 256
  return char(b1, b2, b3, b4)
end

-- algorithm -> fn(body) -> binary digest
local DIGESTS = {
  md5 = function(body)
    return crypto.md5(body)
  end,
  crc32 = function(body)
    return be32(crypto.crc32(body))
  end,
  crc32c = function(body)
    return be32(crypto.crc32c(body))
  end,
  sha1 = function(body)
    return crypto.sha1(body)
  end,
  sha256 = function(body)
    return crypto.sha256(body)
  end,
}
checksum.DIGESTS = DIGESTS

--- checksum.header_name(algorithm) -> "Content-MD5" | "x-amz-checksum-<algorithm>"
function checksum.header_name(algorithm)
  if algorithm == "md5" then
    return "Content-MD5"
  end
  return "x-amz-checksum-" .. algorithm
end

--- checksum.value(algorithm, body) -> base64 digest | nil (an algorithm we do not compute)
function checksum.value(algorithm, body)
  local fn = DIGESTS[algorithm]
  if not fn then
    return nil
  end
  return crypto.base64.encode(fn(body))
end

local function copy(t)
  local out = {}
  for k, v in pairs(t) do
    out[k] = v
  end
  return out
end

--- checksum.apply(trait, request) -> request (a copy when a header was added)
function checksum.apply(trait, request)
  if trait == nil then
    return request
  end
  local body = request.body
  if body == nil or body == "" then
    return request
  end
  local headers = request.headers or {}
  local algorithm
  if trait.request_algorithm_member then
    local given = headers[checksum.ALGORITHM_HEADER]
    if type(given) == "string" then
      algorithm = lower(given)
    end
  end
  if not trait.request_checksum_required and not algorithm then
    return request
  end
  algorithm = algorithm or "md5"
  local name = checksum.header_name(algorithm)
  if headers[name] or headers[lower(name)] then
    return request
  end
  local value = checksum.value(algorithm, body)
  if not value then
    return request
  end
  local out = copy(request)
  out.headers = copy(headers)
  out.headers[name] = value
  return out
end

return checksum
