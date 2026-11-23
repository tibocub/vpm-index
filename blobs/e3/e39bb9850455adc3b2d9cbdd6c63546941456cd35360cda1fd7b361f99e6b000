-- Starburst Galaxy's 429 reading (packages/starburst-galaxy/src/protocol.ts
-- rateLimited): the wait is "try again in N seconds" in the message, else Retry-After.
local errors = require("distilled.errors")
local retry = require("distilled.retry")

local glue = {}

function glue.classify_error(info)
  if info.status ~= 429 then
    return nil
  end
  local message = type(info.message) == "string" and info.message or ""
  local stated = string.match(string.lower(message), "try again in (%d+) seconds?")
  local wait
  if stated then
    wait = tonumber(stated)
  else
    wait = retry.parse_retry_after(info.headers, info.now)
  end
  return errors.new("TooManyRequests", {
    message = info.message,
    status = info.status,
    body = info.body,
    headers = info.headers,
    retry_after = (wait and wait > 0) and wait or nil,
  })
end

return glue
