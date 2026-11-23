-- distilled: the top-level entry point.
local json = require("distilled.json")
local secret = require("distilled.secret")
local Scope = require("distilled.scope")
local errors = require("distilled.errors")

local distilled = {}

distilled.null = json.null
-- distilled.secret is the secret module, and calling it wraps: distilled.secret(key).
distilled.secret = secret
distilled.errors = errors
distilled.json = json
distilled.Scope = Scope

--- distilled.check(value, err) -> value, or raises tostring(err) as a string.
-- For callers that do want to raise (for example a Rex action boundary): gopher-lua's
-- assert rejects table messages, and Rex prints a raised table as "table: 0x...".
-- Raised at level 0: the message is exactly tostring(err), with no "file:line:" prefix
-- (that would point into this file and is noise in the failure Rex shows).
function distilled.check(value, err)
  if value == nil or (value == false and err ~= nil) then
    local message
    if err == nil then
      message = "distilled.check: no value and no error"
    else
      message = tostring(err)
    end
    error(message, 0)
  end
  return value
end

--- distilled.scope(fn) -> ...: a bracket around a block of work (see Scope.with).
function distilled.scope(fn)
  return Scope.with(fn)
end

-- Runtime modules (task 04), loaded on first use so require("distilled") stays cheap:
-- distilled.Client, distilled.rest, distilled.retry, distilled.paginate,
-- distilled.credentials, distilled.host.
local LAZY = {
  Client = "distilled.client",
  rest = "distilled.protocol.rest",
  retry = "distilled.retry",
  paginate = "distilled.paginate",
  credentials = "distilled.credentials",
  host = "distilled.host",
}
-- Functions of those modules, loaded the same way:
-- distilled.file{ data, filename?, content_type? } is distilled.multipart.file, the file
-- part of a multipart body (data may be a secret).
local LAZY_FUNCTIONS = {
  file = { "distilled.multipart", "file" },
}
setmetatable(distilled, {
  __index = function(t, k)
    local name = LAZY[k]
    local v
    if name ~= nil then
      v = require(name)
    elseif LAZY_FUNCTIONS[k] ~= nil then
      v = require(LAZY_FUNCTIONS[k][1])[LAZY_FUNCTIONS[k][2]]
    else
      return nil
    end
    rawset(t, k, v)
    return v
  end,
})

return distilled
