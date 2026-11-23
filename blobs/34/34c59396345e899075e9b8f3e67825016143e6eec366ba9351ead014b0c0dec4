-- Scope: an ordered list of finalizers, run last-in first-out on close.
-- A much smaller thing than Effect's Scope: no fibers, no interruption. Lua 5.1 has no
-- `finally`, and something must end spans, flush exporters and remove temp files on
-- every exit path.
local compat = require("distilled.compat")

local Scope = {}
Scope.__index = Scope

function Scope.new()
  return setmetatable({ finalizers = {}, closed = false }, Scope)
end

--- scope:defer(fn): fn(err_or_nil) runs when the scope closes. Deferring on a closed
-- scope runs fn at once (with nil), so a late resource is still released.
function Scope:defer(fn)
  if type(fn) ~= "function" then
    error("scope:defer: expected a function", 2)
  end
  if self.closed then
    compat.pcall(fn, nil)
    return
  end
  local list = self.finalizers
  list[#list + 1] = fn
end

--- scope:close([err]) -> true | nil, errs
-- Runs every finalizer under compat.pcall (see compat.lua for why not plain pcall), newest first, passing `err` (the reason the scope
-- closes, or nil). Idempotent: a second close does nothing and returns true.
-- errs is a list of whatever the failing finalizers raised.
function Scope:close(err)
  if self.closed then
    return true
  end
  self.closed = true
  local list = self.finalizers
  self.finalizers = {}
  local failures
  for i = #list, 1, -1 do
    local ok, raised = compat.pcall(list[i], err)
    if not ok then
      failures = failures or {}
      failures[#failures + 1] = raised
    end
  end
  if failures then
    return nil, failures
  end
  return true
end

--- Scope.with(fn) -> ...: fn(scope); the scope closes on return and on a raise, then
-- the original raised value is re-raised (level 0, so it is not re-wrapped).
-- A raise from a finalizer does not replace fn's own error.
function Scope.with(fn)
  if type(fn) ~= "function" then
    error("Scope.with: expected a function", 2)
  end
  local scope = Scope.new()
  local results = compat.pack(compat.pcall(fn, scope))
  if results[1] then
    scope:close(nil)
    return compat.unpack(results, 2, results.n)
  end
  scope:close(results[2])
  error(results[2], 0)
end

return Scope
