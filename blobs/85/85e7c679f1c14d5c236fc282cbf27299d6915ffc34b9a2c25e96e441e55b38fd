-- Small shims for what differs between Lua 5.1, LuaJIT, 5.2+ (here 5.5) and gopher-lua.
-- Anything version-specific belongs here so the rest of the library can stay on 5.1.
local compat = {}

-- `unpack` is a global in 5.1/LuaJIT/gopher-lua, `table.unpack` in 5.2+.
-- gopher-lua has no `table.unpack`, 5.5 has no `unpack`.
compat.unpack = rawget(table, "unpack") or rawget(_G, "unpack")

-- Like 5.2's table.pack: keeps trailing nils countable through `n`.
function compat.pack(...)
  return { n = select("#", ...), ... }
end

local loadstring_fn = rawget(_G, "loadstring")

-- compat.pcall(fn, ...) -> true, ... | false, raised
-- Use this instead of pcall or xpcall. It runs fn in a coroutine: coroutine.resume
-- catches a raise like pcall does, without gopher-lua's protected-call bugs.
--
-- gopher-lua (Rex) has two measured bugs, both breaking the upvalues of closures in the
-- frames still running (a closure made earlier keeps writing to a stale copy; measured:
-- `local n = 0; local function bump() n = n + 1 end; <protected call>; bump()` leaves
-- n == 0):
--   1. a plain pcall that catches an error;
--   2. any protected call (pcall or xpcall) that catches an error after another
--      protected call has completed inside it: xpcall(function() xpcall(f, h);
--      error("y") end, h). So xpcall alone is not safe once calls nest.
-- A coroutine that catches an error triggers neither, at any nesting depth.
--
-- Yield-transparent: when fn yields, the yield is passed on to the coroutine that
-- called compat.pcall and its resume values are handed back to fn, so code under
-- compat.pcall behaves as if it were not wrapped. Called outside any coroutine, a yield
-- has nowhere to go and compat.pcall returns false, "attempt to yield from outside a
-- coroutine" (what pcall gives). Limit: a yield cannot be passed on across a C/Go call
-- boundary between the caller's coroutine and compat.pcall (for example compat.pcall
-- inside a table.sort comparator); there the runtime raises from the forwarding yield,
-- as the same yield would without compat.pcall.
local co_create, co_resume, co_status, co_yield, co_running =
  coroutine.create, coroutine.resume, coroutine.status, coroutine.yield, coroutine.running

-- 5.1/LuaJIT/gopher-lua: running() is nil on the main thread; 5.2+: (thread, true)
local function in_coroutine()
  local co, is_main = co_running()
  return co ~= nil and not is_main
end

local YIELD_OUTSIDE = "attempt to yield from outside a coroutine"

function compat.pcall(fn, ...)
  -- a Lua closure: 5.1 coroutines need a Lua function, and fn may be a callable table
  local co = co_create(function(...)
    return fn(...)
  end)
  local r = compat.pack(co_resume(co, ...))
  while r[1] and co_status(co) == "suspended" do
    if not in_coroutine() then
      return false, YIELD_OUTSIDE
    end
    r = compat.pack(co_resume(co, co_yield(compat.unpack(r, 2, r.n))))
  end
  return compat.unpack(r, 1, r.n)
end

-- gopher-lua reports error(msg, level) at level - 1 (error(msg, 2) names the function
-- that raised, not its caller). Measure once, so compat.raise names the right line.
local LEVEL_SHIFT = 0
do
  local getinfo = debug and debug.getinfo
  if getinfo then
    -- error(_, 2) should name the caller; if the reported line falls inside thrower
    -- itself, the runtime is off by one. Probed in a coroutine, not xpcall: compat is
    -- often first required inside a protected call (see compat.pcall).
    local function thrower()
      error("probe", 2)
    end
    local ok, message = co_resume(co_create(function()
      thrower()
    end))
    local info = getinfo(thrower, "S")
    local line = type(message) == "string" and tonumber(string.match(message, ":(%d+): probe$"))
    if not ok and info and line and line >= info.linedefined and line <= info.lastlinedefined then
      LEVEL_SHIFT = 1
    end
  end
end
compat.ERROR_LEVEL_SHIFT = LEVEL_SHIFT

-- compat.raise(message, level): error(message, level) with gopher-lua's level fixed.
-- Level 1 is the function calling compat.raise, 2 its caller, as with error().
function compat.raise(message, level)
  level = level or 1
  if level <= 0 then
    error(message, 0)
  end
  error(message, level + 1 + LEVEL_SHIFT)
end

-- compat.load(chunk_string, chunkname) -> fn | nil, message
-- 5.5's `load` takes strings; 5.1's `load` takes only functions, so use loadstring there.
function compat.load(chunk, chunkname)
  if type(chunk) ~= "string" then
    error("compat.load: chunk must be a string", 2)
  end
  if loadstring_fn then
    return loadstring_fn(chunk, chunkname)
  end
  return load(chunk, chunkname, "t")
end

-- 5.3+ distinguishes integer and float subtypes; tostring(1.0) is "1.0" there.
-- compat.normalize_number turns an integral float into an integer where that subtype
-- exists, so decoded data prints the same on every runtime.
local math_tointeger = rawget(math, "tointeger")
local TWO_53 = 9007199254740992

function compat.normalize_number(n)
  if math_tointeger and n == n and n > -TWO_53 and n < TWO_53 and n == math.floor(n) then
    -- keep -0.0 as a float: tointeger would drop the sign
    if n == 0 and 1 / n < 0 then
      return n
    end
    return math_tointeger(n) or n
  end
  return n
end

-- True when the runtime has an integer subtype and n is stored as one.
local math_type = rawget(math, "type")
function compat.is_integer_subtype(n)
  return math_type ~= nil and math_type(n) == "integer"
end

-- gopher-lua's table.concat pushes every item onto its registry and fails with
-- "registry overflow" past about 2,500 items (measured: 2559 from a shallow stack).
-- compat.concat joins in chunks so any length works everywhere.
local CONCAT_CHUNK = 500
local table_concat = table.concat

function compat.concat(list, sep)
  sep = sep or ""
  local n = #list
  if n <= CONCAT_CHUNK then
    return table_concat(list, sep)
  end
  local parts, np = {}, 0
  for i = 1, n, CONCAT_CHUNK do
    local j = i + CONCAT_CHUNK - 1
    if j > n then
      j = n
    end
    np = np + 1
    parts[np] = table_concat(list, sep, i, j)
  end
  return compat.concat(parts, sep)
end

return compat
