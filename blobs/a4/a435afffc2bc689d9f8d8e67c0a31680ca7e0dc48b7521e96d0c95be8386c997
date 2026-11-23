-- The host table (docs/interfaces.md, "Host"): defaults, and merging of what a user
-- passes as `host = {...}` and as top-level client options.
--
--   local host = require("distilled.host").merge(opts.host, opts)
--
-- Defaults are pure Lua; the core never shells out (AGENTS.md):
--   transport  none: a call without one fails with ConfigError (key "transport")
--   sleep      a busy wait on os.clock: pure Lua cannot sleep. os.clock is CPU time on
--              lua/luajit (it advances while the loop spins) and wall time in gopher-lua.
--              Hosts should pass a real one (distilled.host.rex does).
--   now        os.time
--   epoch      os.time
--   random     a private Park-Miller generator seeded from the clock and an address,
--              so trace ids differ between processes without touching math.random's
--              state (LuaJIT starts math.random with a fixed seed)
--   getenv     os.getenv
--   exec       none
local compat = require("distilled.compat")

local hostlib = {}

hostlib.FIELDS = { "transport", "sleep", "now", "exec", "random", "getenv", "epoch" }
local FIELD_SET = {}
for _, k in ipairs(hostlib.FIELDS) do
  FIELD_SET[k] = true
end
hostlib.FIELD_SET = FIELD_SET

local function busy_sleep(seconds)
  if type(seconds) ~= "number" or seconds ~= seconds or seconds <= 0 then
    return
  end
  local stop = os.clock() + seconds
  while os.clock() < stop do
  end
end

local function make_random()
  local addr = tonumber(string.match(tostring({}), "0x(%x+)") or "0", 16) or 0
  local seed = (os.time() + math.floor((os.clock() * 1e6) % 1e6) + addr) % 2147483646 + 1
  local state = { x = seed }
  return function()
    state.x = (16807 * state.x) % 2147483647
    return (state.x - 1) / 2147483646
  end
end

local function callable(v)
  if type(v) == "function" then
    return true
  end
  local mt = type(v) == "table" and getmetatable(v)
  return type(mt) == "table" and mt.__call ~= nil
end
hostlib.callable = callable

hostlib.TRANSPORT_HINT = 'pass a transport: require("distilled.transport.popen_curl")(), '
  .. 'require("distilled.transport.exec_curl")(exec), '
  .. 'or a whole host: host = require("distilled.host.popen")()'

--- hostlib.check(value, name, level): raises unless value is nil or callable
-- The transport modules are callable too (they construct transports); they carry
-- `transport_module = "<module name>"`, and passing one as a transport is misuse.
function hostlib.check(value, name, level)
  local module = type(value) == "table" and rawget(value, "transport_module")
  if module then
    compat.raise(
      "host field "
        .. name
        .. " is the "
        .. tostring(module)
        .. " module, a transport constructor, not a transport; "
        .. hostlib.TRANSPORT_HINT,
      (level or 1) + 1
    )
  end
  if value ~= nil and not callable(value) then
    compat.raise(
      "host field " .. name .. " must be a function, got " .. type(value),
      (level or 1) + 1
    )
  end
end

--- hostlib.merge(base, top) -> a fresh host table: fields of `top` win over `base`,
-- defaults fill the rest. Neither argument is modified. Unknown fields of `base` are
-- kept (a test host's `sleeps`, `requests`, ...).
function hostlib.merge(base, top)
  local host = {}
  if type(base) == "table" then
    for k, v in pairs(base) do
      host[k] = v
    end
  end
  if type(top) == "table" then
    for _, k in ipairs(hostlib.FIELDS) do
      if top[k] ~= nil then
        host[k] = top[k]
      end
    end
  end
  host.sleep = host.sleep or busy_sleep
  host.now = host.now or os.time
  host.epoch = host.epoch or os.time
  host.random = host.random or make_random()
  host.getenv = host.getenv or os.getenv
  return host
end

--- hostlib.default() -> a host with every default (and no transport)
function hostlib.default()
  return hostlib.merge(nil, nil)
end

hostlib._busy_sleep = busy_sleep

return hostlib
