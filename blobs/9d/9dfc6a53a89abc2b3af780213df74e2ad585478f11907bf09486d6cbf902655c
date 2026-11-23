-- Secrets: a wrapper that prints as "<redacted>" and must be unwrapped explicitly.
-- Replaces Distilled's use of effect/Redacted.
--
-- The value sits in the wrapper's own metatable (one per secret), not in a table field,
-- so pairs() over a secret yields nothing and a generic table dumper cannot leak it.
-- json.encode refuses a secret (it checks __distilled_secret) rather than emitting "{}".
local secret = {}

local REDACTED = "<redacted>"

local function secret_mt(s)
  local mt = getmetatable(s)
  if type(mt) == "table" and rawget(mt, "__distilled_secret") == true then
    return mt
  end
  return nil
end

local function refuse_write()
  error("a secret is read-only", 2)
end

local function show()
  return REDACTED
end

--- secret.wrap(value) -> s. Wrapping a secret returns it unchanged.
function secret.wrap(value)
  if secret_mt(value) then
    return value
  end
  local mt = {
    __distilled_secret = true,
    __tostring = show,
    __newindex = refuse_write,
    __concat = function(a, b)
      -- never splice the value into a string
      return tostring(a) .. tostring(b)
    end,
    __secret_value = value,
  }
  return setmetatable({}, mt)
end

function secret.is(v)
  return secret_mt(v) ~= nil
end

--- secret.unwrap(s_or_value) -> value. A plain value is returned as is.
function secret.unwrap(v)
  local mt = secret_mt(v)
  if mt then
    return rawget(mt, "__secret_value")
  end
  return v
end

--- secret.unwrap_deep(value) -> a copy with every secret unwrapped. Plain tables and
-- arrays are copied (keeping their metatable, so json array marks survive); tables that
-- are reached twice are copied once; the input is not modified. json.null is a leaf and
-- is returned as itself: a copy of it would be a plain table and encode as {}.
function secret.unwrap_deep(value)
  -- required here, not at load time: json requires errors, and nothing in json needs
  -- this module, but keeping secret.lua free of load-time requires keeps it a leaf
  local null = require("distilled.json").null
  local seen = {}
  -- iterative walk: gopher-lua has a shallow Lua call stack
  local function copy_of(v)
    if secret_mt(v) then
      return rawget(getmetatable(v), "__secret_value"), false
    end
    if type(v) ~= "table" or v == null then
      return v, false
    end
    if seen[v] then
      return seen[v], false
    end
    local out = {}
    seen[v] = out
    local mt = getmetatable(v)
    if mt ~= nil then
      setmetatable(out, mt)
    end
    return out, true
  end
  local root, fresh = copy_of(value)
  if not fresh then
    return root
  end
  local work = { { value, root } }
  local n = 1
  while n > 0 do
    local pair = work[n]
    work[n] = nil
    n = n - 1
    local src, dst = pair[1], pair[2]
    for k, v in pairs(src) do
      local c, is_new = copy_of(v)
      rawset(dst, k, c)
      if is_new then
        n = n + 1
        work[n] = { v, c }
      end
    end
  end
  return root
end

secret.REDACTED = REDACTED

-- secret(value) is secret.wrap(value)
setmetatable(secret, {
  __call = function(_, value)
    return secret.wrap(value)
  end,
})

return secret
