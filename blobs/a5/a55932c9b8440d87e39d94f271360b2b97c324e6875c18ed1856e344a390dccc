-- Key objects shared by distilled.crypto.rsa, .ecdsa and .ed25519.
--
--   key.new(kind, public_fields, private_fields?) -> key
--   key.private(k) -> private fields table | nil       (for the signing modules)
--   key.is(v) -> boolean
--
-- A key is a table with its public fields (kind, bits, n, e, curve, x, y, public, ...)
-- and `private = true|false`. Private fields (RSA d, p, q, ...; an EC scalar; an
-- Ed25519 seed) live in the key's own metatable, as distilled.secret does, so pairs(),
-- a table dumper or json.encode cannot reach them, and tostring(key) names only the
-- kind: "<rsa private key, 2048 bits>".
local compat = require("distilled.compat")

local key = {}

local function describe(k)
  local mt = getmetatable(k)
  local what = mt.__distilled_key_kind
  if k.curve then
    what = what .. " " .. k.curve
  end
  local text = "<"
    .. what
    .. (rawget(mt, "__distilled_key_private") and " private" or " public")
    .. " key"
  if k.bits then
    text = text .. ", " .. k.bits .. " bits"
  end
  return text .. ">"
end

function key.new(kind, public, private)
  if type(kind) ~= "string" or type(public) ~= "table" then
    compat.raise("key.new: expected a kind and a table of public fields", 2)
  end
  local mt = {
    __distilled_key_kind = kind,
    __distilled_key_private = private,
    __tostring = describe,
  }
  public.kind = kind
  public.private = private ~= nil
  return setmetatable(public, mt)
end

function key.is(v)
  local mt = type(v) == "table" and getmetatable(v)
  return type(mt) == "table" and rawget(mt, "__distilled_key_kind") ~= nil
end

function key.private(k)
  local mt = getmetatable(k)
  return type(mt) == "table" and rawget(mt, "__distilled_key_private") or nil
end

-- key.cache(k) -> a table for derived values (Montgomery contexts, curve points) kept
-- with the key for its lifetime; it sits in the metatable, out of pairs() and json
function key.cache(k)
  local mt = getmetatable(k)
  local c = rawget(mt, "__distilled_key_cache")
  if not c then
    c = {}
    rawset(mt, "__distilled_key_cache", c)
  end
  return c
end

-- the public half of k (k itself when it is public)
function key.public(k)
  if not k.private then
    return k
  end
  local fields = {}
  for name, v in pairs(k) do
    if name ~= "kind" and name ~= "private" then
      fields[name] = v
    end
  end
  return key.new(k.kind, fields)
end

return key
