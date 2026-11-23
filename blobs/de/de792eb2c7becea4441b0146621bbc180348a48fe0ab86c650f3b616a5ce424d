-- distilled.crypto: hashing, HMAC and encodings in pure Lua 5.1, for request signing.
--
--   crypto.digest(name, message) -> binary digest
--     name: "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512" | "sha3_256"
--           | "keccak256" (Ethereum's Keccak-256, original padding)
--   crypto.sha256(message), crypto.sha1(message), ... -> binary digest
--   crypto.hmac(name, key, message) -> binary MAC     (key may be a distilled.secret)
--   crypto.hmac_sha256(key, message), crypto.hmac_sha1, crypto.hmac_sha512
--   crypto.hex.encode / decode, crypto.base64.encode / decode / url_encode / url_decode
--   crypto.crc32(message [, crc]), crypto.crc32c(message [, crc]) -> number
--   crypto.equal(a, b) -> boolean, comparing every byte (for signature checks)
--
-- Every function works on byte strings; a Lua string is already UTF-8 bytes. The
-- algorithms are table-driven byte code (distilled.crypto.bytes explains why) and give
-- identical results on lua 5.1-5.5, LuaJIT and gopher-lua. Submodules load on first use.
local compat = require("distilled.compat")

local crypto = {}

-- name -> { module, block size in bytes (for HMAC), digest length }
local HASHES = {
  md5 = { "md5", 64, 16 },
  sha1 = { "sha1", 64, 20 },
  sha224 = { "sha2", 64, 28 },
  sha256 = { "sha2", 64, 32 },
  sha384 = { "sha2", 128, 48 },
  sha512 = { "sha2", 128, 64 },
  sha3_256 = { "keccak", 136, 32 },
  keccak256 = { "keccak", 136, 32 },
}
crypto.HASHES = HASHES

local function hash_fn(name)
  local h = HASHES[name]
  if not h then
    return nil
  end
  local m = require("distilled.crypto." .. h[1])
  if h[1] == "sha2" then
    return function(message)
      return m.digest(name, message)
    end
  elseif h[1] == "keccak" then
    return m[name]
  end
  return m.digest
end

local fns = {}
-- crypto.hash_function(name) -> fn(message) -> digest, block size; raises on a bad name
function crypto.hash_function(name)
  local fn = fns[name]
  if not fn then
    fn = hash_fn(name)
    if not fn then
      compat.raise("distilled.crypto: unknown hash " .. tostring(name), 3)
    end
    fns[name] = fn
  end
  return fn, HASHES[name][2]
end

function crypto.digest(name, message)
  local fn = crypto.hash_function(name)
  if type(message) ~= "string" then
    compat.raise("crypto.digest: message must be a string, got " .. type(message), 2)
  end
  return fn(message)
end

function crypto.hmac(name, key, message)
  return require("distilled.crypto.hmac").digest(name, key, message)
end

for name in pairs(HASHES) do
  crypto[name] = function(message)
    if type(message) ~= "string" then
      compat.raise("crypto." .. name .. ": message must be a string, got " .. type(message), 2)
    end
    return crypto.hash_function(name)(message)
  end
  crypto["hmac_" .. name] = function(key, message)
    return require("distilled.crypto.hmac").digest(name, key, message)
  end
end

function crypto.crc32(message, crc)
  return require("distilled.crypto.crc32").crc32(message, crc)
end

function crypto.crc32c(message, crc)
  return require("distilled.crypto.crc32").crc32c(message, crc)
end

-- crypto.equal(a, b): true when the strings are equal. It looks at every byte whatever
-- the first difference, so the time does not tell an attacker how much of a signature
-- matched (as far as an interpreter allows).
function crypto.equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then
    compat.raise("crypto.equal: expected two strings", 2)
  end
  if #a ~= #b then
    return false
  end
  local byte = string.byte
  local diff = 0
  for i = 1, #a do
    if byte(a, i) ~= byte(b, i) then
      diff = diff + 1
    end
  end
  return diff == 0
end

-- crypto.hex and crypto.base64 load on first use
local LAZY = { hex = "distilled.crypto.hex", base64 = "distilled.crypto.base64" }
setmetatable(crypto, {
  __index = function(t, k)
    local name = LAZY[k]
    if name then
      local m = require(name)
      rawset(t, k, m)
      return m
    end
    return nil
  end,
})

return crypto
