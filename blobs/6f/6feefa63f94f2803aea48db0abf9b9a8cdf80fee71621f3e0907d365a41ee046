-- HMAC (RFC 2104) over the hashes of distilled.crypto.
--
--   hmac.digest(name, key, message) -> binary MAC
--     name: a distilled.crypto hash ("sha256", "sha1", "sha512", "md5", ...)
--     key:  a string or a distilled.secret wrapping one (unwrapped here, never logged)
--
-- HMAC(K, m) = H((K' XOR opad) .. H((K' XOR ipad) .. m)), with K' the key hashed when it is
-- longer than the block and zero-padded to the block size.
local compat = require("distilled.compat")
local secret = require("distilled.secret")
local crypto = require("distilled.crypto")

local hmac = {}

local char, gsub, rep = string.char, string.gsub, string.rep

-- char -> char XORed with 0x36 / 0x5c, applied with one gsub each
local IPAD, OPAD

local function pads()
  if not IPAD then
    local X = require("distilled.crypto.bytes").tables().X
    IPAD, OPAD = {}, {}
    for b = 0, 255 do
      IPAD[char(b)] = char(X[b][0x36])
      OPAD[char(b)] = char(X[b][0x5c])
    end
  end
  return IPAD, OPAD
end

function hmac.digest(name, key, message)
  local hash, block = crypto.hash_function(name)
  key = secret.unwrap(key)
  if type(key) ~= "string" then
    compat.raise("hmac.digest: key must be a string or a secret, got " .. type(key), 2)
  end
  if type(message) ~= "string" then
    compat.raise("hmac.digest: message must be a string, got " .. type(message), 2)
  end
  if #key > block then
    key = hash(key)
  end
  key = key .. rep("\0", block - #key)
  local ipad, opad = pads()
  return hash(gsub(key, ".", opad) .. hash(gsub(key, ".", ipad) .. message))
end

return hmac
