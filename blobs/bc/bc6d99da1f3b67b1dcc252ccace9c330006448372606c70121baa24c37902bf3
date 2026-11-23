-- The DER subset that key files and ECDSA signatures use (X.690), reading and writing.
--
--   asn1.read(der [, pos]) -> node, next_pos | nil, err
--     node = { tag = <identifier octet>, value = <content bytes>, pos = <start> }
--   asn1.items(content) -> { node, ... } | nil, err      every TLV of a constructed value
--   asn1.expect(node, tag, what) -> node | nil, err
--   asn1.integer(node) -> bigint | nil, err               non-negative INTEGER only
--   asn1.oid(node) -> "1.2.840.10045.2.1" | nil, err
--   asn1.bit_string(node) -> bytes | nil, err             no unused bits
--   asn1.encode(tag, content) -> der;  asn1.encode_integer(bigint) -> der
--   asn1.encode_oid("1.2.3") -> der
--   asn1.sequence(der, ...) -> der                         SEQUENCE of the arguments
--
-- Only definite lengths (DER); indefinite-length BER is rejected. Tags are one octet
-- (every key format here uses low tag numbers). Nothing recurses over the data: callers
-- walk a known structure with `items`. Errors are InvalidInput and never quote content
-- (it can be key material).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local bigint = require("distilled.crypto.bigint")

local asn1 = {}

local byte, char, sub = string.byte, string.char, string.sub
local floor = math.floor

asn1.INTEGER = 0x02
asn1.BIT_STRING = 0x03
asn1.OCTET_STRING = 0x04
asn1.NULL = 0x05
asn1.OID = 0x06
asn1.SEQUENCE = 0x30
asn1.CONTEXT_0 = 0xa0
asn1.CONTEXT_1 = 0xa1

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = "DER: " .. message })
end
asn1.invalid = invalid

function asn1.read(der, pos)
  pos = pos or 1
  local n = #der
  if pos + 1 > n then
    return invalid("truncated at byte " .. pos)
  end
  local tag, l = byte(der, pos, pos + 1)
  if tag % 32 == 31 then
    return invalid("multi-octet tags are not supported")
  end
  local p = pos + 2
  local length
  if l < 128 then
    length = l
  elseif l == 128 then
    return invalid("indefinite length")
  else
    local count = l - 128
    if count > 4 or p + count - 1 > n then
      return invalid("bad length at byte " .. pos)
    end
    length = 0
    for i = 0, count - 1 do
      length = length * 256 + byte(der, p + i)
    end
    p = p + count
  end
  if p + length - 1 > n then
    return invalid("length past the end at byte " .. pos)
  end
  return { tag = tag, value = sub(der, p, p + length - 1), pos = pos }, p + length
end

function asn1.items(content)
  local out, pos = {}, 1
  local n = #content
  while pos <= n do
    local node, nxt = asn1.read(content, pos)
    if not node then
      return nil, nxt
    end
    out[#out + 1] = node
    pos = nxt
  end
  return out
end

-- the single TLV that fills `der` exactly
function asn1.read_all(der)
  local node, nxt = asn1.read(der, 1)
  if not node then
    return nil, nxt
  end
  if nxt ~= #der + 1 then
    return invalid("trailing bytes after the value")
  end
  return node
end

function asn1.expect(node, tag, what)
  if not node or node.tag ~= tag then
    return invalid("expected " .. what)
  end
  return node
end

function asn1.integer(node)
  if not node or node.tag ~= asn1.INTEGER or #node.value == 0 then
    return invalid("expected an INTEGER")
  end
  if byte(node.value, 1) >= 128 then
    return invalid("negative INTEGER")
  end
  return bigint.from_bytes(node.value)
end

function asn1.oid(node)
  if not node or node.tag ~= asn1.OID or #node.value == 0 then
    return invalid("expected an OBJECT IDENTIFIER")
  end
  local v = node.value
  local parts = {}
  local acc = 0
  for i = 1, #v do
    local b = byte(v, i)
    acc = acc * 128 + b % 128
    if b < 128 then
      if #parts == 0 then
        local first = acc < 80 and floor(acc / 40) or 2
        parts[1] = string.format("%d", first)
        parts[2] = string.format("%d", acc - first * 40)
      else
        parts[#parts + 1] = string.format("%d", acc)
      end
      acc = 0
    elseif acc > 2 ^ 40 then
      return invalid("OBJECT IDENTIFIER component too large")
    end
  end
  if acc ~= 0 or byte(v, #v) >= 128 then
    return invalid("truncated OBJECT IDENTIFIER")
  end
  return table.concat(parts, ".")
end

function asn1.bit_string(node)
  if not node or node.tag ~= asn1.BIT_STRING or #node.value == 0 then
    return invalid("expected a BIT STRING")
  end
  if byte(node.value, 1) ~= 0 then
    return invalid("BIT STRING with unused bits")
  end
  return sub(node.value, 2)
end

---------------------------------------------------------------------------------------
-- writing
---------------------------------------------------------------------------------------

local function encode_length(n)
  if n < 128 then
    return char(n)
  end
  local bytes = {}
  while n > 0 do
    table.insert(bytes, 1, char(n % 256))
    n = floor(n / 256)
  end
  return char(128 + #bytes) .. table.concat(bytes)
end

function asn1.encode(tag, content)
  if type(tag) ~= "number" or type(content) ~= "string" then
    compat.raise("asn1.encode: expected a tag number and a content string", 2)
  end
  return char(tag) .. encode_length(#content) .. content
end

function asn1.encode_integer(x)
  local b = bigint.to_bytes(x)
  if b == "" or byte(b, 1) >= 128 then
    b = "\0" .. b
  end
  return asn1.encode(asn1.INTEGER, b)
end

function asn1.encode_oid(dotted)
  local nums = {}
  for part in dotted:gmatch("%d+") do
    nums[#nums + 1] = tonumber(part)
  end
  local out = {}
  local function base128(v)
    local groups = { char(v % 128) }
    v = floor(v / 128)
    while v > 0 do
      table.insert(groups, 1, char(128 + v % 128))
      v = floor(v / 128)
    end
    out[#out + 1] = table.concat(groups)
  end
  base128(nums[1] * 40 + nums[2])
  for i = 3, #nums do
    base128(nums[i])
  end
  return asn1.encode(asn1.OID, table.concat(out))
end

function asn1.sequence(...)
  return asn1.encode(asn1.SEQUENCE, table.concat({ ... }))
end

return asn1
