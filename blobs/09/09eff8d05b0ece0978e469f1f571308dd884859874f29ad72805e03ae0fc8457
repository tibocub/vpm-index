-- PEM armour and the key formats the packages accept, decoded into distilled.crypto keys.
--
--   pem.decode(text) -> { { label = "PRIVATE KEY", der = <bytes> }, ... } | nil, err
--   pem.encode(label, der) -> text (64-column base64, trailing newline)
--   pem.private_key(input) -> key | nil, err
--   pem.public_key(input) -> key | nil, err
--
-- input: PEM text, DER bytes, or a distilled.secret holding either. Accepted:
--
--   private  "RSA PRIVATE KEY"  PKCS #1 RSAPrivateKey (GitHub App keys)
--            "PRIVATE KEY"      PKCS #8 PrivateKeyInfo: RSA (GCP service accounts),
--                               EC P-256 / secp256k1, Ed25519 (RFC 8410)
--            "EC PRIVATE KEY"   SEC1 ECPrivateKey (Coinbase CDP, AWS login DPoP keys);
--                               an "EC PARAMETERS" block before it is skipped
--   public   "PUBLIC KEY"       SubjectPublicKeyInfo: RSA, EC, Ed25519
--            "RSA PUBLIC KEY"   PKCS #1 RSAPublicKey
--
-- Text with literal "\n" sequences instead of newlines (a key pasted into an
-- environment variable or a JSON string decoded twice) is accepted. Encrypted keys
-- ("ENCRYPTED PRIVATE KEY", "Proc-Type: 4,ENCRYPTED") fail with InvalidInput. Errors
-- name the format, never the content.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local secret = require("distilled.secret")
local asn1 = require("distilled.crypto.asn1")
local base64 = require("distilled.crypto.base64")

local pem = {}

local OID_RSA = "1.2.840.113549.1.1.1"
local OID_EC = "1.2.840.10045.2.1"
local OID_ED25519 = "1.3.101.112"
local CURVES = {
  ["1.2.840.10045.3.1.7"] = "P-256",
  ["1.3.132.0.10"] = "secp256k1",
}
pem.CURVE_OIDS = {
  ["P-256"] = "1.2.840.10045.3.1.7",
  secp256k1 = "1.3.132.0.10",
}

local function invalid(message)
  return nil, errors.new("InvalidInput", { message = message })
end

function pem.decode(text)
  if type(text) ~= "string" then
    compat.raise("pem.decode: expected a string, got " .. type(text), 2)
  end
  text = text:gsub("\\r", ""):gsub("\\n", "\n"):gsub("\r", "")
  local blocks = {}
  local pos = 1
  while true do
    local s, e, label = text:find("%-%-%-%-%-BEGIN ([%w ]+)%-%-%-%-%-", pos)
    if not s then
      break
    end
    local es, ee = text:find("-----END " .. label .. "-----", e + 1, true)
    if not es then
      return invalid("PEM: no END line for " .. label)
    end
    local body = text:sub(e + 1, es - 1)
    if body:find("Proc-Type:", 1, true) then
      return invalid("PEM: encrypted keys are not supported")
    end
    body = body:gsub("%s", "")
    local der = base64.decode(body)
    if not der then
      return invalid("PEM: the " .. label .. " block is not base64")
    end
    blocks[#blocks + 1] = { label = label, der = der }
    pos = ee + 1
  end
  if #blocks == 0 then
    return invalid("PEM: no BEGIN line")
  end
  return blocks
end

function pem.encode(label, der)
  local b = base64.encode(der)
  local lines = { "-----BEGIN " .. label .. "-----" }
  for i = 1, #b, 64 do
    lines[#lines + 1] = b:sub(i, i + 63)
  end
  lines[#lines + 1] = "-----END " .. label .. "-----"
  return table.concat(lines, "\n") .. "\n"
end

---------------------------------------------------------------------------------------
-- DER structures
---------------------------------------------------------------------------------------

-- wrap an asn1 failure with the format being read
local function fail(what, err)
  return invalid(what .. ": " .. (err and err.message or "malformed"))
end

local function rsa_private_pkcs1(der)
  local what = "PKCS #1 RSA private key"
  local seq, err = asn1.read_all(der)
  if not seq or seq.tag ~= asn1.SEQUENCE then
    return fail(what, err)
  end
  local items
  items, err = asn1.items(seq.value)
  if not items or #items < 9 then
    return fail(what, err)
  end
  local f = {}
  local names = { "version", "n", "e", "d", "p", "q", "dp", "dq", "qi" }
  for i, name in ipairs(names) do
    local v, ierr = asn1.integer(items[i])
    if not v then
      return fail(what, ierr)
    end
    f[name] = v
  end
  if #f.version ~= 0 then
    return invalid(what .. ": multi-prime keys are not supported")
  end
  local key, kerr = require("distilled.crypto.rsa").private_key(f)
  if not key then
    return nil, kerr
  end
  return key
end

local function rsa_public_pkcs1(der)
  local what = "PKCS #1 RSA public key"
  local seq, err = asn1.read_all(der)
  if not seq or seq.tag ~= asn1.SEQUENCE then
    return fail(what, err)
  end
  local items
  items, err = asn1.items(seq.value)
  if not items or #items ~= 2 then
    return fail(what, err)
  end
  local n, nerr = asn1.integer(items[1])
  local e, eerr = asn1.integer(items[2])
  if not n or not e then
    return fail(what, nerr or eerr)
  end
  return require("distilled.crypto.rsa").public_key({ n = n, e = e })
end

-- SEC1 ECPrivateKey (RFC 5915); curve may come from the PKCS #8 wrapper
local function ec_private_sec1(der, curve)
  local what = "SEC1 EC private key"
  local seq, err = asn1.read_all(der)
  if not seq or seq.tag ~= asn1.SEQUENCE then
    return fail(what, err)
  end
  local items
  items, err = asn1.items(seq.value)
  if not items or #items < 2 then
    return fail(what, err)
  end
  local version = asn1.integer(items[1])
  if not version or #version ~= 1 or version[1] ~= 1 then
    return invalid(what .. ": unsupported version")
  end
  local d = asn1.expect(items[2], asn1.OCTET_STRING, "an OCTET STRING")
  if not d then
    return invalid(what .. ": the private scalar is missing")
  end
  local point
  for i = 3, #items do
    local item = items[i]
    if item.tag == asn1.CONTEXT_0 then
      local oid_node = asn1.read_all(item.value)
      local oid = oid_node and asn1.oid(oid_node)
      local named = oid and CURVES[oid]
      if not named then
        return invalid(what .. ": unsupported curve " .. tostring(oid))
      end
      if curve and curve ~= named then
        return invalid(what .. ": the curve parameters disagree")
      end
      curve = named
    elseif item.tag == asn1.CONTEXT_1 then
      local bs = asn1.read_all(item.value)
      point = bs and asn1.bit_string(bs)
      if not point then
        return invalid(what .. ": malformed public key")
      end
    end
  end
  if not curve then
    return invalid(what .. ": no curve named")
  end
  return require("distilled.crypto.ecdsa").private_key(curve, d.value, point)
end

local function algorithm(node, what)
  local alg = asn1.expect(node, asn1.SEQUENCE, "an AlgorithmIdentifier")
  if not alg then
    return invalid(what .. ": no AlgorithmIdentifier")
  end
  local parts, err = asn1.items(alg.value)
  if not parts or #parts == 0 then
    return fail(what, err)
  end
  local oid
  oid, err = asn1.oid(parts[1])
  if not oid then
    return fail(what, err)
  end
  local curve
  if oid == OID_EC then
    local param = parts[2] and asn1.oid(parts[2])
    curve = param and CURVES[param]
    if not curve then
      return invalid(what .. ": unsupported EC curve " .. tostring(param))
    end
  elseif oid ~= OID_RSA and oid ~= OID_ED25519 then
    return invalid(what .. ": unsupported key algorithm " .. oid)
  end
  return oid, curve
end

local function pkcs8(der)
  local what = "PKCS #8 private key"
  local seq, err = asn1.read_all(der)
  if not seq or seq.tag ~= asn1.SEQUENCE then
    return fail(what, err)
  end
  local items
  items, err = asn1.items(seq.value)
  if not items or #items < 3 then
    return fail(what, err)
  end
  local version = asn1.integer(items[1])
  if not version or #version > 1 or (version[1] or 0) > 1 then
    return invalid(what .. ": unsupported version")
  end
  local oid, curve = algorithm(items[2], what)
  if not oid then
    return nil, curve
  end
  local body = asn1.expect(items[3], asn1.OCTET_STRING, "an OCTET STRING")
  if not body then
    return invalid(what .. ": no private key")
  end
  if oid == OID_RSA then
    return rsa_private_pkcs1(body.value)
  elseif oid == OID_EC then
    return ec_private_sec1(body.value, curve)
  end
  -- RFC 8410: CurvePrivateKey ::= OCTET STRING (the 32-byte seed)
  local inner = asn1.read_all(body.value)
  if not inner or inner.tag ~= asn1.OCTET_STRING or #inner.value ~= 32 then
    return invalid(what .. ": malformed Ed25519 key")
  end
  return require("distilled.crypto.ed25519").private_key(inner.value)
end

local function spki(der)
  local what = "SubjectPublicKeyInfo"
  local seq, err = asn1.read_all(der)
  if not seq or seq.tag ~= asn1.SEQUENCE then
    return fail(what, err)
  end
  local items
  items, err = asn1.items(seq.value)
  if not items or #items ~= 2 then
    return fail(what, err)
  end
  local oid, curve = algorithm(items[1], what)
  if not oid then
    return nil, curve
  end
  local bits
  bits, err = asn1.bit_string(items[2])
  if not bits then
    return fail(what, err)
  end
  if oid == OID_RSA then
    return rsa_public_pkcs1(bits)
  elseif oid == OID_EC then
    return require("distilled.crypto.ecdsa").public_key(curve, bits)
  end
  return require("distilled.crypto.ed25519").public_key(bits)
end

---------------------------------------------------------------------------------------
-- entry points
---------------------------------------------------------------------------------------

local function input_of(input, fname)
  input = secret.unwrap(input)
  if type(input) ~= "string" then
    compat.raise(fname .. ": expected PEM text, DER bytes or a secret", 3)
  end
  return input
end

local PRIVATE = {
  ["RSA PRIVATE KEY"] = rsa_private_pkcs1,
  ["PRIVATE KEY"] = pkcs8,
  ["EC PRIVATE KEY"] = function(der)
    return ec_private_sec1(der)
  end,
}
local PUBLIC = { ["PUBLIC KEY"] = spki, ["RSA PUBLIC KEY"] = rsa_public_pkcs1 }

local function from_pem(text, table_, kind)
  local blocks, err = pem.decode(text)
  if not blocks then
    return nil, err
  end
  for _, block in ipairs(blocks) do
    local parse = table_[block.label]
    if parse then
      return parse(block.der)
    end
    if block.label == "ENCRYPTED PRIVATE KEY" then
      return invalid("PEM: encrypted keys are not supported")
    end
  end
  return invalid("PEM: no " .. kind .. " key block (found " .. blocks[1].label .. ")")
end

function pem.private_key(input)
  input = input_of(input, "pem.private_key")
  if input:find("-----BEGIN", 1, true) then
    return from_pem(input, PRIVATE, "private")
  end
  -- DER: PKCS #8 has an AlgorithmIdentifier SEQUENCE second; PKCS #1 and SEC1 have
  -- INTEGER, INTEGER and INTEGER, OCTET STRING
  local seq = asn1.read_all(input)
  local items = seq and seq.tag == asn1.SEQUENCE and asn1.items(seq.value)
  if not items or #items < 2 then
    return invalid("not a PEM or DER private key")
  end
  if items[2].tag == asn1.SEQUENCE then
    return pkcs8(input)
  elseif items[2].tag == asn1.OCTET_STRING then
    return ec_private_sec1(input)
  end
  return rsa_private_pkcs1(input)
end

function pem.public_key(input)
  input = input_of(input, "pem.public_key")
  if input:find("-----BEGIN", 1, true) then
    return from_pem(input, PUBLIC, "public")
  end
  local seq = asn1.read_all(input)
  local items = seq and seq.tag == asn1.SEQUENCE and asn1.items(seq.value)
  if not items or #items ~= 2 then
    return invalid("not a PEM or DER public key")
  end
  if items[1].tag == asn1.SEQUENCE then
    return spki(input)
  end
  return rsa_public_pkcs1(input)
end

return pem
