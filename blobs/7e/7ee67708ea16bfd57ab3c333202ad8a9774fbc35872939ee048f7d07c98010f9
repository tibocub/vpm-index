-- Keccak-256 (the Ethereum hash: Keccak with the original 0x01 padding) and SHA3-256
-- (FIPS 202: 0x06 padding), in pure Lua 5.1.
--
--   keccak.keccak256(message) -> 32-byte binary digest
--   keccak.sha3_256(message)  -> 32-byte binary digest
--
-- No Distilled package needs it today (Polymarket's EIP-712 wallet signatures, which
-- would, are not produced by Distilled either: they also need secp256k1). It is here
-- because it was cheap with the byte tables of distilled.crypto.bytes.
--
-- The state is 25 lanes of 8 bytes, kept in a flat table: lane x + 5y, byte k (least
-- significant first) is S[8 * (x + 5y) + k + 1]. One round of Keccak-f[1600] is
-- generated as Lua source (`keccak.source()`); it reads one state table and writes the
-- other, because pi moves every lane.
local compat = require("distilled.compat")
local bytes = require("distilled.crypto.bytes")
local codegen = require("distilled.crypto.codegen")

local keccak = {}

local char, rep = string.char, string.rep
local byte = string.byte

-- rho rotation offsets r[x][y]
local R = {
  [0] = { [0] = 0, 36, 3, 41, 18 },
  [1] = { [0] = 1, 44, 10, 45, 2 },
  [2] = { [0] = 62, 6, 43, 15, 61 },
  [3] = { [0] = 28, 55, 25, 21, 56 },
  [4] = { [0] = 27, 20, 39, 8, 14 },
}

local RC = bytes.words_from_hex(
  [[
0000000000000001 0000000000008082 800000000000808a 8000000080008000 000000000000808b
0000000080000001 8000000080008081 8000000000008009 000000000000008a 0000000000000088
0000000080008009 000000008000000a 000000008000808b 800000000000008b 8000000000008089
8000000000008003 8000000000008002 8000000000000080 000000000000800a 800000008000000a
8000000080008081 8000000000008080 0000000080000001 8000000080008008]],
  8
)

local round_fn, source

local function at(x, y, k)
  return 8 * (x + 5 * y) + k + 1
end

local function generate()
  local lines, w = codegen.writer()
  -- rotation tables, shared across lanes with the same shift amount modulo 8
  local L, names, identity = {}, {}, {}
  local function add_table(tb)
    for i, existing in ipairs(L) do
      if existing == tb then
        return names[i]
      end
    end
    L[#L + 1] = tb
    names[#L] = "T" .. #L
    local is_identity = true
    for b = 0, 255 do
      if tb[b] ~= b then
        is_identity = false
      end
    end
    identity[names[#L]] = is_identity
    return names[#L]
  end
  local plans = {}
  local rot1_tables, rot1_plan = bytes.linear(8, { { "rotl", 1 } })
  local function plan_names(tables, plan)
    local local_names = {}
    for i, tb in ipairs(tables) do
      local_names[i] = add_table(tb)
    end
    return { plan = plan, names = local_names }
  end
  local rot1 = plan_names(rot1_tables, rot1_plan)
  for x = 0, 4 do
    for y = 0, 4 do
      if R[x][y] ~= 0 then
        local tables, plan = bytes.linear(8, { { "rotl", R[x][y] } })
        plans[x .. "," .. y] = plan_names(tables, plan)
      end
    end
  end
  -- one byte of a rotation: the parts have no bit in common, so they are added; an
  -- identity table (a rotation by whole bytes) is no lookup at all
  local function rot_byte(rot, j, src)
    local terms = {}
    for _, p in ipairs(rot.plan[j]) do
      local name = rot.names[p[2]]
      local operand = src .. p[1]
      terms[#terms + 1] = identity[name] and operand or (name .. "[" .. operand .. "]")
    end
    return table.concat(terms, " + ")
  end

  w("local tb, L = ...")
  w("return function(S, D, rc)")
  w("local X, NA = tb.X, tb.NA")
  codegen.bind(w, names, "L[%d]")
  -- theta: C[x] = XOR of the column, D[x] = C[x-1] XOR rotl1(C[x+1])
  local dnames = {}
  for x = 0, 4 do
    for k = 0, 7 do
      dnames[#dnames + 1] = "d" .. x .. "_" .. k
    end
  end
  w("local %s", table.concat(dnames, ", "))
  w("do")
  for x = 0, 4 do
    for k = 0, 7 do
      local col = {}
      for y = 0, 4 do
        col[#col + 1] = "S[" .. at(x, y, k) .. "]"
      end
      w("local c%d_%d = %s", x, k, codegen.xor_tree(col))
    end
  end
  for x = 0, 4 do
    local left, right = (x + 4) % 5, (x + 1) % 5
    for k = 0, 7 do
      w("d%d_%d = X[c%d_%d][%s]", x, k, left, k, rot_byte(rot1, k, "c" .. right .. "_"))
    end
  end
  w("end")
  -- rho and pi into B, row by row; chi and iota write the row into D
  local row_decl = {}
  for X = 0, 4 do
    for k = 0, 7 do
      row_decl[#row_decl + 1] = "b" .. X .. "_" .. k
    end
  end
  for Y = 0, 4 do
    w("do")
    w("local %s", table.concat(row_decl, ", "))
    for X = 0, 4 do
      -- B[X, Y] = rotl(A'[x, y], r[x][y]) with X = y, Y = 2x + 3y (mod 5)
      local y = X
      local x = (3 * (Y - 3 * X)) % 5
      w("do")
      for k = 0, 7 do
        w("local a%d = X[S[%d]][d%d_%d]", k, at(x, y, k), x, k)
      end
      for k = 0, 7 do
        local value = R[x][y] == 0 and ("a" .. k) or rot_byte(plans[x .. "," .. y], k, "a")
        w("b%d_%d = %s", X, k, value)
      end
      w("end")
    end
    for X = 0, 4 do
      for k = 0, 7 do
        local chi =
          string.format("X[b%d_%d][NA[b%d_%d][b%d_%d]]", X, k, (X + 1) % 5, k, (X + 2) % 5, k)
        if X == 0 and Y == 0 then
          chi = "X[" .. chi .. "][rc[" .. k .. "]]"
        end
        w("D[%d] = %s", at(X, Y, k), chi)
      end
    end
    w("end")
  end
  w("end")
  return lines, L
end

local function round_function()
  if not round_fn then
    local lines, L = generate()
    round_fn, source = codegen.compile(lines, "distilled.crypto.keccak", bytes.tables(), L)
  end
  return round_fn
end

local RATE = 136 -- bytes, for a 256-bit output (capacity 512)

local function sponge(message, domain)
  if type(message) ~= "string" then
    compat.raise("keccak: message must be a string, got " .. type(message), 3)
  end
  local round = round_function()
  local X = bytes.tables().X
  local S, T = {}, {}
  for i = 1, 200 do
    S[i], T[i] = 0, 0
  end
  -- pad10*1 with the domain bits: domain byte, zeros, final 0x80 (merged when adjacent)
  local zeros = RATE - 1 - #message % RATE
  local padded
  if zeros == 0 then
    padded = message .. char(domain + 0x80)
  else
    padded = message .. char(domain) .. rep("\0", zeros - 1) .. "\128"
  end
  for off = 0, #padded - 1, RATE do
    local block = { byte(padded, off + 1, off + RATE) }
    for i = 1, RATE do
      S[i] = X[S[i]][block[i]]
    end
    for r = 1, 24, 2 do
      round(S, T, RC[r])
      round(T, S, RC[r + 1])
    end
  end
  return char(compat.unpack(S, 1, 32))
end

function keccak.keccak256(message)
  return sponge(message, 0x01)
end

function keccak.sha3_256(message)
  return sponge(message, 0x06)
end

function keccak.source()
  round_function()
  return source
end

return keccak
