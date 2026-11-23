-- Helpers for the hash modules that generate their compression functions as Lua source
-- (sha2, sha1, md5). The generated code works on bytes with the lookup tables of
-- distilled.crypto.bytes; these helpers write the repetitive parts.
local compat = require("distilled.compat")

local codegen = {}

local floor = math.floor

-- codegen.writer() -> lines, w   where w(fmt, ...) appends one formatted line
function codegen.writer()
  local lines = {}
  return lines,
    function(fmt, ...)
      lines[#lines + 1] = select("#", ...) > 0 and string.format(fmt, ...) or fmt
    end
end

-- "X[X[a][b]][c]": the XOR of a list of expressions, as a balanced tree of lookups
function codegen.xor_tree(list, lo, hi)
  lo, hi = lo or 1, hi or #list
  if lo == hi then
    return list[lo]
  end
  local mid = floor((lo + hi) / 2)
  return "X["
    .. codegen.xor_tree(list, lo, mid)
    .. "]["
    .. codegen.xor_tree(list, mid + 1, hi)
    .. "]"
end

-- codegen.linear(w, width, plan, names, dst, src [, disjoint])
-- Writes `local <dst>j = F(<src>)_j` for each output byte j of a linear function given
-- by its plan (bytes.linear). names[i] is the local holding table i. With `disjoint`
-- (a single rotation or shift: the input bytes reach different output bits), the parts
-- are added instead of XORed, which is one lookup cheaper per part.
function codegen.linear(w, width, plan, names, dst, src, disjoint)
  for j = 0, width - 1 do
    local terms = {}
    for _, p in ipairs(plan[j]) do
      terms[#terms + 1] = names[p[2]] .. "[" .. src .. p[1] .. "]"
    end
    local expr
    if #terms == 0 then
      expr = "0"
    elseif disjoint then
      expr = table.concat(terms, " + ")
    else
      expr = codegen.xor_tree(terms)
    end
    w("local %s%d = %s", dst, j, expr)
  end
end

-- codegen.names("S0_", n) -> { "S0_1", ..., "S0_n" }
function codegen.names(prefix, n)
  local out = {}
  for i = 1, n do
    out[i] = prefix .. i
  end
  return out
end

-- codegen.list(names [, fmt]) -> "a, b, c"; with fmt, item i is string.format(fmt, i)
function codegen.list(names, fmt)
  local out = {}
  for i, n in ipairs(names) do
    out[i] = fmt and string.format(fmt, i) or n
  end
  return table.concat(out, ", ")
end

-- codegen.bind(w, names, fmt): `local n1, n2 = <fmt % 1>, <fmt % 2>` (skipped when empty)
function codegen.bind(w, names, fmt)
  if #names > 0 then
    w("local %s = %s", codegen.list(names), codegen.list(names, fmt))
  end
end

-- codegen.compile(lines, name, ...) -> the generated chunk called with ...
function codegen.compile(lines, name, ...)
  local source = table.concat(lines, "\n")
  local chunk, err = compat.load(source, "=" .. name)
  if not chunk then
    error(name .. ": generated code does not compile: " .. tostring(err))
  end
  return chunk(...), source
end

return codegen
