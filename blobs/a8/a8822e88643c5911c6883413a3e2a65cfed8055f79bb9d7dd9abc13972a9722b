-- A small regular-expression matcher for the JavaScript regular expressions that
-- Distilled's patches carry in error matchers (`message = { matches = "..." }`).
--
--   local re, err = regex.compile("^Cannot (GET|POST) /api/x")
--   re:test(text) -> boolean        -- unanchored search, like JavaScript's RegExp.test
--
-- Lua patterns have no alternation or groups, so this is a separate engine. It follows
-- JavaScript's semantics without flags (no `u`, `i`, `m`, `s`):
--
-- - Text and pattern are read as UTF-16 code units, as JavaScript does: a character
--   outside the BMP is two units, so `.` matches half of it, exactly like Node. Bytes
--   that are not valid UTF-8 become units of their own, outside Unicode: only the same
--   byte in the pattern, `.`, negated classes and \S \W \D match them.
-- - `.` matches anything but \n \r U+2028 U+2029; `^` and `$` match only at the ends of
--   the text; `\s` is JavaScript's whitespace set; `\w` and `\d` are ASCII.
-- - Supported: literals, escapes, `.`, classes and negated classes with ranges (also
--   `[]` and `[^]`), `\d \w \s \D \W \S`, `\b \B`, `* + ?` and `{m}`, `{m,}`, `{m,n}`
--   with lazy forms, capturing, named and `(?:` groups, alternation, `^`, `$`.
--   Annex B leniencies Node applies are kept: a `{` that is not a quantifier is a
--   literal, as are `}` and `]`; `\e` (an unknown identity escape) is `e`.
-- - Refused at compile time, with a message: lookaround, backreferences (`\1`, `\k`),
--   inline flags and modifiers (`(?i)`), Unicode property escapes (`\p{..}`), `\u{..}`,
--   legacy octal escapes. They must never match wrongly, so they never compile.
--
-- Matching only answers "is there a match", so greedy and lazy quantifiers behave the
-- same and the engine can be a Pike VM (a set of NFA threads stepped over the text):
-- linear in the text, no backtracking, no recursion. gopher-lua's call stack is about
-- 250 frames, so a recursive backtracker would overflow on long messages.
local regex = {}

local MAX_PROGRAM = 20000 -- instructions; `{m,n}` copies its operand

-- Units that are not real UTF-16 code units: an invalid UTF-8 byte b becomes
-- INVALID_BASE + b. They match `.`, negated classes, \S \W \D and the same byte.
local INVALID_BASE = 0x110000
local MAX_UNIT = INVALID_BASE + 255

local byte, sub = string.byte, string.sub
local floor = math.floor

---------------------------------------------------------------------------------------
-- UTF-8 -> UTF-16 code units
---------------------------------------------------------------------------------------

local function push_code_point(units, n, cp)
  if cp >= 0x10000 then
    local v = cp - 0x10000
    units[n + 1] = 0xD800 + floor(v / 1024)
    units[n + 2] = 0xDC00 + v % 1024
    return n + 2
  end
  units[n + 1] = cp
  return n + 1
end

local function is_cont(b)
  return b ~= nil and b >= 0x80 and b <= 0xBF
end

-- regex.units(text) -> list of UTF-16 code units (exposed for specs)
local function to_units(text)
  local units, n = {}, 0
  local i, len = 1, #text
  while i <= len do
    local b1 = byte(text, i)
    local cp, size
    if b1 < 0x80 then
      cp, size = b1, 1
    elseif b1 >= 0xC2 and b1 <= 0xDF and is_cont(byte(text, i + 1)) then
      cp, size = (b1 - 0xC0) * 64 + (byte(text, i + 1) - 0x80), 2
    elseif b1 >= 0xE0 and b1 <= 0xEF then
      local b2, b3 = byte(text, i + 1), byte(text, i + 2)
      if is_cont(b2) and is_cont(b3) then
        local v = (b1 - 0xE0) * 4096 + (b2 - 0x80) * 64 + (b3 - 0x80)
        -- reject overlong forms; encoded surrogates pass as the unit they name
        if v >= 0x800 then
          cp, size = v, 3
        end
      end
    elseif b1 >= 0xF0 and b1 <= 0xF4 then
      local b2, b3, b4 = byte(text, i + 1), byte(text, i + 2), byte(text, i + 3)
      if is_cont(b2) and is_cont(b3) and is_cont(b4) then
        local v = (b1 - 0xF0) * 262144 + (b2 - 0x80) * 4096 + (b3 - 0x80) * 64 + (b4 - 0x80)
        if v >= 0x10000 and v <= 0x10FFFF then
          cp, size = v, 4
        end
      end
    end
    if cp == nil then
      n = n + 1
      units[n] = INVALID_BASE + b1
      i = i + 1
    else
      n = push_code_point(units, n, cp)
      i = i + size
    end
  end
  return units, n
end
regex.units = to_units

---------------------------------------------------------------------------------------
-- character sets: sorted, merged lists of { lo, hi } ranges
---------------------------------------------------------------------------------------

local function normalize(ranges)
  table.sort(ranges, function(a, b)
    return a[1] < b[1]
  end)
  local out, n = {}, 0
  for _, r in ipairs(ranges) do
    local last = out[n]
    if last and r[1] <= last[2] + 1 then
      if r[2] > last[2] then
        last[2] = r[2]
      end
    else
      n = n + 1
      out[n] = { r[1], r[2] }
    end
  end
  return out
end

local function complement(ranges)
  local out, n, next_lo = {}, 0, 0
  for _, r in ipairs(normalize(ranges)) do
    if r[1] > next_lo then
      n = n + 1
      out[n] = { next_lo, r[1] - 1 }
    end
    next_lo = r[2] + 1
  end
  if next_lo <= MAX_UNIT then
    out[n + 1] = { next_lo, MAX_UNIT }
  end
  return out
end

local DIGIT = { { 48, 57 } }
local WORD = { { 48, 57 }, { 65, 90 }, { 95, 95 }, { 97, 122 } }
-- ECMAScript WhiteSpace and LineTerminator
local SPACE = normalize({
  { 9, 13 },
  { 32, 32 },
  { 0xA0, 0xA0 },
  { 0x1680, 0x1680 },
  { 0x2000, 0x200A },
  { 0x2028, 0x2029 },
  { 0x202F, 0x202F },
  { 0x205F, 0x205F },
  { 0x3000, 0x3000 },
  { 0xFEFF, 0xFEFF },
})
local CLASS_ESCAPES = {
  d = DIGIT,
  w = WORD,
  s = SPACE,
  D = complement(DIGIT),
  W = complement(WORD),
  S = complement(SPACE),
}
-- `.`: everything but the line terminators
local DOT = complement({ { 10, 10 }, { 13, 13 }, { 0x2028, 0x2029 } })

local function in_set(ranges, c)
  for i = 1, #ranges do
    local r = ranges[i]
    if c < r[1] then
      return false
    end
    if c <= r[2] then
      return true
    end
  end
  return false
end

local function is_word(c)
  return c ~= nil and in_set(WORD, c)
end

---------------------------------------------------------------------------------------
-- parser: pattern units -> tree
---------------------------------------------------------------------------------------
-- nodes: { k = "char", c } | { k = "set", ranges } | { k = "bol" } | { k = "eol" }
--        | { k = "wb", negate } | { k = "cat", items } | { k = "alt", items }
--        | { k = "rep", node, min, max (nil: unbounded) }

local C = {}
for _, ch in ipairs({
  "\\",
  "^",
  "$",
  ".",
  "|",
  "(",
  ")",
  "[",
  "]",
  "{",
  "}",
  "*",
  "+",
  "?",
  "-",
  ",",
  ":",
  "=",
  "!",
  "<",
  ">",
}) do
  C[ch] = byte(ch)
end

local function is_digit(c)
  return c ~= nil and c >= 48 and c <= 57
end

local function hex_value(c)
  if c == nil then
    return nil
  end
  if c >= 48 and c <= 57 then
    return c - 48
  elseif c >= 65 and c <= 70 then
    return c - 55
  elseif c >= 97 and c <= 102 then
    return c - 87
  end
  return nil
end

local function parse(source)
  local p, np = to_units(source)
  local i = 1

  local function fail(reason, at)
    error({ regex_error = true, message = reason, position = at or i }, 0)
  end

  local function peek(offset)
    return p[i + (offset or 0)]
  end

  local function read_hex(count)
    local v = 0
    for k = 0, count - 1 do
      local h = hex_value(p[i + k])
      if h == nil then
        return nil
      end
      v = v * 16 + h
    end
    i = i + count
    return v
  end

  -- an escape after `\` (i points past the backslash). Returns kind, value:
  -- "char", unit | "set", ranges | "wb", negate
  local function parse_escape(in_class)
    local c = p[i]
    if c == nil then
      fail("\\ at end of pattern", i - 1)
    end
    local ch = string.char(c < 128 and c or 63)
    i = i + 1
    if c >= 128 then
      return "char", c
    end
    if CLASS_ESCAPES[ch] then
      return "set", CLASS_ESCAPES[ch]
    end
    if ch == "b" then
      if in_class then
        return "char", 8
      end
      return "wb", false
    elseif ch == "B" then
      if in_class then
        return "char", c
      end
      return "wb", true
    elseif ch == "n" then
      return "char", 10
    elseif ch == "r" then
      return "char", 13
    elseif ch == "t" then
      return "char", 9
    elseif ch == "v" then
      return "char", 11
    elseif ch == "f" then
      return "char", 12
    elseif ch == "0" then
      if is_digit(p[i]) then
        fail("legacy octal escapes are not supported", i - 2)
      end
      return "char", 0
    elseif is_digit(c) then
      fail("backreferences (and legacy octal escapes) are not supported", i - 2)
    elseif ch == "k" then
      fail("named backreferences (\\k) are not supported", i - 2)
    elseif ch == "p" or ch == "P" then
      fail("Unicode property escapes (\\p, \\P) are not supported", i - 2)
    elseif ch == "x" then
      local v = read_hex(2)
      if v == nil then
        return "char", c -- Annex B: "\x" without two hex digits is "x"
      end
      return "char", v
    elseif ch == "u" then
      if p[i] == C["{"] then
        fail("\\u{...} escapes need the u flag, which is not supported", i - 2)
      end
      local v = read_hex(4)
      if v == nil then
        return "char", c
      end
      return "char", v
    elseif ch == "c" then
      local l = p[i]
      if l and ((l >= 65 and l <= 90) or (l >= 97 and l <= 122)) then
        i = i + 1
        return "char", l % 32
      end
      fail("\\c must be followed by a letter", i - 2)
    end
    -- identity escape: the character itself (Annex B accepts letters too)
    return "char", c
  end

  local function parse_class()
    -- i points past "["
    local negate = false
    if p[i] == C["^"] then
      negate = true
      i = i + 1
    end
    local start = i - 1
    local ranges = {}
    local function atom()
      local c = p[i]
      if c == nil then
        fail("unterminated character class", start)
      end
      if c == C["\\"] then
        i = i + 1
        local kind, v = parse_escape(true)
        if kind == "set" then
          return nil, v
        end
        return v
      end
      i = i + 1
      return c
    end
    while true do
      local c = p[i]
      if c == nil then
        fail("unterminated character class", start)
      end
      if c == C["]"] then
        i = i + 1
        break
      end
      local lo, lo_set = atom()
      if p[i] == C["-"] and p[i + 1] ~= nil and p[i + 1] ~= C["]"] then
        i = i + 1
        local hi, hi_set = atom()
        if lo_set or hi_set then
          -- Annex B: a class escape at either end makes "-" a literal
          for _, part in ipairs({ lo_set or { { lo, lo } }, hi_set or { { hi, hi } } }) do
            for _, r in ipairs(part) do
              ranges[#ranges + 1] = { r[1], r[2] }
            end
          end
          ranges[#ranges + 1] = { 45, 45 }
        else
          if lo > hi then
            fail("range out of order in character class", i - 1)
          end
          ranges[#ranges + 1] = { lo, hi }
        end
      elseif lo_set then
        for _, r in ipairs(lo_set) do
          ranges[#ranges + 1] = { r[1], r[2] }
        end
      else
        ranges[#ranges + 1] = { lo, lo }
      end
    end
    ranges = normalize(ranges)
    if negate then
      ranges = complement(ranges)
    end
    return { k = "set", ranges = ranges }
  end

  -- Reads `{m}`, `{m,}`, `{m,n}` at i without consuming. Returns min, max, length or nil.
  local function read_braces()
    if p[i] ~= C["{"] then
      return nil
    end
    local j = i + 1
    local function number()
      local s = j
      local v = 0
      while is_digit(p[j]) do
        v = v * 10 + (p[j] - 48)
        j = j + 1
      end
      if j == s then
        return nil
      end
      return v
    end
    local min = number()
    if min == nil then
      return nil
    end
    local max = min
    if p[j] == C[","] then
      j = j + 1
      if p[j] == C["}"] then
        max = false -- unbounded
      else
        max = number()
        if max == nil then
          return nil
        end
      end
    end
    if p[j] ~= C["}"] then
      return nil
    end
    return min, max, j - i + 1
  end

  local parse_disjunction

  local function parse_term()
    local c = p[i]
    local atom
    if c == C["^"] then
      i = i + 1
      atom = { k = "bol", assertion = true }
    elseif c == C["$"] then
      i = i + 1
      atom = { k = "eol", assertion = true }
    elseif c == C["\\"] then
      i = i + 1
      local kind, v = parse_escape(false)
      if kind == "wb" then
        atom = { k = "wb", negate = v, assertion = true }
      elseif kind == "set" then
        atom = { k = "set", ranges = v }
      else
        atom = { k = "char", c = v }
      end
    elseif c == C["."] then
      i = i + 1
      atom = { k = "set", ranges = DOT }
    elseif c == C["("] then
      local open = i
      i = i + 1
      if p[i] == C["?"] then
        local n1, n2 = p[i + 1], p[i + 2]
        if n1 == C[":"] then
          i = i + 2
        elseif n1 == C["="] or n1 == C["!"] then
          fail("lookahead is not supported", open)
        elseif n1 == C["<"] and (n2 == C["="] or n2 == C["!"]) then
          fail("lookbehind is not supported", open)
        elseif n1 == C["<"] then
          -- named group: same as a capturing group for a yes/no match
          local j = i + 2
          while p[j] ~= nil and p[j] ~= C[">"] do
            local u = p[j]
            if not (is_word(u) or u == 36) then
              fail("invalid group name", j)
            end
            j = j + 1
          end
          if p[j] == nil or j == i + 2 then
            fail("invalid group name", open)
          end
          i = j + 1
        else
          fail("inline flags and group modifiers ((?...)) are not supported", open)
        end
      end
      local inner = parse_disjunction()
      if p[i] ~= C[")"] then
        fail("unterminated group", open)
      end
      i = i + 1
      atom = inner
    elseif c == C["["] then
      i = i + 1
      atom = parse_class()
    elseif c == C["*"] or c == C["+"] or c == C["?"] then
      fail("nothing to repeat")
    elseif c == C["{"] and read_braces() then
      fail("nothing to repeat")
    else
      i = i + 1
      atom = { k = "char", c = c }
    end

    -- quantifier
    local q = p[i]
    local min, max, len
    if q == C["*"] then
      min, max, len = 0, false, 1
    elseif q == C["+"] then
      min, max, len = 1, false, 1
    elseif q == C["?"] then
      min, max, len = 0, 1, 1
    else
      min, max, len = read_braces()
    end
    if min == nil then
      return atom
    end
    if atom.assertion then
      fail("nothing to repeat")
    end
    if max and max < min then
      fail("numbers out of order in {} quantifier")
    end
    i = i + len
    if p[i] == C["?"] then
      i = i + 1 -- lazy: the same set of matches
    end
    return { k = "rep", node = atom, min = min, max = max or nil }
  end

  parse_disjunction = function()
    local alts = {}
    local items = {}
    while true do
      local c = p[i]
      if c == nil or c == C[")"] then
        break
      end
      if c == C["|"] then
        i = i + 1
        alts[#alts + 1] = { k = "cat", items = items }
        items = {}
      else
        items[#items + 1] = parse_term()
      end
    end
    alts[#alts + 1] = { k = "cat", items = items }
    if #alts == 1 then
      return alts[1]
    end
    return { k = "alt", items = alts }
  end

  local tree = parse_disjunction()
  if i <= np then
    fail("unmatched )")
  end
  return tree
end

---------------------------------------------------------------------------------------
-- compiler: tree -> program
---------------------------------------------------------------------------------------
-- instructions: { op = "char", c } | { op = "set", ranges } | { op = "split", x, y }
--               | { op = "jmp", x } | { op = "bol" } | { op = "eol" }
--               | { op = "wb", negate } | { op = "match" }
-- Compiling walks the tree with an explicit stack of "emit" tasks.

local function compile_tree(tree)
  local prog, n = {}, 0
  local function emit(ins)
    n = n + 1
    if n > MAX_PROGRAM then
      error({
        regex_error = true,
        message = "pattern too large (over " .. MAX_PROGRAM .. " instructions)",
        position = 1,
      }, 0)
    end
    prog[n] = ins
    return n
  end

  -- task kinds: { "node", node } | { "fn", function }
  local tasks = { { "node", tree } }
  local nt = 1
  local function push(task)
    nt = nt + 1
    tasks[nt] = task
  end

  while nt > 0 do
    local task = tasks[nt]
    tasks[nt] = nil
    nt = nt - 1
    if task[1] == "fn" then
      task[2]()
    else
      local node = task[2]
      local k = node.k
      if k == "char" then
        emit({ op = "char", c = node.c })
      elseif k == "set" then
        emit({ op = "set", ranges = node.ranges })
      elseif k == "bol" or k == "eol" then
        emit({ op = k })
      elseif k == "wb" then
        emit({ op = "wb", negate = node.negate })
      elseif k == "cat" then
        for j = #node.items, 1, -1 do
          push({ "node", node.items[j] })
        end
      elseif k == "alt" then
        -- split L1, next; L1: a; jmp end; next: split L2, ... ; last: z; end:
        local jumps = {}
        local count = #node.items
        local steps = {}
        for j = 1, count do
          local item = node.items[j]
          if j < count then
            local split
            steps[#steps + 1] = {
              "fn",
              function()
                split = { op = "split" }
                emit(split)
                split.x = n + 1
              end,
            }
            steps[#steps + 1] = { "node", item }
            steps[#steps + 1] = {
              "fn",
              function()
                local jmp = { op = "jmp" }
                emit(jmp)
                jumps[#jumps + 1] = jmp
                split.y = n + 1
              end,
            }
          else
            steps[#steps + 1] = { "node", item }
          end
        end
        steps[#steps + 1] = {
          "fn",
          function()
            for _, jmp in ipairs(jumps) do
              jmp.x = n + 1
            end
          end,
        }
        for j = #steps, 1, -1 do
          push(steps[j])
        end
      elseif k == "rep" then
        local steps = {}
        for _ = 1, node.min do
          steps[#steps + 1] = { "node", node.node }
        end
        if node.max == nil then
          -- L: split body, out; body; jmp L; out:
          local split, loop_at
          steps[#steps + 1] = {
            "fn",
            function()
              split = { op = "split" }
              loop_at = emit(split)
              split.x = n + 1
            end,
          }
          steps[#steps + 1] = { "node", node.node }
          steps[#steps + 1] = {
            "fn",
            function()
              emit({ op = "jmp", x = loop_at })
              split.y = n + 1
            end,
          }
        else
          -- (max - min) optional copies, each skipping to the end
          local splits = {}
          for _ = node.min + 1, node.max do
            steps[#steps + 1] = {
              "fn",
              function()
                local split = { op = "split" }
                emit(split)
                split.x = n + 1
                splits[#splits + 1] = split
              end,
            }
            steps[#steps + 1] = { "node", node.node }
          end
          steps[#steps + 1] = {
            "fn",
            function()
              for _, split in ipairs(splits) do
                split.y = n + 1
              end
            end,
          }
        end
        for j = #steps, 1, -1 do
          push(steps[j])
        end
      end
    end
  end
  emit({ op = "match" })
  return prog, n
end

---------------------------------------------------------------------------------------
-- matcher: Pike VM
---------------------------------------------------------------------------------------

local Matcher = {}
Matcher.__index = Matcher

-- Adds the thread at pc (and everything reachable through jumps and assertions) to
-- list. Returns true when a match instruction is reached.
local function add_thread(prog, marks, gen, list, pc, pos, units, len)
  local stack, ns = { pc }, 1
  while ns > 0 do
    local at = stack[ns]
    stack[ns] = nil
    ns = ns - 1
    if marks[at] ~= gen then
      marks[at] = gen
      local ins = prog[at]
      local op = ins.op
      if op == "match" then
        return true
      elseif op == "jmp" then
        ns = ns + 1
        stack[ns] = ins.x
      elseif op == "split" then
        ns = ns + 1
        stack[ns] = ins.y
        ns = ns + 1
        stack[ns] = ins.x
      elseif op == "bol" then
        if pos == 1 then
          ns = ns + 1
          stack[ns] = at + 1
        end
      elseif op == "eol" then
        if pos == len + 1 then
          ns = ns + 1
          stack[ns] = at + 1
        end
      elseif op == "wb" then
        local boundary = is_word(units[pos - 1]) ~= is_word(units[pos])
        if boundary ~= ins.negate then
          ns = ns + 1
          stack[ns] = at + 1
        end
      else
        list[#list + 1] = at
      end
    end
  end
  return false
end

--- matcher:test(text) -> boolean: is there a match anywhere in text
function Matcher:test(text)
  if type(text) ~= "string" then
    return false
  end
  local prog = self.program
  local units, len = to_units(text)
  local marks, gen = {}, 1
  local clist = {}
  if add_thread(prog, marks, gen, clist, 1, 1, units, len) then
    return true
  end
  for pos = 1, len do
    local c = units[pos]
    gen = gen + 1
    local nlist = {}
    for j = 1, #clist do
      local at = clist[j]
      local ins = prog[at]
      local ok
      if ins.op == "char" then
        ok = ins.c == c
      else
        ok = in_set(ins.ranges, c)
      end
      if ok and add_thread(prog, marks, gen, nlist, at + 1, pos + 1, units, len) then
        return true
      end
    end
    -- unanchored: a new attempt starts at every position
    if add_thread(prog, marks, gen, nlist, 1, pos + 1, units, len) then
      return true
    end
    clist = nlist
  end
  return false
end

function Matcher:__tostring()
  return "/" .. self.source .. "/"
end

--- regex.compile(source) -> matcher | nil, err (SdkError naming the pattern and why)
function regex.compile(source)
  if type(source) ~= "string" then
    error("regex.compile: source must be a string", 2)
  end
  local compat = require("distilled.compat")
  local ok, result = compat.pcall(function()
    local tree = parse(source)
    local prog = compile_tree(tree)
    return prog
  end)
  if not ok then
    if type(result) == "table" and result.regex_error then
      local errors = require("distilled.errors")
      return nil,
        errors.new("SdkError", {
          message = "cannot compile regular expression /"
            .. source
            .. "/: "
            .. result.message
            .. " (at character "
            .. tostring(result.position)
            .. ")",
        })
    end
    error(result, 0) -- a bug in this module
  end
  return setmetatable({ source = source, program = result }, Matcher)
end

--- regex.test(source, text) -> boolean | nil, err: compile (uncached) and test
function regex.test(source, text)
  local m, err = regex.compile(source)
  if not m then
    return nil, err
  end
  return m:test(text)
end

regex.MAX_PROGRAM = MAX_PROGRAM

return regex
