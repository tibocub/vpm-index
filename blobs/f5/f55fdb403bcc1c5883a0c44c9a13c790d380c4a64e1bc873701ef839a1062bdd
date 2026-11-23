-- Response validation against an output schema. Replaces Distilled's
-- `response-validation-strict.ts` (the checker behind `additionalProperties` and
-- `strict` modes; `lenient` does not validate at all).
--
--   validate.check(node, value, registry, { exact = false }) -> true | nil, mismatch
--   mismatch = { path = { "projects", 1, "id" }, expected = "string", actual = 5,
--                missing = true | nil, message = "Expected string, got 5 at [...]" }
--
-- The value is a decoded response with user names (validation runs after keys.decode).
-- Rules, as in Distilled:
-- - scalars check their Lua type; `unknown` accepts anything, json.null included;
--   `blob` is a string, `timestamp` a string or a number; an enum checks its base type,
--   and in exact mode also that the value is one of its values (enums are open
--   otherwise);
-- - a struct needs an object; a required member must be present; json.null satisfies
--   only a nullable member (or a `null`/`unknown` one); an absent optional member is
--   fine;
-- - json.null is a value of any node marked `nullable` (S.nullable, through refs): a
--   sparse list item or map value, or a nullable output root (Distilled's S.NullOr);
-- - exact mode (strict) rejects keys a struct does not declare, except in open structs;
-- - an empty struct accepts any value but null (generated code's opaque output);
-- - a union accepts a value one arm accepts; with one arm its failure is reported;
-- - the first mismatch wins: members in declaration order, then undeclared keys;
--   map keys and undeclared keys in sorted order.
--
-- Paths use Lua indices (1-based) for lists. The walk uses an explicit stack; only a
-- union nests a sub-check (one level per union in the data, bounded by MAX_UNION_DEPTH).
local schema = require("distilled.schema")
local json = require("distilled.json")
local compat = require("distilled.compat")

local validate = {}

local null = json.null
local MAX_UNION_DEPTH = 64
validate.MAX_UNION_DEPTH = MAX_UNION_DEPTH

local function show(v, missing)
  if missing then
    return "nothing (missing key)"
  end
  local tv = type(v)
  if v == nil then
    return "nil"
  elseif v == null then
    return "null"
  elseif tv == "string" then
    if #v > 40 then
      v = string.sub(v, 1, 40) .. "..."
    end
    return string.format("%q", v)
  elseif tv == "table" then
    if schema.is_array_value(v) then
      return "an array"
    end
    return "an object"
  end
  return tostring(v)
end

local function path_text(path)
  local parts = {}
  for i, k in ipairs(path) do
    parts[i] = type(k) == "number" and tostring(k) or string.format("%q", tostring(k))
  end
  return "[" .. compat.concat(parts, ",") .. "]"
end

local function make_mismatch(path, expected, actual, missing)
  local message = "Expected " .. expected .. ", got " .. show(actual, missing)
  if #path > 0 then
    message = message .. " at " .. path_text(path)
  end
  return { path = path, expected = expected, actual = actual, missing = missing, message = message }
end

--- validate.withhold(mismatch) -> a copy whose actual value is "[REDACTED]", for a
-- parse error that must not quote the body (it may hold a secret)
function validate.withhold(m)
  local copy = make_mismatch(m.path, m.expected, "[REDACTED]", false)
  copy.missing = nil
  return copy
end

local function sorted_keys(t)
  local list = {}
  for k in pairs(t) do
    list[#list + 1] = k
  end
  table.sort(list, function(a, b)
    local ta, tb = type(a), type(b)
    if ta ~= tb then
      return ta < tb
    end
    if ta == "number" or ta == "string" then
      return a < b
    end
    return tostring(a) < tostring(b)
  end)
  return list
end

local function describe(node, registry)
  local r = schema.resolve(node, registry)
  if not r then
    return "a value"
  end
  local t = r.t
  if t == "struct" or t == "map" then
    return "object"
  elseif t == "list" then
    return "array"
  elseif t == "union" then
    return "a union member"
  elseif t == "enum" then
    return "an enum value"
  elseif t == "blob" then
    return "string"
  end
  return t
end

-- Builds the path of a failure: links are { parent, key }.
local function path_of(link)
  local rev = {}
  while link do
    rev[#rev + 1] = link[2]
    link = link[1]
  end
  local path = {}
  for i = #rev, 1, -1 do
    path[#path + 1] = rev[i]
  end
  return path
end

-- run(...) -> nil when value matches, else { link, expected, actual, missing }
local function run(root, root_value, registry, exact, union_depth)
  -- tasks: { "value", node, value, link } | { "extra", plan, value, link }
  --      | { "missing", member, nil, link } | { "null", member, value, link }
  local stack = { { "value", root, root_value, nil } }
  local n = 1
  local function push(task)
    n = n + 1
    stack[n] = task
  end
  local function at(link, key)
    return { link, key }
  end
  while n > 0 do
    local task = stack[n]
    stack[n] = nil
    n = n - 1
    local kind, a, value, link = task[1], task[2], task[3], task[4]
    if kind == "missing" then
      return { link, "a value", nil, true }
    elseif kind == "null" then
      return { link, describe(a.schema, registry), value }
    elseif kind == "extra" then
      local plan = a
      for _, k in ipairs(sorted_keys(value)) do
        if not plan.by_name[k] then
          return {
            at(link, k),
            "no value (the schema does not model this key)",
            rawget(value, k),
          }
        end
      end
    elseif value == null and schema.node_nullable(a, registry) then
      -- json.null is a value of a nullable node (S.NullOr): a sparse list item, a sparse
      -- map value, a nullable output root
    else
      local node, err = schema.resolve(a, registry)
      if not node then
        return { link, "a shape in the registry (" .. tostring(err.message) .. ")", value }
      end
      local t = node.t
      local tv = type(value)
      if t == "string" or t == "blob" then
        if tv ~= "string" then
          return { link, "string", value }
        end
      elseif t == "number" then
        if tv ~= "number" then
          return { link, "number", value }
        end
      elseif t == "boolean" then
        if tv ~= "boolean" then
          return { link, "boolean", value }
        end
      elseif t == "null" then
        if value ~= null then
          return { link, "null", value }
        end
      elseif t == "timestamp" then
        if tv ~= "string" and tv ~= "number" then
          return { link, "timestamp (string or number)", value }
        end
      elseif t == "enum" then
        local base = node.base or "string"
        if tv ~= base then
          return { link, base, value }
        end
        if exact then
          local found = false
          for _, v in ipairs(node.values or {}) do
            if v == value then
              found = true
              break
            end
          end
          if not found then
            return { link, "an enum value", value }
          end
        end
      elseif t == "list" then
        if not schema.is_list_value(value) then
          return { link, "array", value }
        end
        for i = #value, 1, -1 do
          push({ "value", node.item, value[i], at(link, i) })
        end
      elseif t == "map" then
        if not schema.is_record_value(value) then
          return { link, "object", value }
        end
        local ks = sorted_keys(value)
        for i = #ks, 1, -1 do
          local k = ks[i]
          push({ "value", node.value, rawget(value, k), at(link, k) })
        end
      elseif t == "struct" then
        local members = node.members or {}
        if #members == 0 then
          if value == nil or value == null then
            return { link, "{}", value }
          end
        else
          if not schema.is_record_value(value) then
            return { link, "object", value }
          end
          local plan = schema.plan(node)
          if exact and not node.open then
            push({ "extra", plan, value, link })
          end
          for i = #members, 1, -1 do
            local m = members[i]
            local v = rawget(value, m.name)
            if v == nil then
              if m.required then
                -- pushed as a task so the first mismatch keeps declaration order
                push({ "missing", m, nil, at(link, m.name) })
              end
            elseif v == null then
              if not (m.nullable or schema.node_nullable(m.schema, registry)) then
                push({ "null", m, v, at(link, m.name) })
              end
            else
              push({ "value", m.schema, v, at(link, m.name) })
            end
          end
        end
      elseif t == "union" then
        local arms = node.arms or {}
        if union_depth >= MAX_UNION_DEPTH then
          return { link, "a value nested less than " .. MAX_UNION_DEPTH .. " unions deep", value }
        end
        local first
        local matched = false
        for _, arm in ipairs(arms) do
          local f = run(arm, value, registry, exact, union_depth + 1)
          if f == nil then
            matched = true
            break
          end
          first = first or f
        end
        if not matched then
          if #arms == 1 and first then
            -- re-root the arm's failure under this path
            local sub = path_of(first[1])
            local l = link
            for _, k in ipairs(sub) do
              l = at(l, k)
            end
            return { l, first[2], first[3], first[4] }
          end
          return { link, "a union member", value }
        end
      end
      -- "unknown" and anything without structure accept every value
    end
  end
  return nil
end

--- validate.check(node, value, registry [, opts]) -> true | nil, mismatch
function validate.check(node, value, registry, opts)
  if type(node) ~= "table" then
    require("distilled.compat").raise("validate.check: node must be a schema node", 2)
  end
  local exact = opts ~= nil and opts.exact == true
  local f = run(node, value, registry, exact, 0)
  if f == nil then
    return true
  end
  return nil, make_mismatch(path_of(f[1]), f[2], f[3], f[4] == true)
end

return validate
