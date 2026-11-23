-- Renaming between user names and wire names, by walking a value and its schema
-- together. Replaces Distilled's `mapKeys` and `mapsVerbatim` (protocol-http.ts).
--
--   keys.encode(node, value, registry) -> value   user names -> wire names
--   keys.decode(node, value, registry) -> value   wire names -> user names
--
-- Both also fix array-ness for the JSON encoder: a table at a list node comes back marked
-- json.array (so an empty list is sent as []), and a table at a map or struct node comes
-- back marked json.object.
--
-- Rules carried over from mapKeys:
-- - Keys the schema does not declare pass through unchanged (generated schemas lag the
--   real APIs). When an undeclared key collides with a member's renamed key, the member
--   wins.
-- - A union picks one arm (schema.pick_arm: array -> first list arm, discriminator,
--   then best-explaining struct arm) and maps with it; with no arm it is verbatim.
-- - A struct with no members is opaque: its value is returned as is.
-- - `string_encoded` members are sent as their string spelling on encode (element-wise
--   for lists; json.null stays null). The top-level pass in request.build does the same.
-- - A table at a node of the wrong kind passes through as is: a json.array-marked table
--   at a map or struct node, a table with non-index keys at a list node. An unmarked
--   table at a map or struct node is an object (so `{ [1] = "a" }` there is {"1":"a"}).
--
-- When no member below a node is renamed or string-encoded (keys.verbatim), encode does
-- not copy: it only marks the tables it is given, in place, and decode returns the value
-- untouched (json.decode has marked its arrays already). request.build hands encode a
-- copy of the caller's input (secrets unwrapped), so the caller's tables are not marked.
--
-- No recursion over data: the walk uses an explicit stack, so gopher-lua's ~250-frame
-- call stack is not a limit. Below json.MAX_DEPTH levels values are left as they are
-- (json.encode then reports the depth, or the cycle).
local schema = require("distilled.schema")
local json = require("distilled.json")
local url = require("distilled.url")

local keys = {}

local null = json.null
local resolve = schema.resolve
local is_container = schema.is_container

---------------------------------------------------------------------------------------
-- verbatim analysis (mapsVerbatim)
---------------------------------------------------------------------------------------

local verbatim_memo = { encode = schema.memo(), decode = schema.memo() }

--- keys.verbatim(node, registry, direction) -> boolean: whether mapping in direction
-- returns every value under node unchanged (no member renamed, and on encode none
-- string-encoded). Computed once per (registry, node, direction).
function keys.verbatim(root, registry, direction)
  local memo = verbatim_memo[direction]
  local cached = memo.get(registry, root)
  if cached ~= nil then
    return cached
  end
  local result = true
  local seen = {}
  local stack, n = { root }, 1
  while n > 0 and result do
    local node = stack[n]
    stack[n] = nil
    n = n - 1
    node = resolve(node, registry)
    if node and not seen[node] then
      seen[node] = true
      local t = node.t
      if t == "union" then
        for _, arm in ipairs(node.arms or {}) do
          n = n + 1
          stack[n] = arm
        end
      elseif t == "list" then
        n = n + 1
        stack[n] = node.item
      elseif t == "map" then
        n = n + 1
        stack[n] = node.value
      elseif t == "struct" then
        for _, m in ipairs(node.members or {}) do
          if
            (m.wire ~= nil and m.wire ~= m.name) or (direction == "encode" and m.string_encoded)
          then
            result = false
            break
          end
          n = n + 1
          stack[n] = m.schema
        end
      end
    end
  end
  memo.set(registry, root, result)
  return result
end

---------------------------------------------------------------------------------------
-- string encoding (StringEncoded)
---------------------------------------------------------------------------------------

--- keys.string_encode(value): String(value), element-wise for lists; json.null stays
-- null ("unset" by null, not "null").
function keys.string_encode(value)
  if value == null then
    return null
  end
  if schema.is_array_value(value) then
    local out = json.array({})
    for i = 1, #value do
      out[i] = keys.string_encode(value[i])
    end
    return out
  end
  return url.text(value)
end

---------------------------------------------------------------------------------------
-- the walk
---------------------------------------------------------------------------------------

-- One step: node and value at a slot. Returns the value to store; pushes children.
-- `copy` false means mark in place and push children without slots.
local function walk(root_node, root_value, registry, direction, copy)
  local encode = direction == "encode"
  local max_depth = json.MAX_DEPTH
  local holder = {}
  -- task: { node, value, out_table | nil, out_key, depth }
  local stack = { { root_node, root_value, holder, 1, 0 } }
  local n = 1

  local function push(node, value, out, key, depth)
    n = n + 1
    stack[n] = { node, value, out, key, depth }
  end

  while n > 0 do
    local task = stack[n]
    stack[n] = nil
    n = n - 1
    local node, value, out, key, depth = task[1], task[2], task[3], task[4], task[5]
    local result = value
    if is_container(value) and depth < max_depth then
      -- resolve refs and unions down to a concrete node
      local guard = 0
      while node do
        node = resolve(node, registry)
        if node and node.t == "union" and guard < 64 then
          guard = guard + 1
          node = schema.pick_arm(node, value, registry, direction)
        else
          break
        end
      end
      local t = node and node.t
      if t == "list" then
        if schema.is_list_value(value) then
          if copy then
            result = json.array({})
            for i = 1, #value do
              push(node.item, value[i], result, i, depth + 1)
            end
          else
            json.array(value)
            for i = 1, #value do
              push(node.item, value[i], nil, i, depth + 1)
            end
          end
        end
      elseif t == "map" then
        if not json.is_array(value) then
          if copy then
            result = json.object({})
            for k, v in pairs(value) do
              push(node.value, v, result, k, depth + 1)
            end
          else
            json.object(value)
            for _, v in pairs(value) do
              push(node.value, v, nil, nil, depth + 1)
            end
          end
        end
      elseif t == "struct" then
        local members = node.members
        if members and #members > 0 and not json.is_array(value) then
          if copy then
            result = json.object({})
            local consumed, targets = {}, {}
            for _, m in ipairs(members) do
              local wire = m.wire or m.name
              local from = encode and m.name or wire
              local to = encode and wire or m.name
              consumed[from] = true
              local v = rawget(value, from)
              if v ~= nil then
                targets[to] = true
                if encode and m.string_encoded then
                  result[to] = keys.string_encode(v)
                else
                  push(m.schema, v, result, to, depth + 1)
                end
              end
            end
            for k, v in pairs(value) do
              if not consumed[k] and not targets[k] then
                result[k] = v
              end
            end
          else
            json.object(value)
            for _, m in ipairs(members) do
              local v = rawget(value, m.name)
              if v ~= nil then
                push(m.schema, v, nil, nil, depth + 1)
              end
            end
          end
        end
      end
    end
    if out ~= nil then
      out[key] = result
    end
  end
  return holder[1]
end

local function check_args(fname, node)
  if type(node) ~= "table" then
    require("distilled.compat").raise("keys." .. fname .. ": node must be a schema node", 3)
  end
end

--- keys.encode(node, value, registry) -> value with wire names, arrays and objects marked
function keys.encode(node, value, registry)
  check_args("encode", node)
  if not is_container(value) then
    return value
  end
  if keys.verbatim(node, registry, "encode") then
    walk(node, value, registry, "encode", false)
    return value
  end
  return walk(node, value, registry, "encode", true)
end

--- keys.decode(node, value, registry) -> value with user names
function keys.decode(node, value, registry)
  check_args("decode", node)
  if not is_container(value) then
    return value
  end
  if keys.verbatim(node, registry, "decode") then
    return value
  end
  return walk(node, value, registry, "decode", true)
end

return keys
