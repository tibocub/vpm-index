-- Secrets in values, logs and error messages. Replaces Distilled's `sensitive.ts`.
--
--   redact.wrap(node, value, registry) -> value      sensitive members become secrets
--   redact.parsed(node, value, registry) -> value    for logs: every sensitive value
--                                                    wrapped whole, whatever its type
--   redact.holds_sensitive(node, registry) -> bool   can a value of node hold a secret
--   redact.plain(node, text, registry) -> text | "[REDACTED]"
--
-- A node holds a secret when a value it reaches is marked sensitive: a member with
-- `sensitive = true`, or a node with `sensitive = true` (through refs), at any depth:
-- members, map values, list items and union arms.
--
-- wrap (Distilled's wrapSensitive) wraps a sensitive value when it is a string, or any
-- non-null value of an `unknown` node. A typed struct is walked instead, so its own
-- sensitive members are wrapped and the rest stays readable. Keys the schema does not
-- model pass through. A union applies every arm (a partial or ambiguous response still
-- has every possible secret wrapped); a map arm skips keys a sibling struct arm names.
-- Values already wrapped stay as they are, so wrap is idempotent.
--
-- The walk uses an explicit stack (gopher-lua's call stack is shallow). A union is
-- handled by walking the value against the list of its arms at once, which is the same
-- as Distilled applying the arms one after the other.
local schema = require("distilled.schema")
local json = require("distilled.json")
local secret = require("distilled.secret")

local redact = {}

redact.REDACTED = "[REDACTED]"

local null = json.null
local resolve = schema.resolve
local node_sensitive = schema.node_sensitive

local holds_memo = schema.memo()

--- redact.holds_sensitive(node, registry) -> boolean (cached per registry and node)
function redact.holds_sensitive(root, registry)
  local cached = holds_memo.get(registry, root)
  if cached ~= nil then
    return cached
  end
  -- Only the root's answer is cached: inside a cycle, a node cut short by `seen` is
  -- not known to be free of secrets (Distilled's "whichever is asked first" case).
  local result = false
  local seen = {}
  local stack, n = { root }, 1
  while n > 0 do
    local node = stack[n]
    stack[n] = nil
    n = n - 1
    if node_sensitive(node, registry) then
      result = true
      break
    end
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
          if m.sensitive then
            result = true
            break
          end
          n = n + 1
          stack[n] = m.schema
        end
        if result then
          break
        end
      end
    end
  end
  holds_memo.set(registry, root, result)
  return result
end

--- redact.plain(node, text, registry): the plain form (a serialized body, a quoted
-- value) of a value of node is "[REDACTED]" whole when node can hold a secret.
function redact.plain(node, text, registry)
  if redact.holds_sensitive(node, registry) then
    return redact.REDACTED
  end
  return text
end

-- Whether wrap wraps v, a value of the sensitive type node.
local function is_secret_value(node, v, whole, registry)
  if whole then
    return v ~= nil and v ~= null
  end
  if type(v) == "string" then
    return true
  end
  if v == nil or v == null then
    return false
  end
  local resolved = resolve(node, registry)
  return resolved ~= nil and resolved.t == "unknown"
end

-- Expands a list of { node, siblings } into concrete nodes: refs resolved, unions
-- replaced by their arms (each arm remembering the names its sibling struct arms use).
local function expand(entries, registry)
  local out = {}
  local work, n = {}, 0
  for i = #entries, 1, -1 do
    n = n + 1
    work[n] = entries[i]
  end
  local guard = 0
  while n > 0 do
    local entry = work[n]
    work[n] = nil
    n = n - 1
    local node = resolve(entry[1], registry)
    if node then
      if node.t == "union" then
        guard = guard + 1
        if guard <= 256 then
          local named = {}
          local arms = {}
          for i, arm in ipairs(node.arms or {}) do
            local a = resolve(arm, registry)
            arms[i] = arm
            if a and a.t == "struct" then
              for _, m in ipairs(a.members or {}) do
                named[m.name] = true
              end
            end
          end
          for i = #arms, 1, -1 do
            n = n + 1
            work[n] = { arms[i], named }
          end
        end
      else
        out[#out + 1] = { node, entry[2] }
      end
    end
  end
  return out
end

-- The slot types for one child: list of { node, sensitive }
local function child_value(types, v, whole, registry)
  if secret.is(v) then
    return v, false
  end
  for _, ty in ipairs(types) do
    if ty[2] and is_secret_value(ty[1], v, whole, registry) then
      return secret.wrap(v), false
    end
  end
  return v, schema.is_container(v)
end

local function wrap(root_node, root_value, registry, whole)
  local holder = {}
  local max_depth = json.MAX_DEPTH
  -- task: { entries = { { node, siblings } }, value, out, key, depth }
  local stack = { { { { root_node } }, root_value, holder, 1, 0 } }
  local n = 1
  while n > 0 do
    local task = stack[n]
    stack[n] = nil
    n = n - 1
    local entries, value, out, key, depth = task[1], task[2], task[3], task[4], task[5]
    local result = value
    if schema.is_container(value) and depth < max_depth then
      local nodes = expand(entries, registry)
      if schema.is_array_value(value) then
        local items = {}
        for _, e in ipairs(nodes) do
          if e[1].t == "list" then
            items[#items + 1] = { e[1].item, node_sensitive(e[1].item, registry) }
          end
        end
        if #items > 0 then
          result = json.array({})
          local child_entries = {}
          for i, ty in ipairs(items) do
            child_entries[i] = { ty[1] }
          end
          for i = 1, #value do
            local v, descend = child_value(items, value[i], whole, registry)
            if descend then
              n = n + 1
              stack[n] = { child_entries, v, result, i, depth + 1 }
            else
              result[i] = v
            end
          end
        end
      else
        local shapes = {}
        for _, e in ipairs(nodes) do
          local t = e[1].t
          if (t == "struct" and #(e[1].members or {}) > 0) or t == "map" then
            shapes[#shapes + 1] = e
          end
        end
        if #shapes > 0 then
          result = json.object({})
          for k, v in pairs(value) do
            local types = {}
            for _, e in ipairs(shapes) do
              local node, siblings = e[1], e[2]
              if node.t == "struct" then
                local m = schema.plan(node).by_name[k]
                if m then
                  types[#types + 1] =
                    { m.schema, m.sensitive == true or node_sensitive(m.schema, registry) }
                end
              elseif not (siblings and siblings[k]) then
                types[#types + 1] = { node.value, node_sensitive(node.value, registry) }
              end
            end
            if #types == 0 then
              result[k] = v
            else
              local wrapped, descend = child_value(types, v, whole, registry)
              if descend then
                local child_entries = {}
                for i, ty in ipairs(types) do
                  child_entries[i] = { ty[1] }
                end
                n = n + 1
                stack[n] = { child_entries, wrapped, result, k, depth + 1 }
              else
                result[k] = wrapped
              end
            end
          end
        end
      end
    end
    out[key] = result
  end
  return holder[1]
end

--- redact.wrap(node, value, registry) -> value with sensitive members as secrets
function redact.wrap(node, value, registry)
  if not schema.is_container(value) then
    return value
  end
  if not redact.holds_sensitive(node, registry) then
    return value
  end
  return wrap(node, value, registry, false)
end

--- redact.parsed(node, value, registry): a parsed value as a log shows it, with every
-- sensitive value wrapped whole, whatever its type (Distilled's redactParsed)
function redact.parsed(node, value, registry)
  if not redact.holds_sensitive(node, registry) then
    return value
  end
  if not schema.is_container(value) then
    return value
  end
  return wrap(node, value, registry, true)
end

return redact
