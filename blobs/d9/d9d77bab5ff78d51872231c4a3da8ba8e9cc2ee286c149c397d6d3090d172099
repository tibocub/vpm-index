-- Schema nodes: the plain tables every layer-2 algorithm reads (docs/interfaces.md,
-- "Schema nodes"). Generated code builds them with the constructors here; the tables
-- themselves are the contract, so hand-built ones work too.
--
--   local S = require("distilled.schema")
--   S.struct{ name = "GetProjectRequest", members = {
--     S.member{ name = "project_id", bind = "label", schema = S.string, required = true },
--   } }
--
-- Replaces Distilled's schema-lite nodes and trait annotations (`schema-lite-impl.ts`,
-- `trait.ts`, `annotations.ts`): a member carries its traits as fields instead.
--
-- Additions to the contract (see STATUS.md, task 03):
-- - any node may carry `sensitive = true` (Smithy puts @sensitive on shapes too, and a
--   list item or map value has no member to carry it);
-- - `S.ref(name)` nodes are resolved through a registry ({ [name] = node }) passed to
--   every algorithm; nothing is global.
--
-- Addition (task 11): any node may carry `nullable = true`: json.null is a value of it
-- (Distilled's `S.NullOr(node)`). A list item or map value has no member to carry
-- `@nullable` (Smithy's sparse lists and maps), and neither does a rawResponse output,
-- so the flag sits on the node: `S.list(S.nullable(S.ref("Thing")))`.
local compat = require("distilled.compat")

local schema = {}

local SCALARS = {
  string = true,
  number = true,
  boolean = true,
  null = true,
  unknown = true,
  blob = true,
  timestamp = true,
}
schema.SCALARS = SCALARS

local BINDS =
  { body = true, label = true, query = true, header = true, payload = true, status = true }
schema.BINDS = BINDS

local function misuse(message)
  compat.raise("distilled.schema: " .. message, 3)
end

---------------------------------------------------------------------------------------
-- constructors
---------------------------------------------------------------------------------------

-- Shared scalar nodes. Treat them as read-only: S.sensitive(S.string) makes a marked
-- copy instead of changing the shared one.
for t in pairs(SCALARS) do
  schema[t] = { t = t }
end

--- S.scalar(t [, fields]) -> a fresh scalar node (fields copied onto it)
function schema.scalar(t, fields)
  if not SCALARS[t] then
    misuse("unknown scalar type " .. tostring(t))
  end
  local node = { t = t }
  for k, v in pairs(fields or {}) do
    node[k] = v
  end
  return node
end

--- S.sensitive(node) -> a copy of node marked sensitive
function schema.sensitive(node)
  if type(node) ~= "table" or type(node.t) ~= "string" then
    misuse("sensitive expects a schema node")
  end
  local copy = {}
  for k, v in pairs(node) do
    copy[k] = v
  end
  copy.sensitive = true
  return copy
end

--- S.nullable(node) -> a copy of node that also accepts json.null (S.NullOr). A ref keeps
-- its name: the flag is read on the node itself, before the ref is followed.
function schema.nullable(node)
  if type(node) ~= "table" or type(node.t) ~= "string" then
    misuse("nullable expects a schema node")
  end
  local copy = {}
  for k, v in pairs(node) do
    copy[k] = v
  end
  copy.nullable = true
  return copy
end

--- S.enum(values [, base]) ; base is "string" (default) or "number"
function schema.enum(values, base)
  if type(values) ~= "table" then
    misuse("enum expects a list of values")
  end
  base = base or "string"
  if base ~= "string" and base ~= "number" then
    misuse("enum base must be string or number")
  end
  return { t = "enum", values = values, base = base }
end

function schema.list(item)
  if type(item) ~= "table" then
    misuse("list expects an item node")
  end
  return { t = "list", item = item }
end

function schema.map(value)
  if type(value) ~= "table" then
    misuse("map expects a value node")
  end
  return { t = "map", value = value }
end

--- S.union(arms [, discriminator]) ; discriminator = { key = "type", values = { ... } },
-- where values[i] is the tag of arms[i]
function schema.union(arms, discriminator)
  if type(arms) ~= "table" or #arms == 0 then
    misuse("union expects a non-empty list of arms")
  end
  if discriminator ~= nil then
    if type(discriminator.key) ~= "string" or type(discriminator.values) ~= "table" then
      misuse("union discriminator needs key and values")
    end
  end
  return { t = "union", arms = arms, discriminator = discriminator }
end

function schema.ref(name)
  if type(name) ~= "string" or name == "" then
    misuse("ref expects a shape name")
  end
  return { t = "ref", name = name }
end

--- S.member{ name, wire, bind, schema, required, nullable, sensitive, greedy, style,
-- string_encoded } -> member, with the defaults of the contract filled in
function schema.member(spec)
  if type(spec) ~= "table" or type(spec.name) ~= "string" or spec.name == "" then
    misuse("member needs a name")
  end
  if type(spec.schema) ~= "table" then
    misuse("member " .. spec.name .. " needs a schema")
  end
  local bind = spec.bind or "body"
  if not BINDS[bind] then
    misuse("member " .. spec.name .. " has unknown bind " .. tostring(bind))
  end
  if spec.style ~= nil and spec.style ~= "comma" and spec.style ~= "deep" then
    misuse("member " .. spec.name .. " has unknown query style " .. tostring(spec.style))
  end
  return {
    name = spec.name,
    wire = spec.wire,
    bind = bind,
    schema = spec.schema,
    required = spec.required == true,
    nullable = spec.nullable == true,
    sensitive = spec.sensitive == true,
    greedy = spec.greedy == true,
    style = spec.style,
    string_encoded = spec.string_encoded == true,
  }
end

--- S.struct{ name, members, open } ; members are member tables (S.member or plain)
function schema.struct(spec)
  if type(spec) ~= "table" then
    misuse("struct expects a table")
  end
  local members = spec.members or {}
  local seen = {}
  for i, m in ipairs(members) do
    if type(m) ~= "table" or type(m.name) ~= "string" or type(m.schema) ~= "table" then
      misuse("struct " .. tostring(spec.name) .. " member " .. i .. " needs a name and a schema")
    end
    if seen[m.name] then
      misuse("struct " .. tostring(spec.name) .. " declares " .. m.name .. " twice")
    end
    seen[m.name] = true
  end
  return { t = "struct", name = spec.name, open = spec.open == true, members = members }
end

---------------------------------------------------------------------------------------
-- resolving refs
---------------------------------------------------------------------------------------

local MAX_REF_CHAIN = 64

--- schema.resolve(node, registry) -> node | nil, err (SdkError)
-- Follows ref nodes (and refs to refs) until a non-ref node.
function schema.resolve(node, registry)
  local hops = 0
  while type(node) == "table" and node.t == "ref" do
    hops = hops + 1
    if hops > MAX_REF_CHAIN then
      local errors = require("distilled.errors")
      return nil, errors.new("SdkError", { message = "schema ref chain too long at " .. node.name })
    end
    local target = registry and registry[node.name]
    if target == nil then
      local errors = require("distilled.errors")
      return nil,
        errors.new("SdkError", {
          message = "schema ref " .. tostring(node.name) .. " is not in the registry",
        })
    end
    node = target
  end
  if type(node) ~= "table" then
    local errors = require("distilled.errors")
    return nil, errors.new("SdkError", { message = "not a schema node: " .. type(node) })
  end
  return node
end

--- schema.wire_name(member) -> the name on the wire (wire, else name)
function schema.wire_name(member)
  return member.wire or member.name
end

-- Whether node is marked sensitive itself, through refs. Missing refs are not.
function schema.node_sensitive(node, registry)
  local hops = 0
  while type(node) == "table" do
    if node.sensitive == true then
      return true
    end
    if node.t ~= "ref" or hops > MAX_REF_CHAIN then
      return false
    end
    hops = hops + 1
    node = registry and registry[node.name]
  end
  return false
end

-- Whether json.null is a value of node: the node (or a ref on the way) is marked
-- nullable, or it resolves to `null` or `unknown`. Missing refs are not.
function schema.node_nullable(node, registry)
  local hops = 0
  while type(node) == "table" do
    if node.nullable == true then
      return true
    end
    if node.t ~= "ref" then
      return node.t == "null" or node.t == "unknown"
    end
    if hops > MAX_REF_CHAIN then
      return false
    end
    hops = hops + 1
    node = registry and registry[node.name]
  end
  return false
end

---------------------------------------------------------------------------------------
-- caches
---------------------------------------------------------------------------------------
-- Results that depend on refs depend on the registry too, so they are cached per
-- (registry, node). Both are long-lived (service tables), as the gopher-lua note in
-- AGENTS.md requires: weak tables are never collected there.

local NO_REGISTRY = {}

--- schema.memo() -> { get = fn(registry, node), set = fn(registry, node, value) }
function schema.memo()
  local by_registry = setmetatable({}, { __mode = "k" })
  local memo = {}
  function memo.get(registry, node)
    local per = by_registry[registry or NO_REGISTRY]
    if per == nil then
      return nil
    end
    return per[node]
  end
  function memo.set(registry, node, value)
    local key = registry or NO_REGISTRY
    local per = by_registry[key]
    if per == nil then
      per = setmetatable({}, { __mode = "k" })
      by_registry[key] = per
    end
    per[node] = value
  end
  return memo
end

---------------------------------------------------------------------------------------
-- per-struct plan (Distilled's planFor / RequestPlan)
---------------------------------------------------------------------------------------

local plans = setmetatable({}, { __mode = "k" })

--- schema.plan(struct_node) -> plan, computed once per node:
-- { node, members, by_bind = { body = {...}, label = {...}, ... }, by_name = { [name] =
--   member }, by_wire = { [wire] = member }, known = { [name] = true },
--   has_body_members = (a body or payload member is declared), payload = member | nil }
function schema.plan(node)
  local plan = plans[node]
  if plan then
    return plan
  end
  if type(node) ~= "table" or node.t ~= "struct" then
    misuse("plan expects a struct node")
  end
  local by_bind = { body = {}, label = {}, query = {}, header = {}, payload = {}, status = {} }
  local by_name, by_wire, known = {}, {}, {}
  local has_body = false
  for _, m in ipairs(node.members or {}) do
    local bind = m.bind or "body"
    local list = by_bind[bind]
    if list == nil then
      list = {}
      by_bind[bind] = list
    end
    list[#list + 1] = m
    by_name[m.name] = m
    by_wire[m.wire or m.name] = m
    known[m.name] = true
    if bind == "body" or bind == "payload" then
      has_body = true
    end
  end
  plan = {
    node = node,
    members = node.members or {},
    by_bind = by_bind,
    by_name = by_name,
    by_wire = by_wire,
    known = known,
    has_body_members = has_body,
    payload = by_bind.payload[1],
  }
  plans[node] = plan
  return plan
end

---------------------------------------------------------------------------------------
-- value helpers shared by keys, redact and validate
---------------------------------------------------------------------------------------

local json_module
local function json()
  json_module = json_module or require("distilled.json")
  return json_module
end

local secret_module
local function secret()
  secret_module = secret_module or require("distilled.secret")
  return secret_module
end

-- A table a walker may descend into: not json.null, not a secret.
function schema.is_container(v)
  return type(v) == "table" and v ~= json().null and not secret().is(v)
end

-- A pure sequence: keys exactly 1..n with n > 0.
local function is_sequence(t)
  local n = 0
  for k in pairs(t) do
    if type(k) ~= "number" then
      return false
    end
    n = n + 1
  end
  return n > 0 and t[n] ~= nil and #t == n
end

--- schema.is_list_value(v): v is a JSON array: marked array, or an unmarked table that
-- is empty or a pure sequence. (An unmarked `{}` is accepted where a list is expected.)
function schema.is_list_value(v)
  if not schema.is_container(v) then
    return false
  end
  local J = json()
  if J.is_array(v) then
    return true
  end
  if J.is_object(v) then
    return false
  end
  return next(v) == nil or is_sequence(v)
end

--- schema.is_array_value(v): definitely an array (marked, or a non-empty sequence).
-- Used where a table could be either and `{}` should count as an object.
function schema.is_array_value(v)
  if not schema.is_container(v) then
    return false
  end
  local J = json()
  if J.is_array(v) then
    return true
  end
  if J.is_object(v) then
    return false
  end
  return is_sequence(v)
end

--- schema.is_record_value(v): a JSON object (a container that is not an array)
function schema.is_record_value(v)
  return schema.is_container(v) and not schema.is_array_value(v)
end

--- schema.pick_arm(union_node, value, registry, direction) -> resolved arm | nil
-- Distilled's arm selection (mapKeys' UnionCases and schema-level unions):
-- 1. an array value takes the first list arm;
-- 2. a discriminator whose key holds a known tag picks that arm (arms whose key sets
--    cannot tell them apart need this);
-- 3. otherwise the struct arm that best explains the value: most present, non-null keys
--    covered minus present keys it cannot explain, needing at least one covered key;
--    ties break by coverage, then declaration order.
-- direction "encode" reads member names, "decode" wire names.
function schema.pick_arm(node, value, registry, direction)
  local arms = {}
  for i, arm in ipairs(node.arms or {}) do
    arms[i] = schema.resolve(arm, registry) or false
  end
  if not schema.is_container(value) then
    return nil
  end
  if schema.is_array_value(value) then
    for _, arm in ipairs(arms) do
      if arm and arm.t == "list" then
        return arm
      end
    end
    return nil
  end
  local disc = node.discriminator
  if disc then
    local tag = rawget(value, disc.key)
    if type(tag) == "string" then
      for i, v in ipairs(disc.values) do
        if v == tag and arms[i] then
          return arms[i]
        end
      end
    end
  end
  local null = json().null
  local present = {}
  for k, v in pairs(value) do
    if v ~= null then
      present[#present + 1] = k
    end
  end
  local best, best_score, best_matched
  for _, arm in ipairs(arms) do
    if arm and arm.t == "struct" then
      local plan = schema.plan(arm)
      local names = direction == "decode" and plan.by_wire or plan.by_name
      local matched, excess = 0, 0
      for _, k in ipairs(present) do
        if names[k] then
          matched = matched + 1
        else
          excess = excess + 1
        end
      end
      local score = matched - excess
      if
        matched > 0
        and (best == nil or score > best_score or (score == best_score and matched > best_matched))
      then
        best, best_score, best_matched = arm, score, matched
      end
    end
  end
  return best
end

return schema
