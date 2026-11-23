-- GraphQL: the Query algebra generated GraphQL clients target. Port of Distilled's
-- core/src/graphql.ts (read its header comment for the design); the semantics, the
-- document text and the error classification are the same, the surface is Lua's.
--
-- A GraphQL document is a selection, not an RPC. Every field is a lazy Query: reading
-- `me.email` records the field, and nothing is sent until a client runs the plan you
-- built (`client:run(plan)`), which paints every field the plan reads onto one selection,
-- posts that one document, then reads the plan's values out of the response.
--
--   local Linear = require("linear")
--   local gql = require("distilled.graphql")
--   local me = Linear.viewer()                       -- a Query; no request yet
--   local plan = {
--     email = me.email,                              -- a field
--     teams = gql.map(Linear.teams({ first = 50 }), function(team)
--       return { id = team.id, key = team.key }      -- a Query per item
--     end),
--   }
--   local value, err = client:run(plan)              -- one POST
--
-- Combinators (free functions, so no GraphQL field name is shadowed):
--   gql.map(q, fn)      on a list: fn(item Query) -> plan per item; on an object: the same
--                       for the one object (null stays null); on a scalar: fn(value)
--   gql.filter(q, fn)   fn(item Query) -> boolean Query; rows are kept after the POST
--   gql.flat_map(q, fn) fn(value) -> value | plan | nil, err, after the POST; a plan with
--                       Queries in it runs as another request
--   gql.of(value)       a literal
--   gql.fn(build)       function(client, ...) return client:run(build(...)) end
--
-- Expected failures are `nil, err` (distilled.errors tables). Building a query raises
-- only for misuse: an unknown field or argument name, a wrong argument type.
--
-- Differences from Distilled (each a Lua necessity or a bug avoided):
-- - Lua tables have no key order: a plan's keys are visited sorted (numbers, then
--   strings), and a field's arguments are bound in the schema's declaration order (TS:
--   the caller's object order). Documents are deterministic; the variable numbering and
--   field order can differ from what TS sends for the same plan.
-- - An unknown field or argument raises (TS: undefined, or the argument silently dropped).
-- - Lists in a plan are walked like any table (TS skips arrays at the top level).
-- - A Query a flat_map callback returns runs as a new request (TS reads it from the
--   response that is already there, where it was never selected).
-- - An empty argument table is no arguments (TS: `field({})` is a second selection).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")

local graphql = {}

local null = json.null

-- Queries, plans and selections are walked recursively (they are built by hand, not
-- decoded from the wire), so their depth is bounded to stay inside gopher-lua's stack.
graphql.MAX_DEPTH = 48

---------------------------------------------------------------------------------------
-- errors (graphql.ts "Errors")
---------------------------------------------------------------------------------------

--- A plan that cannot be compiled (a programming error in the query).
graphql.GqlError = errors.define({ tag = "GqlError" })
--- A GraphQL error no declared matcher recognizes (`err.coordinate`: its root field).
graphql.UnknownGraphQLError = errors.define({ tag = "UnknownGraphQLError" })
--- One response carried errors with different tags; none is hidden (`err.errors`,
-- `err.data` with sensitive fields as secrets, `err.status`).
graphql.GraphQLFailure = errors.define({ tag = "GraphQLFailure" })
--- The request never produced a GraphQL response (network, HTTP, non-JSON).
graphql.GraphQLTransportError = errors.define({ tag = "GraphQLTransportError" })
--- A paginated connection reported more pages without a new cursor (`err.cursor`).
graphql.GraphQLPaginationError = errors.define({ tag = "GraphQLPaginationError" })

-- the generated categories (graphql-client.ts `categories`) -> distilled.errors names
graphql.CATEGORIES = {
  auth = "AuthError",
  badRequest = "BadRequestError",
  notFound = "NotFoundError",
  throttling = "ThrottlingError",
  quota = "QuotaError",
  server = "ServerError",
  conflict = "ConflictError",
}

--- graphql.error_class{ tag, category, retryable } -> class (a generated error class:
-- Category.with<X>Error, and Category.withRetryable({ throttling }) when retryable)
function graphql.error_class(spec)
  local categories = {}
  if spec.category ~= nil then
    local name = graphql.CATEGORIES[spec.category]
    if name == nil then
      compat.raise("graphql.error_class: unknown category " .. tostring(spec.category), 2)
    end
    categories[1] = name
  end
  return errors.define({
    tag = spec.tag,
    categories = categories,
    retryable = spec.retryable == true,
    throttling = spec.retryable == true and spec.category == "throttling",
  })
end

local function gql_error(message)
  return errors.new(graphql.GqlError, { message = message })
end

-- compiler failures are raised as GqlError tables and caught by `compiling`
local function throw(message)
  error(gql_error(message), 0)
end

-- run f(...) and turn what it raises into a GqlError (graphql.ts `compiling`)
local function compiling(f, ...)
  local r = compat.pack(compat.pcall(f, ...))
  if r[1] then
    return true, r[2], r[3], r[4]
  end
  local e = r[2]
  if errors.is(e) then
    return false, e
  end
  return false, gql_error(tostring(e))
end

---------------------------------------------------------------------------------------
-- small helpers
---------------------------------------------------------------------------------------

-- Query objects (see "Query objects" below): the private key of their expression and
-- their metatable
local EXPR = {}
local QUERY_MT = {}

local function is_nullish(v)
  return v == nil or v == null
end

local function is_array(v)
  return type(v) == "table" and json.is_array(v)
end

-- an object from the wire: a table that is not an array, null, a secret or an error
local function is_record(v)
  return type(v) == "table"
    and v ~= null
    and not json.is_array(v)
    and not secret.is(v)
    and not errors.is(v)
    and getmetatable(v) ~= QUERY_MT
end

-- a table a plan may hold other plan values in: no metatable, or a json mark
local function is_plain(v)
  if type(v) ~= "table" or v == null then
    return false
  end
  local mt = getmetatable(v)
  return mt == nil or json.is_array(v) or json.is_object(v)
end

local function key_less(a, b)
  local ta, tb = type(a), type(b)
  if ta ~= tb then
    if ta == "number" then
      return true
    end
    if tb == "number" then
      return false
    end
    return ta < tb
  end
  if ta == "number" or ta == "string" then
    return a < b
  end
  return tostring(a) < tostring(b)
end

local function sorted_keys(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys, key_less)
  return keys
end

-- JavaScript's Boolean(x)
local function truthy(v)
  return not (v == nil or v == false or v == null or v == 0 or v == "" or v ~= v)
end

local function list_of(t)
  return json.array(t)
end

-- a copy with secrets shown as <redacted>, for messages (never a secret in an error)
local function shown(value)
  local function walk(v, depth)
    if secret.is(v) then
      return secret.REDACTED
    end
    if type(v) ~= "table" or v == null or depth > graphql.MAX_DEPTH then
      return v
    end
    local out = {}
    for k, x in pairs(v) do
      out[k] = walk(x, depth + 1)
    end
    if json.is_array(v) then
      json.array(out)
    end
    return out
  end
  local text = json.encode(walk(value, 0))
  return text or "{...}"
end

---------------------------------------------------------------------------------------
-- type metadata (graphql.ts TypeMeta / FieldMeta / TypeRef)
---------------------------------------------------------------------------------------
--
-- meta  = { name, fields = { [name] = field } }   (fields may be filled on first use)
-- field = { name, kind = "scalar" | "object" | "list" | "connection", of = meta,
--           args = { { name, type }, ... } | nil, arg_types = { [name] = type } | nil,
--           sensitive = true | nil }

--- graphql.field(name, kind, of, args, sensitive) -> field. args is a list of
-- { name, type } in declaration order.
function graphql.field(name, kind, of, args, sensitive)
  local f = { name = name, kind = kind, of = of }
  if args ~= nil and #args > 0 then
    f.args = args
    local types = {}
    for _, a in ipairs(args) do
      types[a[1]] = a[2]
    end
    f.arg_types = types
  end
  if sensitive then
    f.sensitive = true
  end
  return f
end

--- graphql.type_meta(name, fields) -> meta (fields: a table, filled later if need be)
function graphql.type_meta(name, fields)
  return { name = name, fields = fields or {} }
end

local SCALAR = { tag = "scalar" }

local function object_ref(meta)
  return { tag = "object", meta = meta }
end

local function list_ref(of)
  return { tag = "list", of = of }
end

local function field_result(parent, field)
  if parent.tag == "list" then
    return list_ref(field_result(parent.of, field))
  end
  if field.kind == "scalar" then
    return SCALAR
  end
  if field.kind == "object" then
    return object_ref(field.of)
  end
  return list_ref(object_ref(field.of)) -- list | connection
end

local function unwrap_list(ref)
  if ref.tag ~= "list" then
    throw("expected a list Query")
  end
  return ref.of
end

local EMPTY = {}

local function fields_of(ref)
  while ref.tag == "list" do
    ref = ref.of
  end
  if ref.tag == "object" then
    return ref.meta.fields
  end
  return EMPTY
end

local function type_name(ref)
  if ref.tag == "list" then
    return "[" .. type_name(ref.of) .. "]"
  end
  if ref.tag == "object" then
    return ref.meta.name
  end
  return "a scalar"
end

---------------------------------------------------------------------------------------
-- Query objects
---------------------------------------------------------------------------------------
--
-- A Query is a table holding its expression under a private key, with a metatable whose
-- __index reads GraphQL fields and whose __call passes arguments. No string key is
-- taken, so every GraphQL field name (even `map`, `pipe`, `expr`) reads as a field.
--
-- expr tags: Root | Prop | Item | MapValue | MapItems | Filter | FlatMap | Literal

local function make(expr)
  return setmetatable({ [EXPR] = expr }, QUERY_MT)
end

local function expr_of(q)
  return rawget(q, EXPR)
end

--- graphql.is_query(v) -> boolean
function graphql.is_query(v)
  return type(v) == "table" and getmetatable(v) == QUERY_MT
end
local is_query = graphql.is_query

local print_expr

QUERY_MT.__index = function(q, key)
  if type(key) ~= "string" then
    return nil
  end
  local expr = rawget(q, EXPR)
  local field = fields_of(expr.type)[key]
  if field == nil then
    compat.raise(
      "graphql: "
        .. type_name(expr.type)
        .. " has no field "
        .. key
        .. " ("
        .. print_expr(expr)
        .. ")",
      2
    )
  end
  return make({ tag = "Prop", parent = expr, field = field, type = field_result(expr.type, field) })
end

QUERY_MT.__newindex = function()
  compat.raise("graphql: a Query is read-only", 2)
end

local function check_args(expr, arg_types, bag, level)
  if type(bag) ~= "table" or is_query(bag) or secret.is(bag) then
    compat.raise(
      "graphql: arguments of " .. print_expr(expr) .. " must be a table, got " .. type(bag),
      level + 1
    )
  end
  for name in pairs(bag) do
    if arg_types == nil or arg_types[name] == nil then
      local valid = {}
      for n in pairs(arg_types or EMPTY) do
        valid[#valid + 1] = n
      end
      table.sort(valid)
      compat.raise(
        "graphql: "
          .. print_expr(expr)
          .. " takes no argument "
          .. tostring(name)
          .. (
            #valid > 0 and (" (valid: " .. table.concat(valid, ", ") .. ")") or " (it takes none)"
          ),
        level + 1
      )
    end
  end
end

-- a copy of expr with `bag` merged over its arguments (graphql.ts applyBag)
local function apply_bag(expr, bag, level)
  local arg_types
  if expr.tag == "Prop" then
    arg_types = expr.field.arg_types
  elseif expr.tag == "Root" then
    arg_types = expr.arg_types
  else
    compat.raise("graphql: only a field takes arguments, not " .. print_expr(expr), level + 1)
  end
  check_args(expr, arg_types, bag, level + 1)
  local copy = {}
  for k, v in pairs(expr) do
    copy[k] = v
  end
  if next(bag) ~= nil then
    local args = {}
    for k, v in pairs(expr.args or EMPTY) do
      args[k] = v
    end
    for k, v in pairs(bag) do
      args[k] = v
    end
    copy.args = args
  end
  return copy
end

QUERY_MT.__call = function(q, bag)
  local expr = rawget(q, EXPR)
  if bag == nil then
    return q
  end
  return make(apply_bag(expr, bag, 2))
end

QUERY_MT.__tostring = function(q)
  return "Query(" .. print_expr(rawget(q, EXPR)) .. ")"
end

--- graphql.root{ op, field, shape, meta, args, arg_order, errors, sensitive } -> Query
-- shape: "root" (an object), "list" (a list of objects), "connection" (a Relay
-- connection read as a list of nodes), "leaf" / "leaf_list" (a scalar or enum, or a list
-- of them). args: the caller's argument table (checked against arg_order, a list of
-- { name, type }). errors: the error specs this root can return (its own and the global
-- ones). graphql.ts root / rootList / rootConnection / rootLeaf.
function graphql.root(spec)
  local ref
  local shape = spec.shape
  if shape == "root" then
    ref = object_ref(spec.meta)
  elseif shape == "list" or shape == "connection" then
    ref = list_ref(object_ref(spec.meta))
  elseif shape == "leaf" then
    ref = SCALAR
  elseif shape == "leaf_list" then
    ref = list_ref(SCALAR)
  else
    compat.raise("graphql.root: unknown shape " .. tostring(shape), 2)
  end
  local arg_types
  if spec.arg_order ~= nil and #spec.arg_order > 0 then
    arg_types = {}
    for _, a in ipairs(spec.arg_order) do
      arg_types[a[1]] = a[2]
    end
  end
  local expr = {
    tag = "Root",
    op = spec.op,
    field = spec.field,
    arg_types = arg_types,
    arg_order = spec.arg_order,
    type = ref,
    connection = shape == "connection" or nil,
    errors = spec.errors or EMPTY,
    sensitive = (spec.sensitive and (shape == "leaf" or shape == "leaf_list")) or nil,
  }
  if spec.args ~= nil then
    check_args(expr, arg_types, spec.args, (spec.level or 1) + 1)
    if next(spec.args) ~= nil then
      local args = {}
      for k, v in pairs(spec.args) do
        args[k] = v
      end
      expr.args = args
    end
  end
  return make(expr)
end

print_expr = function(expr)
  local tag = expr.tag
  if tag == "Root" then
    if expr.args then
      return expr.field .. "(" .. shown(expr.args) .. ")"
    end
    return expr.field
  elseif tag == "Prop" then
    return print_expr(expr.parent) .. "." .. expr.field.name
  elseif tag == "Item" then
    return "$item"
  elseif tag == "MapValue" then
    return "map(" .. print_expr(expr.parent) .. ")"
  elseif tag == "MapItems" then
    return "mapItems(" .. print_expr(expr.parent) .. ")"
  elseif tag == "Filter" then
    return "filter(" .. print_expr(expr.parent) .. ")"
  elseif tag == "FlatMap" then
    return "flatMap(" .. print_expr(expr.parent) .. ")"
  elseif tag == "Literal" then
    return "of(" .. tostring(expr.value) .. ")"
  end
  return "?"
end

--- graphql.describe(q) -> the expression a Query stands for, as text
function graphql.describe(q)
  return print_expr(expr_of(q))
end

---------------------------------------------------------------------------------------
-- combinators (graphql.ts ofQuery, mapQuery, filterQuery, flatMapQuery)
---------------------------------------------------------------------------------------

local function check_query(q, what)
  if not is_query(q) then
    compat.raise("graphql." .. what .. ": expected a Query, got " .. type(q), 3)
  end
end

local function check_fn(fn, what)
  if
    type(fn) ~= "function"
    and not (type(fn) == "table" and getmetatable(fn) and getmetatable(fn).__call)
  then
    compat.raise("graphql." .. what .. ": expected a function", 3)
  end
end

--- graphql.of(value) -> a Query whose value is `value` (never selected)
function graphql.of(value)
  return make({ tag = "Literal", value = value, type = SCALAR })
end

--- graphql.map(q, fn) -> Query
function graphql.map(q, fn)
  check_query(q, "map")
  check_fn(fn, "map")
  local expr = expr_of(q)
  if expr.type.tag == "object" then
    local mapped = fn(make({ tag = "Item", list = expr, type = expr.type }))
    return make({ tag = "MapItems", parent = expr, mapped = mapped, single = true, type = SCALAR })
  end
  if expr.type.tag == "list" then
    local mapped = fn(make({ tag = "Item", list = expr, type = expr.type.of }))
    return make({ tag = "MapItems", parent = expr, mapped = mapped, type = expr.type })
  end
  return make({ tag = "MapValue", parent = expr, fn = fn, type = SCALAR })
end

--- graphql.filter(q, predicate) -> Query (q is a list; predicate(item Query) -> Query)
function graphql.filter(q, predicate)
  check_query(q, "filter")
  check_fn(predicate, "filter")
  local expr = expr_of(q)
  if expr.type.tag ~= "list" then
    compat.raise("graphql.filter: expected a list Query, got " .. print_expr(expr), 2)
  end
  local p = predicate(make({ tag = "Item", list = expr, type = expr.type.of }))
  if not is_query(p) then
    compat.raise("graphql.filter: the predicate must return a Query", 2)
  end
  return make({ tag = "Filter", parent = expr, predicate = expr_of(p), type = expr.type })
end

--- graphql.flat_map(q, fn) -> Query. After the POST, fn(value) returns the result: a
-- value, `nil, err` (the run fails with err), or a plan holding Queries, which runs as
-- another request.
function graphql.flat_map(q, fn)
  check_query(q, "flat_map")
  check_fn(fn, "flat_map")
  return make({ tag = "FlatMap", parent = expr_of(q), fn = fn, type = SCALAR })
end

--- graphql.fn(build) -> function(client, ...) -> value | nil, err (Query.fn)
function graphql.fn(build)
  check_fn(build, "fn")
  return function(client, ...)
    return client:run(build(...))
  end
end

---------------------------------------------------------------------------------------
-- the selection forest (graphql.ts Forest, ensureChild, paint*)
---------------------------------------------------------------------------------------
--
-- sel = { field, alias, args = { { name, var }, ... } | nil, children = { sel, ... },
--         index = { [key] = sel }, is_scalar, is_list, sensitive }

local function empty_sel(field)
  return { field = field, children = {}, index = {}, is_scalar = false, is_list = false }
end

local function empty_forest()
  return {
    kind = nil,
    roots = empty_sel(""),
    vars = {},
    var_i = 0,
    alias_i = 0,
    root_alias = {},
    root_errors = {},
  }
end

local function response_key(sel)
  return sel.alias or sel.field
end

-- bind the present arguments as variables, in declaration order (graphql.ts bindArgs)
-- `after_last`: the pagination cursor was added to the caller's arguments, so it is
-- bound last (TS spreads it after them: `{ ...args, after }`)
local function bind_args(forest, args, arg_types, arg_order, raw_args, after_last)
  if args == nil then
    return nil
  end
  local names = {}
  local listed = {}
  if after_last then
    listed.after = true
  end
  for _, a in ipairs(arg_order or EMPTY) do
    if args[a[1]] ~= nil and not listed[a[1]] then
      names[#names + 1] = a[1]
    end
    listed[a[1]] = true
  end
  for _, k in ipairs(sorted_keys(args)) do
    if not listed[k] then
      names[#names + 1] = k
    end
  end
  if after_last and args.after ~= nil then
    names[#names + 1] = "after"
  end
  if #names == 0 then
    return nil
  end
  local bound = {}
  for _, name in ipairs(names) do
    local var = "v" .. forest.var_i
    forest.var_i = forest.var_i + 1
    forest.vars[#forest.vars + 1] = {
      name = var,
      type = (arg_types and arg_types[name]) or "String",
      value = args[name],
      -- the argument as given (a secret stays one), for span attributes
      raw = raw_args and raw_args[name],
    }
    bound[#bound + 1] = { name, var }
  end
  return bound
end

local function ensure_child(forest, parent, field, opts)
  local raw_args = opts.args
  local args = raw_args
  if args ~= nil then
    -- secrets are sent as their values (unwrapRedactedDeep)
    args = secret.unwrap_deep(args)
  end
  local key = field
  if args ~= nil then
    local text, err = json.encode(args)
    if text == nil then
      throw("arguments of " .. field .. " cannot be sent: " .. tostring(err and err.message or err))
    end
    key = field .. ":" .. text
  end
  local existing = parent.index[key]
  if existing then
    return existing
  end
  local taken = {}
  for _, c in ipairs(parent.children) do
    taken[response_key(c)] = true
  end
  local alias
  if taken[field] then
    repeat
      alias = field .. "_" .. forest.alias_i
      forest.alias_i = forest.alias_i + 1
    until not taken[alias]
  end
  local sel = {
    field = field,
    alias = alias,
    args = bind_args(forest, args, opts.arg_types, opts.arg_order, raw_args, opts.after_last),
    children = {},
    index = {},
    is_scalar = opts.is_scalar or false,
    is_list = opts.is_list or false,
    sensitive = opts.sensitive or nil,
  }
  parent.children[#parent.children + 1] = sel
  parent.index[key] = sel
  return sel
end

local function paint_connection(forest, connection)
  local edges = ensure_child(forest, connection, "edges", { is_list = true })
  ensure_child(forest, edges, "node", {})
end

local function sel_at(roots, path)
  local current = roots
  for _, segment in ipairs(path) do
    local found
    for _, c in ipairs(current.children) do
      if response_key(c) == segment then
        found = c
        break
      end
    end
    if not found then
      throw("internal: missing " .. tostring(segment))
    end
    current = found
  end
  return current
end

local function append(list, ...)
  local out = {}
  for i = 1, #list do
    out[i] = list[i]
  end
  local extra = { ... }
  for i = 1, #extra do
    out[#out + 1] = extra[i]
  end
  return out
end

local function field_opts(field, args, after_last)
  return {
    args = args,
    after_last = after_last,
    arg_types = field.arg_types,
    arg_order = field.args,
    is_scalar = field.kind == "scalar",
    is_list = field.kind == "list",
    sensitive = field.sensitive,
  }
end

local function depth_check(depth)
  if depth > graphql.MAX_DEPTH then
    throw("the query is nested deeper than " .. graphql.MAX_DEPTH .. " levels")
  end
end

local paint_abs
paint_abs = function(forest, expr, depth)
  depth = depth or 0
  depth_check(depth)
  if expr.tag == "Root" then
    if forest.kind ~= nil and forest.kind ~= expr.op then
      throw("cannot mix " .. forest.kind .. " and " .. expr.op .. " in one document")
    end
    forest.kind = expr.op
    local ref = expr.type
    local node = ensure_child(forest, forest.roots, expr.field, {
      args = expr.args,
      arg_types = expr.arg_types,
      arg_order = expr.arg_order,
      after_last = expr.after_last,
      -- leaf roots (`projectDelete: Boolean!`) take no sub-selection
      is_scalar = ref.tag == "scalar" or (ref.tag == "list" and ref.of.tag == "scalar"),
      is_list = ref.tag == "list" and not expr.connection,
      sensitive = expr.sensitive,
    })
    local key = response_key(node)
    forest.root_alias[expr] = key
    forest.root_errors[key] = { field = expr.field, errors = expr.errors }
    if expr.connection then
      paint_connection(forest, node)
      return { key, "edges", "node" }
    end
    return { key }
  elseif expr.tag == "Prop" then
    local parent_path = paint_abs(forest, expr.parent, depth + 1)
    local parent_sel = sel_at(forest.roots, parent_path)
    local opts = field_opts(expr.field, expr.args, expr.after_last)
    local node = ensure_child(forest, parent_sel, expr.field.name, opts)
    local key = response_key(node)
    forest.root_alias[expr] = key
    local path = append(parent_path, key)
    if expr.field.kind == "connection" then
      paint_connection(forest, node)
      return append(path, "edges", "node")
    end
    return path
  end
  throw("paintAbs: " .. tostring(expr.tag))
end

local function connection_node_sel(connection)
  local edges, node
  for _, c in ipairs(connection.children) do
    if c.field == "edges" then
      edges = c
      break
    end
  end
  if edges then
    for _, c in ipairs(edges.children) do
      if c.field == "node" then
        node = c
        break
      end
    end
  end
  if not node then
    throw("internal: connection missing edges.node")
  end
  return node
end

local function rel_sel(forest, expr, list_sel, depth)
  depth_check(depth)
  if expr.tag == "Item" then
    return list_sel
  elseif expr.tag == "Prop" then
    local parent = rel_sel(forest, expr.parent, list_sel, depth + 1)
    local key = forest.root_alias[expr] or expr.field.name
    local child
    for _, c in ipairs(parent.children) do
      if response_key(c) == key then
        child = c
        break
      end
    end
    if not child then
      throw("missing " .. expr.field.name .. " in list selection")
    end
    if expr.field.kind == "connection" then
      return connection_node_sel(child)
    end
    return child
  end
  return list_sel
end

local visit_rel

local function paint_rel(forest, expr, list_sel, depth)
  depth_check(depth)
  local tag = expr.tag
  if tag == "Item" or tag == "Literal" then
    return
  elseif tag == "Prop" then
    paint_rel(forest, expr.parent, list_sel, depth + 1)
    local parent = rel_sel(forest, expr.parent, list_sel, depth + 1)
    local child = ensure_child(forest, parent, expr.field.name, field_opts(expr.field, expr.args))
    forest.root_alias[expr] = response_key(child)
    if expr.field.kind == "connection" then
      paint_connection(forest, child)
    end
  elseif tag == "MapValue" or tag == "FlatMap" then
    paint_rel(forest, expr.parent, list_sel, depth + 1)
  elseif tag == "MapItems" then
    paint_rel(forest, expr.parent, list_sel, depth + 1)
    visit_rel(expr.mapped, forest, rel_sel(forest, expr.parent, list_sel, depth + 1), depth + 1)
  elseif tag == "Filter" then
    paint_rel(forest, expr.parent, list_sel, depth + 1)
    paint_rel(forest, expr.predicate, rel_sel(forest, expr.parent, list_sel, depth + 1), depth + 1)
  elseif tag == "Root" then
    throw("root inside list item")
  end
end

visit_rel = function(plan, forest, list_sel, depth)
  depth_check(depth)
  if is_query(plan) then
    paint_rel(forest, expr_of(plan), list_sel, depth + 1)
    return
  end
  if is_plain(plan) then
    for _, k in ipairs(sorted_keys(plan)) do
      visit_rel(plan[k], forest, list_sel, depth + 1)
    end
  end
end

local function graphql_base(expr)
  local tag = expr.tag
  while tag == "MapValue" or tag == "MapItems" or tag == "Filter" or tag == "FlatMap" do
    expr = expr.parent
    tag = expr.tag
  end
  if tag == "Literal" then
    throw("literal has no graphql base")
  end
  return expr
end

local function in_item(expr)
  while true do
    local tag = expr.tag
    if tag == "Item" then
      return true
    end
    if
      tag == "Prop"
      or tag == "MapValue"
      or tag == "MapItems"
      or tag == "Filter"
      or tag == "FlatMap"
    then
      expr = expr.parent
    else
      return false
    end
  end
end

local function visit_expr(forest, expr, depth)
  depth_check(depth)
  local tag = expr.tag
  if tag == "Root" or tag == "Prop" then
    paint_abs(forest, expr, depth + 1)
  elseif tag == "MapValue" or tag == "FlatMap" then
    visit_expr(forest, expr.parent, depth + 1)
  elseif tag == "MapItems" then
    visit_expr(forest, expr.parent, depth + 1)
    local path = paint_abs(forest, graphql_base(expr.parent), depth + 1)
    visit_rel(expr.mapped, forest, sel_at(forest.roots, path), depth + 1)
  elseif tag == "Filter" then
    visit_expr(forest, expr.parent, depth + 1)
    local path = paint_abs(forest, graphql_base(expr.parent), depth + 1)
    paint_rel(forest, expr.predicate, sel_at(forest.roots, path), depth + 1)
  end
end

local function visit_plan(plan, forest, depth)
  depth_check(depth)
  if is_query(plan) then
    visit_expr(forest, expr_of(plan), depth + 1)
    return
  end
  if is_plain(plan) then
    for _, k in ipairs(sorted_keys(plan)) do
      visit_plan(plan[k], forest, depth + 1)
    end
  end
end

---------------------------------------------------------------------------------------
-- the document (graphql.ts validate, printChildren, emit)
---------------------------------------------------------------------------------------

local function validate_sel(node, depth)
  depth_check(depth)
  for _, child in ipairs(node.children) do
    if not child.is_scalar and #child.children == 0 then
      return 'field "' .. child.field .. '" has no sub-selection'
    end
    local inner = validate_sel(child, depth + 1)
    if inner then
      return inner
    end
  end
  return nil
end

local function print_children(node, indent, lines)
  local pad = string.rep("  ", indent)
  for _, child in ipairs(node.children) do
    local head = child.alias and (child.alias .. ": " .. child.field) or child.field
    if child.args and #child.args > 0 then
      local printed = {}
      for i, a in ipairs(child.args) do
        printed[i] = a[1] .. ": $" .. a[2]
      end
      head = head .. "(" .. table.concat(printed, ", ") .. ")"
    end
    if child.is_scalar then
      lines[#lines + 1] = pad .. head
    else
      lines[#lines + 1] = pad .. head .. " {"
      print_children(child, indent + 1, lines)
      lines[#lines + 1] = pad .. "}"
    end
  end
end

local function emit(forest)
  local err = validate_sel(forest.roots, 0)
  if err then
    throw(err)
  end
  local kind = forest.kind or "query"
  local defs = {}
  local variables, raw_variables = {}, {}
  for i, v in ipairs(forest.vars) do
    defs[i] = "$" .. v.name .. ": " .. v.type
    variables[v.name] = v.value
    raw_variables[v.name] = v.raw
  end
  local header = #defs > 0 and (kind .. " Gql(" .. table.concat(defs, ", ") .. ")")
    or (kind .. " Gql")
  local lines = {}
  print_children(forest.roots, 1, lines)
  return {
    document = header .. " {\n" .. compat.concat(lines, "\n") .. "\n}",
    operation_name = "Gql",
    variables = json.object(variables),
    raw_variables = raw_variables,
    kind = kind,
    tree = forest.roots,
    root_alias = forest.root_alias,
    root_errors = forest.root_errors,
  }
end

--- graphql.compile(plan) -> compiled | false (no Query in the plan) | nil, GqlError
-- compiled = { document, operation_name = "Gql", variables, raw_variables (as given:
--              secrets stay secrets), kind = "query" | "mutation", tree, root_alias,
--              root_errors }
function graphql.compile(plan)
  local ok, compiled = compiling(function()
    local forest = empty_forest()
    visit_plan(plan, forest, 0)
    if #forest.roots.children == 0 then
      return false
    end
    return emit(forest)
  end)
  if not ok then
    return nil, compiled
  end
  return compiled
end

--- graphql.request_body(compiled) -> the table a transport posts as JSON
function graphql.request_body(compiled)
  return {
    query = compiled.document,
    variables = compiled.variables,
    operationName = compiled.operation_name,
  }
end

---------------------------------------------------------------------------------------
-- reading the response (graphql.ts nodesFromConnection, readField, redact*, extract*)
---------------------------------------------------------------------------------------

local function nodes_from_connection(value, depth)
  depth = depth or 0
  if is_nullish(value) then
    return value
  end
  if is_array(value) then
    local out = {}
    for i = 1, #value do
      local v = nodes_from_connection(value[i], depth + 1)
      out[i] = v == nil and null or v
    end
    return list_of(out)
  end
  if type(value) ~= "table" or secret.is(value) then
    return list_of({})
  end
  local edges = rawget(value, "edges")
  if not is_array(edges) then
    return list_of({})
  end
  local out = {}
  for i = 1, #edges do
    local edge = edges[i]
    local node
    if is_nullish(edge) then
      node = edge
    elseif type(edge) == "table" and not secret.is(edge) then
      node = rawget(edge, "node")
    end
    out[i] = node == nil and null or node
  end
  return list_of(out)
end

local function read_key(parent, name)
  if type(parent) ~= "table" or parent == null or secret.is(parent) then
    return nil
  end
  return rawget(parent, name)
end

local function read_field(parent, name)
  if is_nullish(parent) then
    return parent
  end
  if is_array(parent) then
    local out = {}
    for i = 1, #parent do
      local item = parent[i]
      local v
      if is_nullish(item) then
        v = item
      else
        v = read_key(item, name)
      end
      out[i] = v == nil and null or v
    end
    return list_of(out)
  end
  return read_key(parent, name)
end

-- a sensitive scalar as a secret: a string, a JSON object, or each item of a list
local function redact_values(value, depth)
  if is_nullish(value) then
    return value
  end
  if is_array(value) and depth < graphql.MAX_DEPTH then
    local out = {}
    for i = 1, #value do
      out[i] = redact_values(value[i], depth + 1)
    end
    return list_of(out)
  end
  return secret.wrap(value)
end

-- a copy of data with the value of every sensitive field `sel` selects as a secret
local function redact_selected(sel, data, depth)
  depth = depth or 0
  if #sel.children == 0 or type(data) ~= "table" or data == null or secret.is(data) then
    return data
  end
  if depth > graphql.MAX_DEPTH * 2 then
    return data
  end
  if is_array(data) then
    local out = {}
    for i = 1, #data do
      out[i] = redact_selected(sel, data[i], depth + 1)
    end
    return list_of(out)
  end
  local out = {}
  for k, v in pairs(data) do
    out[k] = v
  end
  if getmetatable(data) ~= nil then
    setmetatable(out, getmetatable(data))
  end
  for _, child in ipairs(sel.children) do
    local key = response_key(child)
    if child.sensitive then
      out[key] = redact_values(out[key], 0)
    else
      out[key] = redact_selected(child, out[key], depth + 1)
    end
  end
  return out
end
graphql._redact_selected = redact_selected

local function extract_abs(expr, data, root_alias, depth)
  depth_check(depth)
  if expr.tag == "Root" then
    local raw = read_key(data, root_alias[expr] or expr.field)
    if expr.connection then
      return nodes_from_connection(raw)
    end
    return raw
  elseif expr.tag == "Prop" then
    local value = read_field(
      extract_abs(expr.parent, data, root_alias, depth + 1),
      root_alias[expr] or expr.field.name
    )
    if expr.field.kind == "connection" then
      return nodes_from_connection(value)
    end
    return value
  end
  throw("extractAbs: " .. tostring(expr.tag))
end

local function extract_rel(expr, item, root_alias, depth)
  depth_check(depth)
  if expr.tag == "Item" then
    return item
  elseif expr.tag == "Prop" then
    local value = read_field(
      extract_rel(expr.parent, item, root_alias, depth + 1),
      root_alias[expr] or expr.field.name
    )
    if expr.field.kind == "connection" then
      return nodes_from_connection(value)
    end
    return value
  end
  throw("extractRel: " .. tostring(expr.tag))
end

-- a user callback run after the POST: a raise becomes an SdkError (never a raise out)
local function callback(what, fn, ...)
  local r = compat.pack(compat.pcall(fn, ...))
  if r[1] then
    return r[2], r[3]
  end
  local raised = r[2]
  if errors.is(raised) and raised.tag == "GqlError" then
    error(raised, 0)
  end
  local message = type(raised) == "table" and rawget(raised, "message") or raised
  error(
    errors.new("SdkError", {
      message = "the " .. what .. " callback raised: " .. tostring(message),
      cause = raised,
    }),
    0
  )
end

local interpret_value

local function interpret_expr(expr, data, root_alias, item, depth)
  depth_check(depth)
  local tag = expr.tag
  if tag == "Literal" then
    return expr.value
  elseif tag == "Item" then
    return item
  elseif tag == "Root" or tag == "Prop" then
    if in_item(expr) then
      return extract_rel(expr, item, root_alias, depth + 1)
    end
    return extract_abs(expr, data, root_alias, depth + 1)
  elseif tag == "MapValue" then
    local v = interpret_expr(expr.parent, data, root_alias, item, depth + 1)
    return (callback("map", expr.fn, v))
  elseif tag == "Filter" then
    local list = interpret_expr(expr.parent, data, root_alias, item, depth + 1)
    local out = {}
    if is_array(list) then
      for i = 1, #list do
        local row = list[i]
        if truthy(interpret_expr(expr.predicate, data, root_alias, row, depth + 1)) then
          out[#out + 1] = row
        end
      end
    end
    return list_of(out)
  elseif tag == "MapItems" then
    local list = interpret_expr(expr.parent, data, root_alias, item, depth + 1)
    if expr.single then
      if is_nullish(list) then
        return null
      end
      return interpret_value(expr.mapped, data, root_alias, list, depth + 1)
    end
    local out = {}
    if is_array(list) then
      for i = 1, #list do
        local v = interpret_value(expr.mapped, data, root_alias, list[i], depth + 1)
        out[i] = v == nil and null or v
      end
    end
    return list_of(out)
  elseif tag == "FlatMap" then
    throw("flat_map can only be used at the top of a plan, not inside map or filter")
  end
  throw("interpret: " .. tostring(tag))
end

interpret_value = function(plan, data, root_alias, item, depth)
  depth_check(depth)
  if is_query(plan) then
    return interpret_expr(expr_of(plan), data, root_alias, item, depth + 1)
  end
  if is_plain(plan) then
    local out = {}
    for _, k in ipairs(sorted_keys(plan)) do
      out[k] = interpret_value(plan[k], data, root_alias, item, depth + 1)
    end
    if json.is_array(plan) then
      json.array(out)
    end
    return out
  end
  return plan
end

local function contains_query(plan, depth)
  if depth > graphql.MAX_DEPTH then
    return false
  end
  if is_query(plan) then
    return true
  end
  if is_plain(plan) then
    for _, v in pairs(plan) do
      if contains_query(v, depth + 1) then
        return true
      end
    end
  end
  return false
end

-- the plan's value: Queries read from data, flat_map callbacks run (raises GqlError /
-- SdkError tables; `again(plan)` evaluates a plan a callback returned)
local function interpret_plan(plan, data, root_alias, again, depth)
  depth_check(depth)
  if is_query(plan) then
    local expr = expr_of(plan)
    if expr.tag == "FlatMap" then
      local resolved = interpret_expr(expr.parent, data, root_alias, nil, depth + 1)
      local nxt, err = callback("flat_map", expr.fn, resolved)
      if nxt == nil and err ~= nil then
        error({ returned = err }, 0)
      end
      if contains_query(nxt, 0) then
        local v, e = again(nxt)
        if v == nil and e ~= nil then
          error({ returned = e }, 0)
        end
        return v
      end
      return nxt
    end
    return interpret_expr(expr, data, root_alias, nil, depth + 1)
  end
  if is_plain(plan) then
    local out = {}
    for _, k in ipairs(sorted_keys(plan)) do
      out[k] = interpret_plan(plan[k], data, root_alias, again, depth + 1)
    end
    if json.is_array(plan) then
      json.array(out)
    end
    return out
  end
  return plan
end

-- run interpret_plan, returning value | nil, err
local function interpret(plan, data, root_alias, again)
  local r = compat.pack(compat.pcall(interpret_plan, plan, data, root_alias, again, 0))
  if r[1] then
    return r[2]
  end
  local e = r[2]
  if type(e) == "table" and getmetatable(e) == nil and e.returned ~= nil then
    return nil, e.returned
  end
  if errors.is(e) then
    return nil, e
  end
  return nil, gql_error(tostring(e))
end

--- graphql.evaluate(plan, execute) -> value | nil, err
-- Compile every Query in plan into one document, `execute(compiled) -> data | nil, err`
-- it (one POST, with retries), then read the plan's values from the data. A plan with
-- no Query is interpreted without a request.
function graphql.evaluate(plan, execute)
  local compiled, err = graphql.compile(plan)
  if compiled == nil then
    return nil, err
  end
  local data, root_alias = json.object({}), {}
  if compiled then
    local d, xerr = execute(compiled)
    if d == nil then
      return nil, xerr
    end
    data = d
    root_alias = compiled.root_alias
  end
  return interpret(plan, data, root_alias, function(nxt)
    return graphql.evaluate(nxt, execute)
  end)
end

---------------------------------------------------------------------------------------
-- classifying GraphQL errors (graphql.ts classify, execute's `once`)
---------------------------------------------------------------------------------------

--- graphql.error_spec(class, matchers, { retryable, global }) -> spec
function graphql.error_spec(class, matchers, opts)
  opts = opts or EMPTY
  return {
    tag = class.tag,
    class = class,
    matchers = matchers or {},
    retryable = opts.retryable == true,
    global = opts.global == true,
  }
end

local function unique_by_tag(specs)
  local seen, out = {}, {}
  for _, s in ipairs(specs) do
    if not seen[s.tag] then
      seen[s.tag] = true
      out[#out + 1] = s
    end
  end
  return out
end

local function retry_after_seconds(header)
  if type(header) ~= "string" then
    return nil
  end
  if string.find(header, "^%d+$") or string.find(header, "^%d+%.%d+$") then
    return json.decode(header)
  end
  return nil
end
graphql._retry_after_seconds = retry_after_seconds

local function wire_typeof(entry)
  if entry == null then
    return "null"
  end
  local t = type(entry)
  if t == "table" then
    return "object"
  end
  if t == "nil" then
    return "undefined"
  end
  return t
end

--- graphql.classify(compiled, entry, response) -> err
-- The most specific matcher among the errors the root at path[1] declares (the global
-- errors for an error with no path); a tie between different tags is ambiguous and stays
-- UnknownGraphQLError.
function graphql.classify(compiled, entry, response)
  local raw
  if is_record(entry) then
    raw = entry
  else
    raw = {
      message = type(entry) == "string" and entry
        or ("malformed GraphQL error entry (" .. wire_typeof(entry) .. ")"),
    }
  end
  local raw_path = is_array(raw.path) and raw.path or nil
  local root
  if raw_path and type(raw_path[1]) == "string" then
    root = compiled.root_errors[raw_path[1]]
  end
  -- a malformed path or locations is left out
  local path = raw_path
  if raw_path then
    for i = 1, #raw_path do
      local k = raw_path[i]
      if type(k) ~= "string" and type(k) ~= "number" then
        path = nil
        break
      end
    end
  end
  local locations = nil
  if is_array(raw.locations) then
    locations = raw.locations
    for i = 1, #raw.locations do
      local l = raw.locations[i]
      if not is_record(l) or type(l.line) ~= "number" or type(l.column) ~= "number" then
        locations = nil
        break
      end
    end
  end
  local candidates
  if root then
    candidates = root.errors
  else
    local globals = {}
    for _, key in ipairs(sorted_keys(compiled.root_errors)) do
      for _, s in ipairs(compiled.root_errors[key].errors) do
        if s.global then
          globals[#globals + 1] = s
        end
      end
    end
    candidates = unique_by_tag(globals)
  end
  local extensions = is_record(raw.extensions) and raw.extensions or EMPTY
  local code
  if type(extensions.code) == "string" then
    code = extensions.code
  elseif type(extensions.errorCode) == "string" then
    code = extensions.errorCode
  end
  local message = type(raw.message) == "string" and raw.message or ""
  local headers = response and response.headers or EMPTY
  local server_trace_id
  if type(extensions.traceId) == "string" then
    server_trace_id = extensions.traceId
  elseif type(raw.traceId) == "string" then
    server_trace_id = raw.traceId
  end
  local props = {
    message = message,
    code = code,
    path = path,
    locations = locations,
    extensions = raw.extensions,
    server_trace_id = server_trace_id,
    status = response and response.status or nil,
    retry_after = retry_after_seconds(headers["retry-after"]),
  }
  local best_score, best_spec, ambiguous = -1, nil, false
  for _, spec in ipairs(candidates) do
    for _, m in ipairs(spec.matchers) do
      if
        (m.code == nil or m.code == code)
        and (m.message == nil or m.message == message)
        and (m.messageIncludes == nil or string.find(message, m.messageIncludes, 1, true) ~= nil)
      then
        local score = (m.code and 1 or 0) + (m.message and 4 or 0) + (m.messageIncludes and 2 or 0)
        if score > best_score then
          best_score = score
          best_spec = spec
          ambiguous = false
        elseif score == best_score and spec.tag ~= best_spec.tag then
          ambiguous = true
        end
      end
    end
  end
  if best_spec and not ambiguous then
    return errors.new(best_spec.class, props)
  end
  props.coordinate = root and root.field or nil
  return errors.new(graphql.UnknownGraphQLError, props)
end

local function failure_message(list)
  local parts = {}
  for i, e in ipairs(list) do
    local at = ""
    if type(e.path) == "table" and #e.path > 0 then
      local segs = {}
      for j = 1, #e.path do
        segs[j] = tostring(e.path[j])
      end
      at = " at " .. table.concat(segs, ".")
    end
    parts[i] = tostring(e.tag) .. at .. ": " .. tostring(e.message)
  end
  return table.concat(parts, "; ")
end

--- graphql.result(compiled, response) -> data | nil, err
-- response = { data, errors, status, headers } (what a transport read). Without errors a
-- response must carry a data object. Errors are classified; several with different tags
-- are one GraphQLFailure holding them all (and the partial data).
function graphql.result(compiled, response)
  local data = redact_selected(compiled.tree, response.data)
  local raw = is_array(response.errors) and response.errors or EMPTY
  if #raw == 0 then
    if not is_record(response.data) then
      return nil,
        errors.new(graphql.GraphQLTransportError, {
          message = "GraphQL response has no data object and no errors",
          status = response.status,
        })
    end
    return data
  end
  local issues = {}
  for i = 1, #raw do
    issues[i] = graphql.classify(compiled, raw[i], response)
  end
  local first = issues[1]
  local same = true
  for i = 2, #issues do
    if issues[i].tag ~= first.tag then
      same = false
      break
    end
  end
  if same then
    return nil, first
  end
  return nil,
    errors.new(graphql.GraphQLFailure, {
      message = failure_message(issues),
      errors = issues,
      data = data,
      status = response.status,
    })
end

--- graphql.is_retryable(compiled, err) -> boolean
-- Queries are retried while every failure is retryable: a transport error with no
-- status, 429 or 5xx; or GraphQL errors whose classes the roots declare retryable.
function graphql.is_retryable(compiled, err)
  if not errors.is(err) then
    return false
  end
  if err.tag == "GraphQLTransportError" then
    local s = err.status
    return s == nil or s == 429 or s >= 500
  end
  local retryable = {}
  for _, root in pairs(compiled.root_errors) do
    for _, s in ipairs(root.errors) do
      if s.retryable then
        retryable[s.tag] = true
      end
    end
  end
  if err.tag == "GraphQLFailure" then
    for _, issue in ipairs(err.errors or EMPTY) do
      if not retryable[issue.tag] then
        return false
      end
    end
    return true
  end
  return retryable[err.tag] == true
end

---------------------------------------------------------------------------------------
-- pagination (graphql.ts connectionOf, withCursor, fetchPage, pagesQuery, itemsQuery)
---------------------------------------------------------------------------------------
--
-- A connection Query hides edges/pageInfo. Paging re-evaluates the query once per page:
-- it sets the connection's `after` argument, paints `pageInfo { hasNextPage endCursor }`
-- next to `edges`, and stops when hasNextPage is false.

local function connection_of(expr)
  local base = graphql_base(expr)
  local is_connection = (base.tag == "Root" and base.connection == true)
    or (base.tag == "Prop" and base.field.kind == "connection")
  if not is_connection or in_item(base) then
    throw("pages needs a Relay connection, got " .. print_expr(base))
  end
  local arg_types = base.tag == "Root" and base.arg_types or base.field.arg_types
  if not arg_types or arg_types.after == nil then
    throw(print_expr(base) .. ' takes no "after" cursor')
  end
  return base
end

local function with_cursor(expr, connection, after)
  if expr == connection then
    local copy = {}
    for k, v in pairs(expr) do
      copy[k] = v
    end
    local args = {}
    for k, v in pairs(expr.args or EMPTY) do
      args[k] = v
    end
    if args.after == nil then
      copy.after_last = true
    end
    args.after = after
    copy.args = next(args) ~= nil and args or nil
    return copy
  end
  local tag = expr.tag
  if tag == "MapItems" or tag == "Filter" or tag == "MapValue" or tag == "FlatMap" then
    local copy = {}
    for k, v in pairs(expr) do
      copy[k] = v
    end
    copy.parent = with_cursor(expr.parent, connection, after)
    return copy
  end
  throw("withCursor: " .. tostring(tag))
end

local function read_path(data, path)
  local current = data
  for _, segment in ipairs(path) do
    if is_nullish(current) then
      return nil
    end
    if is_array(current) then
      throw("pages cannot page a connection inside a list")
    end
    current = read_key(current, segment)
  end
  return current
end

local function page_document(q, connection, after)
  local page_expr = with_cursor(expr_of(q), connection, after)
  local forest = empty_forest()
  visit_expr(forest, page_expr, 0)
  local node_path = paint_abs(forest, with_cursor(connection, connection, after), 0)
  local connection_path = {}
  for i = 1, #node_path - 2 do
    connection_path[i] = node_path[i]
  end
  local page_info = ensure_child(forest, sel_at(forest.roots, connection_path), "pageInfo", {})
  ensure_child(forest, page_info, "hasNextPage", { is_scalar = true })
  ensure_child(forest, page_info, "endCursor", { is_scalar = true })
  return page_expr, connection_path, emit(forest)
end

local Pages = {}
Pages.__index = Pages

--- graphql.pages(q, execute [, kind]) -> iterator over pages (kind "pages", each a list
-- of items) or items (kind "items"), the API of distilled.paginate's iterators:
--   for page in it do ... end ; if it.err then ... end
--   local list, err = it:collect([limit]) ; it:close()
-- Starts from the query's own `after` argument, if any. An item that is null is
-- json.null (nil would end a `for` loop).
function graphql.pages(q, execute, kind)
  if not is_query(q) then
    compat.raise("graphql.pages: expected a Query, got " .. type(q), 2)
  end
  return setmetatable({
    kind = kind or "pages",
    err = nil,
    done = false,
    pages = 0,
    count = 0,
    _q = q,
    _execute = execute,
    _buffer = nil,
    _index = 0,
  }, Pages)
end

function Pages:_fail(err)
  self.err = err
  self.done = true
  return nil
end

function Pages:_next_page()
  if self.done then
    return nil
  end
  if not self._connection then
    local ok, connection = compiling(connection_of, expr_of(self._q))
    if not ok then
      return self:_fail(connection)
    end
    self._connection = connection
    local after = connection.args and connection.args.after
    self._after = type(after) == "string" and after or nil
    self._seen = {}
  end
  local connection = self._connection
  local ok, page_expr, connection_path, compiled =
    compiling(page_document, self._q, connection, self._after)
  if not ok then
    return self:_fail(page_expr)
  end
  local data, err = self._execute(compiled)
  if data == nil then
    return self:_fail(err)
  end
  local items, ierr = interpret(make(page_expr), data, compiled.root_alias, function(nxt)
    return graphql.evaluate(nxt, self._execute)
  end)
  if ierr ~= nil then
    return self:_fail(ierr)
  end
  local iok, info = compiling(read_path, data, append(connection_path, "pageInfo"))
  if not iok then
    return self:_fail(info)
  end
  self.pages = self.pages + 1
  local cursor = nil
  if type(info) == "table" and info ~= null and not secret.is(info) then
    cursor = rawget(info, "endCursor")
  end
  if cursor == null then
    cursor = nil
  end
  if is_nullish(items) then
    items = list_of({})
  end
  local has_next = type(info) == "table" and info ~= null and rawget(info, "hasNextPage") == true
  if not has_next then
    self.done = true
    return items
  end
  if cursor == nil or cursor == self._after or self._seen[cursor] then
    -- the page is not handed out: the stream fails instead (fetchPage)
    return self:_fail(errors.new(graphql.GraphQLPaginationError, {
      message = print_expr(connection) .. " returned a non-advancing cursor",
      cursor = cursor == nil and null or cursor,
    }))
  end
  self._seen[cursor] = true
  self._after = cursor
  return items
end

--- it() -> the next page (a list) or item; nil at the end or on failure (it.err)
function Pages:__call()
  if self.kind == "pages" then
    local page = self:_next_page()
    if page ~= nil then
      self.count = self.count + 1
    end
    return page
  end
  while true do
    local buffer = self._buffer
    if buffer and self._index < #buffer then
      self._index = self._index + 1
      self.count = self.count + 1
      return buffer[self._index]
    end
    local page = self:_next_page()
    if page == nil then
      return nil
    end
    self._buffer = is_array(page) and page or list_of({})
    self._index = 0
  end
end

--- it:collect([limit]) -> list | nil, err
function Pages:collect(limit)
  if limit ~= nil and (type(limit) ~= "number" or limit < 0) then
    compat.raise("collect: limit must be a non-negative number", 2)
  end
  local list = list_of({})
  if limit == 0 then
    self:close()
    return list
  end
  while true do
    local v = self()
    if v == nil then
      break
    end
    list[#list + 1] = v
    if limit ~= nil and #list >= limit then
      self:close()
      break
    end
  end
  if self.err then
    return nil, self.err
  end
  return list
end

--- it:close(): stop fetching. Idempotent.
function Pages:close()
  self.done = true
  self._buffer = nil
end

graphql._print_expr = print_expr

return graphql
