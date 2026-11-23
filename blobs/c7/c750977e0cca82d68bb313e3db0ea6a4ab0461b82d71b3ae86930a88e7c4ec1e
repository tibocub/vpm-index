-- A generated GraphQL SDK module: the root builders (`Linear.viewer()`), the client
-- class (`Linear.new{...}`) and the typed error classes, built from the generated schema
-- data. Replaces what graphql-client.ts writes into each package's src/graphql.ts (the
-- TypeMeta tables, the error specs and the `Linear = { viewer: ..., teams: ... }` object).
--
--   return require("distilled.graphql.sdk").build({
--     name = "Linear",                     -- the TS sdkName
--     schema = "linear.schema",            -- the data module, required on first use
--     transport = { ... },                 -- distilled.graphql.client's transport facts
--     options = { ... },                   -- client options (Client.define)
--     telemetry = true | false,            -- false: no document spans (--no-telemetry)
--   })
--
-- The schema module returns plain data (see gen/graphql.lua for its writer):
--   { roots = { query = <block>, mutation = <block> }, objects = { [Type] = <block> },
--     unions = { "Name", ... }, errors = { [Tag] = { category, retryable, matchers } },
--     global_errors = { "Tag", ... }, telemetry = { ... } }
-- A block is text, one entry per line, parsed the first time it is needed, so a large
-- schema (GitHub: about 1,100 object types) loads as a handful of string constants:
--   object field:  <name> <s|o|l|c> <Type|-> [sensitive] [<arg>=<GraphQLType> ...]
--   root:          <export> <field> <root|list|connection|leaf|leaf_list> <Type|->
--                  <field-only error tags, comma separated, or -> [sensitive] [args]
local compat = require("distilled.compat")
local graphql = require("distilled.graphql")

local sdk = {}

local KINDS = { s = "scalar", o = "object", l = "list", c = "connection" }

-- module names a root cannot take (the generator refuses a model that would need one)
sdk.RESERVED = {
  new = true,
  Class = true,
  errors = true,
  schema = true,
  type = true,
  roots = true,
}

local function split(line)
  local t = {}
  for word in string.gmatch(line, "%S+") do
    t[#t + 1] = word
  end
  return t
end

-- the args and the sensitive flag of a line's tokens from `first` on
local function tail(tokens, first, where)
  local args, sensitive = {}, false
  for i = first, #tokens do
    local tok = tokens[i]
    if tok == "sensitive" then
      sensitive = true
    else
      local name, ty = string.match(tok, "^([%w_]+)=(%S+)$")
      if not name then
        error("graphql schema " .. where .. ": bad token " .. tok, 0)
      end
      args[#args + 1] = { name, ty }
    end
  end
  return args, sensitive
end

--- sdk.registry(data) -> types: types[name] is the TypeMeta of an object, interface or
-- union type (fields parsed on first use); nil for any other name
function sdk.registry(data)
  local objects = data.objects or {}
  local unions = {}
  for _, name in ipairs(data.unions or {}) do
    unions[name] = true
  end
  local types = {}
  local function parse_fields(meta)
    local block = objects[meta.name]
    local fields = {}
    for line in string.gmatch(block, "[^\n]+") do
      local tok = split(line)
      local kind = KINDS[tok[2]]
      if not kind or not tok[3] then
        error("graphql schema " .. meta.name .. ": bad field line " .. line, 0)
      end
      local args, sensitive = tail(tok, 4, meta.name .. "." .. tok[1])
      local of = nil
      if kind ~= "scalar" then
        of = types[tok[3]]
        if of == nil then
          error("graphql schema " .. meta.name .. "." .. tok[1] .. ": unknown type " .. tok[3], 0)
        end
      end
      fields[tok[1]] = graphql.field(tok[1], kind, of, args, sensitive)
    end
    return fields
  end
  local FIELDS_MT = {
    __index = function(meta, key)
      if key ~= "fields" then
        return nil
      end
      local fields = parse_fields(meta)
      rawset(meta, "fields", fields)
      return fields
    end,
  }
  setmetatable(types, {
    __index = function(t, name)
      local meta
      if objects[name] then
        meta = setmetatable({ name = name }, FIELDS_MT)
      elseif unions[name] then
        -- a union reads as its __typename only (graphql-client.ts)
        meta = graphql.type_meta(name, {
          __typename = graphql.field("__typename", "scalar"),
        })
      else
        return nil
      end
      rawset(t, name, meta)
      return meta
    end,
  })
  return types
end

--- sdk.error_classes(data) -> classes, specs: classes[tag] = error class,
-- specs[tag] = graphql.error_spec
function sdk.error_classes(data)
  local global = {}
  for _, tag in ipairs(data.global_errors or {}) do
    global[tag] = true
  end
  local classes, specs = {}, {}
  for tag, e in pairs(data.errors or {}) do
    local class = graphql.error_class({ tag = tag, category = e.category, retryable = e.retryable })
    classes[tag] = class
    specs[tag] = graphql.error_spec(class, e.matchers, {
      retryable = e.retryable,
      global = global[tag],
    })
  end
  return classes, specs
end

--- sdk.roots(data, types, specs) -> roots: roots[export] = root descriptor
function sdk.roots(data, types, specs)
  local globals = {}
  local names = {}
  for _, tag in ipairs(data.global_errors or {}) do
    names[#names + 1] = tag
  end
  table.sort(names)
  for _, tag in ipairs(names) do
    globals[#globals + 1] = specs[tag]
  end
  local roots = {}
  for _, op in ipairs({ "query", "mutation" }) do
    local block = data.roots and data.roots[op]
    for line in string.gmatch(block or "", "[^\n]+") do
      local tok = split(line)
      local export, field, shape, target, own = tok[1], tok[2], tok[3], tok[4], tok[5]
      if not own then
        error("graphql schema roots: bad line " .. line, 0)
      end
      local args, sensitive = tail(tok, 6, export)
      local errs = {}
      if own ~= "-" then
        for tag in string.gmatch(own, "[^,]+") do
          errs[#errs + 1] = specs[tag]
        end
      end
      for _, s in ipairs(globals) do
        errs[#errs + 1] = s
      end
      local meta = nil
      if target ~= "-" then
        meta = types[target]
      end
      roots[export] = {
        op = op,
        field = field,
        shape = shape,
        meta = meta,
        arg_order = #args > 0 and args or nil,
        errors = errs,
        sensitive = sensitive,
      }
    end
  end
  return roots
end

--- sdk.build(spec) -> module
function sdk.build(spec)
  local M = {}
  local loaded = nil
  local function load()
    if loaded == nil then
      local data = spec.schema
      if type(data) == "string" then
        data = require(data)
      end
      local types = sdk.registry(data)
      local classes, specs = sdk.error_classes(data)
      loaded = {
        data = data,
        types = types,
        classes = classes,
        specs = specs,
        roots = sdk.roots(data, types, specs),
      }
    end
    return loaded
  end

  local telemetry = nil
  if spec.telemetry ~= false then
    -- the client asks for it on its first traced document
    telemetry = setmetatable({}, {
      __index = function(t, k)
        local data = load().data.telemetry or {}
        for key, v in pairs(data) do
          rawset(t, key, v)
        end
        setmetatable(t, nil)
        return rawget(t, k)
      end,
    })
  end

  local Class = require("distilled.graphql.client").define({
    name = spec.name,
    transport = spec.transport,
    telemetry = telemetry,
    options = spec.options,
  })
  M.Class = Class

  --- M.new{ ... } -> client
  function M.new(opts)
    return Class.new(opts)
  end

  --- M.type(name) -> TypeMeta of a GraphQL object, interface or union type, or nil
  function M.type(name)
    return load().types[name]
  end

  --- M.roots() -> sorted list of the root builder names
  function M.roots()
    local list = {}
    for name in pairs(load().roots) do
      list[#list + 1] = name
    end
    table.sort(list)
    return list
  end

  M.errors = setmetatable({}, {
    __index = function(t, tag)
      local class = load().classes[tag]
      if class ~= nil then
        rawset(t, tag, class)
      end
      return class
    end,
  })

  return setmetatable(M, {
    __index = function(t, name)
      if type(name) ~= "string" then
        return nil
      end
      local root = load().roots[name]
      if root == nil then
        return nil
      end
      local fn = function(args)
        return graphql.root({
          op = root.op,
          field = root.field,
          shape = root.shape,
          meta = root.meta,
          args = args,
          arg_order = root.arg_order,
          errors = root.errors,
          sensitive = root.sensitive,
          level = 2,
        })
      end
      rawset(t, name, fn)
      return fn
    end,
    __newindex = function()
      compat.raise((spec.name or "graphql") .. ": the module is read-only", 2)
    end,
  })
end

return sdk
