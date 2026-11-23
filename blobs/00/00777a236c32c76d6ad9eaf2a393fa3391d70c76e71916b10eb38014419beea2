-- Clients: one table of configuration (credentials, host, retry, validation, tracing)
-- and a method per operation. Replaces Distilled's Context / Layer wiring: Lua has no
-- ambient context, so the client carries it and `client:with{}` derives a scoped one.
--
--   local Neon = Client.define{ service = service, protocol = protocol, options = {
--     api_key = { secret = true, env = "NEON_API_KEY", required = true },
--     base_url = { default = "https://console.neon.tech/api/v2" },
--   } }
--   local neon = Neon.new{ api_key = key, transport = transport }
--   local project, err = neon:get_project{ project_id = "p1" }
--   local all, err = neon:list_projects_items{}:collect(50)
--   local stream, err = boat:execute_sandbox_command_stream{ ... }   -- ops with op.stream
--   for item, item_err in stream:iter() do ... end                 -- distilled.stream
--   local patient = neon:with{ retry = { max_retries = 5 } }
--   neon:close()
--
-- The option names of new/with are the provider's options plus COMMON_OPTIONS; any
-- other name is misuse and raises with the list of valid names.
local compat = require("distilled.compat")
local credentials = require("distilled.credentials")
local errors = require("distilled.errors")
local hostlib = require("distilled.host")
local noop = require("distilled.trace.noop")
local operation = require("distilled.operation")
local paginate = require("distilled.paginate")
local retry = require("distilled.retry")
local Scope = require("distilled.scope")

local Client = {}

Client.COMMON_OPTIONS = {
  "host",
  "transport",
  "sleep",
  "now",
  "exec",
  "random",
  "getenv",
  "epoch",
  "retry",
  "deadline_s",
  "tracing",
  "tracer",
  "trace_parent",
  "validation",
  "budget",
  "server_hint_cap_s",
  "user_agent",
}
local COMMON = {}
for _, k in ipairs(Client.COMMON_OPTIONS) do
  COMMON[k] = true
end

local RESERVED_METHODS = { with = true, close = true, new = true, define = true }
local VALIDATION = { lenient = true, additional = true, strict = true }
local LEVELS = { off = true, operation = true, debug = true }
local OPTION_SPEC_FIELDS =
  { secret = true, env = true, default = true, required = true, type = true, doc = true }
local OPTION_TYPES = { string = true, number = true, boolean = true, table = true }

local function misuse(message, level)
  compat.raise(message, (level or 1) + 1)
end

local function sorted(set)
  local list = {}
  for k in pairs(set) do
    list[#list + 1] = k
  end
  table.sort(list)
  return list
end

---------------------------------------------------------------------------------------
-- tracing
---------------------------------------------------------------------------------------

local function stderr_write(text)
  local err = rawget(io, "stderr")
  if err then
    err:write(text)
  else
    io.write(text)
  end
end

local function check_tracing(v, level)
  if v == nil or LEVELS[v] then
    return
  end
  if type(v) ~= "table" then
    misuse(
      'tracing must be "off", "operation", "debug" or { level, file, max_bytes, exporter }',
      level + 1
    )
  end
  for k in pairs(v) do
    if k ~= "level" and k ~= "file" and k ~= "max_bytes" and k ~= "exporter" then
      misuse(
        "unknown tracing field " .. tostring(k) .. " (valid: exporter, file, level, max_bytes)",
        level + 1
      )
    end
  end
  if v.level ~= nil and not LEVELS[v.level] then
    misuse('tracing.level must be "off", "operation" or "debug"', level + 1)
  end
end

-- the tracer for an option value; distilled.trace is required only when tracing is on
local function make_tracer(opts, host, service)
  if opts.tracer ~= nil then
    return opts.tracer
  end
  local t = opts.tracing
  local level = type(t) == "table" and (t.level or "operation") or t
  if level == nil or level == "off" then
    return noop
  end
  local trace = require("distilled.trace")
  local list = {}
  if type(t) == "table" then
    local e = t.exporter
    if hostlib.callable(e) then
      list[#list + 1] = e
    elseif type(e) == "table" then
      for i = 1, #e do
        list[#list + 1] = e[i]
      end
    end
    if t.file then
      list[#list + 1] = trace.exporters.file({ path = t.file, max_bytes = t.max_bytes })
    end
  end
  if #list == 0 then
    list[1] = trace.exporters.console({ write = stderr_write })
  end
  return trace.new({
    level = level,
    exporter = list,
    host = host,
    service_name = service.name,
    parent = opts.trace_parent or host.getenv("TRACEPARENT"),
  })
end

---------------------------------------------------------------------------------------
-- option checking
---------------------------------------------------------------------------------------

local function check_options(class, opts, level)
  level = level + 1
  if type(opts) ~= "table" then
    misuse(class.name .. ".new: expected a table of options", level)
  end
  for k, v in pairs(opts) do
    if not COMMON[k] and not class.option_specs[k] then
      misuse(
        class.name
          .. ": unknown option "
          .. tostring(k)
          .. " (valid: "
          .. table.concat(class.valid_names, ", ")
          .. ")",
        level
      )
    end
    local spec = class.option_specs[k]
    if spec then
      if spec.secret then
        if not credentials.is_source(v) then
          misuse(
            class.name .. ": option " .. k .. " must be a string, a secret or a function",
            level
          )
        end
      elseif spec.type and type(v) ~= spec.type then
        misuse(
          class.name .. ": option " .. k .. " must be a " .. spec.type .. ", got " .. type(v),
          level
        )
      end
    end
  end
  if opts.host ~= nil and type(opts.host) ~= "table" then
    local hint = ""
    if hostlib.callable(opts.host) then
      -- distilled.host.popen and distilled.host.rex are functions that build a host
      hint = ' (got a function: call it, e.g. host = require("distilled.host.popen")())'
    end
    misuse(class.name .. ": host must be a table" .. hint, level)
  end
  for _, k in ipairs(hostlib.FIELDS) do
    hostlib.check(opts[k], k, level)
    if type(opts.host) == "table" then
      hostlib.check(opts.host[k], "host." .. k, level)
    end
  end
  retry.check_spec(opts.retry, level)
  for _, k in ipairs({ "deadline_s", "server_hint_cap_s" }) do
    if opts[k] ~= nil and (type(opts[k]) ~= "number" or opts[k] ~= opts[k] or opts[k] < 0) then
      misuse(class.name .. ": " .. k .. " must be a non-negative number of seconds", level)
    end
  end
  check_tracing(opts.tracing, level)
  if
    opts.tracer ~= nil and (type(opts.tracer) ~= "table" or type(opts.tracer.with) ~= "function")
  then
    misuse(class.name .. ": tracer must be a tracer (distilled.trace.new{...})", level)
  end
  if opts.validation ~= nil and not VALIDATION[opts.validation] then
    misuse(class.name .. ': validation must be "lenient", "additional" or "strict"', level)
  end
  if opts.budget ~= nil and not retry.is_budget(opts.budget) then
    misuse(class.name .. ": budget must be retry.new_budget{...}", level)
  end
  if opts.trace_parent ~= nil and type(opts.trace_parent) ~= "string" then
    misuse(class.name .. ": trace_parent must be a traceparent string", level)
  end
  if opts.user_agent ~= nil and type(opts.user_agent) ~= "string" then
    misuse(class.name .. ": user_agent must be a string", level)
  end
end

---------------------------------------------------------------------------------------
-- instances
---------------------------------------------------------------------------------------

-- build a client from checked options; `shared` carries what a parent passes on
local function build(class, opts, shared)
  shared = shared or {}
  local service = class.service
  local host = hostlib.merge(opts.host, opts)

  -- credentials: one cell per secret option, shared with derived clients unless the
  -- derived client overrides that option
  local cells = {}
  for name, spec in pairs(class.option_specs) do
    if spec.secret then
      local inherited = shared.cells and shared.cells[name]
      if inherited and not (shared.overrides and shared.overrides[name] ~= nil) then
        cells[name] = inherited
      else
        local source = opts[name]
        local fallback = false
        if source == nil and spec.env then
          -- a function source, so a rotated key is picked up on refresh
          source = credentials.from_env(spec.env)
          fallback = true
        end
        if source == nil and spec.default ~= nil then
          source = spec.default
        end
        cells[name] = credentials.cell(source)
        cells[name].env_fallback = fallback
      end
    end
  end

  local function resolve_credentials()
    local creds = {}
    for name, spec in pairs(class.option_specs) do
      local value
      if spec.secret then
        local cell = cells[name]
        if cell.source ~= nil then
          local v, err = credentials.get(cell, host, name)
          if v == nil then
            -- an unset env fallback is an absent option: required -> the error below
            if not (cell.env_fallback and errors.is_tag(err, "ConfigError")) then
              return nil, err
            end
          end
          value = v
        end
      else
        value = opts[name]
        if value == nil and spec.env then
          local e = host.getenv(spec.env)
          if e ~= nil and e ~= "" then
            value = e
          end
        end
        if value == nil then
          value = spec.default
        end
      end
      if value == nil and spec.required then
        local hint = spec.env and (" or set " .. spec.env) or ""
        return nil,
          errors.new("ConfigError", {
            message = class.name
              .. ": option "
              .. name
              .. " is required: pass "
              .. name
              .. " = ..."
              .. hint,
            key = name,
          })
      end
      creds[name] = value
    end
    return creds
  end

  local function refresh_credentials()
    local any = false
    for _, cell in pairs(cells) do
      if credentials.clear(cell) then
        any = true
      end
    end
    return any
  end

  -- retry policies, resolved once per operation
  local retry_spec = opts.retry
  if opts.deadline_s ~= nil or opts.server_hint_cap_s ~= nil then
    local merged = {}
    if type(retry_spec) == "table" and not retry.is_preset(retry_spec) then
      for k, v in pairs(retry_spec) do
        merged[k] = v
      end
    elseif retry_spec ~= nil then
      merged.preset = retry_spec
    end
    merged.deadline_s = merged.deadline_s or opts.deadline_s
    merged.server_hint_cap_s = merged.server_hint_cap_s or opts.server_hint_cap_s
    retry_spec = merged
  end
  local budget = opts.budget or shared.budget or retry.default_budget
  local policies = {}
  local function policy_for(name, op)
    local cached = policies[name]
    if cached then
      return cached[1], cached[2]
    end
    local policy, settings = retry.policy_for(retry_spec, op.retry)
    if policy.budget ~= nil then
      policy.budget = budget
    end
    policies[name] = { policy, settings }
    return policy, settings
  end

  local trace_holder = shared.trace
  if trace_holder == nil then
    trace_holder = { tracer = make_tracer(opts, host, service), depth = 0 }
  end

  local state = {
    class = class,
    service = service,
    protocol = class.protocol,
    opts = opts,
    host = host,
    cells = cells,
    budget = budget,
    trace = trace_holder,
    scope = shared.scope or Scope.new(),
    info_for = class.info_for,
    policy_for = policy_for,
    refresh_credentials = refresh_credentials,
    ctx = {
      service = service,
      credentials = resolve_credentials,
      host = host,
      tracer = trace_holder.tracer,
      validation = opts.validation or "lenient",
      user_agent = opts.user_agent,
    },
  }
  return setmetatable({ _state = state }, class.mt)
end

---------------------------------------------------------------------------------------
-- Client.define
---------------------------------------------------------------------------------------

--- Client.define{ service, protocol, options, name } -> Class
function Client.define(spec)
  if type(spec) ~= "table" then
    misuse("Client.define: expected { service, protocol, options }", 2)
  end
  local service, protocol = spec.service, spec.protocol
  if type(service) ~= "table" or type(service.ops) ~= "table" then
    misuse("Client.define: service must be a service descriptor with ops", 2)
  end
  if type(protocol) ~= "table" or type(protocol.call) ~= "function" then
    misuse("Client.define: protocol must have a call(ctx, op, input) function", 2)
  end
  local class_name = spec.name or service.name or "client"
  local option_specs = {}
  for name, o in pairs(spec.options or {}) do
    if COMMON[name] then
      misuse(
        "Client.define: option " .. name .. " is a common client option and cannot be redefined",
        2
      )
    end
    if type(o) ~= "table" then
      misuse("Client.define: option " .. tostring(name) .. " must be a table", 2)
    end
    for k in pairs(o) do
      if not OPTION_SPEC_FIELDS[k] then
        misuse("Client.define: option " .. name .. " has an unknown field " .. tostring(k), 2)
      end
    end
    if o.type ~= nil and not OPTION_TYPES[o.type] then
      misuse("Client.define: option " .. name .. " has an unknown type " .. tostring(o.type), 2)
    end
    option_specs[name] = o
  end
  local valid = {}
  for k in pairs(COMMON) do
    valid[k] = true
  end
  for k in pairs(option_specs) do
    valid[k] = true
  end

  local class = {
    name = class_name,
    service = service,
    protocol = protocol,
    option_specs = option_specs,
    valid_names = sorted(valid),
    methods = {},
  }

  -- span facts, built once per operation on the first traced call
  local infos = {}
  function class.info_for(name, op)
    local info = infos[name]
    if info == nil then
      info = operation.info(service, op)
      infos[name] = info
    end
    return info
  end

  local mt = { __index = class.methods }
  mt.__tostring = function()
    return class_name .. " client"
  end
  class.mt = mt

  local function check_self(self, method)
    if getmetatable(self) ~= mt then
      compat.raise(
        class_name
          .. ": call client:"
          .. method
          .. "(...) with a colon, not client."
          .. method
          .. "(...)",
        3
      )
    end
  end

  local methods = class.methods
  local function add(name, fn)
    if RESERVED_METHODS[name] or methods[name] then
      misuse("Client.define: operation method " .. name .. " collides with another method", 3)
    end
    methods[name] = fn
  end

  for _, name in ipairs(sorted(service.ops)) do
    local op = service.ops[name]
    add(name, function(self, input)
      check_self(self, name)
      return operation.call(self._state, name, input)
    end)
  end
  for _, name in ipairs(sorted(service.ops)) do
    local op = service.ops[name]
    if op.pagination then
      local trait = op.pagination
      -- op.pagination_methods renames a sibling that would take a real operation's name
      -- (the generator's naming.operation_names: Exa's list_websets_all_items)
      local renamed = op.pagination_methods or {}
      local function iterate(kind)
        local method = renamed[kind] or (name .. "_" .. kind)
        return function(self, input)
          check_self(self, method)
          local state = self._state
          local holder = state.trace
          local info = class.info_for(name, op)
          local function page(page_input)
            return operation.call(state, name, page_input)
          end
          return paginate[kind](page, input, trait, {
            tracer = holder.tracer,
            name = info.name,
            attributes = { ["rpc.method"] = info.attributes["rpc.method"] },
            on_finish = function()
              if holder.depth == 0 then
                holder.tracer:flush()
              end
            end,
          })
        end
      end
      add(renamed.pages or (name .. "_pages"), iterate("pages"))
      add(renamed.items or (name .. "_items"), iterate("items"))
    end
  end

  -- `<op>_stream` for every operation with op.stream (task 29): stream | nil, err
  for _, name in ipairs(sorted(service.ops)) do
    local op = service.ops[name]
    if type(op.stream) == "table" then
      local method = op.stream.method or (name .. "_stream")
      add(method, function(self, input, opts)
        check_self(self, method)
        return operation.stream(self._state, name, input, opts)
      end)
    end
  end

  --- client:with{ ... } -> a derived client. Options are a shallow override of this
  -- client's; the budget, the credentials cache (for options not overridden) and the
  -- tracer (unless tracing/tracer is overridden) are shared.
  methods.with = function(self, overrides)
    check_self(self, "with")
    overrides = overrides or {}
    check_options(class, overrides, 2)
    local state = self._state
    local merged = {}
    for k, v in pairs(state.opts) do
      merged[k] = v
    end
    for k, v in pairs(overrides) do
      merged[k] = v
    end
    local shared = {
      cells = state.cells,
      overrides = overrides,
      budget = overrides.budget or state.budget,
      scope = state.scope,
    }
    if overrides.tracing == nil and overrides.tracer == nil and overrides.trace_parent == nil then
      shared.trace = state.trace
    end
    return build(class, merged, shared)
  end

  --- client:close() -> true | nil, err: exports buffered spans and closes the client's
  -- scope. Calls still work afterwards (a derived client shares the tracer).
  methods.close = function(self)
    check_self(self, "close")
    local state = self._state
    local ok, err = state.trace.tracer:flush()
    local closed, errs = state.scope:close()
    if not ok then
      return nil, err
    end
    if not closed then
      return nil, errs[1]
    end
    return true
  end

  --- Class.new{ ... } -> client
  function class.new(opts)
    if opts == nil then
      opts = {}
    end
    check_options(class, opts, 2)
    local copy = {}
    for k, v in pairs(opts) do
      copy[k] = v
    end
    return build(class, copy, nil)
  end

  function class.is(v)
    return getmetatable(v) == mt
  end

  return class
end

return Client
