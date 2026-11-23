-- request.build: an operation and an input -> the HTTP request to send. Pure: no
-- network, no clock. Replaces Distilled's `buildRequest` (protocol-http.ts).
--
--   request.build{ op = op, input = t, registry = shapes, base_url = "https://...",
--                  headers = { ... },                   -- applied first (auth etc.)
--                  map_member_header = fn(name, value) -> value,   -- optional
--                  unknown_key_to_wire = fn(key) -> wire,          -- optional
--                  empty_json_body = false,                        -- optional
--                  query_style = "dotted" | "brackets",            -- optional
--                  random = fn() -> [0, 1), host = { random } }  -- multipart boundary
--     -> { method, url, headers, body = string | nil } | nil, err (InvalidInput, SdkError)
--
-- What it does, in Distilled's order and with its reasons:
-- 1. Secrets anywhere in the input (and in `headers`) are unwrapped here, at the last
--    moment, on a copy (secret.unwrap_deep); the caller's tables are not changed.
-- 2. Labels are checked before anything else: `.` and `..` (for a greedy `{name+}`
--    label, any segment) fail with InvalidInput, because the URL parser resolves them
--    and `DELETE /things/..` would go out as `DELETE /`. A missing label also fails
--    (Distilled leaves `{name}` in the path; here there is no type checker to stop it).
-- 3. Labels are percent-encoded like encodeURIComponent; greedy labels per segment.
-- 4. Query: scalars `k=v`, lists repeat the key, nested tables go dotted (`name.exact=v`;
--    sending `[object Object]` used to "succeed" with zero results). `style = "comma"`
--    joins a list into one parameter; `style = "deep"` expands a struct member into
--    `name.key=v` after renaming, skipping nulls. `query_style = "brackets"` spells
--    nested values `a[b]=1` and lists `a[0]=x` (Stripe).
-- 5. Headers: lowercased names, String(value). A value holding CR or LF is refused
--    (InvalidInput), so a member cannot inject a header.
-- 6. Body members go out under their wire names (keys.encode); `string_encoded` members
--    as their string spelling. Input keys the schema does not declare pass through as
--    body fields (generated schemas lag real APIs; dropping them would break callers).
-- 7. A `payload` member is the whole body: JSON, or the string itself when its schema is
--    `blob` or the operation declares `body_media_type`.
-- 8. Body rules: a bodied method other than DELETE sends `{}` when body members are
--    declared but unset (some endpoints reject a missing body); GET and HEAD send a body
--    only when body members carry values (some APIs document GET with a body).
-- 9. content-type is set for JSON and form bodies; a member bound to the content-type
--    header wins (a Kubernetes merge patch is application/merge-patch+json).
-- 10. json.null in the input is sent as null; an absent key is omitted.
-- 11. `content_type = "multipart"`: the body is multipart/form-data (see
--    multipart_parts below and distilled/multipart.lua), whatever the method, as in
--    Distilled. The boundary comes from `random` (or `host.random`).
-- 12. `op.accept` (smithy.api#http accept, MongoDB Atlas's versioned media types) is the
--    Accept header, over the protocol's headers; a member bound to Accept still wins.
-- 13. `op.unsupported` (a runtime gap the provider spec acknowledged, e.g. "streaming")
--    fails every call with SdkError before anything is built.
-- 14. A path placeholder no label member fills (the model lost the member: proxmox
--    `{url_seq}`) is filled from the input key of that name, checked and encoded like a
--    label, and that key is not sent in the body. Without it the call fails with
--    InvalidInput (Distilled sends the placeholder as is).
local schema = require("distilled.schema")
local json = require("distilled.json")
local secret = require("distilled.secret")
local errors = require("distilled.errors")
local keys = require("distilled.keys")
local url = require("distilled.url")
local compat = require("distilled.compat")
local multipart = require("distilled.multipart")

local request = {}

local null = json.null
local BODYLESS = { GET = true, HEAD = true }
-- One shared node for operations without an input: plans are cached per node, and
-- gopher-lua never collects weak tables, so no per-call nodes.
local EMPTY_INPUT = schema.struct({ name = "Empty", members = {} })

local function invalid(member, message)
  return errors.new("InvalidInput", { member = member, message = message })
end

local function sdk_error(op, message)
  return errors.new("SdkError", { message = "operation " .. tostring(op.name) .. ": " .. message })
end

-- Distilled's invalidLabel: a value whose segment is "." or ".." would address another
-- resource, percent-encoded or not, so no encoding can carry it.
local function invalid_label(member, text, greedy)
  local bad = false
  if greedy then
    for segment in string.gmatch(text .. "/", "([^/]*)/") do
      if segment == "." or segment == ".." then
        bad = true
        break
      end
    end
  else
    bad = text == "." or text == ".."
  end
  if bad then
    return invalid(
      member,
      "Input member "
        .. member
        .. " cannot be "
        .. string.format("%q", text)
        .. ": as a path label it would address another resource"
    )
  end
  return nil
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
    return a < b
  end)
  return list
end

-- appendQuery: lists repeat the name, nested tables go dotted, scalars String(v).
-- Explicit stack, pushed in reverse so pairs come out in order. Table keys in sorted
-- order (Lua tables have no insertion order).
local function append_query(q, name, value)
  local stack, n = { { name, value } }, 1
  while n > 0 do
    local item = stack[n]
    stack[n] = nil
    n = n - 1
    local k, v = item[1], item[2]
    if schema.is_array_value(v) then
      for i = #v, 1, -1 do
        n = n + 1
        stack[n] = { k, v[i] }
      end
    elseif schema.is_container(v) then
      local ks = sorted_keys(v)
      for i = #ks, 1, -1 do
        local sub = rawget(v, ks[i])
        if sub ~= nil then
          n = n + 1
          stack[n] = { k .. "." .. tostring(ks[i]), sub }
        end
      end
    elseif v ~= nil then
      q:add(k, url.text(v))
    end
  end
end

-- flattenToFormPairs: nested tables become a[b][c], lists index as a[0] (0-based, as in
-- JavaScript); null and absent entries are dropped. `order` lists the top-level keys.
local function form_pairs(q, obj, order)
  -- items: { "obj", table, prefix, order } | { "pair", key, value }
  local stack, n = { { "obj", obj, nil, order } }, 1
  while n > 0 do
    local item = stack[n]
    stack[n] = nil
    n = n - 1
    if item[1] == "pair" then
      q:add(item[2], item[3])
    else
      local t, prefix = item[2], item[3]
      local ks = item[4] or sorted_keys(t)
      local expanded = {}
      for _, key in ipairs(ks) do
        local value = rawget(t, key)
        if value ~= nil and value ~= null then
          local full = prefix and (prefix .. "[" .. tostring(key) .. "]") or tostring(key)
          if schema.is_array_value(value) then
            for i = 1, #value do
              local entry = value[i]
              if entry ~= nil and entry ~= null then
                local indexed = full .. "[" .. tostring(i - 1) .. "]"
                if schema.is_record_value(entry) then
                  expanded[#expanded + 1] = { "obj", entry, indexed }
                else
                  expanded[#expanded + 1] = { "pair", indexed, url.text(entry) }
                end
              end
            end
          elseif schema.is_container(value) then
            expanded[#expanded + 1] = { "obj", value, full }
          else
            expanded[#expanded + 1] = { "pair", full, url.text(value) }
          end
        end
      end
      for i = #expanded, 1, -1 do
        n = n + 1
        stack[n] = expanded[i]
      end
    end
  end
end

local function check_header_value(member, value)
  if string.find(value, "[\r\n]") then
    return invalid(
      member,
      "Input member " .. member .. " cannot hold a line break: it is sent as a header"
    )
  end
  return nil
end

local function misuse(message)
  compat.raise("request.build: " .. message, 3)
end

-- Multipart parts, Distilled's rules (protocol-http.ts, multipart branch of buildRequest):
-- - each body member is a part under its wire name, in declaration order (undeclared
--   keys after, sorted); a payload member holding a record is the parts instead, one per
--   entry, in sorted key order (JavaScript keeps insertion order; a Lua table has none);
-- - a payload member holding one file (or a string at a `blob` payload) is one file part
--   under the member's wire name;
-- - json.null and absent members are omitted;
-- - binary values are file parts: a distilled.file with its own filename (the wire name
--   when it has none, as for a nameless Blob) and content type, or a string at a `blob`
--   node (Distilled's Uint8Array: filename = wire name, application/octet-stream);
-- - a non-empty list whose elements are all binary is one part per element under the
--   same name (`-F documents=@a.pdf -F documents=@b.txt`);
-- - any other table is one JSON-encoded part (an empty list is "[]"), scalars are text
--   parts spelled like String(v).
-- Distilled's `FormDataFile()` binding (files under their own filename) has no Smithy
-- trait in the models, so there is no such bind here.
local function multipart_parts(op, body, body_order, body_nodes, raw_body, raw_member, registry)
  local entries, nodes = body, body_nodes
  local order = body_order
  local raw_node = raw_member and schema.resolve(raw_member.schema, registry)
  if
    raw_body ~= nil
    and (
      multipart.is_file(raw_body)
      or (type(raw_body) == "string" and raw_node and raw_node.t == "blob")
    )
  then
    -- a payload that is one file is one part under the member's wire name (Distilled
    -- would spread a Uint8Array payload into one text part per byte index)
    local wire = raw_member.wire or raw_member.name
    entries, order, nodes = { [wire] = raw_body }, { wire }, { [wire] = raw_member.schema }
  elseif raw_body ~= nil and schema.is_record_value(raw_body) then
    entries, order, nodes = raw_body, sorted_keys(raw_body), {}
    local pnode = raw_node
    for _, k in ipairs(order) do
      if pnode and pnode.t == "map" then
        nodes[k] = pnode.value
      elseif pnode and pnode.t == "struct" then
        for _, pm in ipairs(pnode.members or {}) do
          if (pm.wire or pm.name) == k then
            nodes[k] = pm.schema
          end
        end
      end
    end
  end

  local function is_blob(node)
    local r = node and schema.resolve(node, registry)
    return r ~= nil and r.t == "blob"
  end
  local function binary(v, blob)
    return multipart.is_file(v) or (blob and type(v) == "string")
  end

  local parts = {}
  local function add_binary(key, v)
    if multipart.is_file(v) then
      if type(v.data) ~= "string" then
        return invalid(key, "Input member " .. key .. ": a file's data must be a string")
      end
      parts[#parts + 1] =
        { name = key, value = v.data, filename = v.filename or key, content_type = v.content_type }
    else
      parts[#parts + 1] = { name = key, value = v, filename = key }
    end
    return nil
  end

  for _, key in ipairs(order) do
    local value = rawget(entries, key)
    local node = nodes[key]
    if value ~= nil and value ~= null then
      local name = tostring(key)
      if binary(value, is_blob(node)) then
        local bad = add_binary(name, value)
        if bad then
          return nil, bad
        end
      else
        local item_blob = false
        local r = node and schema.resolve(node, registry)
        if r and r.t == "list" then
          item_blob = is_blob(r.item)
        end
        local all_binary = schema.is_array_value(value) and #value > 0
        if all_binary then
          for i = 1, #value do
            if not binary(value[i], item_blob) then
              all_binary = false
              break
            end
          end
        end
        if all_binary then
          for i = 1, #value do
            local bad = add_binary(name, value[i])
            if bad then
              return nil, bad
            end
          end
        elseif type(value) == "table" then
          local text, err = json.encode(value)
          if not text then
            return nil,
              invalid(
                nil,
                "cannot encode the multipart part "
                  .. name
                  .. " of "
                  .. tostring(op.name)
                  .. ": "
                  .. tostring(err.message)
              )
          end
          parts[#parts + 1] = { name = name, value = text }
        else
          parts[#parts + 1] = { name = name, value = url.text(value) }
        end
      end
    end
  end
  return parts
end

--- request.build(args) -> request | nil, err
function request.build(args)
  if type(args) ~= "table" then
    misuse("expected a table of arguments")
  end
  local op = args.op
  if type(op) ~= "table" or type(op.method) ~= "string" or type(op.uri) ~= "string" then
    misuse("op must be an operation descriptor with method and uri")
  end
  local base_url = args.base_url or ""
  if type(base_url) ~= "string" then
    misuse("base_url must be a string")
  end
  if op.unsupported ~= nil then
    return nil,
      sdk_error(
        op,
        "distilled-lua cannot perform "
          .. tostring(op.unsupported)
          .. " operations yet (the client has it for completeness; the provider spec's"
          .. " allow_unsupported emitted it)"
      )
  end
  local registry = args.registry

  -- the plan (Distilled fails here when the Http trait is missing)
  local node = EMPTY_INPUT
  if op.input ~= nil then
    local resolved, err = schema.resolve(op.input, registry)
    if not resolved then
      return nil, sdk_error(op, err.message)
    end
    node = resolved
  end
  if node.t ~= "struct" then
    return nil, sdk_error(op, "input schema must be a struct, got " .. tostring(node.t))
  end
  local plan = schema.plan(node)

  local input = args.input
  if input == nil then
    input = {}
  elseif type(input) ~= "table" or input == null or json.is_array(input) then
    return nil, invalid(nil, "the input of " .. tostring(op.name) .. " must be a table")
  end
  -- secrets unwrapped on a copy; json.null kept; a cycle stays a cycle (json.encode reports it)
  input = secret.unwrap_deep(input)

  -- labels first, before anything else is read
  local uri = op.uri
  for _, m in ipairs(plan.by_bind.label) do
    local value = rawget(input, m.name)
    if value == nil then
      return nil,
        invalid(m.name, "Input member " .. m.name .. " is required: it fills the path " .. op.uri)
    end
    local text = url.text(value)
    local wire = m.wire or m.name
    local greedy = m.greedy == true or string.find(uri, "{" .. wire .. "+}", 1, true) ~= nil
    local refused = invalid_label(m.name, text, greedy)
    if refused then
      return nil, refused
    end
    if greedy then
      uri = url.fill(uri, wire, url.encode_greedy_label(text), true)
    else
      uri = url.fill(uri, wire, url.encode_component(text), false)
    end
  end
  -- placeholders left in the path have no label member (14 above)
  local path_keys = {}
  for _, p in ipairs(url.placeholders(string.match(uri, "^[^?]*"))) do
    local value = rawget(input, p.name)
    if value == nil then
      return nil,
        invalid(
          p.name,
          "the path "
            .. op.uri
            .. " has a {"
            .. p.name
            .. "} that no input member fills; pass it as input."
            .. p.name
        )
    end
    local text = url.text(value)
    local refused = invalid_label(p.name, text, p.greedy)
    if refused then
      return nil, refused
    end
    local encoded = p.greedy and url.encode_greedy_label(text) or url.encode_component(text)
    uri = url.fill(uri, p.name, encoded, p.greedy)
    path_keys[p.name] = true
  end

  local headers = {}
  for name, value in pairs(args.headers or {}) do
    headers[string.lower(name)] = url.text(secret.unwrap(value))
  end
  if op.accept ~= nil then
    headers["accept"] = op.accept
  end
  local member_content_type
  local map_member_header = args.map_member_header
  local query = url.query()
  local body, body_order, body_keys = {}, {}, 0
  local body_nodes = {} -- wire name -> member schema (multipart: which strings are bytes)
  local has_body_members = plan.has_body_members
  local raw_body, raw_member

  for _, m in ipairs(plan.members) do
    local value = rawget(input, m.name)
    local bind = m.bind or "body"
    local wire = m.wire or m.name
    if value ~= nil and bind ~= "label" and bind ~= "status" then
      if bind == "header" then
        local name = string.lower(wire)
        local text = url.text(value)
        if map_member_header then
          text = map_member_header(name, text)
        end
        local refused = check_header_value(m.name, text)
        if refused then
          return nil, refused
        end
        headers[name] = text
        if name == "content-type" then
          member_content_type = text
        end
      elseif bind == "query" then
        if m.style == "comma" and schema.is_list_value(value) then
          local parts = {}
          for i = 1, #value do
            parts[i] = url.text(value[i])
          end
          query:add(wire, compat.concat(parts, ","))
        elseif m.style == "deep" then
          local mapped = keys.encode(m.schema, value, registry)
          if schema.is_container(mapped) then
            local ks = sorted_keys(mapped)
            for _, k in ipairs(ks) do
              local v = rawget(mapped, k)
              if v ~= nil and v ~= null then
                append_query(query, wire .. "." .. tostring(k), v)
              end
            end
          end
        elseif args.query_style == "brackets" then
          form_pairs(query, { [wire] = value }, { wire })
        else
          append_query(query, wire, value)
        end
      elseif bind == "payload" then
        raw_body = keys.encode(m.schema, value, registry)
        raw_member = m
      else
        if body[wire] == nil then
          body_order[#body_order + 1] = wire
        end
        body_nodes[wire] = m.schema
        if m.string_encoded then
          body[wire] = keys.string_encode(value)
        else
          body[wire] = keys.encode(m.schema, value, registry)
        end
        body_keys = body_keys + 1
      end
    end
  end

  -- undeclared input keys pass through as body fields
  local unknown_key_to_wire = args.unknown_key_to_wire
  for _, key in ipairs(sorted_keys(input)) do
    if not plan.known[key] and not path_keys[key] then
      if type(key) ~= "string" then
        return nil,
          invalid(
            nil,
            "the input of " .. tostring(op.name) .. " has a non-string key " .. tostring(key)
          )
      end
      local wire = unknown_key_to_wire and unknown_key_to_wire(key) or key
      if body[wire] == nil then
        body_order[#body_order + 1] = wire
      end
      body[wire] = rawget(input, key)
      body_keys = body_keys + 1
      has_body_members = true
    end
  end

  local target = base_url .. uri
  if not query:empty() then
    target = target .. "?" .. query:encode()
  end
  local method = string.upper(op.method)
  local bodied = not BODYLESS[method]
  local out = { method = method, url = target, headers = headers }

  local function encode_json(value)
    local text, err = json.encode(value)
    if not text then
      return nil,
        invalid(
          nil,
          "cannot encode the request body of " .. tostring(op.name) .. ": " .. tostring(err.message)
        )
    end
    return text
  end

  if op.content_type == "multipart" then
    local parts, perr =
      multipart_parts(op, body, body_order, body_nodes, raw_body, raw_member, registry)
    if not parts then
      return nil, perr
    end
    local random = args.random or (type(args.host) == "table" and args.host.random) or nil
    local encoded, eerr = multipart.encode(parts, { random = random })
    if not encoded then
      return nil, eerr
    end
    out.body = encoded.body
    headers["content-type"] = encoded.content_type
    return out
  end

  if op.content_type == "form-urlencoded" and bodied then
    local form = url.query()
    if raw_body ~= nil and schema.is_record_value(raw_body) then
      form_pairs(form, raw_body, nil)
    else
      form_pairs(form, body, body_order)
    end
    out.body = form:encode()
    headers["content-type"] = "application/x-www-form-urlencoded"
    return out
  end

  if raw_body ~= nil and bodied then
    local media = member_content_type or op.body_media_type
    local raw_node = schema.resolve(raw_member.schema, registry)
    local is_blob = raw_node ~= nil and raw_node.t == "blob"
    if type(raw_body) == "string" and (is_blob or op.body_media_type ~= nil) then
      out.body = raw_body
      headers["content-type"] = media or "application/octet-stream"
      return out
    end
    local text, err = encode_json(raw_body)
    if not text then
      return nil, err
    end
    out.body = text
    headers["content-type"] = media or "application/json"
    return out
  end

  if
    body_keys > 0
    or ((has_body_members or args.empty_json_body == true) and bodied and method ~= "DELETE")
  then
    local text, err = encode_json(json.object(body))
    if not text then
      return nil, err
    end
    out.body = text
    headers["content-type"] = member_content_type or "application/json"
  end
  return out
end

return request
