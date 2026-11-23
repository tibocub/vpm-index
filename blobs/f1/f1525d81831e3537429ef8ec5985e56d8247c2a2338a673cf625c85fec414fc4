-- The AWS restXml protocol (Route 53, CloudFront, S3 Control; S3 itself is task 25's).
--
-- Port of Distilled's packages/s3/src/protocols/rest-xml.ts: HTTP bindings as restJson1
-- (aws/http.lua), XML bodies with xmlName / xmlFlattened / xmlAttribute / xmlNamespace,
-- errors as <ErrorResponse><Error> or <Error>, an empty error body named after its
-- status, and S3's HTML error pages. Same interface as aws/json_protocols.lua.
local codec = require("distilled.aws.codec")
-- compat.concat: gopher-lua's table.concat fails past ~2,500 items (a long list)
local compat = require("distilled.compat")
local http = require("distilled.aws.http")
local json = require("distilled.json")
local url = require("distilled.url")
local xml = require("distilled.xml")

local M = { name = "restXml" }

local escape = xml.escape
local null = json.null

local function resolve(node, registry)
  return codec.resolve(node, registry)
end

local function sorted_keys(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  return keys
end

-- ` xmlns="uri"` or ` xmlns:prefix="uri"`
local function ns_attribute(ns)
  if type(ns) ~= "table" or ns.uri == nil then
    return ""
  end
  return " xmlns" .. (ns.prefix and (":" .. ns.prefix) or "") .. '="' .. escape(ns.uri) .. '"'
end

local function element(tag, content, ns)
  return "<" .. tag .. (ns or "") .. ">" .. content .. "</" .. tag .. ">"
end

-- the element name of a structure used as a document root: its xmlName, else its name
local function root_name(node, fallback)
  return node and (node.xml_name or node.name) or fallback
end

local serialize_value, serialize_object, serialize_map

local function scalar_text(v)
  return escape(url.text(v))
end

serialize_value = function(node, value, tag, ns, registry, depth)
  if value == nil or value == null or depth > codec.MAX_DEPTH then
    return ""
  end
  node = resolve(node, registry)
  if type(value) ~= "table" then
    local content = scalar_text(value)
    return tag and element(tag, content, ns) or content
  end
  if node and node.t == "map" and tag then
    return serialize_map(node, value, tag, false, ns, registry, depth)
  end
  if node and node.t == "list" then
    local item_node = resolve(node.item, registry)
    if tag then
      local item_tag = node.item_xml_name or (item_node and item_node.xml_name) or "member"
      local item_ns = ns_attribute(node.item_xmlns)
      local parts = {}
      for i = 1, #value do
        parts[i] = serialize_value(node.item, value[i], item_tag, item_ns, registry, depth + 1)
      end
      return element(tag, compat.concat(parts), ns)
    end
    local parts = {}
    for i = 1, #value do
      parts[i] = serialize_value(
        node.item,
        value[i],
        item_node and item_node.name,
        i == 1 and ns or "",
        registry,
        depth + 1
      )
    end
    return compat.concat(parts)
  end
  return serialize_object(node, value, tag, ns, registry, depth)
end

serialize_object = function(node, value, tag, ns, registry, depth)
  local attrs, elems = {}, {}
  for _, m in ipairs(node and node.members or {}) do
    local v = value[m.name]
    if v ~= nil and v ~= null then
      local name = m.xml_name or m.name
      if m.attr then
        attrs[#attrs + 1] = name .. '="' .. escape(url.text(v)) .. '"'
      else
        local mns = ns_attribute(m.xmlns)
        local target = resolve(m.schema, registry)
        if target and target.t == "map" then
          elems[#elems + 1] = serialize_map(target, v, name, m.flat, mns, registry, depth + 1)
        elseif type(v) ~= "table" or not (target and target.t == "list") then
          elems[#elems + 1] = serialize_value(m.schema, v, name, mns, registry, depth + 1)
        elseif m.flat then
          local parts = {}
          for i = 1, #v do
            parts[i] = serialize_value(target.item, v[i], name, mns, registry, depth + 1)
          end
          elems[#elems + 1] = compat.concat(parts)
        else
          elems[#elems + 1] = serialize_value(m.schema, v, name, mns, registry, depth + 1)
        end
      end
    end
  end
  if not tag then
    return compat.concat(elems)
  end
  local attr_text = (ns or "") .. (#attrs > 0 and (" " .. compat.concat(attrs, " ")) or "")
  return "<" .. tag .. attr_text .. ">" .. compat.concat(elems) .. "</" .. tag .. ">"
end

serialize_map = function(node, value, tag, flattened, ns, registry, depth)
  local key_tag = node.key_name or "key"
  local value_tag = node.value_name or "value"
  local key_ns = ns_attribute(node.key_xmlns)
  local value_ns = ns_attribute(node.value_xmlns)
  local entries = {}
  for _, k in ipairs(sorted_keys(value)) do
    local v = value[k]
    if v ~= nil then
      entries[#entries + 1] = element(key_tag, escape(k), key_ns)
        .. serialize_value(node.value, v, value_tag, value_ns, registry, depth + 1)
    end
  end
  if flattened then
    local out = {}
    for i, e in ipairs(entries) do
      out[i] = element(tag, e, ns)
    end
    return compat.concat(out)
  end
  local wrapped = {}
  for i, e in ipairs(entries) do
    wrapped[i] = "<entry>" .. e .. "</entry>"
  end
  return element(tag, compat.concat(wrapped), ns)
end

-- The namespace of a document root: its shape's, or the service's.
local function root_ns(node, service_ns)
  if node and node.xmlns then
    return ns_attribute(node.xmlns)
  end
  if service_ns then
    return ns_attribute({ uri = service_ns })
  end
  return ""
end

function M.encode(p, op, input)
  local registry = p.registry
  local node = resolve(op.input, registry)
  local parts, err = http.bind_input(op, node, input, p.env)
  if not parts then
    return nil, err
  end
  local request = parts.request
  local headers = request.headers
  local pm, pv = parts.payload_member, parts.payload_value
  local input_ns = root_ns(node, p.aws.xmlns)
  if pm ~= nil and pv ~= nil then
    local target = resolve(pm.schema, registry)
    local t = target and target.t
    if target and target.streaming then
      request.body = pv
      request.streaming_input = true
      local mt = pm.media_type or target.media_type
      if mt ~= nil and headers["Content-Type"] == nil then
        headers["Content-Type"] = mt
      end
    elseif t == "blob" then
      request.body = pv
      if headers["Content-Type"] == nil then
        headers["Content-Type"] = pm.media_type or target.media_type or "application/octet-stream"
      end
    elseif type(pv) == "string" then
      request.body = pv
      -- a string payload is text unless its @mediaType says otherwise
      if headers["Content-Type"] == nil then
        headers["Content-Type"] = pm.media_type or target.media_type or "text/plain"
      end
    else
      headers["Content-Type"] = "application/xml"
      local payload_ns = (target and target.xmlns) and ns_attribute(target.xmlns) or input_ns
      local tag = pm.xml_name or root_name(target, pm.name)
      request.body = serialize_value(pm.schema, pv, tag, payload_ns, registry, 0)
    end
  elseif parts.has_body then
    headers["Content-Type"] = "application/xml"
    -- the body members, keyed by member name for the serializer
    local body = {}
    for _, m in ipairs(node.members or {}) do
      if (m.bind or "body") == "body" then
        body[m.name] = parts.body[m.wire or m.name]
      end
    end
    request.body = serialize_object(node, body, root_name(node), input_ns, registry, 0)
  end
  return request
end

---------------------------------------------------------------------------------------
-- deserialization
---------------------------------------------------------------------------------------

local deserialize_value, deserialize_object

local function element_text(v)
  if type(v) == "table" and not xml.is_list(v) and v["#text"] ~= nil then
    return v["#text"]
  end
  return v
end

local function as_list(v)
  if xml.is_list(v) then
    return v
  end
  return { v }
end

local function is_empty_object(v)
  return type(v) == "table" and not xml.is_list(v) and next(v) == nil
end

local function read_map(value, flattened, key_tag, value_tag, read_value)
  local result = {}
  local entries = value
  if not flattened then
    if type(value) ~= "table" or xml.is_list(value) then
      return json.object(result)
    end
    entries = value.entry
    if entries == nil then
      entries = value.Entry
    end
  end
  if entries == nil then
    return json.object(result)
  end
  for _, entry in ipairs(as_list(entries)) do
    if type(entry) == "table" and not xml.is_list(entry) then
      local k = element_text(entry[key_tag])
      if type(k) == "string" then
        result[k] = read_value(entry[value_tag])
      end
    end
  end
  return json.object(result)
end

local function is_structure(node)
  return node and node.t == "struct" and not node.open
end

deserialize_value = function(node, value, registry, depth, flattened)
  if value == nil or depth > codec.MAX_DEPTH then
    return nil
  end
  node = resolve(node, registry)
  if not node then
    return value
  end
  local t = node.t
  if t == "map" then
    if value == "" then
      return (not flattened) and json.object({}) or nil
    end
    return read_map(
      value,
      flattened,
      node.key_name or "key",
      node.value_name or "value",
      function(v)
        return deserialize_value(node.value, v, registry, depth + 1)
      end
    )
  end
  local structure = is_structure(node)
  if not structure then
    value = element_text(value)
  end
  if value == "" or is_empty_object(value) then
    if structure then
      return json.object({})
    elseif t == "list" then
      return json.array({})
    end
    if value == "" and (t == "string" or t == "enum" or t == "blob") then
      return ""
    end
    return nil
  end
  if t == "list" then
    local item = resolve(node.item, registry)
    local tag = node.item_xml_name or (item and item.xml_name) or node.item_id
    local unwrapped = value
    if type(value) == "table" and not xml.is_list(value) then
      if tag and value[tag] ~= nil then
        unwrapped = value[tag]
      elseif value.member ~= nil then
        unwrapped = value.member
      end
    end
    local out = {}
    for _, x in ipairs(as_list(unwrapped)) do
      out[#out + 1] = deserialize_value(node.item, x, registry, depth + 1)
    end
    return json.array(out)
  end
  if type(value) == "string" then
    if
      t == "number"
      or (t == "enum" and node.base == "number")
      or (t == "timestamp" and node.format == "epoch-seconds")
    then
      return http.js_number(value)
    elseif t == "boolean" then
      return (string.gsub(value, "^%s*(.-)%s*$", "%1")) == "true"
    end
    return value
  end
  if type(value) == "table" and not xml.is_list(value) and t == "struct" then
    return deserialize_object(node, value, registry, depth + 1)
  end
  return value
end

deserialize_object = function(node, value, registry, depth)
  local result = {}
  for _, m in ipairs(node.members or {}) do
    local bind = m.bind or "body"
    -- members bound to response headers are not in the body; a response has no query
    -- or path, so query and label members are read from it
    if bind ~= "header" and bind ~= "prefix_headers" then
      local key = m.name
      local name = m.xml_name or key
      if bind == "payload" then
        result[key] = deserialize_value(m.schema, value, registry, depth + 1)
      elseif m.attr then
        local a = value["@_" .. name]
        if a ~= nil then
          result[key] = deserialize_value(m.schema, a, registry, depth + 1)
        end
      else
        local v = value[name]
        if v ~= nil then
          local target = resolve(m.schema, registry)
          if m.flat and target and target.t == "list" then
            local out = {}
            for _, x in ipairs(as_list(v)) do
              out[#out + 1] = deserialize_value(target.item, x, registry, depth + 1)
            end
            result[key] = json.array(out)
          else
            local d = deserialize_value(
              m.schema,
              v,
              registry,
              depth + 1,
              m.flat and target and target.t == "map"
            )
            if d ~= nil then
              result[key] = d
            end
          end
        end
      end
    end
  end
  return json.object(result)
end

local function parse(text)
  local tree, err = xml.decode(text)
  if not tree then
    return nil, codec.parse_error(err.message)
  end
  return tree
end

local function first_value(tree)
  for _, v in pairs(tree) do
    return v
  end
  return nil
end

function M.read(p, op, res)
  local registry = p.registry
  local node = resolve(op.output, registry)
  local read, bad = http.bind_response(node, res.status, res.headers, p.env, {
    empty_prefix_map = true,
  })
  if bad then
    return {
      unreadable = codec.parse_error(
        "Response header " .. bad .. " is not base64, as its @mediaType requires"
      ),
      as_read = read,
      members = read,
      by_name = true,
    }
  end
  local payload
  for _, m in ipairs(node.members or {}) do
    if m.bind == "payload" then
      payload = m
    end
  end
  local text = res.body or ""
  if payload then
    local target = resolve(payload.schema, registry)
    local t = target and target.t
    if t == "blob" then
      if text ~= "" then
        read[payload.name] = text
      end
      return { members = read, by_name = true, raw = { [payload.name] = true } }
    end
    if text ~= "" then
      if t == "string" or t == "enum" or (target and target.tagged_union and false) then
        read[payload.name] = text
      else
        local tree, err = parse(text)
        if not tree then
          return { unreadable = err, as_read = text }
        end
        local tag = payload.xml_name or root_name(target, payload.name)
        local root = tree[tag]
        if root == nil then
          root = first_value(tree) or tree
        end
        read[payload.name] = deserialize_value(payload.schema, root, registry, 0)
      end
    end
    return { members = read, by_name = true }
  end
  if text ~= "" then
    local tree, err = parse(text)
    if not tree then
      return { unreadable = err, as_read = text }
    end
    local content = tree[root_name(node)]
    if node.unwrapped_output or (op and op.aws and op.aws.unwrapped_output) then
      -- aws.customizations#s3UnwrappedXmlOutput: the root element's text is the member
      local member
      for _, m in ipairs(node.members or {}) do
        if (m.xml_name or m.name) == root_name(node) then
          member = m
        end
      end
      if member and content ~= nil then
        local v = content
        if type(v) == "table" then
          if v["#text"] ~= nil then
            v = v["#text"]
          else
            local only_attrs = true
            for k in pairs(v) do
              only_attrs = only_attrs and string.sub(k, 1, 2) == "@_"
            end
            v = (not only_attrs) and v or nil
          end
        end
        read[member.name] = v
      end
    elseif type(content) == "table" and not xml.is_list(content) then
      local body = deserialize_object(node, content, registry, 0)
      for k, v in pairs(body) do
        read[k] = v
      end
    end
  end
  return { members = read, by_name = true }
end

local STATUS_CODES = {
  [400] = "BadRequest",
  [403] = "AccessDenied",
  [404] = "NotFound",
  [405] = "MethodNotAllowed",
  [409] = "Conflict",
  [412] = "PreconditionFailed",
  [416] = "InvalidRange",
  [500] = "InternalError",
  [503] = "ServiceUnavailable",
}

local function parse_html_error(html)
  local data, code = {}, nil
  local lower = string.lower(html)
  local pos = 1
  while true do
    local s, e = string.find(lower, "<li>", pos, true)
    if not s then
      break
    end
    local close = string.find(lower, "</li>", e + 1, true)
    if not close then
      break
    end
    local inner = string.sub(html, e + 1, close - 1)
    local k, v = string.match(inner, "^([^:<]+):%s*([^<]*)$")
    if k then
      k = string.gsub(string.gsub(k, "^%s+", ""), "%s+$", "")
      v = string.gsub(string.gsub(v, "^%s+", ""), "%s+$", "")
      if k == "Code" then
        code = require("distilled.aws.json_protocols").sanitize_error_code(v)
      else
        data[k] = v
      end
    end
    pos = close + 5
  end
  if not code then
    return nil
  end
  return code, data
end

function M.read_error(p, op, res)
  local text = res.body or ""
  local status = res.status
  local server_failure = status >= 500 and status < 600
  local withheld = p.withhold_errors and "[REDACTED]" or text
  if text == "" then
    local code = STATUS_CODES[status]
      or (server_failure and "InternalError" or ("HttpError" .. tostring(status)))
    return code, {}
  end
  local function fail(err)
    if server_failure then
      return "InternalError", {}
    end
    return nil, err
  end
  if string.find(string.lower(string.gsub(text, "^%s+", "")), "^<html") then
    local code, data = parse_html_error(text)
    if code then
      return code, data
    end
    return fail(codec.parse_error("Could not parse HTML error response: " .. withheld))
  end
  local tree, err = parse(text)
  if not tree then
    return fail(err)
  end
  local content
  local er = tree.ErrorResponse
  if type(er) == "table" and not xml.is_list(er) and type(er.Error) == "table" then
    content = er.Error
  end
  if not content and type(tree.Error) == "table" then
    content = tree.Error
  end
  if type(content) ~= "table" or xml.is_list(content) then
    return fail(codec.parse_error("Could not find Error element in XML response: " .. withheld))
  end
  if type(content.Code) ~= "string" then
    return fail(codec.parse_error("No Code element found in error response: " .. withheld))
  end
  local data = {}
  for k, v in pairs(content) do
    if k ~= "Code" then
      data[k] = v
    end
  end
  return require("distilled.aws.json_protocols").sanitize_error_code(content.Code), data
end

return M
