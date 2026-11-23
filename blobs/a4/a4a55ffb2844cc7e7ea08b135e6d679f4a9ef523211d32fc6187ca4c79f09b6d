-- The AWS query protocols: awsQuery and ec2Query (form-encoded requests, XML responses).
--
-- Ports of Distilled's packages/aws/src/protocols/aws-query.ts and ec2-query.ts, with
-- the XML helpers of packages/s3/src/util/xml.ts (extractXmlRoot, elementText,
-- readXmlMap, unwrapArrayValue). The two differ in:
--
--   query keys   awsQuery: xmlName, else the member name; ec2Query: ec2QueryName, else
--                xmlName or the member name with its first letter upper-cased
--   lists        awsQuery: Key.member.N (Key.N flattened), an empty list is "Key=";
--                ec2Query: always Key.N, an empty list is left out
--   maps         awsQuery: Key.entry.N.key / .value (Key.N flattened); ec2Query: none
--   responses    awsQuery: <OpResponse><OpResult>...; ec2Query: <OpResponse>...
--   errors       awsQuery: <ErrorResponse><Error>...; ec2Query: <Response><Errors><Error>
--
-- Same interface as aws/json_protocols.lua (encode, read, read_error).
local codec = require("distilled.aws.codec")
-- compat.concat: gopher-lua's table.concat fails past ~2,500 items (a long list)
local compat = require("distilled.compat")
local json = require("distilled.json")
local url = require("distilled.url")
local xml = require("distilled.xml")

local M = {}

local sub, upper, lower = string.sub, string.upper, string.lower
local enc = url.encode_component
local null = json.null

local function cap(s)
  return upper(sub(s, 1, 1)) .. sub(s, 2)
end

local function lower_first(s)
  return lower(sub(s, 1, 1)) .. sub(s, 2)
end

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

--- M.member_xml_name(m, registry): getXmlNameProp: the member's xmlName, else the one of
-- the shape it targets (aws-query reads through to the target)
function M.member_xml_name(m, registry)
  if m.xml_name then
    return m.xml_name
  end
  local target = resolve(m.schema, registry)
  return target and target.xml_name or nil
end

local function item_xml_name(list, registry)
  if list.item_xml_name then
    return list.item_xml_name
  end
  local item = resolve(list.item, registry)
  return item and item.xml_name or nil
end

---------------------------------------------------------------------------------------
-- serialization
---------------------------------------------------------------------------------------

local serialize_value

local function query_key(ec2, m, registry)
  if ec2 then
    if m.ec2_name then
      return m.ec2_name
    end
    return cap(M.member_xml_name(m, registry) or m.name)
  end
  return M.member_xml_name(m, registry) or m.name
end

local function serialize_members(ec2, node, value, prefix, params, registry, depth)
  for _, m in ipairs(node.members or {}) do
    local v = value[m.name]
    if v ~= nil and v ~= null then
      local key = query_key(ec2, m, registry)
      local full = prefix ~= "" and (prefix .. "." .. key) or key
      serialize_value(ec2, m.schema, v, full, params, registry, m, depth + 1)
    end
  end
end

serialize_value = function(ec2, node, value, key, params, registry, member, depth)
  if value == nil or value == null or depth > codec.MAX_DEPTH then
    return
  end
  node = resolve(node, registry)
  if type(value) ~= "table" then
    params[#params + 1] = enc(key) .. "=" .. enc(url.text(value))
    return
  end
  if node and node.t == "list" then
    if #value == 0 then
      if not ec2 then
        params[#params + 1] = enc(key) .. "="
      end
      return
    end
    local flat = member and member.flat
    local tag = item_xml_name(node, registry) or "member"
    for i = 1, #value do
      local item_key
      if ec2 or flat then
        item_key = key .. "." .. i
      else
        item_key = key .. "." .. tag .. "." .. i
      end
      serialize_value(ec2, node.item, value[i], item_key, params, registry, nil, depth + 1)
    end
    return
  end
  if node and node.t == "map" then
    if ec2 then
      -- ec2-query.ts has no map branch: a map's members are none
      return
    end
    local keys = {}
    for _, k in ipairs(sorted_keys(value)) do
      if value[k] ~= nil then
        keys[#keys + 1] = k
      end
    end
    if #keys == 0 then
      return
    end
    local flat = member and member.flat
    local key_name = node.key_name or "key"
    local value_name = node.value_name or "value"
    for i, k in ipairs(keys) do
      local entry = flat and (key .. "." .. i) or (key .. ".entry." .. i)
      params[#params + 1] = enc(entry .. "." .. key_name) .. "=" .. enc(k)
      serialize_value(
        ec2,
        node.value,
        value[k],
        entry .. "." .. value_name,
        params,
        registry,
        nil,
        depth + 1
      )
    end
    return
  end
  if node and node.t == "struct" then
    serialize_members(ec2, node, value, key, params, registry, depth)
  end
end

local function query_protocol(ec2)
  local impl = { name = ec2 and "ec2Query" or "awsQuery" }

  function impl.encode(p, op, input)
    local node = resolve(op.input, p.registry)
    local encoded, f = codec.encode(node, input, p.env)
    if f then
      return nil, codec.parse_error(codec.failure_message(f, p.withhold_input))
    end
    local params = { "Action=" .. enc(op.name), "Version=" .. enc(p.aws.version or "") }
    serialize_members(ec2, node, encoded, "", params, p.registry, 0)
    return {
      method = "POST",
      path = "/",
      query = {},
      headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
      body = compat.concat(params, "&"),
    }
  end

  ---------------------------------------------------------------------------------
  -- XML responses
  ---------------------------------------------------------------------------------

  local deserialize_value, deserialize_object

  -- elementText: `{ "#text": "a", "@_xmlns": ... }` -> "a"
  local function element_text(v)
    if type(v) == "table" and not xml.is_list(v) and v["#text"] ~= nil then
      return v["#text"]
    end
    return v
  end

  local function unwrap_array(value, primary, fallbacks)
    if type(value) ~= "table" or xml.is_list(value) then
      return value
    end
    if primary and value[primary] ~= nil then
      return value[primary]
    end
    for _, tag in ipairs(fallbacks) do
      if value[tag] ~= nil then
        return value[tag]
      end
    end
    return value
  end

  local function as_list(v)
    if xml.is_list(v) then
      return v
    end
    return { v }
  end

  local function is_number_node(node)
    return node.t == "number"
      or (node.t == "enum" and node.base == "number")
      or (node.t == "timestamp" and node.format == "epoch-seconds")
  end

  local function element_tag(list, registry)
    local item = resolve(list.item, registry)
    if ec2 then
      return list.item_id
    end
    return list.item_xml_name or (item and item.xml_name) or list.item_id
  end

  -- readXmlMap
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

  local function map_value(node, registry, v, depth)
    -- empty <value/> elements are empty strings
    if v == nil or v == "" then
      return ""
    end
    local d = deserialize_value(node.value, v, registry, depth + 1)
    if d == nil then
      return ""
    end
    return d
  end

  deserialize_value = function(node, value, registry, depth)
    if value == nil or depth > codec.MAX_DEPTH then
      return nil
    end
    node = resolve(node, registry)
    if not node then
      return value
    end
    local t = node.t
    if ec2 then
      if value == "" then
        return (t == "string" or t == "enum" or t == "blob") and "" or nil
      end
      if t == "map" then
        return read_map(
          value,
          false,
          node.key_name or "key",
          node.value_name or "value",
          function(v)
            return deserialize_value(node.value, v, registry, depth + 1)
          end
        )
      end
    else
      if t == "map" then
        if value == "" then
          return json.object({})
        end
        return read_map(
          value,
          false,
          node.key_name or "key",
          node.value_name or "value",
          function(v)
            return map_value(node, registry, v, depth)
          end
        )
      end
      if value == "" then
        return (t == "string" or t == "enum" or t == "blob") and "" or nil
      end
    end
    value = element_text(value)
    if t == "list" then
      local unwrapped = unwrap_array(
        value,
        element_tag(node, registry),
        ec2 and { "member", "item" } or { "member" }
      )
      if ec2 and (unwrapped == nil or unwrapped == "") then
        return nil
      end
      local out = {}
      for _, item in ipairs(as_list(unwrapped)) do
        local d = deserialize_value(node.item, item, registry, depth + 1)
        if d ~= nil or not ec2 then
          out[#out + 1] = d
        end
      end
      return json.array(out)
    end
    if type(value) == "string" then
      if is_number_node(node) then
        return require("distilled.aws.http").js_number(value)
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
      local key = m.name
      local xml_name = M.member_xml_name(m, registry) or key
      if m.attr then
        local a = value["@_" .. xml_name]
        if a ~= nil then
          result[key] = deserialize_value(m.schema, a, registry, depth + 1)
        end
      else
        local v = value[key]
        if v == nil then
          v = value[xml_name]
        end
        if ec2 and v == nil then
          v = value[lower_first(key)]
          if v == nil then
            v = value[lower_first(xml_name)]
          end
        end
        if v ~= nil then
          local target = resolve(m.schema, registry)
          if target and target.t == "list" then
            local el = target.item
            if ec2 then
              local arr = unwrap_array(v, target.item_id, { "item", "member" })
              local out = {}
              if arr ~= nil and arr ~= "" then
                for _, item in ipairs(as_list(arr)) do
                  local d = deserialize_value(el, item, registry, depth + 1)
                  if d ~= nil then
                    out[#out + 1] = d
                  end
                end
              end
              result[key] = json.array(out)
            else
              if v == "" then
                result[key] = json.array({})
              else
                local arr = unwrap_array(v, element_tag(target, registry), { "member" })
                local out = {}
                local empty = arr == nil
                  or arr == ""
                  or (type(arr) == "table" and not xml.is_list(arr) and next(arr) == nil)
                if not empty then
                  for _, item in ipairs(as_list(arr)) do
                    if item ~= nil and item ~= "" then
                      out[#out + 1] = deserialize_value(el, item, registry, depth + 1)
                    end
                  end
                end
                result[key] = json.array(out)
              end
            end
          elseif target and target.t == "map" and m.flat and not ec2 then
            result[key] = read_map(
              v,
              true,
              target.key_name or "key",
              target.value_name or "value",
              function(x)
                return map_value(target, registry, x, depth)
              end
            )
          else
            result[key] = deserialize_value(m.schema, v, registry, depth + 1)
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

  -- extractXmlRoot: the root element's content
  local function root_of(tree)
    for _, v in pairs(tree) do
      return v
    end
    return tree
  end

  function impl.read(p, op, res)
    local node = resolve(op.output, p.registry)
    local text = res.body or ""
    if text == "" then
      return { members = json.object({}), by_name = true }
    end
    local tree, err = parse(text)
    if not tree then
      return { unreadable = err, as_read = text }
    end
    local content = root_of(tree)
    if not ec2 and type(content) == "table" and not xml.is_list(content) then
      -- the *Result element (GetUserResult, ListUsersResult)
      local keys = sorted_keys(content)
      for _, k in ipairs(keys) do
        if sub(k, -6) == "Result" then
          content = content[k]
          break
        end
      end
    end
    local members = json.object({})
    if type(content) == "table" and not xml.is_list(content) then
      members = deserialize_object(node, content, p.registry, 0)
    end
    return { members = members, by_name = true }
  end

  function impl.read_error(p, op, res)
    local text = res.body or ""
    local withheld = p.withhold_errors and "[REDACTED]" or text
    if text == "" then
      return nil, codec.parse_error("Empty error response body")
    end
    local tree, err = parse(text)
    if not tree then
      return nil, err
    end
    local content, request_id
    local function from_response(r)
      if type(r) ~= "table" or xml.is_list(r) then
        return
      end
      if type(r.RequestID) == "string" then
        request_id = r.RequestID
      end
      local errs = r.Errors
      if type(errs) == "table" and not xml.is_list(errs) and type(errs.Error) == "table" then
        local e = errs.Error
        content = xml.is_list(e) and e[1] or e
      end
    end
    if ec2 then
      from_response(tree.Response)
    else
      local er = tree.ErrorResponse
      if type(er) == "table" and not xml.is_list(er) then
        if type(er.Error) == "table" then
          content = er.Error
        end
        if type(er.RequestId) == "string" then
          request_id = er.RequestId
        end
      end
      -- legacy query services (SimpleDB) wrap errors EC2-style
      if not content then
        from_response(tree.Response)
      end
    end
    if type(content) ~= "table" then
      return nil,
        codec.parse_error(
          "Could not find Error element in "
            .. (ec2 and "EC2 " or "")
            .. "XML response: "
            .. withheld
        )
    end
    local raw = content.Code
    if type(raw) ~= "string" then
      return nil, codec.parse_error("No Code element found in error response: " .. withheld)
    end
    local data = {}
    for k, v in pairs(content) do
      if k ~= "Code" then
        data[k] = v
      end
    end
    if request_id then
      data[ec2 and "RequestID" or "RequestId"] = request_id
    end
    return require("distilled.aws.json_protocols").sanitize_error_code(raw), data
  end

  return impl
end

M.awsQuery = query_protocol(false)
M.ec2Query = query_protocol(true)

return M
