-- The AWS JSON protocols: awsJson1_0, awsJson1_1 and restJson1.
--
-- Ports of Distilled's packages/aws/src/protocols/aws-json.ts and rest-json.ts, with
-- util/error.ts (sanitizeErrorCode, extractJsonErrorCode/Data). Each protocol is a table:
--
--   impl.encode(p, op, input) -> request | nil, err
--   impl.read(p, op, res) -> read | nil, err   -- a 2xx response, before decoding:
--     read = { members = { [name] = wire value }, body = <wire object> | nil,
--              unreadable = ParseError | nil, as_read = <value> }
--   impl.read_error(p, op, res) -> code, data | nil, err
--
-- `p` is the protocol's per-call context (aws/protocol.lua): { service, aws, registry,
-- env (codec env), what ("DynamoDB.GetItem"), withhold_output, withhold_errors }.
local codec = require("distilled.aws.codec")
local http = require("distilled.aws.http")
local json = require("distilled.json")

local M = {}

local find, sub, gsub = string.find, string.sub, string.gsub

--- M.sanitize_error_code(value): the first of a ", "-joined list, before ":", after "#"
function M.sanitize_error_code(value)
  local code = value
  local comma = find(code, ",", 1, true)
  if comma then
    code = sub(code, 1, comma - 1)
  end
  code = gsub(gsub(code, "^%s+", ""), "%s+$", "")
  local colon = find(code, ":", 1, true)
  if colon then
    code = sub(code, 1, colon - 1)
  end
  local hash = find(code, "#", 1, true)
  if hash then
    code = sub(code, hash + 1)
  end
  return code
end

-- JSON.parse with a reviver turning null into undefined: nulls are dropped
local function drop_nulls(v, depth)
  if type(v) ~= "table" or depth > codec.MAX_DEPTH then
    return v
  end
  if json.is_array(v) then
    local out = {}
    for i = 1, #v do
      local x = v[i]
      if x ~= json.null then
        out[#out + 1] = drop_nulls(x, depth + 1)
      end
    end
    return json.array(out)
  end
  local out = {}
  for k, x in pairs(v) do
    if x ~= json.null then
      out[k] = drop_nulls(x, depth + 1)
    end
  end
  return json.object(out)
end

local function is_object(v)
  return type(v) == "table" and v ~= json.null and not json.is_array(v)
end

local function error_code_header(headers)
  return headers["x-amzn-errortype"] or headers["x-amz-errortype"]
end

local function json_error_code(body)
  if type(body.__type) == "string" then
    return body.__type
  end
  if type(body.code) == "string" then
    return body.code
  end
  return nil
end

local function error_data(body)
  local out = {}
  for k, v in pairs(body) do
    if k ~= "__type" and k ~= "code" then
      out[k] = v
    end
  end
  return out
end

local function withheld(p, text, which)
  if p[which] then
    return "[REDACTED]"
  end
  return text
end

-- a 2xx JSON body: the parsed object, {} for an empty body, unreadable for bad JSON
local function read_json_body(p, text)
  if text == nil or text == "" then
    return json.object({})
  end
  local parsed = json.decode(text)
  if parsed == nil then
    return nil,
      codec.parse_error("Failed to parse JSON body: " .. withheld(p, text, "withhold_output"))
  end
  if type(parsed) == "table" and parsed ~= json.null then
    return parsed
  end
  return json.object({})
end

---------------------------------------------------------------------------------------
-- awsJson1_0 / awsJson1_1
---------------------------------------------------------------------------------------

local function aws_json(version)
  local content_type = "application/x-amz-json-" .. version
  local impl = { name = "awsJson" .. string.gsub(version, "%.", "_") }

  function impl.encode(p, op, input)
    local node = codec.resolve(op.input, p.registry)
    local encoded, f = codec.encode(node, input, p.env)
    if f then
      return nil, codec.parse_error(codec.failure_message(f, p.withhold_input))
    end
    local target = p.aws.target and p.aws.target ~= "" and (p.aws.target .. "." .. op.name)
      or op.name
    local headers = { ["Content-Type"] = content_type, ["X-Amz-Target"] = target }
    if p.aws.query_compatible then
      headers["x-amzn-query-mode"] = "true"
    end
    return {
      method = "POST",
      path = "/",
      query = {},
      headers = headers,
      body = json.encode(encoded or json.object({})),
    }
  end

  function impl.read(p, op, res)
    local body, err = read_json_body(p, res.body)
    if not body then
      return { unreadable = err, as_read = res.body }
    end
    return { members = {}, body = body }
  end

  function impl.read_error(p, op, res)
    local text = res.body or ""
    local body = json.object({})
    if text ~= "" then
      local parsed = json.decode(text)
      if parsed == nil then
        return nil,
          codec.parse_error(
            "Failed to parse error JSON body: " .. withheld(p, text, "withhold_errors")
          )
      end
      if is_object(parsed) then
        body = drop_nulls(parsed, 0)
      end
    end
    local raw = error_code_header(res.headers) or json_error_code(body)
    if not raw then
      return nil,
        codec.parse_error(
          "No error code found in response. Headers: "
            .. json.encode(res.headers)
            .. ", Body: "
            .. withheld(p, text, "withhold_errors")
        )
    end
    return M.sanitize_error_code(raw), error_data(body)
  end

  return impl
end

M.awsJson1_0 = aws_json("1.0")
M.awsJson1_1 = aws_json("1.1")

---------------------------------------------------------------------------------------
-- restJson1
---------------------------------------------------------------------------------------

local rest = { name = "restJson1" }
M.restJson1 = rest

-- Whether an input has a member that could go in the body (not bound elsewhere).
local function body_capable(node)
  for _, m in ipairs(node.members or {}) do
    local b = m.bind or "body"
    if b == "body" then
      return true
    end
  end
  return false
end

local function payload_of(node)
  for _, m in ipairs(node.members or {}) do
    if m.bind == "payload" then
      return m
    end
  end
  return nil
end

local function is_structure(node, registry)
  node = codec.resolve(node, registry)
  return node ~= nil and node.t == "struct" and not node.tagged_union and not node.union
end

function rest.encode(p, op, input)
  local node = codec.resolve(op.input, p.registry)
  local parts, err = http.bind_input(op, node, input, p.env)
  if not parts then
    return nil, err
  end
  local request = parts.request
  local headers = request.headers
  local user_type = headers["Content-Type"] ~= nil
  local pm, pv = parts.payload_member, parts.payload_value
  local registry = p.registry
  if pm ~= nil and pv ~= nil then
    local target = codec.resolve(pm.schema, registry)
    local t = target and target.t
    if target and target.streaming then
      request.body = pv
      request.streaming_input = true
      if not user_type then
        headers["Content-Type"] = pm.media_type or target.media_type or "application/octet-stream"
      end
    elseif t == "blob" then
      request.body = pv
      if not user_type then
        headers["Content-Type"] = pm.media_type or target.media_type or "application/octet-stream"
      end
    elseif t == "string" or t == "enum" then
      request.body = pv
      if not user_type then
        headers["Content-Type"] = pm.media_type or target.media_type or "text/plain"
      end
    else
      request.body = json.encode(pv)
      if not user_type then
        headers["Content-Type"] = "application/json"
      end
    end
  elseif parts.has_body then
    request.body = json.encode(parts.body)
    if not user_type then
      headers["Content-Type"] = "application/json"
    end
  elseif
    body_capable(node)
    or (payload_of(node) ~= nil and is_structure(payload_of(node).schema, registry))
  then
    -- body-capable members exist but none were set: an explicit empty JSON document,
    -- as AWS SDK v3 / botocore send (resource-explorer-2 rejects an absent body)
    request.body = "{}"
    if not user_type then
      headers["Content-Type"] = "application/json"
    end
  end
  -- customizations/api-gateway.ts and glacier.ts (applyGlacierCustomizations)
  local sdk_id = p.aws.sdk_id
  if sdk_id == "API Gateway" then
    headers["Accept"] = "application/json"
  elseif sdk_id == "Glacier" and p.aws.version then
    headers["X-Amz-Glacier-Version"] = p.aws.version
  end
  return request
end

function rest.read(p, op, res)
  local node = codec.resolve(op.output, p.registry)
  local read, bad = http.bind_response(node, res.status, res.headers, p.env)
  if bad then
    return {
      unreadable = codec.parse_error(
        "Response header " .. bad .. " is not base64, as its @mediaType requires"
      ),
      as_read = read,
      members = read,
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
    local target = codec.resolve(payload.schema, p.registry)
    local t = target and target.t
    if t == "blob" then
      if text ~= "" then
        read[payload.name] = text
      end
      return { members = read, raw = { [payload.name] = true } }
    elseif t == "string" or t == "enum" then
      if text ~= "" then
        read[payload.name] = text
      end
      return { members = read }
    end
    if text ~= "" then
      local parsed = json.decode(text)
      if parsed == nil then
        return {
          unreadable = codec.parse_error(
            "Failed to parse JSON body: " .. withheld(p, text, "withhold_output")
          ),
          as_read = text,
        }
      end
      read[payload.name] = parsed
    end
    return { members = read }
  end
  local body
  if text ~= "" then
    local parsed = json.decode(text)
    if parsed == nil then
      return {
        unreadable = codec.parse_error(
          "Failed to parse JSON body: " .. withheld(p, text, "withhold_output")
        ),
        as_read = text,
      }
    end
    if is_object(parsed) then
      body = parsed
    end
  end
  return { members = read, body = body or json.object({}) }
end

function rest.read_error(p, op, res)
  local text = res.body or ""
  local body = json.object({})
  if text ~= "" then
    local parsed = json.decode(text)
    if parsed == nil then
      -- API Gateway-fronted services answer plain text: the text is the message, and
      -- the declared errors are matched by status
      return "", { message = text }
    end
    if is_object(parsed) then
      body = drop_nulls(parsed, 0)
    end
  end
  local raw = error_code_header(res.headers) or json_error_code(body)
  if not raw then
    return "", error_data(body)
  end
  return M.sanitize_error_code(raw), error_data(body)
end

return M
