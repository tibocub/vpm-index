-- HTTP bindings of the AWS REST protocols (restJson1, restXml): input members to the
-- path, query, headers and payload; response headers and status back to members.
--
-- Port of Distilled's packages/s3/src/util/serialize-input.ts (bindInputToRequest,
-- encodeLabel, invalidAwsLabel), util/headers.ts (formatHeaderList, splitHeader,
-- headerReader) and util/query-params.ts (extractStaticQueryParams).
--
-- A request here is { method, path, query = { { name, value | nil }, ... }, headers =
-- { [Name] = value }, body, streaming_input }; aws/protocol.lua turns it into the
-- transport's request after endpoint resolution and signing.
local codec = require("distilled.aws.codec")
-- compat.concat: gopher-lua's table.concat fails past ~2,500 items (a long list)
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local url = require("distilled.url")

local http = {}

local find, sub, gsub = string.find, string.sub, string.gsub

--- http.encode_label(s): encodeURIComponent, plus !'()* (the AWS SDKs' extended form)
function http.encode_label(s)
  return (
    gsub(url.encode_component(s), "[!'()*]", function(c)
      return string.format("%%%02X", string.byte(c))
    end)
  )
end

--- http.encode_greedy_label(s): each "/"-separated segment encoded, the "/" kept
function http.encode_greedy_label(s)
  local out = {}
  for _, seg in ipairs(require("distilled.aws.endpoint").split(s, "/")) do
    out[#out + 1] = http.encode_label(seg)
  end
  return compat.concat(out, "/")
end

local function invalid_input(member, message)
  return errors.new("InvalidInput", { member = member, message = message })
end

--- http.invalid_label(member, text, greedy) -> InvalidInput | nil
-- "" would drop the segment; "." and ".." (any segment of a greedy label) are resolved
-- by URL parsers, so either would address another resource.
function http.invalid_label(member, text, greedy)
  local bad = text == ""
  if not bad then
    if greedy then
      for _, seg in ipairs(require("distilled.aws.endpoint").split(text, "/")) do
        bad = bad or seg == "." or seg == ".."
      end
    else
      bad = text == "." or text == ".."
    end
  end
  if bad then
    return invalid_input(
      member,
      "Input member "
        .. member
        .. " cannot be "
        .. json.encode(text)
        .. ": as a path label it would address another resource"
    )
  end
  return nil
end

--- http.invalid_host_label(member, value) -> InvalidInput
function http.invalid_host_label(member, value)
  return invalid_input(
    member,
    "Input member "
      .. member
      .. " cannot be "
      .. json.encode(value)
      .. ": as a host label it would address another host"
  )
end

--- http.format_header_list(values, quote) -> "a, b" (an element with a comma or a
-- double quote is quoted when `quote`; timestamps are never quoted)
function http.format_header_list(values, quote)
  local parts = {}
  for i, v in ipairs(values) do
    local text = url.text(v)
    if quote and (find(text, ",", 1, true) or find(text, '"', 1, true)) then
      text = '"' .. gsub(text, '"', '\\"') .. '"'
    end
    parts[i] = text
  end
  return compat.concat(parts, ", ")
end

--- http.split_header(value) -> values: split on commas outside quoted strings, trimmed,
-- quoted values unquoted
function http.split_header(value)
  local parts = {}
  local quoted = false
  local start = 1
  for i = 1, #value do
    local c = sub(value, i, i)
    if c == '"' and sub(value, i - 1, i - 1) ~= "\\" then
      quoted = not quoted
    elseif c == "," and not quoted then
      parts[#parts + 1] = sub(value, start, i - 1)
      start = i + 1
    end
  end
  parts[#parts + 1] = sub(value, start)
  for i, part in ipairs(parts) do
    local text = gsub(gsub(part, "^%s+", ""), "%s+$", "")
    if #text >= 2 and sub(text, 1, 1) == '"' and sub(text, -1) == '"' then
      text = gsub(sub(text, 2, -2), '\\"', '"')
    end
    parts[i] = text
  end
  return parts
end

-- http-dates hold a comma: every second comma ends one
local function split_http_dates(value)
  local parts = require("distilled.aws.endpoint").split(value, ",")
  local out = {}
  for i = 1, #parts, 2 do
    local text = parts[i] .. (parts[i + 1] and ("," .. parts[i + 1]) or "")
    out[#out + 1] = (gsub(gsub(text, "^%s+", ""), "%s+$", ""))
  end
  return out
end

local function js_number(text)
  -- Number(text): "" is 0, surrounding whitespace allowed, anything else NaN
  local t = gsub(gsub(text, "^%s+", ""), "%s+$", "")
  if t == "" then
    return 0
  end
  local n = json.decode(t)
  if type(n) == "number" then
    return n
  end
  if t == "NaN" or t == "Infinity" or t == "+Infinity" or t == "-Infinity" then
    return ({ NaN = 0 / 0, Infinity = 1 / 0, ["+Infinity"] = 1 / 0, ["-Infinity"] = -1 / 0 })[t]
  end
  local h = string.match(t, "^0[xX](%x+)$")
  if h then
    return tonumber(h, 16)
  end
  return 0 / 0
end
http.js_number = js_number

local NOT_BASE64 = {}
http.NOT_BASE64 = NOT_BASE64

-- the wire value of a scalar header: numbers and booleans parsed, the rest kept
local function scalar_reader(node, ts)
  local t = node and node.t
  if t == "number" or (t == "enum" and node.base == "number") then
    return js_number
  elseif t == "boolean" then
    return function(v)
      return v == "true"
    end
  elseif t == "timestamp" and ts == "epoch-seconds" then
    return js_number
  end
  return function(v)
    return v
  end
end

--- http.read_header(member, value, registry) -> the wire value (before codec.decode):
-- a list header split, numbers and booleans parsed, a `@mediaType` string base64-decoded
-- (http.NOT_BASE64 when it is not base64)
function http.read_header(member, value, registry)
  local node = codec.resolve(member.schema, registry)
  if node and node.t == "string" and (member.media_type or node.media_type) then
    if not find(value, "^[A-Za-z0-9+/]*=?=?$") or #value % 4 ~= 0 then
      return NOT_BASE64
    end
    local text = codec.from_base64(value)
    if text == nil then
      return NOT_BASE64
    end
    return text
  end
  if node and node.t == "list" then
    local item = codec.resolve(node.item, registry)
    local item_ts = item
      and item.t == "timestamp"
      and (member.item_ts or item.format or "http-date")
    local read = scalar_reader(item, item_ts)
    local parts = item_ts == "http-date" and split_http_dates(value) or http.split_header(value)
    local out = {}
    for i, p in ipairs(parts) do
      out[i] = read(p)
    end
    return json.array(out)
  end
  local ts = node and node.t == "timestamp" and (member.ts or node.format or "http-date")
  return scalar_reader(node, ts)(value)
end

-- the text of an encoded scalar for a header, label or query value
local function text_of(v)
  return url.text(v)
end

--- http.encode_failure(failure, member_name, env) -> ParseError (Distilled's input
-- encoder failure; the value is withheld when env.withhold)
function http.encode_failure(f, name, env)
  return codec.parse_error(codec.failure_message(codec.within(f, name), env.withhold))
end

--- http.bind_input(op, node, input, env) -> parts | nil, err
-- parts = { request = { method, path, query, headers }, payload_member, payload_value
-- (the raw user value for a blob / streaming payload, else encoded), body (encoded body
-- members keyed by wire name), has_body (a body member was set) }
function http.bind_input(op, node, input, env)
  local request = { method = op.method or "POST", path = op.uri or "/", query = {}, headers = {} }
  local query_names = {}
  local body, has_body = {}, false
  local payload_member, payload_value
  local query_params
  local registry = env.registry
  -- timestamps default to http-date in headers and date-time in the query and path
  local header_env, text_env = {}, {}
  for k, v in pairs(env) do
    header_env[k], text_env[k] = v, v
  end
  header_env.timestamp, text_env.timestamp = "http-date", "date-time"
  -- a required member the caller left out fails before anything is bound, whatever it
  -- binds to (Distilled's schema encode: `Expected a value, got undefined at ["Key"]`)
  for _, m in ipairs(node.members or {}) do
    if m.required and (input[m.name] == nil or input[m.name] == json.null) then
      return nil, http.encode_failure(codec.mismatch("a value", nil), m.name, env)
    end
  end
  for _, m in ipairs(node.members or {}) do
    local raw = input[m.name]
    if raw ~= nil and raw ~= json.null then
      local bind = m.bind or "body"
      local target = codec.resolve(m.schema, registry)
      local value
      if bind == "payload" and target and target.t == "blob" then
        value = require("distilled.secret").unwrap(raw)
        if type(value) ~= "string" then
          return nil, http.encode_failure(codec.mismatch("a string of bytes", value), m.name, env)
        end
      else
        local f
        local b = m.bind or "body"
        local menv = (b == "header" or b == "prefix_headers") and header_env
          or ((b == "query" or b == "label" or b == "query_params") and text_env)
          or env
        value, f = codec.encode_member(m, raw, menv)
        if f then
          return nil, http.encode_failure(f, m.name, env)
        end
      end
      if bind == "header" then
        local h
        if type(value) == "table" then
          local item = target and target.t == "list" and codec.resolve(target.item, registry)
          h = http.format_header_list(value, not (item and item.t == "timestamp"))
        elseif target and target.t == "string" and (m.media_type or target.media_type) then
          h = codec.to_base64(value)
        else
          h = text_of(value)
        end
        request.headers[m.wire or m.name] = h
      elseif bind == "label" then
        local text = text_of(value)
        local bad = http.invalid_label(m.name, text, m.greedy)
        if bad then
          return nil, bad
        end
        local encoded = m.greedy and http.encode_greedy_label(text) or http.encode_label(text)
        local name = m.wire or m.name
        local s, e = find(request.path, "{" .. name .. "+}", 1, true)
        if not s then
          s, e = find(request.path, "{" .. name .. "}", 1, true)
        end
        if s then
          request.path = sub(request.path, 1, s - 1) .. encoded .. sub(request.path, e + 1)
        end
      elseif bind == "query" then
        local name = m.wire or m.name
        if type(value) == "table" then
          for _, v in ipairs(value) do
            request.query[#request.query + 1] = { name, text_of(v) }
          end
        else
          request.query[#request.query + 1] = { name, text_of(value) }
        end
        query_names[name] = true
      elseif bind == "query_params" then
        query_params = value
      elseif bind == "prefix_headers" then
        if type(value) == "table" then
          local keys = {}
          for k in pairs(value) do
            keys[#keys + 1] = k
          end
          table.sort(keys)
          for _, k in ipairs(keys) do
            request.headers[(m.wire or "") .. k] = text_of(value[k])
          end
        end
      elseif bind == "payload" then
        payload_member, payload_value = m, value
      elseif bind ~= "status" then
        body[m.wire or m.name] = value
        has_body = true
      end
    end
  end
  -- a named @httpQuery member wins over an @httpQueryParams key of the same name
  if type(query_params) == "table" then
    local keys = {}
    for k in pairs(query_params) do
      keys[#keys + 1] = k
    end
    table.sort(keys)
    for _, k in ipairs(keys) do
      if not query_names[k] then
        local v = query_params[k]
        if type(v) == "table" then
          for _, x in ipairs(v) do
            request.query[#request.query + 1] = { k, text_of(x) }
          end
        else
          request.query[#request.query + 1] = { k, text_of(v) }
        end
        query_names[k] = true
      end
    end
  end
  -- extractStaticQueryParams: "/{Bucket}?tagging" -> path and a query pair, unless set
  local q = find(request.path, "?", 1, true)
  if q then
    local static = sub(request.path, q + 1)
    request.path = sub(request.path, 1, q - 1)
    for param in string.gmatch(static, "[^&]+") do
      local eq = find(param, "=", 1, true)
      local k = eq and sub(param, 1, eq - 1) or param
      local v = eq and sub(param, eq + 1) or ""
      -- JavaScript's split("=") keeps only the text up to a second "="
      local eq2 = eq and find(v, "=", 1, true)
      if eq2 then
        v = sub(v, 1, eq2 - 1)
      end
      if k ~= "" and not query_names[k] then
        request.query[#request.query + 1] = { k, v }
        query_names[k] = true
      end
    end
  end
  return {
    request = request,
    payload_member = payload_member,
    payload_value = payload_value,
    body = json.object(body),
    has_body = has_body,
  }
end

--- http.bind_response(node, status, headers, env, opts) -> read, not_base64_header
-- read = { [member name] = wire value } for the status and header members (prefix
-- headers as a map; `opts.empty_prefix_map` keeps an empty one, as restXml does).
function http.bind_response(node, status, headers, env, opts)
  local read = {}
  local bad
  for _, m in ipairs(node.members or {}) do
    local bind = m.bind
    if bind == "status" then
      read[m.name] = status
    elseif bind == "header" then
      local v = headers[string.lower(m.wire or m.name)]
      if v ~= nil then
        local r = http.read_header(m, v, env.registry)
        if r == NOT_BASE64 then
          bad = bad or (m.wire or m.name)
          r = v
        end
        read[m.name] = r
      end
    elseif bind == "prefix_headers" then
      local prefix = string.lower(m.wire or "")
      local map, any = {}, false
      for k, v in pairs(headers) do
        if sub(k, 1, #prefix) == prefix then
          map[sub(k, #prefix + 1)] = v
          any = true
        end
      end
      if any or (opts and opts.empty_prefix_map) then
        read[m.name] = json.object(map)
      end
    end
  end
  return read, bad
end

--- http.query_string(pairs) -> "a=1&b" (encodeURIComponent; an empty value is the key
-- alone, as Distilled's toHttpRequest writes it)
function http.query_string(pairs_list)
  local parts = {}
  for _, p in ipairs(pairs_list) do
    local k, v = p[1], p[2]
    if v ~= nil and v ~= "" then
      parts[#parts + 1] = url.encode_component(k) .. "=" .. url.encode_component(v)
    else
      parts[#parts + 1] = url.encode_component(k)
    end
  end
  return compat.concat(parts, "&")
end

return http
