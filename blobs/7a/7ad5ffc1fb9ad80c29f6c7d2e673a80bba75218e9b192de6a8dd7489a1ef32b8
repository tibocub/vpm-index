-- The Smithy endpoint rules engine, for AWS services.
--
--   local endpoint = require("distilled.aws.endpoint")
--   local result = endpoint.resolve(rule_set, { Region = "us-east-1", Bucket = "b" })
--   -- result = { url = "...", properties = { ... }, headers = { [name] = { v, ... } } }
--   --        | nil, message   (the rule set's error rule, or "No matching endpoint rule")
--
-- Distilled compiles each service's `smithy.rules#endpointRuleSet` to JavaScript at
-- generation time (packages/aws/scripts/compile-rules.ts) and runs it with the helpers of
-- packages/s3/src/rules-engine/ (standard-functions.ts, aws-functions.ts). We emit the rule
-- set as data and interpret it here instead; the semantics are those of the compiled code,
-- which differ from a strict reading of the Smithy spec in a few places, kept on purpose:
--
-- - a condition without `assign` passes when its value is JavaScript-truthy (so "" and 0
--   fail it); with `assign`, when the value is neither nil nor false;
-- - a template `{Name}` / `{Name#path}` writes JavaScript's String(value) ("undefined" for
--   an unset reference), with no `{{` escaping;
-- - parameters get their `default` when unset; `required` is not checked.
--
-- Rule trees are shallow (a few levels, S3's is the deepest at about 12), so evaluation
-- recurses over the tree with a depth bound (MAX_DEPTH) for gopher-lua's short stack.
local url = require("distilled.url")

local endpoint = {}

local MAX_DEPTH = 100
endpoint.MAX_DEPTH = MAX_DEPTH

local find, sub, gsub, lower = string.find, string.sub, string.gsub, string.lower

---------------------------------------------------------------------------------------
-- standard functions (standard-functions.ts)
---------------------------------------------------------------------------------------

-- split(s, sep) like JavaScript's String.prototype.split with a plain separator: empty
-- fields are kept.
local function split(s, sep)
  local out, start = {}, 1
  while true do
    local at = find(s, sep, start, true)
    if not at then
      out[#out + 1] = sub(s, start)
      return out
    end
    out[#out + 1] = sub(s, start, at - 1)
    start = at + #sep
  end
end
endpoint.split = split

local function js_truthy(v)
  return v ~= nil and v ~= false and v ~= "" and v ~= 0
end

local function is_array(v)
  return type(v) == "table" and (v[1] ~= nil or next(v) == nil)
end

--- endpoint.get_attr(value, path): `foo.bar[0].baz`; list indices are 0-based.
function endpoint.get_attr(value, path)
  if value == nil then
    return nil
  end
  local result = value
  for seg in string.gmatch(path, "[^%.%[%]]+") do
    if result == nil then
      return nil
    end
    if find(seg, "^%d+$") then
      if type(result) == "table" and is_array(result) then
        result = result[tonumber(seg) + 1]
      elseif type(result) == "table" then
        result = result[seg]
      else
        return nil
      end
    elseif type(result) == "table" and not (result[1] ~= nil) then
      result = result[seg]
    else
      return nil
    end
  end
  return result
end

local function single_host_label(label)
  if #label < 1 or #label > 63 then
    return false
  end
  if #label == 1 then
    return find(label, "^[A-Za-z0-9]$") ~= nil
  end
  return find(label, "^[A-Za-z0-9][A-Za-z0-9%-]*[A-Za-z0-9]$") ~= nil
end

--- endpoint.is_valid_host_label(value, allow_sub_domains) -> boolean
function endpoint.is_valid_host_label(value, allow_sub_domains)
  if type(value) ~= "string" or value == "" then
    return false
  end
  if js_truthy(allow_sub_domains) then
    for _, label in ipairs(split(value, ".")) do
      if not single_host_label(label) then
        return false
      end
    end
    return true
  end
  return single_host_label(value)
end

--- endpoint.is_ip_address(host) -> boolean (isIpAddress: IPv4 dotted quads, or anything
-- with a colon made of hex digits and colons, brackets allowed)
function endpoint.is_ip_address(host)
  if find(host, "^%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?$") then
    for _, octet in ipairs(split(host, ".")) do
      if tonumber(octet) > 255 then
        return false
      end
    end
    return true
  end
  if find(host, ":", 1, true) then
    local v6 = gsub(gsub(host, "^%[", ""), "%]$", "")
    return find(v6, "^[0-9a-fA-F:]+$") ~= nil
  end
  return false
end

--- endpoint.parse_url(value) -> { scheme, authority, path, normalizedPath, isIp } | nil
-- WHATWG parsing through distilled.sigv4's parser (http and https only); a URL with a
-- query is refused, and a URL with no explicit path has path "" as the Java reference
-- implementation reports it.
function endpoint.parse_url(value)
  if type(value) ~= "string" then
    return nil
  end
  local parsed = require("distilled.sigv4")._parse_url(value)
  if not parsed or (parsed.query ~= nil and parsed.query ~= "") then
    return nil
  end
  local path = parsed.path
  if path == "/" and not find(value, parsed.host .. "/", 1, true) then
    path = ""
  end
  local normalized = path
  if sub(normalized, 1, 1) ~= "/" then
    normalized = "/" .. normalized
  end
  if sub(normalized, -1) ~= "/" then
    normalized = normalized .. "/"
  end
  return {
    scheme = parsed.scheme,
    authority = parsed.host,
    path = path,
    normalizedPath = normalized,
    isIp = endpoint.is_ip_address(parsed.hostname),
  }
end

--- endpoint.substring(input, start, stop, reverse) -> string | nil
function endpoint.substring(input, start, stop, reverse)
  if type(input) ~= "string" then
    return nil
  end
  local i = type(start) == "number" and start or 0
  local j = type(stop) == "number" and stop or #input
  if i < 0 or j < 0 or i >= j or j > #input then
    return nil
  end
  if js_truthy(reverse) then
    return sub(input, #input - j + 1, #input - i)
  end
  return sub(input, i + 1, j)
end

---------------------------------------------------------------------------------------
-- AWS functions (aws-functions.ts)
---------------------------------------------------------------------------------------

local partition_data
local function partitions()
  if not partition_data then
    partition_data = require("distilled.aws.partitions")
    local regex = require("distilled.regex")
    for _, p in ipairs(partition_data.partitions) do
      p.matcher = assert(regex.compile(p.regionRegex))
    end
  end
  return partition_data
end

local OUTPUT_KEYS = {
  "name",
  "dnsSuffix",
  "dualStackDnsSuffix",
  "supportsFIPS",
  "supportsDualStack",
  "implicitGlobalRegion",
}

local function partition_info(outputs, extra)
  local info = {}
  for _, k in ipairs(OUTPUT_KEYS) do
    info[k] = outputs[k]
  end
  for k, v in pairs(extra or {}) do
    info[k] = v
  end
  return info
end

--- endpoint.partition(region) -> partition info | nil
-- A region listed by name, then one a partition's regionRegex matches, then `aws`.
function endpoint.partition(region)
  if type(region) ~= "string" then
    return nil
  end
  local data = partitions()
  for _, p in ipairs(data.partitions) do
    if p.regions[region] then
      return partition_info(p.outputs, p.regions[region])
    end
  end
  for _, p in ipairs(data.partitions) do
    if p.matcher:test(region) then
      return partition_info(p.outputs)
    end
  end
  for _, p in ipairs(data.partitions) do
    if p.id == "aws" then
      return partition_info(p.outputs)
    end
  end
  return nil
end

--- endpoint.dns_suffix(region) -> the partition's DNS suffix (amazonaws.com by default)
function endpoint.dns_suffix(region)
  local p = endpoint.partition(region)
  return p and p.dnsSuffix or "amazonaws.com"
end

--- endpoint.parse_arn(value) -> { partition, service, region, accountId, resourceId } | nil
function endpoint.parse_arn(value)
  if type(value) ~= "string" then
    return nil
  end
  local segments = split(value, ":")
  if #segments < 6 then
    return nil
  end
  local rest = {}
  for i = 6, #segments do
    rest[#rest + 1] = segments[i]
  end
  local resource = table.concat(rest, ":")
  if segments[1] ~= "arn" or segments[2] == "" or segments[3] == "" or resource == "" then
    return nil
  end
  local ids = {}
  for _, r in ipairs(rest) do
    for _, part in ipairs(split(r, "/")) do
      ids[#ids + 1] = part
    end
  end
  return {
    partition = segments[2],
    service = segments[3],
    region = segments[4],
    accountId = segments[5],
    resourceId = ids,
  }
end

--- endpoint.is_virtual_hostable_s3_bucket(value, allow_sub_domains) -> boolean
function endpoint.is_virtual_hostable_s3_bucket(value, allow_sub_domains)
  if type(value) ~= "string" then
    return false
  end
  if js_truthy(allow_sub_domains) then
    for _, label in ipairs(split(value, ".")) do
      if not endpoint.is_virtual_hostable_s3_bucket(label, false) then
        return false
      end
    end
    return true
  end
  if not endpoint.is_valid_host_label(value, false) then
    return false
  end
  if #value < 3 or #value > 63 or value ~= lower(value) then
    return false
  end
  return not endpoint.is_ip_address(value)
end

---------------------------------------------------------------------------------------
-- evaluation
---------------------------------------------------------------------------------------

local FUNCTIONS = {}
FUNCTIONS["isSet"] = function(a)
  return a ~= nil
end
FUNCTIONS["not"] = function(a)
  return not js_truthy(a)
end
FUNCTIONS["booleanEquals"] = function(a, b)
  return a == b
end
FUNCTIONS["stringEquals"] = FUNCTIONS["booleanEquals"]
FUNCTIONS["getAttr"] = function(v, path)
  return endpoint.get_attr(v, path)
end
FUNCTIONS["aws.partition"] = function(r)
  return endpoint.partition(r)
end
FUNCTIONS["aws.parseArn"] = function(v)
  return endpoint.parse_arn(v)
end
FUNCTIONS["aws.isVirtualHostableS3Bucket"] = function(v, sub_domains)
  return endpoint.is_virtual_hostable_s3_bucket(v, sub_domains)
end
FUNCTIONS["parseURL"] = function(v)
  return endpoint.parse_url(v)
end
FUNCTIONS["substring"] = function(s, i, j, rev)
  return endpoint.substring(s, i, j, rev)
end
FUNCTIONS["uriEncode"] = function(v)
  if type(v) ~= "string" then
    return nil
  end
  -- RFC 3986 (Smithy's uriEncode, the endpoint tests): also !'()*, which JavaScript's
  -- encodeURIComponent keeps. Distilled uses encodeURIComponent, and fails the 18 S3
  -- endpoint tests with a bucket named "bucket!"; we do not copy that.
  return (
    gsub(url.encode_component(v), "[!'()*]", function(c)
      return string.format("%%%02X", string.byte(c))
    end)
  )
end
FUNCTIONS["isValidHostLabel"] = function(v, sub_domains)
  return endpoint.is_valid_host_label(v, sub_domains)
end

-- The functions the engine knows; the generator refuses a rule set calling another.
endpoint.FUNCTIONS = FUNCTIONS

local eval

-- "{Region}.{PartitionResult#dnsSuffix}" -> the text, JavaScript template semantics.
local function template(s, scope)
  if not find(s, "{", 1, true) then
    return s
  end
  return (
    gsub(s, "{([^}]+)}", function(expr)
      local hash = find(expr, "#", 1, true)
      local v
      if hash then
        v = endpoint.get_attr(scope[sub(expr, 1, hash - 1)], (gsub(sub(expr, hash + 1), "#", ".")))
      else
        v = scope[expr]
      end
      return url.text(v)
    end)
  )
end

local function call(fn, argv, scope, depth)
  local f = FUNCTIONS[fn]
  if not f then
    return nil, "unknown rules engine function " .. tostring(fn)
  end
  local args = {}
  local n = argv and #argv or 0
  for i = 1, n do
    local v, err = eval(argv[i], scope, depth + 1)
    if err then
      return nil, err
    end
    args[i] = v
  end
  return f(args[1], args[2], args[3], args[4]), nil
end

eval = function(expr, scope, depth)
  if depth > MAX_DEPTH then
    return nil, "endpoint rule expression nested deeper than " .. MAX_DEPTH
  end
  local t = type(expr)
  if t == "string" then
    return template(expr, scope)
  elseif t ~= "table" then
    return expr
  end
  if type(expr.ref) == "string" then
    return scope[expr.ref]
  end
  if type(expr.fn) == "string" then
    return call(expr.fn, expr.argv, scope, depth)
  end
  local out = {}
  for k, v in pairs(expr) do
    local value, err = eval(v, scope, depth + 1)
    if err then
      return nil, err
    end
    out[k] = value
  end
  return out
end

local function endpoint_result(e, scope, depth)
  local u, err = eval(e.url, scope, depth)
  if err then
    return nil, err
  end
  local properties, headers = {}, {}
  for k, v in pairs(e.properties or {}) do
    properties[k], err = eval(v, scope, depth)
    if err then
      return nil, err
    end
  end
  for k, values in pairs(e.headers or {}) do
    local list = {}
    for i, v in ipairs(values) do
      list[i], err = eval(v, scope, depth)
      if err then
        return nil, err
      end
    end
    headers[k] = list
  end
  return { url = url.text(u), properties = properties, headers = headers }
end

-- Evaluate one rule: returns "endpoint", result | "error", message | nil (no match),
-- and a fourth value for an engine failure.
local function run_rule(rule, scope, depth)
  if depth > MAX_DEPTH then
    return "error", nil, "endpoint rules nested deeper than " .. MAX_DEPTH
  end
  local assigned = {}
  local function restore()
    for i = #assigned, 1, -1 do
      local a = assigned[i]
      scope[a.name] = a.old
    end
  end
  for _, cond in ipairs(rule.conditions or {}) do
    local v, err = call(cond.fn, cond.argv, scope, depth)
    if err then
      restore()
      return "error", nil, err
    end
    if cond.assign then
      assigned[#assigned + 1] = { name = cond.assign, old = scope[cond.assign] }
      scope[cond.assign] = v
      if v == nil or v == false then
        restore()
        return nil
      end
    elseif not js_truthy(v) then
      restore()
      return nil
    end
  end
  local kind, value, err
  if rule.type == "tree" then
    for _, child in ipairs(rule.rules or {}) do
      kind, value, err = run_rule(child, scope, depth + 1)
      if kind then
        break
      end
    end
  elseif rule.type == "endpoint" then
    value, err = endpoint_result(rule.endpoint, scope, depth)
    kind = "endpoint"
  elseif rule.type == "error" then
    value, err = eval(rule.error, scope, depth)
    value = url.text(value)
    kind = "error"
  else
    err = "unknown endpoint rule type " .. tostring(rule.type)
    kind = "error"
  end
  restore()
  return kind, value, err
end

--- endpoint.resolve(rule_set, params) -> { url, properties, headers } | nil, message, failed
-- `message` is the rule set's error (an EndpointError for the caller); `failed` is true
-- when the engine itself could not evaluate the rules (an unknown function, too deep).
function endpoint.resolve(rule_set, params)
  local scope = {}
  for name, def in pairs(rule_set.parameters or {}) do
    local v = params[name]
    if v == nil then
      v = def.default
    end
    scope[name] = v
  end
  for _, rule in ipairs(rule_set.rules or {}) do
    local kind, value, err = run_rule(rule, scope, 1)
    if err then
      return nil, err, true
    end
    if kind == "endpoint" then
      return value
    elseif kind == "error" then
      return nil, value
    end
  end
  return nil, "No matching endpoint rule"
end

--- endpoint.functions_of(rule_set) -> sorted list of the function names it calls
-- (the generator checks them against endpoint.FUNCTIONS). Walks with an explicit stack.
function endpoint.functions_of(rule_set)
  local seen, out = {}, {}
  local stack = { rule_set.rules }
  while #stack > 0 do
    local v = stack[#stack]
    stack[#stack] = nil
    if type(v) == "table" then
      if type(v.fn) == "string" and not seen[v.fn] then
        seen[v.fn] = true
        out[#out + 1] = v.fn
      end
      for _, x in pairs(v) do
        if type(x) == "table" then
          stack[#stack + 1] = x
        end
      end
    end
  end
  table.sort(out)
  return out
end

return endpoint
