-- The AWS protocol object a generated AWS client hands to Client.define.
--
-- Port of Distilled's packages/s3/src/protocol.ts (the call: idempotency tokens ->
-- serializer -> checksum middleware -> endpoint resolution -> host prefix -> SigV4) and
-- client/response-parser.ts (success decoding by validation mode, error matching), with
-- the wire protocols in aws/json_protocols.lua, aws/query.lua and aws/rest_xml.lua.
--
--   local protocol = aws.new(service, {
--     protocol = "awsJson1_0" | "awsJson1_1" | "restJson1" | "awsQuery" | "ec2Query"
--              | "restXml",
--     target = "DynamoDB_20120810",     -- awsJson: X-Amz-Target is <target>.<Op>
--     sdk_id, signing_name, endpoint_prefix, version, xmlns, query_compatible,
--     auth = nil (sigv4) | "bearer" | "sigv2", sigv4a, default_ts,
--     errors = { [tag] = { query_code, status, synthetic, headers } },
--     rules = function() return <ruleset JSON text> end,
--   })
--   protocol.call(ctx, op, input) / protocol.encode(ctx, op, input, opts) /
--   protocol.decode(ctx, op, response)
--   aws.options(auth) -> the client options of an AWS client
--
-- Region: input.region (when the operation has no region member of its own), the
-- `region` option, then the region the credentials carry (AWS_REGION,
-- AWS_DEFAULT_REGION, the profile's region). Credentials: the `credentials` option (a
-- source: aws.credentials.chain{...}, .static{...}, a function, or a secret table),
-- else the default chain (aws.credentials.default).
local codec = require("distilled.aws.codec")
local compat = require("distilled.compat")
local aws_credentials = require("distilled.aws.credentials")
local aws_errors = require("distilled.aws.errors")
local endpoint = require("distilled.aws.endpoint")
local errors = require("distilled.errors")
local http = require("distilled.aws.http")
local json = require("distilled.json")
local noop = require("distilled.trace.noop")
local secret = require("distilled.secret")

local M = {}

M.VERSION = "1"
M.USER_AGENT = "distilled-lua/aws"

local IMPLS = {
  awsJson1_0 = function()
    return require("distilled.aws.json_protocols").awsJson1_0
  end,
  awsJson1_1 = function()
    return require("distilled.aws.json_protocols").awsJson1_1
  end,
  restJson1 = function()
    return require("distilled.aws.json_protocols").restJson1
  end,
  awsQuery = function()
    return require("distilled.aws.query").awsQuery
  end,
  ec2Query = function()
    return require("distilled.aws.query").ec2Query
  end,
  restXml = function()
    return require("distilled.aws.rest_xml")
  end,
}
M.PROTOCOLS = IMPLS

-- Operations with a streaming input sign UNSIGNED-PAYLOAD, except on the services that
-- reconstruct the canonical request from the body (protocol.ts hasStreamingInput).
local SIGNS_STREAMING_PAYLOAD = {
  ["Glacier"] = true,
  ["SageMaker Runtime"] = true,
  ["AppConfig"] = true,
  ["ApiGatewayManagementApi"] = true,
  ["Bedrock Runtime"] = true,
  ["IoT Data Plane"] = true,
  ["IoT Wireless"] = true,
  ["Lambda"] = true,
}

--- M.options(auth) -> option specs for Client.define
function M.options(auth)
  local o = {
    region = {
      type = "string",
      doc = "the AWS region (else AWS_REGION, AWS_DEFAULT_REGION, the profile's region)",
    },
    endpoint = {
      type = "string",
      env = "AWS_ENDPOINT_URL",
      doc = "a custom endpoint URL (LocalStack, a proxy): replaces the endpoint rules",
    },
    credentials = {
      secret = true,
      default = aws_credentials.default,
      doc = "a credentials source (distilled.aws.credentials); default: the provider chain",
    },
  }
  if auth == "bearer" then
    o.token = { secret = true, env = "AWS_BEARER_TOKEN", doc = "the bearer token" }
  end
  return o
end

-- the members of an input node, cached on the node (a long-lived schema table)
local function input_node(service, op)
  return codec.resolve(op.input, service.shapes)
end

local function has_member(node, name)
  for _, m in ipairs(node and node.members or {}) do
    if m.name == name then
      return true
    end
  end
  return false
end

-- a random UUID v4 from host.random (idempotency tokens)
local function uuid(random)
  local hex = "0123456789abcdef"
  local out = {}
  for i = 1, 32 do
    local n = math.floor(random() * 16)
    if i == 13 then
      n = 4
    elseif i == 17 then
      n = 8 + (n % 4)
    end
    out[#out + 1] = string.sub(hex, n + 1, n + 1)
  end
  local s = table.concat(out)
  return string.sub(s, 1, 8)
    .. "-"
    .. string.sub(s, 9, 12)
    .. "-"
    .. string.sub(s, 13, 16)
    .. "-"
    .. string.sub(s, 17, 20)
    .. "-"
    .. string.sub(s, 21, 32)
end
M._uuid = uuid

local function lower_headers(h)
  local out = {}
  for k, v in pairs(h or {}) do
    out[string.lower(k)] = v
  end
  return out
end

local function header_lookup(headers, name)
  local lname = string.lower(name)
  for k, v in pairs(headers) do
    if string.lower(k) == lname then
      return v, k
    end
  end
  return nil
end

-- X-Amzn-Trace-Id from a span (core telemetry-xray.ts traceHeader)
function M.xray_header(trace_id, span_id, sampled)
  return "Root=1-"
    .. string.sub(trace_id, 1, 8)
    .. "-"
    .. string.sub(trace_id, 9)
    .. ";Parent="
    .. span_id
    .. ";Sampled="
    .. (sampled and "1" or "0")
end

local function now_epoch(host)
  local f = host.epoch or os.time
  return f()
end

---------------------------------------------------------------------------------------
-- the protocol object
---------------------------------------------------------------------------------------

function M.new(service, args)
  if type(service) ~= "table" or type(args) ~= "table" then
    compat.raise("distilled.aws.protocol.new: expected (service, args)", 2)
  end
  local load_impl = IMPLS[args.protocol]
  if not load_impl then
    compat.raise("distilled.aws.protocol.new: unknown protocol " .. tostring(args.protocol), 2)
  end
  local impl = load_impl()
  local protocol = { name = args.protocol, args = args }
  local facts = args.errors or {}
  local key_cache = {}
  local rules -- decoded on first use
  local rules_loaded = false
  local endpoint_cache, endpoint_cache_size = {}, 0

  local function ruleset()
    if not rules_loaded then
      rules_loaded = true
      if args.rules then
        local text = args.rules()
        rules = type(text) == "string" and json.decode(text) or text
      end
    end
    return rules
  end

  -- what an operation's messages may quote (s3/src/util/codec.ts inputEncoder,
  -- outputBody, errorBody): nothing of a shape that can hold a secret. Cached on the
  -- descriptor, a long-lived key.
  local function withhold_of(op, registry)
    local w = op._aws_withhold
    if w == nil then
      local redact = require("distilled.redact")
      local errs = false
      for _, tag in ipairs(op.errors or {}) do
        local cls = service.errors and service.errors[tag]
        local f = facts[tag]
        local body = f and f.shape and registry[f.shape]
        if cls and body and redact.holds_sensitive(body, registry) then
          errs = true
        end
      end
      w = {
        input = op.input ~= nil and redact.holds_sensitive(op.input, registry) or false,
        output = op.output ~= nil and redact.holds_sensitive(op.output, registry) or false,
        errors = errs,
      }
      op._aws_withhold = w
    end
    return w
  end

  local function pctx(ctx, op)
    local registry = service.shapes
    local w = op and withhold_of(op, registry) or {}
    return {
      aws = args,
      registry = registry,
      env = {
        registry = registry,
        timestamp = args.default_ts,
        wire_keys = args.protocol == "restJson1"
          or args.protocol == "awsJson1_0"
          or args.protocol == "awsJson1_1",
        withhold = w.input or nil,
      },
      validation = ctx and ctx.validation or "lenient",
      withhold_input = w.input or nil,
      withhold_output = w.output or nil,
      withhold_errors = w.errors or nil,
    }
  end

  -- region / credentials from the client's resolved options
  local function identity_of(opts, host)
    local creds = secret.unwrap(opts.credentials)
    if type(creds) ~= "table" then
      return nil,
        errors.new("ConfigError", {
          message = "the credentials option must give a table { access_key_id, secret_access_key, session_token? }",
          key = "credentials",
        })
    end
    if creds.region == nil then
      -- a plain function or secret source: the region from the environment / profile
      local copy = {}
      for k, v in pairs(creds) do
        copy[k] = v
      end
      copy.region = aws_credentials.region(host)
      creds = copy
    end
    return creds
  end

  -- endpoint rules -> { url, signing_region, signing_name } | nil, err
  local function resolve_endpoint(op, input, region, node)
    local rs = ruleset()
    local signing_region, signing_name = region, args.signing_name
    if rs == nil then
      return {
        url = "https://"
          .. (args.signing_name or args.endpoint_prefix)
          .. "."
          .. region
          .. "."
          .. endpoint.dns_suffix(region),
        signing_region = region,
        signing_name = signing_name,
      }
    end
    local params = { Region = region }
    local key = region
    local static = op.aws and op.aws.static_params
    if static then
      for k, v in pairs(static) do
        params[k] = v
      end
    end
    local context_members = {}
    for _, m in ipairs(node.members or {}) do
      if m.context_param then
        local v = input[m.name]
        if v ~= nil and v ~= json.null then
          params[m.context_param] = secret.unwrap(v)
          context_members[#context_members + 1] = m
        end
        if type(v) == "table" then
          key = nil
        elseif key then
          key = key .. "\0" .. type(v) .. tostring(v)
        end
      end
    end
    local cached = key and endpoint_cache[op.name .. "\0" .. key]
    local resolved = cached
    if not resolved then
      local e, message = endpoint.resolve(rs, params)
      if not e then
        return nil, errors.new(aws_errors.EndpointError, { message = tostring(message) })
      end
      resolved = e
      if key then
        if endpoint_cache_size >= 64 then
          endpoint_cache, endpoint_cache_size = {}, 0
        end
        endpoint_cache[op.name .. "\0" .. key] = resolved
        endpoint_cache_size = endpoint_cache_size + 1
      end
    end
    local schemes = resolved.properties and resolved.properties.authSchemes
    local sigv4a
    if type(schemes) == "table" and type(schemes[1]) == "table" then
      local first = schemes[1]
      local has_v4 = false
      for _, s in ipairs(schemes) do
        has_v4 = has_v4 or (type(s) == "table" and s.name == "sigv4")
      end
      if first.name == "sigv4a" and not has_v4 then
        sigv4a = true
      end
      if first.signingRegion then
        signing_region = first.signingRegion
      end
      if first.signingName then
        signing_name = first.signingName
      end
    end
    return {
      url = resolved.url,
      signing_region = signing_region,
      signing_name = signing_name,
      sigv4a = sigv4a,
      context_members = context_members,
    }
  end

  -- adjustRequestPath: a label the rules moved into the host comes off the path
  local function adjust_path(request, url, context_members, input)
    local host = string.match(url, "^%a[%w+.-]*://([^/:?#]+)")
    local path = string.match(url, "^%a[%w+.-]*://[^/?#]*(/[^?#]*)") or ""
    if not host then
      return
    end
    for _, m in ipairs(context_members) do
      if m.bind == "label" then
        local v = input[m.name]
        if type(v) == "string" then
          local prefix = "/" .. http.encode_label(v)
          local trimmed = string.gsub(path, "/$", "")
          if string.sub(host, 1, #v + 1) == v .. "." or string.sub(trimmed, -#prefix) == prefix then
            if string.sub(request.path, 1, #prefix) == prefix then
              local rest = string.sub(request.path, #prefix + 1)
              if rest == "/" then
                rest = ""
              end
              request.path = rest
              return
            end
          end
        end
      end
    end
  end

  --- protocol.encode(ctx, op, input, opts) -> request | nil, err  (no send)
  -- opts = the client's resolved options (ctx.credentials()), or { region, credentials }
  function protocol.encode(ctx, op, input, opts)
    ctx = ctx or {}
    opts = opts or {}
    local host = ctx.host or {}
    if type(input) ~= "table" then
      input = {}
    end
    local node = input_node(service, op)
    local p = pctx(ctx, op)

    -- the call's region (RegionInput): input.region, unless the op models `region`
    local call_region
    local copy = {}
    for k, v in pairs(input) do
      copy[k] = v
    end
    if not has_member(node, "region") and type(copy.region) == "string" then
      call_region = copy.region
      copy.region = nil
    end
    input = copy

    local identity, ierr
    if args.auth == "bearer" then
      identity = {}
    elseif opts.credentials ~= nil then
      identity, ierr = identity_of(opts, host)
      if not identity then
        return nil, ierr
      end
    else
      return nil, errors.new("ConfigError", { message = "no AWS credentials", key = "credentials" })
    end
    if identity.expiration and aws_credentials.expired(identity, now_epoch(host)) then
      -- the operation layer clears the credentials cache and calls once more
      return nil,
        errors.new("Unauthorized", {
          message = "the AWS credentials expired ("
            .. tostring(identity.provider or "source")
            .. ")",
          expired = true,
        })
    end
    local region = call_region or opts.region or identity.region
    if region == nil or region == "" then
      return nil,
        errors.new(aws_credentials.MissingRegion, {
          message = "no AWS region: pass region = ..., or set AWS_REGION (or AWS_DEFAULT_REGION)",
          hints = {
            "Set AWS_REGION (or AWS_DEFAULT_REGION).",
            "Or set `region` on the profile in ~/.aws/config.",
          },
        })
    end

    -- idempotency tokens the caller did not set
    for _, m in ipairs(node.members or {}) do
      if m.idempotency_token and input[m.name] == nil then
        input[m.name] = uuid(host.random or math.random)
      end
    end

    local request, err = impl.encode(p, op, input)
    if not request then
      return nil, err
    end
    local headers = request.headers
    if op._aws_event_input then
      -- an input event stream (distilled.aws.stream): the body is the signed events, sent
      -- after the request; the request is signed for them (middleware-eventstream)
      request.body = nil
      request.streaming_input = nil
      for k in pairs(headers) do
        local l = string.lower(k)
        if l == "content-type" or l == "x-amz-content-sha256" then
          headers[k] = nil
        end
      end
      headers["Content-Type"] = "application/vnd.amazon.eventstream"
      headers["X-Amz-Content-Sha256"] = "STREAMING-AWS4-HMAC-SHA256-EVENTS"
    end

    -- requestCompression (middleware/compression.ts): gzip a body of known size of at
    -- least 10 KiB, appending "gzip" to any Content-Encoding the caller set
    if op.aws and op.aws.gzip and type(request.body) == "string" then
      local gzip = require("distilled.aws.gzip")
      if #request.body >= gzip.MIN_COMPRESSION_SIZE_BYTES then
        request.body = gzip.compress(request.body)
        local name = "Content-Encoding"
        for k in pairs(headers) do
          if string.lower(k) == "content-encoding" then
            name = k
          end
        end
        headers[name] = headers[name] and (headers[name] .. ", gzip") or "gzip"
      end
    end

    -- httpChecksum (middleware/checksum.ts): Content-MD5, or the requested algorithm
    local checksum = op.aws and op.aws.checksum
    if checksum and request.body ~= nil and request.body ~= "" then
      local algorithm = header_lookup(headers, "x-amz-sdk-checksum-algorithm")
      algorithm = algorithm and string.lower(algorithm) or nil
      if checksum.required or algorithm then
        algorithm = algorithm or "md5"
        local name = algorithm == "md5" and "Content-MD5" or ("x-amz-checksum-" .. algorithm)
        if not header_lookup(headers, name) then
          local crypto = require("distilled.crypto")
          if algorithm == "md5" then
            headers[name] = crypto.base64.encode(crypto.md5(request.body))
          elseif algorithm == "crc32" then
            headers[name] = crypto.base64.encode(
              require("distilled.crypto.crc32").bytes(crypto.crc32(request.body))
            )
          elseif algorithm == "crc32c" then
            headers[name] = crypto.base64.encode(
              require("distilled.crypto.crc32").bytes(crypto.crc32c(request.body))
            )
          elseif algorithm == "sha256" then
            headers[name] = crypto.base64.encode(crypto.sha256(request.body))
          elseif algorithm == "sha1" then
            headers[name] = crypto.base64.encode(crypto.sha1(request.body))
          end
        end
      end
    end

    -- endpoint: the custom one, else the rules
    local custom = opts.endpoint
    local url, signing_region, signing_name = nil, region, args.signing_name
    if custom ~= nil and custom ~= "" then
      url = string.gsub(custom, "/$", "")
    else
      local e, eerr = resolve_endpoint(op, input, region, node)
      if not e then
        return nil, eerr
      end
      if e.sigv4a then
        return nil,
          errors.new("SdkError", {
            message = (args.sdk_id or "this service")
              .. ": the endpoint requires SigV4A signing, which distilled-lua does not implement",
          })
      end
      url = e.url
      signing_region, signing_name = e.signing_region, e.signing_name
      adjust_path(request, url, e.context_members or {}, input)
      -- smithy.api#endpoint hostPrefix (not with a custom endpoint)
      local prefix = op.aws and op.aws.host_prefix
      if prefix then
        local bad
        local resolved_prefix = string.gsub(prefix, "{([%w_]+)}", function(member)
          local v = input[member]
          v = v == nil and "" or tostring(secret.unwrap(v))
          if not endpoint.is_valid_host_label(v, true) then
            bad = bad or http.invalid_host_label(member, v)
          end
          return v
        end)
        if bad then
          return nil, bad
        end
        local scheme_end = string.find(url, "://", 1, true)
        if scheme_end then
          local host_start = scheme_end + 3
          if string.sub(url, host_start, host_start + #resolved_prefix - 1) ~= resolved_prefix then
            url = string.sub(url, 1, host_start - 1)
              .. resolved_prefix
              .. string.sub(url, host_start)
          end
        end
      end
    end

    local query = http.query_string(request.query or {})
    local full = url .. (request.path or "/") .. (query ~= "" and ("?" .. query) or "")
    local out = {
      method = request.method,
      url = full,
      headers = headers,
      body = request.body,
    }
    if args.auth == "bearer" then
      local token = opts.token and secret.unwrap(opts.token)
      if token == nil then
        return nil, errors.new("ConfigError", { message = "no bearer token", key = "token" })
      end
      headers["Authorization"] = "Bearer " .. token
      return out
    end
    if args.auth == "sigv2" then
      -- SimpleDB (sigv2.ts): the signature travels in the form body
      return require("distilled.aws.sigv2").sign({
        request = out,
        credentials = identity,
        now_epoch = now_epoch(host),
      })
    end

    -- SigV4
    local has_sha = header_lookup(headers, "x-amz-content-sha256") ~= nil
    local service_checksum = header_lookup(headers, "x-amz-checksum") ~= nil
    local streaming_input = request.streaming_input == true
      and not SIGNS_STREAMING_PAYLOAD[args.sdk_id]
    local unsigned_payload = (streaming_input or (service_checksum and request.body ~= nil))
      and not has_sha
    if op.aws and op.aws.unsigned_payload and not has_sha then
      unsigned_payload = true
    end
    local sign_headers = headers
    if unsigned_payload then
      sign_headers = {}
      for k, v in pairs(headers) do
        sign_headers[k] = v
      end
      sign_headers["X-Amz-Content-Sha256"] = "UNSIGNED-PAYLOAD"
    end
    local signed, serr = require("distilled.sigv4").sign({
      request = {
        method = out.method,
        url = out.url,
        headers = sign_headers,
        body = (not unsigned_payload) and out.body or nil,
      },
      credentials = {
        access_key_id = identity.access_key_id,
        secret_access_key = identity.secret_access_key,
        session_token = identity.session_token,
      },
      region = signing_region,
      service = signing_name,
      now_epoch = now_epoch(host),
      hash_payload = (args.sdk_id == "S3 Control" or args.sdk_id == "Glacier")
        and not unsigned_payload
        and not has_sha,
      key_cache = key_cache,
    })
    if not signed then
      return nil, serr
    end
    signed.body = out.body
    return signed
  end

  ---------------------------------------------------------------------------------
  -- decoding
  ---------------------------------------------------------------------------------

  local function what(op)
    return (args.sdk_id or service.name or "AWS") .. "." .. tostring(op.name)
  end

  local function decode_env(p, by_name, header)
    local env = {
      registry = p.registry,
      timestamp = header and "http-date" or p.env.timestamp,
      by_name = by_name,
    }
    local mode = p.validation
    if mode == "strict" then
      env.exact = "closed"
    elseif mode == "additional" then
      env.exact = true
    end
    return env
  end

  local function decode_success(ctx, op, res)
    local p = pctx(ctx, op)
    local registry = p.registry
    local node = codec.resolve(op.output, registry)
    if node == nil then
      return json.object({})
    end
    local redact = require("distilled.redact")
    local sensitive = redact.holds_sensitive(node, registry)
    local read = impl.read(p, op, res)
    local strict = p.validation ~= "lenient"
    if read.unreadable then
      if strict or sensitive then
        return nil, read.unreadable
      end
      return read.as_read
    end
    local out
    local failure
    if read.by_name then
      out, failure = codec.decode(node, read.members or json.object({}), decode_env(p, true))
      -- a blob payload is the body's bytes as read, not base64 to decode
      if out and type(out) == "table" and read.raw then
        for name in pairs(read.raw) do
          out[name] = read.members[name]
        end
      end
    else
      local body = read.body or json.object({})
      out, failure = codec.decode(node, body, decode_env(p, false))
      if out and type(out) == "table" then
        for _, m in ipairs(node.members or {}) do
          local v = read.members and read.members[m.name]
          if v ~= nil then
            if read.raw and read.raw[m.name] then
              out[m.name] = v
            else
              local d, f = codec.decode_member(m, v, decode_env(p, false, m.bind == "header"))
              if f then
                failure = failure or codec.within(f, m.name)
              else
                out[m.name] = d
              end
            end
          end
        end
      end
    end
    if failure then
      local message = what(op)
        .. " response does not match its output schema: "
        .. codec.failure_message(failure, sensitive)
      if strict then
        return nil, codec.parse_error(message)
      end
      -- lenient: decode again keeping what does not fit
      out = codec.decode(node, read.by_name and read.members or read.body or {}, {
        registry = registry,
        timestamp = p.env.timestamp,
        by_name = read.by_name,
      })
    end
    -- a streaming payload the response leaves empty is "" (Distilled returns an empty
    -- stream: S3 GetObject of an empty object)
    if type(out) == "table" then
      for _, m in ipairs(node.members or {}) do
        if m.bind == "payload" and out[m.name] == nil then
          local target = codec.resolve(m.schema, registry)
          if target and target.streaming and target.t == "blob" then
            out[m.name] = ""
          end
        end
      end
    end
    if sensitive and out ~= nil then
      out = redact.wrap(node, out, registry)
    end
    return out
  end

  -- the error for a wire code and its data (an error body's fields), as matched against
  -- the operation's classes: read_error's result, or an event stream's exception
  local function build_error(ctx, op, res, code, data)
    local p = pctx(ctx, op)
    data = data or {}
    if type(data.Message) == "string" and data.message == nil then
      data.message = data.Message
    end
    local message = type(data.message) == "string" and data.message or ""
    local tbl = aws_errors.table_for(op, service, facts)
    local cls, fallback, hits = aws_errors.match(tbl, code, res.status, message)
    if fallback == "internal" then
      return errors.new(aws_errors.InternalError, { status = res.status, headers = res.headers })
    elseif fallback == "parse" then
      return codec.parse_error(
        "No error code found in response and "
          .. tostring(hits)
          .. " declared errors match status "
          .. tostring(res.status)
          .. ". Data: "
          .. (json.encode(data) or "?")
      )
    end
    if cls then
      local fields = {
        status = res.status,
        code = code,
        headers = res.headers,
      }
      local f = facts[cls.tag] or {}
      for _, h in ipairs(f.headers or {}) do
        local v = res.headers[h.header]
        if v ~= nil then
          if h.kind == "number" then
            data[h.name] = http.js_number(v)
          elseif h.kind == "boolean" then
            data[h.name] = v == "true"
          else
            data[h.name] = v
          end
        end
      end
      -- a JSON error body decodes through the error's structure (jsonName, timestamps,
      -- nested shapes); a body that does not fit keeps its wire values
      if f.shape and p.registry[f.shape] then
        local decoded = codec.decode(p.registry[f.shape], data, decode_env(p, false))
        if type(decoded) == "table" then
          for k, v in pairs(decoded) do
            data[k] = v
          end
        end
      end
      for _, name in ipairs(cls.fields or {}) do
        local v = data[name]
        if v == nil then
          local lc = string.lower(string.sub(name, 1, 1)) .. string.sub(name, 2)
          v = data[lc]
        end
        if v ~= nil and fields[name] == nil then
          fields[name] = v
        end
      end
      if message ~= "" then
        fields.message = message
      else
        fields.message = cls.tag
      end
      return errors.new(cls, fields)
    end
    return errors.new(aws_errors.UnknownAwsError, {
      status = res.status,
      code = code,
      body = data,
      headers = res.headers,
      service = args.sdk_id,
      operation = op.name,
      message = message ~= "" and message
        or (code ~= "" and code or ("HTTP " .. tostring(res.status))),
    })
  end

  local function decode_failure(ctx, op, res)
    local code, data = impl.read_error(pctx(ctx, op), op, res)
    if code == nil then
      -- unreadable error bodies: a ParseError (data is the error)
      return data
    end
    return build_error(ctx, op, res, code, data)
  end

  --- protocol.decode(ctx, op, response) -> value | nil, err
  function protocol.decode(ctx, op, res)
    local r = {
      status = res.status,
      headers = lower_headers(res.headers),
      body = res.body or "",
    }
    if r.status >= 200 and r.status < 300 then
      return decode_success(ctx, op, r)
    end
    return nil, decode_failure(ctx, op, r)
  end

  ---------------------------------------------------------------------------------
  -- the call
  ---------------------------------------------------------------------------------

  -- credentials, the signed request, trace propagation, user agent | nil, err
  local function prepare(ctx, op, input)
    local tracer = ctx.tracer or noop
    local opts, cerr = {}, nil
    if ctx.credentials then
      opts, cerr = tracer:with("distilled.credentials", { debug = true }, function()
        return ctx.credentials()
      end)
      -- an optionalAuth operation needs credentials too, as in Distilled (which signs
      -- every request): the client resolves every option at once, so without them
      -- there is no region or endpoint either
      if opts == nil then
        return nil, cerr
      end
    end

    local req, berr = tracer:with("distilled.request.build", { debug = true }, function()
      return protocol.encode(ctx, op, input, opts)
    end)
    if req == nil then
      return nil, berr
    end
    local h = req.headers
    -- trace propagation: X-Amzn-Trace-Id (xray) or traceparent (w3c)
    local propagate = service.telemetry and service.telemetry.propagate
    if propagate ~= false then
      local current = tracer:current()
      if propagate == "xray" then
        if current and current.recording and current.trace_id then
          h["x-amzn-trace-id"] = M.xray_header(current.trace_id, current.span_id, true)
        else
          local tp = tracer:traceparent()
          local trace_id, span_id, flags = tp and string.match(tp, "^%x%x%-(%x+)%-(%x+)%-(%x%x)$")
          if trace_id then
            h["x-amzn-trace-id"] = M.xray_header(trace_id, span_id, flags ~= "00")
          end
        end
      else
        local tp = tracer:traceparent()
        if tp then
          h["traceparent"] = tp
        end
      end
    end
    if h["user-agent"] == nil then
      h["user-agent"] = ctx.user_agent or M.USER_AGENT
    end
    req.timeout = ctx.timeout
    local span = ctx.span or noop.NOOP_SPAN
    local server = string.match(req.url, "^%a[%w+.-]*://([^/:?#]+)")
    span:set("http.request.method", req.method)
    span:set("server.address", server)
    if ctx.attempt then
      ctx.attempt.host = server
    end
    return req, opts
  end

  -- what distilled.aws.stream needs of this protocol
  local kit = {
    service = service,
    args = args,
    what = what,
    decode = function(ctx, op, res)
      return protocol.decode(ctx, op, res)
    end,
    decode_success = decode_success,
    build_error = build_error,
    prepare = prepare,
    identity = function(opts, host)
      if args.auth == "bearer" or args.auth == "sigv2" then
        return nil
      end
      return identity_of(opts, host)
    end,
  }

  --- protocol.stream(ctx, op, input) -> parts, nil, meta | nil, err, meta
  -- An event stream operation (op.stream), its events delivered as they arrive; see
  -- distilled.aws.stream. parts = { status, headers, output, next, close, send?,
  -- close_input? } (send / close_input for the operations that stream events both ways).
  function protocol.stream(ctx, op, input)
    ctx = ctx or {}
    return require("distilled.aws.stream").stream(kit, ctx, op, input)
  end

  function protocol.call(ctx, op, input)
    local tracer = ctx.tracer or noop
    local span = ctx.span or noop.NOOP_SPAN
    local host = ctx.host or {}
    local attempt = ctx.attempt or {}
    if op.unsupported then
      return nil,
        errors.new("SdkError", {
          message = what(op)
            .. ": "
            .. tostring(op.unsupported)
            .. " operations are not supported yet",
        })
    end
    if op.stream and op.stream.input then
      return nil,
        errors.new("SdkError", {
          message = what(op)
            .. " streams events both ways: call it through its _stream method (stream:send(event), stream:close_input())",
        })
    end

    local req, berr = prepare(ctx, op, input)
    if req == nil then
      return nil, berr
    end

    local server = attempt.host or string.match(req.url, "^%a[%w+.-]*://([^/:?#]+)")

    local transport = host.transport
    if transport == nil then
      return nil,
        errors.new("ConfigError", {
          message = 'no transport; pass host = require("distilled.host.popen")() (or transport = ...)',
          key = "transport",
        })
    end
    local res, terr = tracer:with("distilled.transport", {
      debug = true,
      attributes = { ["http.request.method"] = req.method, ["server.address"] = server },
    }, function(s)
      local r, e = transport(req)
      if type(r) == "table" then
        s:set("http.response.status_code", r.status)
      end
      return r, e
    end)
    if type(res) ~= "table" then
      if not errors.is(terr) then
        terr = errors.new("TransportError", { message = "transport failed: " .. tostring(terr) })
      end
      return nil, terr
    end
    if type(res.status) ~= "number" then
      return nil, errors.new("TransportError", { message = "the transport returned no status" })
    end
    local headers = lower_headers(res.headers)
    res = { status = res.status, headers = headers, body = res.body or "" }
    local meta = { status = res.status, headers = headers }
    attempt.status = res.status
    if res.status >= 300 then
      attempt.hint_ms = require("distilled.retry").bounded_hint_ms(headers)
    end
    span:set("http.response.status_code", res.status)

    local value, derr = tracer:with("distilled.decode", { debug = true }, function()
      if op.stream and res.status >= 200 and res.status < 300 then
        -- an output event stream read whole: its events as a list (distilled.aws.stream)
        return require("distilled.aws.stream").collect(kit, ctx, op, res)
      end
      return protocol.decode(ctx, op, res)
    end)
    if value == nil and derr ~= nil then
      return nil, derr, meta
    end
    return value, nil, meta
  end

  return protocol
end

return M
