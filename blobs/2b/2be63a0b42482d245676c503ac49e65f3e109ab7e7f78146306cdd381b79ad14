-- OTLP/HTTP exporter: POSTs spans as OTLP/JSON to <endpoint>/v1/traces.
--
--   local exporter = require("distilled.trace.otlp_http"){
--     endpoint = "http://127.0.0.1:4318",   -- the collector's OTLP HTTP base URL
--     transport = host.transport,          -- any transport(request) (required in Rex)
--     headers = { authorization = ... },   -- optional; values may be secrets
--     timeout = 5, service_name = nil,
--   }
--   -- also reachable as require("distilled.trace").exporters.otlp_http{ ... }
--
-- The exporter calls the transport directly, never through a traced client, so exporting
-- spans produces no spans (no recursion). Failures are returned (nil, SdkError), never
-- raised; the tracer folds them into flush()'s "trace export failed" error. A 2xx answer
-- whose body reports `partialSuccess.rejectedSpans` is a failure too, naming the count.
-- Messages never include header values or the endpoint's query or userinfo.
local errors = require("distilled.errors")
local json = require("distilled.json")
local otlp = require("distilled.trace.otlp")
local secret = require("distilled.secret")
local compat = require("distilled.compat")

local function export_error(message, fields)
  fields = fields or {}
  fields.message = "otlp_http: " .. message
  return errors.new("SdkError", fields)
end

-- the endpoint without userinfo, query or fragment, for messages
local function safe_endpoint(url)
  local s = string.gsub(url, "^([%a][%w+.-]*://)[^/@]*@", "%1")
  s = string.gsub(s, "[?#].*$", "")
  return s
end

local function traces_url(endpoint)
  local base = string.gsub(endpoint, "/+$", "")
  if string.find(base, "/v1/traces$") then
    return base
  end
  return base .. "/v1/traces"
end

local function default_transport()
  -- stock Lua only; in Rex pass host.transport (io.popen raises there)
  return require("distilled.transport.popen_curl")()
end

return function(opts)
  if type(opts) ~= "table" or type(opts.endpoint) ~= "string" or opts.endpoint == "" then
    compat.raise("otlp_http: expected { endpoint = string, transport = fn? }", 2)
  end
  local transport = opts.transport or (opts.host and opts.host.transport)
  if transport ~= nil and type(transport) ~= "function" and type(transport) ~= "table" then
    compat.raise("otlp_http: transport must be a function", 2)
  end
  if type(transport) == "table" and rawget(transport, "transport_module") then
    compat.raise(
      "otlp_http: transport is the "
        .. tostring(rawget(transport, "transport_module"))
        .. " module, a transport constructor, not a transport; "
        .. require("distilled.host").TRANSPORT_HINT,
      2
    )
  end
  local url = traces_url(opts.endpoint)
  local shown = safe_endpoint(url)
  local timeout = opts.timeout or 5

  return function(spans, meta)
    if #spans == 0 then
      return true
    end
    transport = transport or default_transport()
    local body, enc_err = json.encode(otlp.encode(spans, {
      service_name = opts.service_name or (meta and meta.service_name),
    }))
    if not body then
      return nil, export_error("cannot encode spans: " .. tostring(enc_err))
    end
    local headers = { ["content-type"] = "application/json", accept = "application/json" }
    for k, v in pairs(opts.headers or {}) do
      headers[string.lower(k)] = secret.unwrap(v)
    end
    local res, err = transport({
      method = "POST",
      url = url,
      headers = headers,
      body = body,
      timeout = timeout,
    })
    if not res then
      return nil,
        export_error(
          "POST " .. shown .. " failed: " .. (errors.is(err) and err.message or tostring(err)),
          { cause = err }
        )
    end
    if res.status < 200 or res.status > 299 then
      local snippet = string.sub(res.body or "", 1, 200)
      return nil,
        export_error(
          "POST "
            .. shown
            .. " returned HTTP "
            .. tostring(res.status)
            .. (snippet ~= "" and (": " .. snippet) or ""),
          { status = res.status }
        )
    end
    -- OTLP: a 200 may still carry partialSuccess with rejected spans
    if res.body and string.find(res.body, "rejectedSpans", 1, true) then
      local doc = json.decode(res.body)
      local partial = type(doc) == "table" and doc.partialSuccess
      local rejected = type(partial) == "table" and tonumber(partial.rejectedSpans)
      if rejected and rejected > 0 then
        return nil,
          export_error(
            "collector rejected "
              .. rejected
              .. " of "
              .. #spans
              .. " spans: "
              .. tostring(partial.errorMessage or ""),
            { status = res.status }
          )
      end
    end
    return true
  end
end
