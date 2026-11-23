-- Spans <-> OTLP/JSON (the JSON Protobuf encoding of ExportTraceServiceRequest).
--
-- Checked against the OTLP 1.11.1 specification ("JSON Protobuf Encoding") and
-- opentelemetry-proto trace.proto / common.proto:
--   - keys are lowerCamelCase field names: resourceSpans, scopeSpans, traceId, ...
--   - traceId / spanId / parentSpanId are hex strings, not base64
--   - enums are integers only: kind (SPAN_KIND_*), status.code (STATUS_CODE_*)
--   - 64-bit integers are decimal strings: startTimeUnixNano, endTimeUnixNano,
--     timeUnixNano, AnyValue.intValue
--   - AnyValue is one of stringValue | boolValue | intValue | doubleValue |
--     arrayValue { values } (kvlistValue and bytesValue are not produced)
--   - doubles that JSON cannot carry use the proto3 JSON strings "NaN", "Infinity"
local json = require("distilled.json")

local otlp = {}

otlp.SCOPE_NAME = "distilled-lua"
otlp.SCOPE_VERSION = "0.1.0"
otlp.DEFAULT_SERVICE_NAME = "unknown_service"

-- Span.SpanKind
otlp.KIND = { internal = 1, server = 2, client = 3, producer = 4, consumer = 5 }
-- Status.StatusCode
otlp.STATUS = { unset = 0, ok = 1, error = 2 }

local KIND_NAME, STATUS_NAME = {}, {}
for k, v in pairs(otlp.KIND) do
  KIND_NAME[v] = k
end
for k, v in pairs(otlp.STATUS) do
  STATUS_NAME[v] = k
end

local TWO_53 = 9007199254740992

local function any_value(v)
  local tv = type(v)
  if tv == "string" then
    return { stringValue = v }
  elseif tv == "boolean" then
    return { boolValue = v }
  elseif tv == "number" then
    if v ~= v then
      return { doubleValue = "NaN" }
    elseif v == 1 / 0 then
      return { doubleValue = "Infinity" }
    elseif v == -1 / 0 then
      return { doubleValue = "-Infinity" }
    elseif v == math.floor(v) and v > -TWO_53 and v < TWO_53 then
      return { intValue = string.format("%.0f", v) }
    end
    return { doubleValue = v }
  elseif tv == "table" then
    local values = {}
    for i = 1, #v do
      values[i] = any_value(v[i])
    end
    return { arrayValue = { values = json.array(values) } }
  end
  return { stringValue = tostring(v) }
end
otlp.any_value = any_value

local function key_values(attrs)
  local keys = {}
  for k in pairs(attrs or {}) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  local out = {}
  for i, k in ipairs(keys) do
    out[i] = { key = k, value = any_value(attrs[k]) }
  end
  return json.array(out)
end

local function encode_span(s)
  local events = {}
  for i, e in ipairs(s.events or {}) do
    events[i] = { timeUnixNano = e.time_ns, name = e.name, attributes = key_values(e.attributes) }
  end
  local status = { code = otlp.STATUS[s.status and s.status.code or "unset"] or 0 }
  if s.status and s.status.message ~= nil then
    status.message = s.status.message
  end
  local out = {
    traceId = s.trace_id,
    spanId = s.span_id,
    name = s.name,
    kind = otlp.KIND[s.kind] or 0,
    startTimeUnixNano = s.start_ns,
    endTimeUnixNano = s.end_ns or s.start_ns,
    attributes = key_values(s.attributes),
    events = json.array(events),
    status = status,
  }
  if s.parent_span_id then
    out.parentSpanId = s.parent_span_id
  end
  return out
end

--- otlp.encode(spans, { service_name }) -> an ExportTraceServiceRequest table
function otlp.encode(spans, opts)
  opts = opts or {}
  local list = {}
  for i, s in ipairs(spans) do
    list[i] = encode_span(s)
  end
  return {
    resourceSpans = json.array({
      {
        resource = {
          attributes = key_values({
            ["service.name"] = opts.service_name or otlp.DEFAULT_SERVICE_NAME,
          }),
        },
        scopeSpans = json.array({
          {
            scope = { name = otlp.SCOPE_NAME, version = otlp.SCOPE_VERSION },
            spans = json.array(list),
          },
        }),
      },
    }),
  }
end

--- otlp.encode_line(spans, opts) -> one line of JSON (no newline) | nil, err
function otlp.encode_line(spans, opts)
  return json.encode(otlp.encode(spans, opts))
end

---------------------------------------------------------------------------------------
-- decoding (for dl trace --file and tests)
---------------------------------------------------------------------------------------

local function from_any(v)
  if type(v) ~= "table" then
    return nil
  end
  if v.stringValue ~= nil then
    return v.stringValue
  elseif v.boolValue ~= nil then
    return v.boolValue
  elseif v.intValue ~= nil then
    -- intValue is a decimal string; json.decode reads it the same on every runtime
    local n = json.decode(tostring(v.intValue))
    return type(n) == "number" and n or v.intValue
  elseif v.doubleValue ~= nil then
    local d = v.doubleValue
    if d == "NaN" then
      return 0 / 0
    elseif d == "Infinity" then
      return 1 / 0
    elseif d == "-Infinity" then
      return -1 / 0
    end
    return tonumber(d) or d
  elseif v.arrayValue ~= nil then
    local out = {}
    for i, x in ipairs(v.arrayValue.values or {}) do
      out[i] = from_any(x)
    end
    return out
  end
  return nil
end

local function from_kvs(list)
  local out = {}
  for _, kv in ipairs(list or {}) do
    if type(kv) == "table" and type(kv.key) == "string" then
      out[kv.key] = from_any(kv.value)
    end
  end
  return out
end

local function hex(v)
  if type(v) ~= "string" or v == "" then
    return nil
  end
  return string.lower(v)
end

--- otlp.decode(doc) -> spans | nil, err. doc is an ExportTraceServiceRequest as a table
-- or JSON text. Each span also gets `service_name` from its resource.
function otlp.decode(doc)
  if type(doc) == "string" then
    local value, err = json.decode(doc)
    if value == nil then
      return nil, err
    end
    doc = value
  end
  if type(doc) ~= "table" then
    local errors = require("distilled.errors")
    return nil, errors.new("ParseError", { message = "OTLP document is not an object" })
  end
  local spans = {}
  for _, rs in ipairs(doc.resourceSpans or {}) do
    local resource = from_kvs(rs.resource and rs.resource.attributes)
    for _, ss in ipairs(rs.scopeSpans or {}) do
      for _, s in ipairs(ss.spans or {}) do
        local events = {}
        for i, e in ipairs(s.events or {}) do
          events[i] = {
            name = e.name,
            time_ns = e.timeUnixNano and tostring(e.timeUnixNano),
            attributes = from_kvs(e.attributes),
          }
        end
        local st = s.status or {}
        spans[#spans + 1] = {
          trace_id = hex(s.traceId),
          span_id = hex(s.spanId),
          parent_span_id = hex(s.parentSpanId),
          name = s.name,
          kind = KIND_NAME[s.kind] or "internal",
          start_ns = s.startTimeUnixNano and tostring(s.startTimeUnixNano),
          end_ns = s.endTimeUnixNano and tostring(s.endTimeUnixNano),
          attributes = from_kvs(s.attributes),
          events = events,
          status = { code = STATUS_NAME[st.code] or "unset", message = st.message },
          service_name = resource["service.name"],
        }
      end
    end
  end
  return spans
end

--- otlp.decode_lines(text) -> spans | nil, err: an OTLP/JSON lines file (one request per
-- line, blank lines ignored). The error names the failing line.
function otlp.decode_lines(text)
  local spans = {}
  local n = 0
  for line in string.gmatch(text, "[^\n]+") do
    n = n + 1
    if string.find(line, "%S") then
      local list, err = otlp.decode(line)
      if not list then
        err.message = "line " .. n .. ": " .. tostring(err.message)
        return nil, err
      end
      for _, s in ipairs(list) do
        spans[#spans + 1] = s
      end
    end
  end
  return spans
end

return otlp
