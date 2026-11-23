-- Span exporters: memory, file, console, and otlp_http (POST to a collector; loaded on use
-- from distilled.trace.otlp_http).
--
-- Each exporter is called as exporter(spans, meta) -> true | nil, err, where spans is the
-- list documented in docs/interfaces.md and meta = { service_name }. The tracer calls
-- them from flush() under compat.pcall, so an exporter failure never reaches a traced
-- call; exporters still return nil, err rather than raise.
local errors = require("distilled.errors")

local exporters = {}

local function export_error(message)
  return errors.new("SdkError", { message = message })
end

--- exporters.memory() -> exporter; exporter.spans accumulates every exported span,
-- exporter:clear() empties it. The exporter is a callable table.
function exporters.memory()
  local m = { spans = {} }
  function m.clear(self)
    self = self or m
    self.spans = {}
  end
  return setmetatable(m, {
    __call = function(self, spans)
      local list = self.spans
      for _, s in ipairs(spans) do
        list[#list + 1] = s
      end
      return true
    end,
  })
end

-- size of the file at path in bytes, or nil when it does not exist
local function file_size(path)
  local f = io.open(path, "rb")
  if not f then
    return nil
  end
  local size = f:seek("end")
  f:close()
  return size
end

--- exporters.file{ path, max_bytes, service_name } -> exporter
-- Appends one OTLP/JSON ExportTraceServiceRequest ({"resourceSpans":[...]}) per line.
-- When the file already exceeds max_bytes it is truncated before writing, so it stays
-- near the limit without rotation. Uses only io.open (works in Rex).
function exporters.file(opts)
  if type(opts) ~= "table" or type(opts.path) ~= "string" then
    error("exporters.file: expected { path = string, max_bytes = number? }", 2)
  end
  local path, max_bytes = opts.path, opts.max_bytes
  local otlp = require("distilled.trace.otlp")
  return function(spans, meta)
    if #spans == 0 then
      return true
    end
    local line, err =
      otlp.encode_line(spans, { service_name = opts.service_name or (meta and meta.service_name) })
    if not line then
      return nil, export_error("trace file: cannot encode spans: " .. tostring(err))
    end
    local mode = "ab"
    if max_bytes then
      local size = file_size(path)
      if size and size > max_bytes then
        mode = "wb"
      end
    end
    local f, open_err = io.open(path, mode)
    if not f then
      return nil, export_error("trace file: cannot open " .. path .. ": " .. tostring(open_err))
    end
    local ok, write_err = f:write(line, "\n")
    f:close()
    if not ok then
      return nil, export_error("trace file: cannot write " .. path .. ": " .. tostring(write_err))
    end
    return true
  end
end

--- exporters.console{ write } -> exporter: writes the span tree (trace.tree) of each
-- flush through write(text); write defaults to io.write.
function exporters.console(opts)
  opts = opts or {}
  local write = opts.write or io.write
  local tree = require("distilled.trace.tree")
  return function(spans)
    if #spans == 0 then
      return true
    end
    write(tree.render(spans, { durations = opts.durations }))
    return true
  end
end

-- exporters.otlp_http{ endpoint, transport, headers, timeout, service_name }
exporters.otlp_http = function(opts)
  return require("distilled.trace.otlp_http")(opts)
end

return exporters
