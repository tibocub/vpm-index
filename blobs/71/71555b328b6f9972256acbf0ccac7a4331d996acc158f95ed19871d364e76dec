-- The no-op tracer and the shared non-recording span. Requires nothing, so a client with
-- tracing off holds `require("distilled.trace.noop")` and never loads the tracer
-- (distilled.trace). distilled.trace re-exports both as trace.noop and trace.NOOP_SPAN.
--
-- Nothing here allocates per call: noop:with(name, opts, fn) is fn(NOOP_SPAN).
local span_methods = { recording = false }
function span_methods.set() end
function span_methods.event() end
function span_methods.fail() end
function span_methods.finish() end

local function ignore_write() end

-- Empty proxies, so a stray assignment (span.recording = true, noop.level = "debug")
-- cannot change the shared objects.
local NOOP_SPAN = setmetatable({}, { __index = span_methods, __newindex = ignore_write })

local tracer_methods = { level = "off", NOOP_SPAN = NOOP_SPAN }
function tracer_methods.start()
  return NOOP_SPAN
end
function tracer_methods.with(_, _, _, fn)
  return fn(NOOP_SPAN)
end
function tracer_methods.current()
  return nil
end
function tracer_methods.traceparent()
  return nil
end
function tracer_methods.attach()
  return false
end
function tracer_methods.detach()
  return false
end
function tracer_methods.flush()
  return true
end

-- require("distilled.trace.noop") is the tracer itself: noop.level, noop:with(...)
return setmetatable({}, { __index = tracer_methods, __newindex = ignore_write })
