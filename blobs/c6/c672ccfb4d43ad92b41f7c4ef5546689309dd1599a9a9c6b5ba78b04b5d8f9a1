-- Spans -> an indented text tree, for the console exporter, `dl trace` and golden files.
--
--   trace 4bf92f3577b34da6a3ce929d0e0e4736
--     Neon.GetProject client 412.0ms ERROR "rate limited" error.type=TooManyRequests
--       distilled.attempt 100.0ms ERROR "HTTP 429" n=1
--         @ retry +0.0ms reason=TooManyRequests
--
-- One header line per trace, then its spans: children under parents in start order,
-- then each span's events. A line is: name, kind (when not internal), duration in ms,
-- status (unset | ok | ERROR "<message>"), attributes sorted by key. Output depends only
-- on the span list, so it is deterministic. tree.golden(spans) also replaces ids with
-- trace-1 / span-1 placeholders and drops durations, for committed comparison files.
local json = require("distilled.json")
local trace = require("distilled.trace")

local tree = {}

-- decimal strings compare by length, then text (they have no leading zeros)
local function ns_less(a, b)
  a, b = a or "", b or ""
  if #a ~= #b then
    return #a < #b
  end
  return a < b
end

local function quote(s)
  local out = string.gsub(s, '[%c"\\]', function(c)
    if c == "\n" then
      return "\\n"
    elseif c == "\t" then
      return "\\t"
    elseif c == "\r" then
      return "\\r"
    elseif c == '"' or c == "\\" then
      return "\\" .. c
    end
    return string.format("\\%03d", string.byte(c))
  end)
  return '"' .. out .. '"'
end

local function show_scalar(v)
  local tv = type(v)
  if tv == "string" then
    if v ~= "" and string.find(v, "^[%w%._/:%-%+@<>]+$") then
      return v
    end
    return quote(v)
  elseif tv == "number" then
    if v ~= v then
      return "NaN"
    elseif v == 1 / 0 then
      return "Infinity"
    elseif v == -1 / 0 then
      return "-Infinity"
    end
    return (json._format_number(v))
  end
  return tostring(v)
end

local function show_value(v)
  if type(v) == "table" then
    local parts = {}
    for i = 1, #v do
      parts[i] = show_scalar(v[i])
    end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  return show_scalar(v)
end
tree.show_value = show_value

local function show_attrs(attrs)
  local keys = {}
  for k in pairs(attrs or {}) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  local parts = {}
  for i, k in ipairs(keys) do
    parts[i] = k .. "=" .. show_value(attrs[k])
  end
  return table.concat(parts, " ")
end

local function ms(x)
  return string.format("%.1fms", x)
end

local function status_text(s)
  local st = s.status or {}
  if st.code == "error" then
    if st.message ~= nil then
      return "ERROR " .. quote(tostring(st.message))
    end
    return "ERROR"
  end
  return st.code or "unset"
end

local function span_line(s, durations)
  local parts = { s.name or "?" }
  if s.kind and s.kind ~= "internal" then
    parts[#parts + 1] = s.kind
  end
  if durations then
    parts[#parts + 1] = ms(trace.ns_diff_ms(s.start_ns, s.end_ns or s.start_ns))
  end
  parts[#parts + 1] = status_text(s)
  local a = show_attrs(s.attributes)
  if a ~= "" then
    parts[#parts + 1] = a
  end
  return table.concat(parts, " ")
end

local function event_line(s, e, durations)
  local parts = { "@", e.name or "?" }
  if durations and e.time_ns then
    parts[#parts + 1] = "+" .. ms(trace.ns_diff_ms(s.start_ns, e.time_ns))
  end
  local a = show_attrs(e.attributes)
  if a ~= "" then
    parts[#parts + 1] = a
  end
  return table.concat(parts, " ")
end

-- index the spans: children per span (start order) and roots grouped by trace
local function build(spans)
  local by_id = {}
  local index = {}
  for i, s in ipairs(spans) do
    index[s] = i
    if s.span_id then
      by_id[s.span_id] = s
    end
  end
  local function before(a, b)
    if a.start_ns ~= b.start_ns then
      return ns_less(a.start_ns, b.start_ns)
    end
    return index[a] < index[b]
  end
  local children = {}
  local roots = {}
  for _, s in ipairs(spans) do
    local p = s.parent_span_id and by_id[s.parent_span_id]
    if p and p ~= s then
      children[p] = children[p] or {}
      table.insert(children[p], s)
    else
      roots[#roots + 1] = s
    end
  end
  for _, list in pairs(children) do
    table.sort(list, before)
  end
  table.sort(roots, before)
  local traces, by_trace = {}, {}
  for _, r in ipairs(roots) do
    local key = r.trace_id or "?"
    local group = by_trace[key]
    if not group then
      group = { trace_id = r.trace_id, remote_parent = nil, roots = {} }
      by_trace[key] = group
      traces[#traces + 1] = group
    end
    if r.parent_span_id and not group.remote_parent then
      group.remote_parent = r.parent_span_id
    end
    group.roots[#group.roots + 1] = r
  end
  return traces, children
end

-- The lines of one trace: { "span", span, depth } and { "event", event, depth, owner },
-- depth first, a span's events and children merged by time (an event before a child
-- that starts at the same instant). Explicit stack: gopher-lua has a shallow call stack.
local function walk(group, children)
  local out = {}
  local stack = {}
  for i = #group.roots, 1, -1 do
    stack[#stack + 1] = { "span", group.roots[i], 0 }
  end
  while #stack > 0 do
    local item = table.remove(stack)
    out[#out + 1] = item
    if item[1] == "span" then
      local s, depth = item[2], item[3]
      local merged = {}
      local kids = children[s] or {}
      local events = s.events or {}
      local i, j = 1, 1
      while i <= #events or j <= #kids do
        local e, k = events[i], kids[j]
        if e and (not k or not ns_less(k.start_ns, e.time_ns or "")) then
          merged[#merged + 1] = { "event", e, depth + 1, s }
          i = i + 1
        else
          merged[#merged + 1] = { "span", k, depth + 1 }
          j = j + 1
        end
      end
      for m = #merged, 1, -1 do
        stack[#stack + 1] = merged[m]
      end
    end
  end
  return out
end

--- tree.order(spans) -> { { trace_id, remote_parent, spans = { { span, depth }, ... } }, ... }
-- Traces in order of their first root; spans depth first, children in start order.
function tree.order(spans)
  local traces, children = build(spans)
  local out = {}
  for g, group in ipairs(traces) do
    local list = {}
    for _, item in ipairs(walk(group, children)) do
      if item[1] == "span" then
        list[#list + 1] = { item[2], item[3] }
      end
    end
    out[g] = { trace_id = group.trace_id, remote_parent = group.remote_parent, spans = list }
  end
  return out
end

--- tree.render(spans [, { durations = true }]) -> text (ends with a newline unless empty)
function tree.render(spans, opts)
  opts = opts or {}
  local durations = opts.durations ~= false
  local lines = {}
  local traces, children = build(spans)
  for _, group in ipairs(traces) do
    local header = "trace " .. tostring(group.trace_id)
    if group.remote_parent then
      header = header .. " (parent " .. group.remote_parent .. ")"
    end
    lines[#lines + 1] = header
    for _, item in ipairs(walk(group, children)) do
      local pad = string.rep("  ", item[3] + 1)
      if item[1] == "span" then
        lines[#lines + 1] = pad .. span_line(item[2], durations)
      else
        lines[#lines + 1] = pad .. event_line(item[4], item[2], durations)
      end
    end
  end
  if #lines == 0 then
    return ""
  end
  return table.concat(lines, "\n") .. "\n"
end

-- replace every known id inside a string value with its placeholder
local function replace_ids(v, names)
  if type(v) == "string" then
    return (string.gsub(v, "%x+", function(h)
      return names[h]
    end))
  elseif type(v) == "table" then
    local out = {}
    for i = 1, #v do
      out[i] = replace_ids(v[i], names)
    end
    return out
  end
  return v
end

local function map_attrs(attrs, names)
  local out = {}
  for k, v in pairs(attrs or {}) do
    out[k] = replace_ids(v, names)
  end
  return out
end

--- tree.normalize(spans) -> a copy with ids replaced by trace-N / span-N / remote-N in
-- tree order (ids appearing inside string values too). Every timestamp is replaced by
-- its rank among all of them, so order (and event placement) survives but values do not.
function tree.normalize(spans)
  local names = {}
  local counts = { trace = 0, span = 0, remote = 0 }
  local function name(kind, id)
    if id == nil then
      return nil
    end
    if not names[id] then
      counts[kind] = counts[kind] + 1
      names[id] = kind .. "-" .. counts[kind]
    end
    return names[id]
  end
  local ordered = {}
  for _, group in ipairs(tree.order(spans)) do
    name("trace", group.trace_id)
    for _, item in ipairs(group.spans) do
      name("span", item[1].span_id)
      ordered[#ordered + 1] = item[1]
    end
  end
  for _, s in ipairs(ordered) do
    name("remote", s.parent_span_id)
  end
  local stamps, seen = {}, {}
  local function stamp(ns)
    if ns ~= nil and not seen[ns] then
      seen[ns] = true
      stamps[#stamps + 1] = ns
    end
  end
  for _, s in ipairs(ordered) do
    stamp(s.start_ns)
    stamp(s.end_ns)
    for _, e in ipairs(s.events or {}) do
      stamp(e.time_ns)
    end
  end
  table.sort(stamps, ns_less)
  local rank = {}
  for i, ns in ipairs(stamps) do
    rank[ns] = string.format("%012d", i)
  end
  local out = {}
  for i, s in ipairs(ordered) do
    local events = {}
    for j, e in ipairs(s.events or {}) do
      events[j] = {
        name = e.name,
        time_ns = e.time_ns and rank[e.time_ns],
        attributes = map_attrs(e.attributes, names),
      }
    end
    local st = s.status or {}
    out[i] = {
      trace_id = names[s.trace_id],
      span_id = names[s.span_id],
      parent_span_id = s.parent_span_id and names[s.parent_span_id],
      name = s.name,
      kind = s.kind,
      start_ns = s.start_ns and rank[s.start_ns],
      end_ns = s.end_ns and rank[s.end_ns],
      attributes = map_attrs(s.attributes, names),
      events = events,
      status = { code = st.code, message = st.message and replace_ids(st.message, names) },
    }
  end
  return out
end

--- tree.golden(spans) -> the tree of tree.normalize(spans) without durations
function tree.golden(spans)
  return tree.render(tree.normalize(spans), { durations = false })
end

return tree
