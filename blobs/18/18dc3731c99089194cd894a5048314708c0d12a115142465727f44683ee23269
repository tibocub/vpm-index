-- Full-duplex HTTP through curl: the request body is written while the response is read
-- (AWS bidirectional event streams). What both duplex transports share; the processes
-- come from distilled.transport.popen_curl (stock Lua: FIFOs) and
-- distilled.transport.exec_curl_duplex (an exec.start with stdin kept open: Rex).
--
--   local conn, err = duplex(request)     -- request.body must be nil
--   conn:write(bytes) -> true | nil, err  -- the next piece of the request body
--   conn:close_input()                    -- the body ends (curl sees EOF)
--   conn:response() -> { status, headers, body = reader } | nil, err  (blocks for the head)
--   conn:close()                          -- stops curl; idempotent
--   reader: read_exact(n), read_line(), read_all(), close() (the stream contract)
--
-- How curl is driven (measured with curl 8.7, task 31):
-- * `upload-file = "."`: the body is standard input read in non-blocking mode. With
--   `upload-file = "-"` curl blocks reading stdin and handles no response data until the
--   next input arrives, so a reply to the first event is held until the second is sent.
-- * The body goes out chunked on HTTP/1.1 (curl's choice for a body of unknown size; no
--   Transfer-Encoding header is set, HTTP/2 forbids it), as DATA frames on HTTP/2 (`http2` for https,
--   as the AWS streaming services require); both were seen to deliver each write at
--   once and each response piece as it came.
-- * No write-out trailer (the body has no known end) and no max-time (a stream lasts as
--   long as the caller keeps it): curl's exit status, read when the body ends, tells a
--   clean end from a failure.
local common = require("distilled.transport.curl_common")
local errors = require("distilled.errors")

local M = {}

-- The fd curl writes its header dump to: the process modules open it (popen: a FIFO in
-- the private directory; Rex: duplicated onto stderr). Headers come first, the HTTP
-- trailers after the body; reader:trailers() reads them once the body has ended.
M.HEADER_FD = 5

--- M.config(request, body_path) -> curl config text
-- Without body_path: a duplex transfer (the body from stdin, `upload-file = "."`).
-- With body_path: a one-way streaming transfer whose body curl reads from that file
-- (request.body, written there by the caller), the response read as it arrives.
function M.config(req, body_path)
  local copy = {}
  for k, v in pairs(req) do
    copy[k] = v
  end
  if not body_path then
    copy.body = nil
  end
  copy.timeout = nil
  if copy.http2 == nil and string.find(req.url, "^[hH][tT][tT][pP][sS]://") then
    copy.http2 = true
  end
  local text = common.config(copy, { body_path = body_path })
  -- no write-out: the stream has no trailer to find
  local lines = {}
  local data_line
  for line in string.gmatch(text, "[^\n]+") do
    if string.find(line, "^data%-binary = ") then
      data_line = line
    elseif string.find(line, "^dump%-header = ") then
      -- the header dump (every header block, then the HTTP trailers after the body) on
      -- its own channel, fd HEADER_FD, so trailers never mix with the body (task 29b)
      lines[#lines + 1] = 'dump-header = "/dev/fd/' .. M.HEADER_FD .. '"'
    elseif not string.find(line, "^write%-out = ") then
      lines[#lines + 1] = line
    end
  end
  lines[#lines + 1] = "no-buffer"
  -- Timeouts of a streamed transfer (task 29): request.timeout bounds the connection
  -- only (a stream lasts as long as the caller keeps it); request.max_time bounds the
  -- whole transfer; request.idle_timeout stops a transfer that receives nothing for that
  -- many seconds (curl: less than 1 byte/s averaged over idle_timeout seconds).
  local function secs(v)
    return string.format("%.3f", v > 0.001 and v or 0.001)
  end
  if type(req.timeout) == "number" and req.timeout == req.timeout then
    lines[#lines + 1] = "connect-timeout = " .. secs(req.timeout)
  end
  if type(req.max_time) == "number" and req.max_time == req.max_time then
    lines[#lines + 1] = "max-time = " .. secs(req.max_time)
  end
  if type(req.idle_timeout) == "number" and req.idle_timeout >= 1 then
    lines[#lines + 1] = "speed-limit = 1"
    lines[#lines + 1] = "speed-time = " .. tostring(math.ceil(req.idle_timeout))
  end
  lines[#lines + 1] = "no-progress-meter"
  if not body_path then
    lines[#lines + 1] = 'upload-file = "."'
  elseif data_line then
    lines[#lines + 1] = data_line -- last, as curl_common explains
  end
  return table.concat(lines, "\n") .. "\n"
end

local function transport_error(message, fields)
  local f = { message = message }
  for k, v in pairs(fields or {}) do
    f[k] = v
  end
  return errors.new("TransportError", f)
end

-- proc: { write(bytes) -> true | nil, msg; close_stdin(); read(n) -> bytes ("" or short
-- at EOF); read_line() -> line with its "\n" | rest | "" at EOF; head_line() -> the next
-- line of the header channel (same shape); finish() -> exit code, stderr, the rest of
-- the header channel (after EOF: the trailers); kill() }

--- M.conn(proc, request) -> conn
function M.conn(proc, req)
  local conn = { closed = false }
  local failed -- the error once curl is known to have failed
  local finished = false
  local trailer_text
  local function failure()
    if not finished then
      finished = true
      local code, stderr, rest = proc.finish()
      trailer_text = rest
      if code ~= 0 then
        failed = common.failure({ code = code, stderr = stderr, request = req })
      end
    end
    return failed
  end

  function conn:write(bytes)
    if conn.closed then
      return nil, transport_error("the duplex transfer is closed")
    end
    local ok, msg = proc.write(bytes)
    if not ok then
      return nil,
        failure() or transport_error("curl stopped reading the request body: " .. tostring(msg))
    end
    return true
  end

  function conn:close_input()
    proc.close_stdin()
  end

  local reader = { closed = false }
  function reader:read_exact(n)
    if reader.closed then
      return nil, transport_error("the body reader is closed")
    end
    local got = proc.read(n)
    if got and #got == n then
      return got
    end
    local err = failure()
    if err then
      return nil, err
    end
    if not got or got == "" then
      return nil, nil
    end
    return nil,
      transport_error("the response body ended inside a frame", { eof = true, partial = got })
  end
  function reader:read_line()
    local line = proc.read_line()
    if line == nil or line == "" then
      local err = failure()
      if err then
        return nil, err
      end
      return nil, nil
    end
    if string.sub(line, -1) ~= "\n" then
      -- the body ended without a newline: a cut connection must not pass a half line
      -- off as the last one
      local err = failure()
      if err then
        return nil, err
      end
    end
    line = string.gsub(line, "\n$", "")
    line = string.gsub(line, "\r$", "")
    return line
  end
  function reader:read_all()
    local parts = {}
    while true do
      local piece = proc.read(65536)
      if not piece or piece == "" then
        break
      end
      parts[#parts + 1] = piece
      if #piece < 65536 then
        break
      end
    end
    local err = failure()
    if err then
      return nil, err
    end
    return table.concat(parts)
  end
  --- reader:trailers() -> { [lowercase name] = value } | nil: the HTTP trailers, once the
  -- body has ended (waits for curl to exit); nil when the reply had none
  local parsed_trailers
  function reader:trailers()
    if parsed_trailers == nil then
      failure()
      local t, any = {}, false
      for line in string.gmatch(trailer_text or "", "[^\r\n]+") do
        -- curl's own messages share the channel in Rex (stderr): not trailers
        if not string.find(line, "^curl: ") and not string.find(line, "^HTTP/") then
          local name, value = string.match(line, "^([%w!#$%%&'*+%-.^_`|~]+):%s*(.-)%s*$")
          if name then
            name = string.lower(name)
            t[name] = t[name] and (t[name] .. ", " .. value) or value
            any = true
          end
        end
      end
      parsed_trailers = any and t or false
    end
    return parsed_trailers or nil
  end

  function reader:close()
    reader.closed = true
    conn:close()
  end

  -- the head: header blocks until a final (non-1xx) status
  function conn:response()
    while true do
      local status_line = proc.head_line()
      if status_line == nil or status_line == "" then
        return nil, failure() or transport_error("curl output has no HTTP status line")
      end
      local code = string.match(status_line, "^HTTP/[%d.]+%s+(%d%d%d)")
      local status = code and tonumber(code)
      if not status then
        -- in Rex the header channel is stderr: curl's own failure message lands here
        return nil,
          failure() or transport_error("curl output does not start with an HTTP status line")
      end
      local block = { status_line }
      while true do
        local line = proc.head_line()
        if line == nil or line == "" then
          return nil, failure() or transport_error("the response head was cut short")
        end
        if line == "\r\n" or line == "\n" then
          break
        end
        block[#block + 1] = line
      end
      if status >= 200 then
        local headers = {}
        local last
        for i = 2, #block do
          local line = string.gsub(block[i], "\r?\n$", "")
          if string.find(line, "^[ \t]") and last then
            headers[last] = headers[last] .. " " .. string.match(line, "^%s*(.-)%s*$")
          else
            local name, value = string.match(line, "^([^:]+):%s*(.-)%s*$")
            if name then
              name = string.lower(name)
              headers[name] = headers[name] and (headers[name] .. ", " .. value) or value
              last = name
            end
          end
        end
        return { status = status, headers = headers, body = reader }
      end
    end
  end

  function conn:close()
    if conn.closed then
      return
    end
    conn.closed = true
    proc.kill()
  end

  return conn
end

--- M.with_entries(transport, entries) -> a callable table: the transport (a function, or
-- a table that already has entry points) plus `entries` ({ stream = fn, duplex = fn })
-- for the ones it lacks. distilled.host.popen and distilled.host.rex use it.
function M.with_entries(transport, entries)
  local t = {}
  if type(transport) == "table" then
    for k, v in pairs(transport) do
      t[k] = v
    end
  end
  for k, v in pairs(entries) do
    if t[k] == nil then
      t[k] = v
    end
  end
  return setmetatable(t, {
    __call = function(_, req)
      return transport(req)
    end,
  })
end

return M
