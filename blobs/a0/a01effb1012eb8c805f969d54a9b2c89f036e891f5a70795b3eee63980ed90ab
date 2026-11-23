-- What both curl transports share: checking a request, writing the curl config text, and
-- turning curl's output back into a response or a TransportError.
--
-- Secrets: the URL, the method and every header travel inside the config text, which a
-- transport hands to curl on standard input (exec_curl) or in a 0600 temp file
-- (popen_curl), never as process arguments, so nothing secret shows in `ps`. The body
-- goes through a file curl reads (`data-binary = "@path"`), so it arrives byte for byte
-- with no escaping and no size limit.
--
-- Output layout, on curl's stdout, in order:
--   every response header block (`dump-header = "-"`: 1xx blocks, then the final one;
--   several when redirects are followed), the body, the HTTP trailers if the response
--   has any (curl writes them to the header dump after the body: HTTP/2 trailers, or a
--   chunked HTTP/1.1 body's), then the write-out trailer
--   "\n" .. TRAILER .. " <http_code> <size_download> <size_header>".
-- size_header counts the header blocks but not the HTTP trailers (measured with curl
-- 8.7 against Node's http and http2 servers), so the body starts right after them, is
-- size_download bytes long and may hold anything, including text that looks like
-- headers or like the trailer; what lies between it and the write-out is the trailers.
--
-- request.http2 = true asks for HTTP/2 (gRPC, task 23): `http2-prior-knowledge` for
-- http:// (gRPC servers do not upgrade from HTTP/1.1), `http2` (ALPN) for https://.
local errors = require("distilled.errors")
local compat = require("distilled.compat")

local M = {}

M.TRAILER = "--distilled-curl-write-out--"

-- curl exit codes worth naming (curl's libcurl-errors / man page "EXIT CODES")
local TIMEOUT_CODE = 28
local NOT_FOUND_CODES = { [127] = true } -- the shell could not find curl
local TLS_CODES = {
  [35] = true,
  [51] = true,
  [53] = true,
  [54] = true,
  [58] = true,
  [59] = true,
  [60] = true,
  [77] = true,
  [80] = true,
  [83] = true,
  [90] = true,
  [91] = true,
}

local function invalid(message, member)
  return errors.new("InvalidInput", { message = message, member = member })
end

-- RFC 9110 token characters (a header name)
local function is_token(s)
  return type(s) == "string" and s ~= "" and string.find(s, "^[%w!#$%%&'*+%-.^_`|~]+$") ~= nil
end

-- A value inside a double-quoted curl config string. curl's config parser undoes `\\`,
-- `\"`, `\t`, `\n`, `\r`, `\v`; any other byte is taken as is. CR, LF and NUL are refused
-- before this is called (a config line cannot carry them, and a header must not).
local function quote(value)
  return '"' .. string.gsub(value, '[\\"]', "\\%0") .. '"'
end
M.quote = quote

--- M.check(request) -> true | nil, err (InvalidInput)
-- The request contract from docs/interfaces.md, plus what curl's config cannot carry.
function M.check(req)
  if type(req) ~= "table" then
    return nil, invalid("transport: request must be a table")
  end
  if type(req.method) ~= "string" or not is_token(req.method) then
    return nil, invalid("transport: request.method must be an HTTP method token", "method")
  end
  if type(req.url) ~= "string" or not string.find(req.url, "^[hH][tT][tT][pP][sS]?://") then
    return nil, invalid("transport: request.url must be an http:// or https:// URL", "url")
  end
  if string.find(req.url, "[%z\1-\32\127]") then
    return nil, invalid("transport: request.url contains whitespace or a control character", "url")
  end
  if req.headers ~= nil and type(req.headers) ~= "table" then
    return nil, invalid("transport: request.headers must be a table", "headers")
  end
  for name, value in pairs(req.headers or {}) do
    if not is_token(name) then
      -- the name is not secret; the value may be, so it is never quoted back
      return nil,
        invalid("transport: invalid header name " .. string.format("%q", tostring(name)), "headers")
    end
    if type(value) ~= "string" and type(value) ~= "number" then
      return nil, invalid("transport: header " .. name .. " must be a string", "headers")
    end
    if string.find(tostring(value), "[%z\r\n]") then
      return nil, invalid("transport: header " .. name .. " contains CR, LF or NUL", "headers")
    end
  end
  if req.body ~= nil and type(req.body) ~= "string" then
    return nil, invalid("transport: request.body must be a string or nil", "body")
  end
  if req.timeout ~= nil and (type(req.timeout) ~= "number" or req.timeout ~= req.timeout) then
    return nil, invalid("transport: request.timeout must be a number of seconds", "timeout")
  end
  if req.http2 ~= nil and type(req.http2) ~= "boolean" then
    return nil, invalid("transport: request.http2 must be a boolean", "http2")
  end
  return true
end

local function sorted_names(headers)
  local names = {}
  for name in pairs(headers or {}) do
    names[#names + 1] = name
  end
  table.sort(names, function(a, b)
    return string.lower(a) < string.lower(b)
  end)
  return names
end

-- seconds for curl's --max-time: curl takes a decimal; keep it positive and finite
local function max_time(seconds)
  if seconds <= 0 then
    seconds = 0.001
  end
  if seconds > 1e9 then
    seconds = 1e9
  end
  return string.format("%.3f", seconds)
end

--- M.config(request, { body_path, follow_redirects, max_redirects }) -> text
-- The request must have passed M.check. body_path is the file curl reads the body from
-- (required when request.body is not nil).
function M.config(req, opts)
  opts = opts or {}
  local lines = {
    "silent",
    "show-error",
    "globoff", -- `[]{}` in a URL are literal, not curl ranges
    'proto = "=http,https"',
    'proto-redir = "=http,https"',
  }
  local function add(line)
    lines[#lines + 1] = line
  end
  add("url = " .. quote(req.url))
  if req.http2 then
    add(string.find(req.url, "^[hH][tT][tT][pP][sS]") and "http2" or "http2-prior-knowledge")
  end
  local method = string.upper(req.method)
  if method == "HEAD" then
    -- `request = "HEAD"` makes curl wait for a body that never comes; `head` does not,
    -- and prints the headers itself (so no dump-header below).
    add("head")
  else
    add("request = " .. quote(req.method))
    add('dump-header = "-"')
  end
  local has_type = false
  for _, name in ipairs(sorted_names(req.headers)) do
    local value = tostring(req.headers[name])
    local lower = string.lower(name)
    if lower == "content-type" then
      has_type = true
    end
    if value == "" then
      add("header = " .. quote(name .. ";")) -- `name;` sends an empty header; `name:` removes it
    else
      add("header = " .. quote(name .. ": " .. value))
    end
  end
  -- curl adds `Expect: 100-continue` to large bodies and waits up to a second for the
  -- answer; fetch never does. And `data-binary` implies a form content type.
  add('header = "Expect:"')
  if req.body ~= nil then
    if not has_type then
      add('header = "Content-Type:"')
    end
    if type(opts.body_path) ~= "string" then
      compat.raise("curl_common.config: a request with a body needs opts.body_path", 2)
    end
  end
  if req.timeout then
    add("max-time = " .. max_time(req.timeout))
  end
  if opts.follow_redirects then
    add("location")
    add("max-redirs = " .. tostring(opts.max_redirects or 10))
  end
  add(
    "write-out = " .. quote("\\n" .. M.TRAILER .. " %{http_code} %{size_download} %{size_header}")
  )
  if req.body ~= nil then
    -- Last, always: curl reads a `data-binary = "@file"` file when it parses that line.
    -- exec_curl's body file is /dev/fd/3, which shares its offset with the stdin `dd`
    -- copies the config from; a config line after this one could still be in flight, and
    -- curl would take its bytes as body (found in task 23: a cut write-out, a body 8
    -- bytes long instead of 1, about one full test run in three).
    add("data-binary = " .. quote("@" .. opts.body_path))
  end
  return compat.concat(lines, "\n") .. "\n"
end

-- plain (non-pattern) replacement of every occurrence of `needle` in `s`
local function replace_plain(s, needle, replacement)
  if needle == "" then
    return s
  end
  local parts, start = {}, 1
  while true do
    local i, j = string.find(s, needle, start, true)
    if not i then
      break
    end
    parts[#parts + 1] = string.sub(s, start, i - 1)
    parts[#parts + 1] = replacement
    start = j + 1
  end
  if #parts == 0 then
    return s
  end
  parts[#parts + 1] = string.sub(s, start)
  return compat.concat(parts)
end

--- M.scrub(text, request) -> text with every header value, the URL's query and userinfo,
-- and a short body replaced by <redacted>. curl's messages name the host and port, but
-- some (a malformed URL, a bad header) echo what they were given.
function M.scrub(text, req)
  text = tostring(text or "")
  if type(req) ~= "table" then
    return text
  end
  local secrets = {}
  for _, value in pairs(req.headers or {}) do
    secrets[#secrets + 1] = tostring(value)
  end
  if type(req.url) == "string" then
    local query = string.match(req.url, "%?([^#]*)")
    if query then
      secrets[#secrets + 1] = query
    end
    local userinfo = string.match(req.url, "^[%a][%w+.-]*://([^/?#]*)@")
    if userinfo then
      secrets[#secrets + 1] = userinfo
    end
  end
  if type(req.body) == "string" and #req.body <= 4096 then
    secrets[#secrets + 1] = req.body
  end
  -- longest first, so a value that contains another is replaced whole
  table.sort(secrets, function(a, b)
    return #a > #b
  end)
  for _, s in ipairs(secrets) do
    if #s >= 4 then
      text = replace_plain(text, s, "<redacted>")
    end
  end
  return text
end

-- the first line of curl's stderr that says what went wrong
local function curl_message(stderr)
  stderr = tostring(stderr or "")
  local line = string.match(stderr, "curl: %(%d+%)[^\r\n]*")
  if line then
    return line
  end
  for l in string.gmatch(stderr, "[^\r\n]+") do
    if string.find(l, "%S") then
      return l
    end
  end
  return nil
end

--- M.failure{ code, stderr, timed_out, request, not_found, message } -> err (TransportError)
-- code is curl's exit status (or the shell's 127). Messages are scrubbed of anything the
-- request carried.
function M.failure(info)
  local code = info.code
  local message = info.message or curl_message(info.stderr)
  local timeout = info.timed_out == true or code == TIMEOUT_CODE
  if info.not_found or NOT_FOUND_CODES[code] then
    message = "curl not found: " .. (message or "the curl program could not be started")
  elseif info.timed_out and code ~= TIMEOUT_CODE then
    message = "curl did not finish in time and was stopped"
  elseif not message then
    message = "curl exited with code " .. tostring(code)
  end
  local err = errors.new("TransportError", {
    message = M.scrub(message, info.request),
    curl_code = type(code) == "number" and code or nil,
    timeout = timeout or nil,
    tls = (type(code) == "number" and TLS_CODES[code]) or nil,
  })
  if timeout then
    err.categories.TimeoutError = true
  end
  return err
end

-- Parses one header block (lines after the status line). Names are lowercased; repeated
-- names are joined with ", "; an obsolete folded line (leading space) continues the
-- previous value.
local function parse_block(block)
  local status_line = string.match(block, "^[^\r\n]*")
  local status = tonumber(string.match(status_line, "^HTTP/[%d.]+%s+(%d%d%d)"))
  local headers = {}
  local last
  local first = true
  for line in string.gmatch(block, "[^\r\n]+") do
    if first then
      first = false
    elseif string.find(line, "^[ \t]") and last then
      headers[last] = headers[last] .. " " .. string.match(line, "^%s*(.-)%s*$")
    else
      local name, value = string.match(line, "^([^:]+):%s*(.-)%s*$")
      if name then
        name = string.lower(name)
        if headers[name] then
          headers[name] = headers[name] .. ", " .. value
        else
          headers[name] = value
        end
        last = name
      end
    end
  end
  return status, headers
end

-- The header blocks curl dumped, in order: { { status, headers }, ... }
local function parse_head(head)
  local blocks = {}
  local pos = 1
  local len = #head
  while pos <= len do
    local s = string.find(head, "HTTP/", pos, true)
    if not s then
      break
    end
    local e1, e2 = string.find(head, "\r?\n\r?\n", s)
    local block = string.sub(head, s, (e1 or len + 1) - 1)
    local status, headers = parse_block(block)
    if status then
      blocks[#blocks + 1] = { status = status, headers = headers }
    end
    pos = (e2 or len) + 1
  end
  return blocks
end

--- M.parse(stdout, request) -> response | nil, err
-- stdout is everything curl printed for a transfer that exited 0.
function M.parse(out, req)
  out = out or ""
  local tail_start = #out - 127
  if tail_start < 1 then
    tail_start = 1
  end
  local tail = string.sub(out, tail_start)
  -- the last trailer in the tail (the body may contain the marker text too); found
  -- with a plain search because the marker is full of pattern characters
  local at, code, size, head_size
  local search = 1
  local marker = "\n" .. M.TRAILER .. " "
  while true do
    local i, j = string.find(tail, marker, search, true)
    if not i then
      break
    end
    local c, n, h = string.match(tail, "^(%d+) (%d+) ?(%d*)%s*$", j + 1)
    if c then
      at, code, size, head_size = i, c, n, h
    end
    search = i + 1
  end
  if not at then
    return nil,
      errors.new(
        "TransportError",
        { message = "curl output has no write-out trailer (is this curl 7.75 or newer?)" }
      )
  end
  local trailer_from = tail_start + at - 1 -- index of the "\n" starting the trailer
  size = tonumber(size)
  local body_end = trailer_from - 1
  local body_start = body_end - size + 1
  -- HTTP trailers sit between the body and the write-out: with size_header the body
  -- starts right after the header blocks, and anything after it is the trailers
  local trailer_text
  head_size = tonumber(head_size)
  if head_size and head_size + size < body_end and head_size >= 0 then
    local start = head_size + 1
    local gap = string.sub(out, start + size, body_end)
    if string.find(gap, "^[%w!#$%%&'*+%-.^_`|~]+:") then
      body_start = start
      body_end = start + size - 1
      trailer_text = gap
    end
  end
  if body_start < 1 then
    return nil,
      errors.new(
        "TransportError",
        { message = "curl output is shorter than the body size it reported" }
      )
  end
  local head = string.sub(out, 1, body_start - 1)
  local blocks = parse_head(head)
  local final = blocks[#blocks]
  if not final then
    return nil, errors.new("TransportError", { message = "curl output has no HTTP status line" })
  end
  local status = final.status
  local reported = tonumber(code)
  if reported and reported ~= 0 and reported ~= status then
    status = reported -- trust curl's own reading if the header dump disagrees
  end
  local body = ""
  if size > 0 and string.upper(req and req.method or "") ~= "HEAD" then
    body = string.sub(out, body_start, body_end)
  end
  local res = { status = status, headers = final.headers, body = body }
  if trailer_text then
    local _, trailers = parse_block("trailers\r\n" .. trailer_text)
    res.trailers = trailers
  end
  return res
end

--- M.exec_timeout(request, margin) -> seconds | nil: how long the process may run
function M.exec_timeout(req, margin)
  if req.timeout then
    return (req.timeout > 0 and req.timeout or 0.001) + (margin or 2)
  end
  return nil
end

return M
