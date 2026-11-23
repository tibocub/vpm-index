-- A curl transport for stock Lua and LuaJIT, through io.popen. (Rex has no io.popen; use
-- exec_curl there, or distilled.host.rex.)
--
--   local transport = require("distilled.transport.popen_curl")([opts])
--   opts = { curl = "curl", follow_redirects = false, tmpdir = nil ($TMPDIR or /tmp) }
--   transport(request) -> response; transport.stream(request) -> { status, headers,
--   body = reader }; transport.duplex(request) -> conn (see "Streams" in
--   docs/interfaces.md). The result is a callable table.
--
-- io.popen gives one direction only: we can read curl's stdout or write its stdin, not
-- both. Reading stdout matters more (the response may be megabytes), so the request goes
-- through files instead of stdin:
-- * `mktemp` creates each file (config, body, stderr) with mode 0600 at creation
--   (mkstemp), so no file is readable by another user at any moment; io.open on an
--   existing file keeps its mode. The shell that runs curl also sets `umask 077`.
-- * The config file holds the URL, method and headers (the API key); the body file
--   holds the exact body bytes; stderr goes to its own file so it cannot mix with the
--   body on stdout.
-- * Every file is removed by a scope finalizer, on success, on failure and on a raise.
-- * curl's argv names only file paths: `curl -q --config <path>`. Its exit status is
--   printed after the output (LuaJIT's pipe close does not return it).
local common = require("distilled.transport.curl_common")
local errors = require("distilled.errors")
local compat = require("distilled.compat")
local Scope = require("distilled.scope")

-- a word for /bin/sh: single-quoted, with embedded single quotes closed and escaped
local function sh_quote(s)
  return "'" .. string.gsub(s, "'", "'\\''") .. "'"
end

local function transport_error(message)
  return errors.new("TransportError", { message = message })
end

-- runs a shell command and returns its whole stdout, or nil, err
local function read_command(cmd)
  local popen = io.popen
  if type(popen) ~= "function" then
    return nil, transport_error("popen_curl: io.popen is not available here (in Rex use exec_curl)")
  end
  local ok, f = compat.pcall(popen, cmd, "r")
  if not ok or not f then
    return nil,
      transport_error(
        "popen_curl: io.popen failed"
          .. (ok and "" or (": " .. tostring(f)))
          .. " (in Rex use exec_curl)"
      )
  end
  local out = f:read("*a")
  f:close()
  return out or ""
end

-- makes n temp files with mktemp in dir (default $TMPDIR, else /tmp); returns a list of
-- paths or nil, err
local function make_temp_files(n, dir)
  local template = dir and sh_quote(dir .. "/distilled-curl.XXXXXX")
    or '"${TMPDIR:-/tmp}/distilled-curl.XXXXXX"'
  local cmds = {}
  for i = 1, n do
    cmds[i] = "mktemp " .. template
  end
  local out, err = read_command("umask 077; " .. table.concat(cmds, " && "))
  if not out then
    return nil, err
  end
  local paths = {}
  for line in string.gmatch(out, "[^\n]+") do
    paths[#paths + 1] = line
  end
  if #paths ~= n then
    for _, p in ipairs(paths) do
      os.remove(p)
    end
    return nil, transport_error("popen_curl: mktemp failed")
  end
  return paths
end

local function write_file(path, data)
  local f, open_err = io.open(path, "wb")
  if not f then
    return nil, transport_error("popen_curl: cannot write a temp file: " .. tostring(open_err))
  end
  local ok, write_err = f:write(data)
  f:close()
  if not ok then
    return nil, transport_error("popen_curl: cannot write a temp file: " .. tostring(write_err))
  end
  return true
end

local function read_file(path)
  local f = io.open(path, "rb")
  if not f then
    return ""
  end
  local data = f:read("*a") or ""
  f:close()
  return data
end

local function new(opts)
  opts = opts or {}
  if type(opts) ~= "table" then
    compat.raise("popen_curl: expected an options table", 2)
  end
  local curl = opts.curl or "curl"
  local config_opts =
    { follow_redirects = opts.follow_redirects, max_redirects = opts.max_redirects }

  local function send(scope, req)
    local has_body = req.body ~= nil
    local paths, err = make_temp_files(has_body and 3 or 2, opts.tmpdir)
    if not paths then
      return nil, err
    end
    scope:defer(function()
      for _, p in ipairs(paths) do
        os.remove(p)
      end
    end)
    local config_path, stderr_path, body_path = paths[1], paths[2], paths[3]
    local ok, write_err
    if has_body then
      ok, write_err = write_file(body_path, req.body)
      if not ok then
        return nil, write_err
      end
    end
    local o = {}
    for k, v in pairs(config_opts) do
      o[k] = v
    end
    o.body_path = body_path
    ok, write_err = write_file(config_path, common.config(req, o))
    if not ok then
      return nil, write_err
    end
    local cmd = "umask 077; "
      .. sh_quote(curl)
      .. " -q --config "
      .. sh_quote(config_path)
      .. " 2>"
      .. sh_quote(stderr_path)
      .. "; printf '\\n%d' \"$?\""
    local out, run_err = read_command(cmd)
    if not out then
      return nil, run_err
    end
    -- the exit status is the last line
    local status_at = nil
    local from = #out - 16
    if from < 1 then
      from = 1
    end
    local i, _, code = string.find(out, "\n(%d+)$", from)
    if i then
      status_at = i
    end
    if not status_at then
      return nil, transport_error("popen_curl: the shell printed no exit status")
    end
    code = tonumber(code)
    out = string.sub(out, 1, status_at - 1)
    if code ~= 0 then
      return nil, common.failure({ code = code, stderr = read_file(stderr_path), request = req })
    end
    return common.parse(out, req)
  end

  local function transport(req)
    local ok, err = common.check(req)
    if not ok then
      return nil, err
    end
    return Scope.with(function(scope)
      return send(scope, req)
    end)
  end
  -- The streaming entry points (task 29 contract, docs/interfaces.md "Streams"):
  -- transport.stream(request) -> { status, headers, body = reader } and
  -- transport.duplex(request) -> conn. Both run curl in the background on FIFOs
  -- (distilled.transport.popen_curl_duplex, built in task 31), loaded on first use.
  local entries = {}
  local function lazy(kind)
    return function(req)
      if entries[kind] == nil then
        local pd = require("distilled.transport.popen_curl_duplex")
        entries[kind] = kind == "stream" and pd.streaming(opts) or pd.duplex(opts)
      end
      return entries[kind](req)
    end
  end
  return setmetatable({ stream = lazy("stream"), duplex = lazy("duplex") }, {
    __call = function(_, req)
      return transport(req)
    end,
  })
end

--- popen_curl.sleep(seconds): wait in a child `sleep` process (wall time; stock Lua has
-- no sleep). Lives here because this is the one core module allowed to use io.popen
-- (AGENTS.md); distilled.host.popen hands it to clients. Ignores non-positive, NaN and
-- non-number values.
local function shell_sleep(seconds)
  if type(seconds) ~= "number" or seconds ~= seconds or seconds <= 0 then
    return
  end
  local p = io.popen(string.format("sleep %.3f", seconds))
  if p then
    p:read("*a")
    p:close()
  end
end

-- transport_module: distilled.host.check refuses this table as a transport (task 09)
return setmetatable({
  new = new,
  sleep = shell_sleep,
  transport_module = "distilled.transport.popen_curl",
}, {
  __call = function(_, opts)
    return new(opts)
  end,
})
