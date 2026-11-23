-- Streaming and full-duplex curl transfers for stock Lua and LuaJIT (io.popen), task 31.
-- Kept apart from distilled.transport.popen_curl so task 29 (which owns that module and
-- the `stream` entry point) can adopt it without merge conflicts; like popen_curl, it is
-- a module allowed to shell out (AGENTS.md names popen_curl; this is its companion).
--
--   local pd = require("distilled.transport.popen_curl_duplex")
--   local duplex = pd.duplex([opts])     -- duplex(request) -> conn (curl_duplex's contract)
--   local stream = pd.streaming([opts])  -- stream(request) -> { status, headers, body = reader }
--   opts = { curl = "curl", tmpdir = nil ($TMPDIR or /tmp) }
--
-- io.popen is one-way, so curl runs in the background with its stdin and stdout on two
-- FIFOs in a private directory (mktemp -d, mode 0700): Lua writes the body into one and
-- reads the response from the other, each through io.open, as it comes (measured: lua
-- 5.5 and luajit return each read as soon as curl writes the bytes). The directory also
-- holds the config (URL and headers: secrets never reach argv), the body of a one-way
-- transfer, curl's stderr, its pid and its exit status; it is removed when the transfer
-- ends or is closed. Lua keeps a reader of its own on the stdin FIFO, so a write after
-- curl exited cannot kill the process with SIGPIPE (the status file is checked before
-- every write instead). close() kills curl and removes the directory.
local common = require("distilled.transport.curl_common")
local errors = require("distilled.errors")
local compat = require("distilled.compat")
local popen_curl = require("distilled.transport.popen_curl")

local function sh_quote(s)
  return "'" .. string.gsub(s, "'", "'\\''") .. "'"
end

local function transport_error(message)
  return errors.new("TransportError", { message = message })
end

local function read_command(cmd)
  if type(io.popen) ~= "function" then
    return nil,
      transport_error(
        "popen_curl_duplex: io.popen is not available here (in Rex use distilled.host.rex)"
      )
  end
  local ok, f = compat.pcall(io.popen, cmd, "r")
  if not ok or not f then
    return nil, transport_error("popen_curl_duplex: io.popen failed")
  end
  local out = f:read("*a")
  f:close()
  return out or ""
end

local function write_file(path, data)
  local f, open_err = io.open(path, "wb")
  if not f then
    return nil,
      transport_error("popen_curl_duplex: cannot write a temp file: " .. tostring(open_err))
  end
  local ok, write_err = f:write(data)
  f:close()
  if not ok then
    return nil,
      transport_error("popen_curl_duplex: cannot write a temp file: " .. tostring(write_err))
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

local function transfer_new(opts, one_way)
  opts = opts or {}
  local curl = opts.curl or "curl"
  local curl_duplex = require("distilled.transport.curl_duplex")
  return function(req)
    local ok, err = common.check(req)
    if not ok then
      return nil, err
    end
    if req.body ~= nil and not one_way then
      return nil,
        errors.new("InvalidInput", {
          message = "transport.duplex: the body is written through conn:write, not request.body",
          member = "body",
        })
    end
    local template = opts.tmpdir and sh_quote(opts.tmpdir .. "/distilled-duplex.XXXXXX")
      or '"${TMPDIR:-/tmp}/distilled-duplex.XXXXXX"'
    local dir, derr = read_command(
      "umask 077; d=$(mktemp -d "
        .. template
        .. ') && mkfifo "$d/in" "$d/out" "$d/hdr" && printf %s "$d"'
    )
    if not dir or dir == "" or string.find(dir, "[\r\n]") then
      return nil, derr or transport_error("popen_curl: mktemp -d / mkfifo failed")
    end
    local files = { "config", "body", "in", "out", "hdr", "err", "pid", "status" }
    local function path(name)
      return dir .. "/" .. name
    end
    local w, keep, r, h
    local cleaned = false
    local function cleanup()
      if cleaned then
        return
      end
      cleaned = true
      for _, f in ipairs({ w, keep, r, h }) do
        if f then
          compat.pcall(function()
            f:close()
          end)
        end
      end
      for _, name in ipairs(files) do
        os.remove(path(name))
      end
      os.remove(dir)
    end
    local wok, werr = write_file(
      path("config"),
      curl_duplex.config(req, one_way and req.body ~= nil and "body" or nil)
    )
    if wok and one_way and req.body ~= nil then
      wok, werr = write_file(path("body"), req.body)
    end
    if not wok then
      cleanup()
      return nil, werr
    end
    local script = "cd "
      .. sh_quote(dir)
      .. " && { "
      .. sh_quote(curl)
      .. " -q --config config <"
      .. (one_way and "/dev/null" or "in")
      .. " >out 2>err "
      .. curl_duplex.HEADER_FD
      .. ">hdr & echo $! >pid; wait $!; echo $? >status; }"
    local started, serr = read_command("umask 077; (" .. script .. ") >/dev/null 2>&1 </dev/null &")
    if not started then
      cleanup()
      return nil, serr
    end
    -- the same order as the shell's redirections (<in, then >out): neither side waits
    -- on a FIFO the other has not reached
    if not one_way then
      w = io.open(path("in"), "wb")
      keep = w and io.open(path("in"), "rb")
    end
    r = (one_way or keep) and io.open(path("out"), "rb")
    -- the header channel last: the shell opens `>out` before `5>hdr`
    h = r and io.open(path("hdr"), "rb")
    if not h then
      cleanup()
      return nil, transport_error("popen_curl: cannot open the duplex FIFOs")
    end
    if w and w.setvbuf then
      w:setvbuf("no")
    end
    local function exited()
      local f = io.open(path("status"), "rb")
      if f then
        f:close()
        return true
      end
      return false
    end
    local stdin_open = not one_way
    local proc = {}
    function proc.write(bytes)
      if not stdin_open then
        return nil, "the request body is closed"
      end
      if exited() then
        return nil, "curl has exited"
      end
      local okw, e = w:write(bytes)
      if okw then
        okw, e = w:flush()
      end
      if not okw then
        return nil, tostring(e)
      end
      return true
    end
    function proc.close_stdin()
      if stdin_open and w then
        stdin_open = false
        w:close()
        w = nil
      end
    end
    function proc.read(n)
      if cleaned then
        return ""
      end
      return r:read(n) or ""
    end
    function proc.read_line()
      if cleaned then
        return ""
      end
      -- "*L" keeps the newline, so a last line cut by a dropped connection shows (task 29)
      local line = r:read("*L")
      if line == nil then
        return ""
      end
      return line
    end
    function proc.head_line()
      if cleaned then
        return ""
      end
      return h:read("*L") or ""
    end
    function proc.finish()
      local code
      for _ = 1, 200 do
        local text = read_file(path("status"))
        code = tonumber(string.match(text, "%d+"))
        if code then
          break
        end
        popen_curl.sleep(0.05)
      end
      local stderr = read_file(path("err"))
      -- curl has exited: what is left on the header channel is the trailers
      local rest = h and h:read("*a") or ""
      cleanup()
      return code or -1, stderr, rest
    end
    function proc.kill()
      if not cleaned then
        if not exited() then
          local pid = string.match(read_file(path("pid")), "%d+")
          if pid then
            os.execute("kill " .. pid .. " 2>/dev/null")
            -- the background shell writes `status` once curl is gone: wait for it, or
            -- it lands after cleanup and leaves the directory behind (task 29)
            for _ = 1, 40 do
              if exited() then
                break
              end
              popen_curl.sleep(0.05)
            end
          end
        end
        cleanup()
      end
    end
    local conn = curl_duplex.conn(proc, req)
    if one_way then
      local res, rerr = conn:response()
      if not res then
        conn:close()
      end
      return res, rerr
    end
    return conn
  end
end

return {
  duplex = function(opts)
    return transfer_new(opts, false)
  end,
  streaming = function(opts)
    return transfer_new(opts, true)
  end,
}
