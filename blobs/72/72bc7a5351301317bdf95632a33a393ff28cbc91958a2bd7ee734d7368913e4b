-- A curl transport over an `exec(argv, opts)` function with Rex's contract:
--   exec(argv, { stdin = string, timeout = seconds }) ->
--     { code, ok, stdout, stderr, timed_out } | nil, message (the program never ran)
-- In Rex that is rex.exec (io.popen raises there); see distilled.host.rex.
--
--   local transport = require("distilled.transport.exec_curl")(rex.exec [, opts])
--   opts = { curl = "curl", margin_s = 2, follow_redirects = false, start = nil }
--   With exec.start (rex.exec.start) or opts.start, the result is a callable table with
--   transport.stream / transport.duplex (task 29; distilled.transport.exec_curl_duplex).
--
-- How the request reaches curl without a process argument or a temp file:
-- * no body: argv is `curl -q --config -` and the config text is the whole stdin;
-- * a body: stdin is the config text followed by the body bytes, and argv is
--     sh -c 'exec 3<&0; dd bs=1 count="$1" 2>/dev/null | "$2" -q --config -' sh <n> curl
--   dd reads exactly the n config bytes (bs=1: it never reads ahead) and pipes them to
--   curl as its config; fd 3 is the original stdin, now positioned at the body, and the
--   config says `data-binary = "@/dev/fd/3"`. curl reaches the body only after the config
--   pipe closes, which is after dd has taken its n bytes. Nothing is written to disk, so
--   nothing is left behind even when the process is killed.
-- `-q` (first argument) stops curl reading ~/.curlrc.
local common = require("distilled.transport.curl_common")
local compat = require("distilled.compat")

local BODY_SCRIPT = 'exec 3<&0; dd bs=1 count="$1" 2>/dev/null | "$2" -q --config -'

local function new(exec, opts)
  if type(exec) ~= "function" and not (type(exec) == "table" and getmetatable(exec)) then
    compat.raise("exec_curl: expected exec(argv, opts) (for example rex.exec)", 2)
  end
  opts = opts or {}
  local curl = opts.curl or "curl"
  local margin = opts.margin_s or 2
  local config_opts =
    { follow_redirects = opts.follow_redirects, max_redirects = opts.max_redirects }

  local function transport(req)
    local ok, err = common.check(req)
    if not ok then
      return nil, err
    end
    local argv, stdin
    if req.body ~= nil then
      config_opts.body_path = "/dev/fd/3"
      local config = common.config(req, config_opts)
      argv = { "sh", "-c", BODY_SCRIPT, "sh", tostring(#config), curl }
      stdin = config .. req.body
    else
      config_opts.body_path = nil
      stdin = common.config(req, config_opts)
      argv = { curl, "-q", "--config", "-" }
    end
    local result, exec_err =
      exec(argv, { stdin = stdin, timeout = common.exec_timeout(req, margin) })
    if not result then
      return nil, common.failure({ not_found = true, message = tostring(exec_err), request = req })
    end
    if result.timed_out or result.code ~= 0 then
      return nil,
        common.failure({
          code = result.code,
          stderr = result.stderr,
          timed_out = result.timed_out,
          request = req,
        })
    end
    return common.parse(result.stdout, req)
  end
  -- The streaming entry points (task 29 contract) need exec.start (rex.exec.start: a
  -- process whose stdout arrives in pieces); without it the transport cannot stream.
  local start = opts.start
  if start == nil and type(exec) == "table" then
    start = rawget(exec, "start")
  end
  if start == nil then
    return transport
  end
  local duplex_mod = require("distilled.transport.exec_curl_duplex")
  local function start_fn(argv, o)
    return start(argv, o)
  end
  return setmetatable({
    stream = duplex_mod.streaming(start_fn, opts),
    duplex = duplex_mod.new(start_fn, opts),
  }, {
    __call = function(_, req)
      return transport(req)
    end,
  })
end

-- transport_module: distilled.host.check refuses this table as a transport (task 09)
return setmetatable({ new = new, transport_module = "distilled.transport.exec_curl" }, {
  __call = function(_, exec, opts)
    return new(exec, opts)
  end,
})
