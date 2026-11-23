-- E2B envd's host (packages/e2b/src/credentials.ts envdBaseUrlFor): E2B Cloud
-- (domain e2b.app) serves every sandbox at https://sandbox.<domain>, routed by the
-- E2b-Sandbox-Id header; any other domain at https://<port>-<sandbox_id>.<domain>.
-- A base_url option, when given, wins.
--
-- glue.methods (task 30): envd's server-streaming Connect RPCs, hand-written in
-- Distilled's packages/e2b/src/connect.ts because no model declares them. They become
-- client methods returning a stream of decoded events:
--
--   process:     start_process_stream{ process = { cmd, args, envs, cwd }, pty, tag, stdin }
--                connect_process_stream{ process = { pid = 1 } | { tag = "t" } }
--                  items: { _tag = "Start", pid } | { _tag = "Stdout" | "Stderr" | "Pty",
--                  data = <bytes> } | { _tag = "End", exitCode, exited, status, error? }
--                  | { _tag = "KeepAlive" }
--   filesystem:  watch_dir_stream{ path, recursive, includeEntry, allowNetworkMounts }
--                  items: { _tag = "Start" } | { _tag = "KeepAlive" }
--                  | { _tag = "Filesystem", name, type, entry? }
--
-- Closing the stream closes the connection; the process keeps running (connect.ts).
local connect = require("distilled.protocol.connect")
local errors = require("distilled.errors")
local json = require("distilled.json")
local base64 = require("distilled.crypto.base64")

local glue = {}
-- helpers are reachable as glue.<name> but are not hooks (the generator checks pairs)
local helpers = {}
setmetatable(glue, { __index = helpers })

local SHARED_SANDBOX_HOST_DOMAINS = { ["e2b.app"] = true }

function glue.base_url(s)
  if type(s.base_url) == "string" and s.base_url ~= "" then
    return s.base_url
  end
  local domain = s.domain or "e2b.app"
  if SHARED_SANDBOX_HOST_DOMAINS[domain] then
    return "https://sandbox." .. domain
  end
  return "https://" .. tostring(s.port or "49983") .. "-" .. tostring(s.sandbox_id) .. "." .. domain
end

-- a JSON object or array (connect.ts isRecord)
local function is_record(v)
  return type(v) == "table" and v ~= json.null
end

-- JavaScript's Boolean(v) for a JSON value
local function truthy(v)
  return v ~= nil and v ~= json.null and v ~= false and v ~= 0 and v ~= ""
end

-- JavaScript's Number(v ?? 0) for a JSON value
local function number_of(v)
  if v == nil or v == json.null then
    return 0
  end
  if type(v) == "number" then
    return v
  end
  if type(v) == "boolean" then
    return v and 1 or 0
  end
  if type(v) == "string" then
    local s = string.gsub(string.gsub(v, "^%s+", ""), "%s+$", "")
    if s == "" then
      return 0
    end
    local n = json.decode(s)
    if type(n) == "number" then
      return n
    end
  end
  return 0 / 0
end

local function parse_error(info, message, cause)
  local class = info.client.protocol.parse_class or "E2BParseError"
  return errors.new(class, {
    message = "cannot decode an envd " .. tostring(info.method) .. " message: " .. cause,
    body = message,
    cause = cause,
  })
end

-- connect.ts fromBase64: bytes of a base64 string, "" for anything else
local function from_base64(info, message, v)
  if type(v) ~= "string" then
    return ""
  end
  local bytes = base64.decode(v)
  if bytes == nil then
    return nil, parse_error(info, message, "invalid base64")
  end
  return bytes
end

--- helpers.process_event(message, info) -> event | nil, err (connect.ts decodeProcessEvent)
function helpers.process_event(message, info)
  local event = is_record(message) and message.event or nil
  if not is_record(event) then
    return nil, parse_error(info, message, "missing event")
  end
  if is_record(event.start) then
    return { _tag = "Start", pid = number_of(event.start.pid) }
  end
  if is_record(event.data) then
    local data = event.data
    for _, k in ipairs({ { "stdout", "Stdout" }, { "stderr", "Stderr" }, { "pty", "Pty" } }) do
      if data[k[1]] ~= nil then
        local bytes, err = from_base64(info, message, data[k[1]])
        if bytes == nil then
          return nil, err
        end
        return { _tag = k[2], data = bytes }
      end
    end
    return { _tag = "Stdout", data = "" }
  end
  if is_record(event["end"]) then
    local e = event["end"]
    return {
      _tag = "End",
      exitCode = number_of(e.exitCode),
      exited = truthy(e.exited),
      status = type(e.status) == "string" and e.status or "",
      error = type(e.error) == "string" and e.error or nil,
    }
  end
  if is_record(event.keepalive) then
    return { _tag = "KeepAlive" }
  end
  return nil, parse_error(info, message, "unknown process event")
end

--- helpers.watch_dir_event(message, info) -> event | nil, err (connect.ts decodeWatchDirEvent)
function helpers.watch_dir_event(message, info)
  if not is_record(message) then
    return nil, parse_error(info, message, "not an object")
  end
  if is_record(message.start) then
    return { _tag = "Start" }
  end
  if is_record(message.keepalive) then
    return { _tag = "KeepAlive" }
  end
  if is_record(message.filesystem) then
    local e = message.filesystem
    return {
      _tag = "Filesystem",
      name = type(e.name) == "string" and e.name or "",
      type = type(e.type) == "string" and e.type or "EVENT_TYPE_UNSPECIFIED",
      entry = is_record(e.entry) and e.entry or nil,
    }
  end
  return nil, parse_error(info, message, "unknown watch event")
end

local CODE_CLASS = {
  invalid_argument = "BadRequest",
  failed_precondition = "BadRequest",
  out_of_range = "BadRequest",
  unauthenticated = "Unauthorized",
  permission_denied = "Forbidden",
  not_found = "NotFound",
  already_exists = "Conflict",
  aborted = "Conflict",
}

--- helpers.connect_error(info) -> err (connect.ts connectError)
-- info = { error = { code, message }, body, status, client }
function helpers.connect_error(info)
  local e = info.error or {}
  local message = e.message or e.code or "envd call failed"
  local tag = e.code and CODE_CLASS[e.code]
  if tag then
    return errors.new(tag, { message = message, status = info.status })
  end
  return errors.new(info.client.protocol.unknown_class or "UnknownE2BError", {
    status = info.status,
    code = e.code,
    message = e.message, -- as connect.ts: no message when the error has none
    body = info.body,
  })
end

--- helpers.stream_failure(info) -> err: a streaming envd call's failure (connect.ts
-- serverStream): a non-2xx reply before the stream (info.phase "status") or the
-- end-of-stream envelope's error (info.phase "end", status 200)
function helpers.stream_failure(info)
  if info.phase ~= "status" then
    return helpers.connect_error(info)
  end
  local e = info.error or {}
  local body = info.body
  local body_message = is_record(body) and type(body.message) == "string" and body.message or nil
  local state = info.client
  if info.status == 502 then
    local class = state.service.errors and state.service.errors.SandboxNotRunning
      or "SandboxNotRunning"
    local id = state.opts and state.opts.sandbox_id
    return errors.new(class, {
      status = 502,
      code = 502,
      message = e.message or body_message or ("sandbox " .. tostring(id) .. " is not running"),
    })
  end
  -- an unmapped 5xx is a server fault worth a retry, as in core's REST protocol
  if info.status >= 500 and e.code == nil then
    return errors.new("InternalServerError", {
      status = info.status,
      message = e.message or body_message or ("HTTP " .. tostring(info.status)),
    })
  end
  if e.code == nil and info.status == 404 then
    local method = string.gsub(tostring(info.method), "^/", "")
    return errors.new("NotFound", { status = 404, message = "envd " .. method .. " not found" })
  end
  return helpers.connect_error(info)
end

local function method(name, uri, decode)
  return connect.stream_method({
    op = { name = name, uri = uri, errors = { "SandboxNotRunning" } },
    fail = helpers.stream_failure,
    decode = decode,
  })
end

--- glue.methods(service) -> { [name] = fn(client, input) -> stream | nil, err }
function glue.methods(service)
  local name = service and service.name
  if name == "e2b.process" then
    return {
      start_process_stream = method(
        "StartProcess",
        "/process.Process/Start",
        helpers.process_event
      ),
      connect_process_stream = method(
        "ConnectProcess",
        "/process.Process/Connect",
        helpers.process_event
      ),
    }
  end
  if name == "e2b.filesystem" then
    return {
      watch_dir_stream = method(
        "WatchDir",
        "/filesystem.Filesystem/WatchDir",
        helpers.watch_dir_event
      ),
    }
  end
  return {}
end

return glue
