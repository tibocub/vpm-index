-- Credentials: where a secret option's value comes from, resolved on first use and held
-- as a secret. Replaces Distilled's per-provider Credentials services (config.ts and each
-- package's credentials.ts) with one rule: a source is a string, a secret, or a function.
--
--   credentials.resolve(source, host) -> secret | nil, err
--   credentials.from_env(name)      -> source: host.getenv(name) (or the first of a list)
--   credentials.from_file(path)     -> source: the file's text, trailing whitespace trimmed
--   credentials.from_command(argv)  -> source: the command's stdout through host.exec
--
-- Errors never quote the value (nor a file's contents or a command's output): a
-- credential that is wrong is still a credential.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local secret = require("distilled.secret")

local credentials = {}

local function config_error(message, key)
  return errors.new("ConfigError", { message = message, key = key })
end

local function callable(v)
  if type(v) == "function" then
    return true
  end
  local mt = type(v) == "table" and getmetatable(v)
  return mt and type(mt) == "table" and mt.__call ~= nil and not secret.is(v) or false
end

--- credentials.is_source(v) -> v is a string, a secret or callable
function credentials.is_source(v)
  return type(v) == "string" or secret.is(v) or callable(v)
end

--- credentials.is_refreshable(source) -> resolving it again may give another value
function credentials.is_refreshable(source)
  return callable(source) and not secret.is(source)
end

local function trim_trailing(s)
  return (string.gsub(s, "%s+$", ""))
end

--- credentials.resolve(source, host [, name]) -> secret | nil, err
-- A string or a secret is the value. A function is called as fn(host) and returns the
-- value, or nil, err (an error table, or a message that becomes a ConfigError); a raise
-- becomes an SdkError. An empty value is a ConfigError. `name` (an option name) is used
-- in messages and as err.key.
function credentials.resolve(source, host, name)
  local label = name and ("credential " .. name) or "credential"
  local value = source
  if credentials.is_refreshable(source) then
    local ok, v, err = compat.pcall(source, host or {})
    if not ok then
      local message = type(v) == "table" and rawget(v, "message") or v
      return nil,
        errors.new("SdkError", {
          message = "the " .. label .. " source raised: " .. tostring(message),
          cause = v,
        })
    end
    if v == nil then
      if errors.is(err) then
        return nil, err
      end
      if err ~= nil then
        return nil, config_error("the " .. label .. " source failed: " .. tostring(err), name)
      end
      return nil, config_error("the " .. label .. " source returned no value", name)
    end
    value = v
  end
  if value == nil then
    return nil, config_error("no value for the " .. label, name)
  end
  local plain = secret.unwrap(value)
  if plain == "" then
    return nil, config_error("the " .. label .. " is empty", name)
  end
  return secret.wrap(plain)
end

--- credentials.from_env(name | { name, ... }) -> source reading host.getenv (default
-- os.getenv). With a list, the first variable that is set and not empty wins, like the
-- `process.env.A ?? process.env.B` chains of Distilled's credentials.ts files. Unset or
-- empty is a ConfigError naming the variables.
function credentials.from_env(name)
  local names = type(name) == "table" and name or { name }
  if #names == 0 then
    compat.raise("credentials.from_env: expected a variable name", 2)
  end
  for _, n in ipairs(names) do
    if type(n) ~= "string" or n == "" then
      compat.raise("credentials.from_env: expected a variable name", 2)
    end
  end
  local label = names[1]
  if #names > 1 then
    local rest = {}
    for i = 2, #names do
      rest[#rest + 1] = names[i]
    end
    label = names[1] .. " (or " .. compat.concat(rest, ", ") .. ")"
  end
  return function(host)
    local getenv = (host and host.getenv) or os.getenv
    for _, n in ipairs(names) do
      local v = getenv(n)
      if v ~= nil and v ~= "" then
        return v
      end
    end
    return nil, config_error("environment variable " .. label .. " is not set", names[1])
  end
end

--- credentials.from_file(path) -> source reading the file; trailing whitespace (the
-- usual final newline) is trimmed. A missing, unreadable or empty file is a ConfigError.
function credentials.from_file(path)
  if type(path) ~= "string" or path == "" then
    compat.raise("credentials.from_file: expected a path", 2)
  end
  return function()
    local f = io.open(path, "rb")
    if not f then
      return nil, config_error("cannot read the credential file " .. path, path)
    end
    local text = f:read("*a")
    f:close()
    text = trim_trailing(text or "")
    if text == "" then
      return nil, config_error("the credential file " .. path .. " is empty", path)
    end
    return text
  end
end

--- credentials.from_command(argv [, opts]) -> source running argv through host.exec
-- (`opts.timeout` seconds is passed on). Its stdout, trailing whitespace trimmed, is the
-- value. A host without exec, a failed start, a non-zero exit or empty output is a
-- ConfigError; the message names the program and the exit code, never the output.
function credentials.from_command(argv, opts)
  if type(argv) ~= "table" or type(argv[1]) ~= "string" then
    compat.raise("credentials.from_command: expected an argv list", 2)
  end
  opts = opts or {}
  local program = argv[1]
  return function(host)
    local exec = host and host.exec
    if type(exec) ~= "function" and not callable(exec) then
      return nil,
        config_error(
          "credentials.from_command needs a host with exec (to run " .. program .. ")",
          "exec"
        )
    end
    local res, message = exec(argv, { timeout = opts.timeout })
    if type(res) ~= "table" then
      return nil,
        config_error(
          "cannot run the credential command " .. program .. ": " .. tostring(message),
          program
        )
    end
    if res.timed_out then
      return nil, config_error("the credential command " .. program .. " timed out", program)
    end
    if res.ok == false or (res.code ~= nil and res.code ~= 0) then
      return nil,
        config_error(
          "the credential command " .. program .. " exited with code " .. tostring(res.code),
          program
        )
    end
    local out = trim_trailing(res.stdout or "")
    if out == "" then
      return nil, config_error("the credential command " .. program .. " printed nothing", program)
    end
    return out
  end
end

---------------------------------------------------------------------------------------
-- the cache a client holds
---------------------------------------------------------------------------------------

--- credentials.cell(source) -> { source, value } : one option's cached resolution.
-- Clients derived with `with` share the cells of the options they do not override.
function credentials.cell(source)
  return { source = source, value = nil }
end

--- credentials.get(cell, host, name) -> secret | nil, err (resolves on first use)
function credentials.get(cell, host, name)
  if cell.value ~= nil then
    return cell.value
  end
  local v, err = credentials.resolve(cell.source, host, name)
  if v == nil then
    return nil, err
  end
  cell.value = v
  return v
end

--- credentials.clear(cell) -> true when the cell's source can give a new value (and the
-- cache was cleared), false for fixed values (a string or a secret cannot change)
function credentials.clear(cell)
  if not credentials.is_refreshable(cell.source) then
    return false
  end
  cell.value = nil
  return true
end

return credentials
