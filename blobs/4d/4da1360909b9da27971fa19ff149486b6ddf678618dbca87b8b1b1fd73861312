-- Retry: policies as data, backoff, the per-host budget, server hints and the run loop.
--
-- Ported from Distilled: retry.ts (Backoff, budgets, the presets, defaultWith),
-- retry-after.ts (Retry-After, RateLimit), retry-state.ts (hostOf, bounded hints) and
-- api.ts (applyRetry, retryWith, backoffDelay, backoffSleep).
--
--   retry.run(fn, { policy, host, tracer, span, deadline_s, server_hint_cap_s })
--     -> value, nil, meta | nil, err, meta
--
-- fn(attempt) runs one try. `attempt = { n, timeout }` (timeout: seconds left before the
-- deadline, or nil). The protocol records what the retry layer reads after a failure on
-- the same table: `attempt.host` (the request's host, keys the budget), `attempt.status`
-- (the response status; a status below 300 refills the budget) and `attempt.hint_ms`
-- (the response's bounded hint). Distilled keeps these per fiber (retry-state.ts); a
-- table per try does the same without a global.
--
-- Durations: policy fields end in `_ms` (Distilled's numbers); err.retry_after,
-- deadline_s, server_hint_cap_s and host.sleep are seconds.
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local noop = require("distilled.trace.noop")

local retry = {}

local floor = math.floor

local function misuse(message, level)
  compat.raise("retry: " .. message, (level or 2) + 1)
end

---------------------------------------------------------------------------------------
-- numbers as JavaScript's Number(text) reads them (RateLimit values)
---------------------------------------------------------------------------------------

local function trim(s)
  return (string.gsub(string.gsub(s, "^%s+", ""), "%s+$", ""))
end
retry._trim = trim

-- Number(text) for decimal text; nil where JavaScript gives NaN or an infinity. Written
-- out because gopher-lua's tonumber rejects exponents ("1e5").
local function js_number(text)
  local s = trim(text)
  if s == "" then
    return 0
  end
  local sign, int, frac, exp = string.match(s, "^([+-]?)(%d*)%.?(%d*)[eE]?([+-]?%d*)$")
  if sign == nil or (int == "" and frac == "") then
    return nil
  end
  if string.find(s, "[eE]") and (exp == "" or exp == "+" or exp == "-") then
    return nil
  end
  if not string.find(s, "[eE]") and exp ~= "" then
    return nil
  end
  local n = 0
  for i = 1, #int do
    n = n * 10 + (string.byte(int, i) - 48)
  end
  local scale = 1
  for i = 1, #frac do
    scale = scale / 10
    n = n + (string.byte(frac, i) - 48) * scale
  end
  if exp ~= "" then
    local e = tonumber(exp)
    if e == nil then
      return nil
    end
    n = n * 10 ^ e
  end
  if n ~= n or n == 1 / 0 then
    return nil
  end
  if sign == "-" then
    n = -n
  end
  return n
end
retry._js_number = js_number

---------------------------------------------------------------------------------------
-- server hints (retry-after.ts): all results in seconds
---------------------------------------------------------------------------------------

local MONTHS = {
  jan = 1,
  feb = 2,
  mar = 3,
  apr = 4,
  may = 5,
  jun = 6,
  jul = 7,
  aug = 8,
  sep = 9,
  oct = 10,
  nov = 11,
  dec = 12,
}

-- days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm)
local function days_from_civil(y, m, d)
  if m <= 2 then
    y = y - 1
  end
  local era = floor(y / 400)
  local yoe = y - era * 400
  local mp = (m + 9) % 12
  local doy = floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + floor(yoe / 4) - floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

local function unix_time(y, mon, d, hh, mm, ss)
  local m = MONTHS[string.lower(mon)]
  y, d, hh, mm, ss = tonumber(y), tonumber(d), tonumber(hh), tonumber(mm), tonumber(ss)
  if not m or not y or d < 1 or d > 31 or hh > 23 or mm > 59 or ss > 60 then
    return nil
  end
  return days_from_civil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss
end

--- retry.parse_http_date(text) -> unix seconds | nil
-- The three forms RFC 9110 requires a recipient to accept: IMF-fixdate
-- ("Sun, 06 Nov 1994 08:49:37 GMT"), RFC 850 ("Sunday, 06-Nov-94 08:49:37 GMT") and
-- asctime ("Sun Nov  6 08:49:37 1994"). Distilled uses Date.parse, which also reads
-- these; other text Date.parse might accept is not a valid Retry-After.
function retry.parse_http_date(text)
  local s = trim(text)
  local d, mon, y, hh, mm, ss =
    string.match(s, "^%a+,%s+(%d%d?)%s+(%a%a%a)%s+(%d%d%d%d)%s+(%d%d):(%d%d):(%d%d)%s+GMT$")
  if d then
    return unix_time(y, mon, d, hh, mm, ss)
  end
  d, mon, y, hh, mm, ss =
    string.match(s, "^%a+,%s+(%d%d?)%-(%a%a%a)%-(%d%d)%s+(%d%d):(%d%d):(%d%d)%s+GMT$")
  if d then
    -- two-digit years as JavaScript's Date.parse reads them: 00-49 -> 20xx, 50-99 -> 19xx
    local yy = tonumber(y)
    return unix_time(yy < 50 and 2000 + yy or 1900 + yy, mon, d, hh, mm, ss)
  end
  local rest
  mon, d, hh, mm, ss, y, rest =
    string.match(s, "^%a+%s+(%a%a%a)%s+(%d%d?)%s+(%d%d):(%d%d):(%d%d)%s+(%d%d%d%d)(.*)$")
  if mon and (rest == "" or string.match(rest, "^%s+GMT$")) then
    return unix_time(y, mon, d, hh, mm, ss)
  end
  return nil
end

--- retry.parse_retry_after(headers [, now]) -> seconds | nil
-- `retry-after` as delay-seconds (digits only) or an HTTP-date relative to `now` (unix
-- seconds, default os.time()); a date in the past is 0. Only the lowercase key is read.
function retry.parse_retry_after(headers, now)
  local raw = type(headers) == "table" and headers["retry-after"] or nil
  if type(raw) ~= "string" then
    return nil
  end
  local s = trim(raw)
  if s == "" then
    return nil
  end
  if string.find(s, "^%d+$") then
    return js_number(s)
  end
  -- anything that looks numeric but is not delay-seconds is refused (Date.parse("-5")
  -- is 0 on some engines)
  if string.find(s, "^[-+]?%d+$") or string.find(s, "^[-+]?%d+%.%d+$") then
    return nil
  end
  local at = retry.parse_http_date(s)
  if at == nil then
    return nil
  end
  local delta = at - (now or os.time())
  return delta > 0 and delta or 0
end

--- retry.parse_ratelimit(headers) -> seconds | nil
-- The IETF `RateLimit` header (`r=0, t=30`, `limit=100, remaining=0, reset=30`,
-- `"default";r=0;t=30`): the reset time, only while the remaining quota is exactly 0.
function retry.parse_ratelimit(headers)
  local raw = type(headers) == "table" and headers["ratelimit"] or nil
  if type(raw) ~= "string" or raw == "" then
    return nil
  end
  local remaining, reset
  for piece in string.gmatch(raw, "[^,;]+") do
    local eq = string.find(piece, "=", 1, true)
    if eq then
      local key = string.lower(trim(string.sub(piece, 1, eq - 1)))
      local num = js_number(string.sub(piece, eq + 1))
      if num ~= nil then
        if key == "r" or key == "remaining" then
          remaining = num
        elseif key == "t" or key == "reset" then
          reset = num
        end
      end
    end
  end
  if remaining ~= 0 then
    return nil
  end
  if reset == nil or reset < 0 then
    return nil
  end
  return reset
end

--- retry.parse_server_hint(headers [, now]) -> seconds | nil: Retry-After, else RateLimit
function retry.parse_server_hint(headers, now)
  local s = retry.parse_retry_after(headers, now)
  if s ~= nil then
    return s
  end
  return retry.parse_ratelimit(headers)
end

--- retry.parse_for_status(status, headers [, now]) -> seconds | nil
-- Only for statuses whose built-in class declares retry_after (errors.RETRYABLE_STATUSES),
-- so a BadRequest never carries a stale hint.
function retry.parse_for_status(status, headers, now)
  if not errors.RETRYABLE_STATUSES[status] then
    return nil
  end
  return retry.parse_server_hint(headers, now)
end

-- whole, non-negative milliseconds; anything else is no hint
local function parse_ms(value)
  if type(value) ~= "string" then
    return nil
  end
  local s = trim(value)
  if not string.find(s, "^%d+$") or #s > 15 then
    return nil
  end
  return js_number(s)
end

--- retry.bounded_hint_ms(headers) -> ms | nil
-- `x-amz-retry-after` or `x-distilled-retry-after` (milliseconds), the larger when both
-- are set (retry-state.ts boundedHintOf).
function retry.bounded_hint_ms(headers)
  if type(headers) ~= "table" then
    return nil
  end
  local amz = parse_ms(headers["x-amz-retry-after"])
  local distilled = parse_ms(headers["x-distilled-retry-after"])
  if amz == nil then
    return distilled
  end
  if distilled == nil then
    return amz
  end
  return amz > distilled and amz or distilled
end

--- retry.host_of(url) -> the host of url without port or userinfo; "" when it has none
function retry.host_of(url)
  if type(url) ~= "string" then
    return ""
  end
  local scheme_end = string.find(url, "://", 1, true)
  if not scheme_end then
    return ""
  end
  local start = scheme_end + 3
  local stop = string.find(url, "[/?#]", start) or (#url + 1)
  local authority = string.sub(url, start, stop - 1)
  local at = string.find(authority, "@[^@]*$")
  if at then
    authority = string.sub(authority, at + 1)
  end
  if string.sub(authority, -1) ~= "]" then
    local colon = string.find(authority, ":[^:]*$")
    if colon then
      authority = string.sub(authority, 1, colon - 1)
    end
  end
  return authority
end

---------------------------------------------------------------------------------------
-- budget (retry.ts makeBudget)
---------------------------------------------------------------------------------------

local Budget = {}
Budget.__index = Budget

--- retry.new_budget{ initial = 100, max = 500, transient_cost = 14, throttling_cost = 5 }
-- A token bucket per key (the request's host). A retry withdraws its cost; a successful
-- response adds one token up to `max`; a retry that succeeds gets its cost back. When a
-- bucket cannot pay, the call fails instead of retrying, so a failing dependency sees
-- bounded extra load. Buckets start at 100, not full: many short-lived clients each
-- starting full would together retry a failing service at nearly max_retries times its
-- load (Distilled's reasoning, after AWS Retry Behavior 2.1).
function retry.new_budget(opts)
  opts = opts or {}
  return setmetatable({
    initial = opts.initial or 100,
    max = opts.max or 500,
    transient_cost = opts.transient_cost or 14,
    throttling_cost = opts.throttling_cost or 5,
    buckets = {},
  }, Budget)
end

function retry.is_budget(v)
  return type(v) == "table" and getmetatable(v) == Budget
end

function Budget:_bucket(key)
  local b = self.buckets[key]
  if b == nil then
    b = { tokens = self.initial }
    self.buckets[key] = b
  end
  return b
end

--- budget:withdraw(key, throttling) -> cost | nil (nil: the bucket cannot pay)
function Budget:withdraw(key, throttling)
  local b = self:_bucket(key)
  local cost = throttling and self.throttling_cost or self.transient_cost
  if b.tokens < cost then
    return nil
  end
  b.tokens = b.tokens - cost
  return cost
end

--- budget:refund(key, cost): a retry that succeeded; its success already added a token
function Budget:refund(key, cost)
  local b = self:_bucket(key)
  b.tokens = math.min(self.max, b.tokens + cost - 1)
end

--- budget:success(key): a successful response from key adds one token
function Budget:success(key)
  local b = self:_bucket(key)
  b.tokens = math.min(self.max, b.tokens + 1)
end

function Budget:tokens(key)
  return self:_bucket(key).tokens
end

function Budget:reset()
  self.buckets = {}
end

--- retry.default_budget: shared by every client that does not pass `budget`
retry.default_budget = retry.new_budget()

---------------------------------------------------------------------------------------
-- policies
---------------------------------------------------------------------------------------

retry.DEFAULT_SERVER_HINT_CAP_S = 60
retry.BOUNDED_HINT_MAX_EXTRA_MS = 5000

local POLICY_FIELDS = {
  when = "function",
  max_retries = "number",
  base_ms = "number",
  throttling_base_ms = "number",
  factor = "number",
  cap_ms = "number",
  full_jitter = "boolean",
  jitter_ms = "number",
  min_throttle_ms = "number",
  server_hint = "boolean",
  budget = "budget",
  long_poll = "boolean",
}
-- what a client's `retry` table may hold besides policy fields
local SETTING_FIELDS = { deadline_s = "number", server_hint_cap_s = "number", preset = "preset" }

local PRESET_MT = { __index = function() end }

local function preset(name, fields)
  fields.name = name
  return setmetatable(fields, PRESET_MT)
end

function retry.is_preset(v)
  return type(v) == "table" and getmetatable(v) == PRESET_MT
end

--- retry.DEFAULT: for calls at runtime, after AWS's Retry Behavior 2.1: retries only
-- transient errors (errors.is_transient), at most 2 retries, full jitter
-- random() * min(20 s, base * 2^n) with base 50 ms or 1 s for throttling, honours server
-- hints, draws from the budget.
retry.DEFAULT = preset("default", {
  when = errors.is_transient,
  base_ms = 50,
  throttling_base_ms = 1000,
  factor = 2,
  cap_ms = 20000,
  max_retries = 2,
  full_jitter = true,
  server_hint = true,
  budget = retry.default_budget,
})

-- Distilled's throttlingFactory / transientFactory: 1 s base, factor 2, 5 s cap, 50 ms of
-- jitter, server hints, no retry limit and no budget (for deploy tools that wait out
-- longer outages). Use them with a deadline.
retry.THROTTLING = preset("throttling", {
  when = errors.is_throttling,
  base_ms = 1000,
  factor = 2,
  cap_ms = 5000,
  jitter_ms = 50,
  server_hint = true,
})
retry.TRANSIENT = preset("transient", {
  when = errors.is_transient,
  base_ms = 1000,
  factor = 2,
  cap_ms = 5000,
  jitter_ms = 50,
  server_hint = true,
})
retry.NONE = preset("none", {
  when = function()
    return false
  end,
  base_ms = 0,
  factor = 1,
  cap_ms = 0,
  max_retries = 0,
})

local PRESETS = {
  default = retry.DEFAULT,
  throttling = retry.THROTTLING,
  transient = retry.TRANSIENT,
  none = retry.NONE,
}

local function copy_policy(p)
  local out = {}
  for k in pairs(POLICY_FIELDS) do
    out[k] = rawget(p, k)
  end
  out.name = rawget(p, "name")
  return out
end

local function field_names()
  local names = {}
  for k in pairs(POLICY_FIELDS) do
    names[#names + 1] = k
  end
  for k in pairs(SETTING_FIELDS) do
    names[#names + 1] = k
  end
  table.sort(names)
  return table.concat(names, ", ")
end

local function check_field(key, value, level)
  local want = POLICY_FIELDS[key] or SETTING_FIELDS[key]
  if want == nil then
    misuse("unknown retry option " .. tostring(key) .. " (valid: " .. field_names() .. ")", level)
  end
  if want == "budget" then
    if value ~= false and not retry.is_budget(value) then
      misuse("retry option budget must be retry.new_budget{...} or false", level)
    end
  elseif want == "preset" then
    if not (retry.is_preset(value) or PRESETS[value]) then
      misuse("retry option preset must be a preset or a preset name", level)
    end
  elseif type(value) ~= want then
    misuse("retry option " .. key .. " must be a " .. want .. ", got " .. type(value), level)
  elseif want == "number" and (value ~= value or value < 0) then
    misuse("retry option " .. key .. " must be a non-negative number", level)
  end
end

--- retry.check_spec(spec [, level]): raises (misuse) unless spec is a valid client `retry`
-- option: nil, a preset, a preset name, or a table of policy and setting fields.
function retry.check_spec(spec, level)
  level = (level or 1) + 1
  if spec == nil or retry.is_preset(spec) then
    return
  end
  if type(spec) == "string" then
    if not PRESETS[spec] then
      misuse('unknown retry preset "' .. spec .. '" (default, throttling, transient, none)', level)
    end
    return
  end
  if type(spec) ~= "table" then
    misuse("the retry option must be a preset, a preset name or a table", level)
  end
  for k, v in pairs(spec) do
    check_field(k, v, level)
  end
end

--- retry.policy_for(spec, op_retry) -> policy, settings
-- spec: the client's `retry` option (see check_spec); op_retry: the operation's
-- `distilled.retry#policy` numbers ({ max_attempts, base_ms, throttling_base_ms, cap_ms,
-- factor, long_poll }). The operation's numbers replace the default's only when the client
-- set no policy (Distilled's defaultWith; a caller's policy ignores them). A spec holding
-- only settings (deadline_s, server_hint_cap_s) is "no policy".
-- settings = { deadline_s, server_hint_cap_s }.
function retry.policy_for(spec, op_retry)
  local settings = {}
  local base, own = retry.DEFAULT, false
  if type(spec) == "string" then
    base, own = PRESETS[spec], true
  elseif retry.is_preset(spec) then
    base, own = spec, true
  elseif type(spec) == "table" then
    settings.deadline_s = spec.deadline_s
    settings.server_hint_cap_s = spec.server_hint_cap_s
    if spec.preset ~= nil then
      base = PRESETS[spec.preset] or spec.preset
      own = true
    end
    for k in pairs(spec) do
      if POLICY_FIELDS[k] then
        own = true
      end
    end
  end
  local policy = copy_policy(base)
  if own and type(spec) == "table" and not retry.is_preset(spec) then
    for k, v in pairs(spec) do
      if POLICY_FIELDS[k] then
        policy[k] = v
      end
    end
    policy.name = "custom"
  elseif not own and type(op_retry) == "table" then
    if op_retry.max_attempts ~= nil then
      policy.max_retries = op_retry.max_attempts - 1
    end
    for _, k in ipairs({ "base_ms", "throttling_base_ms", "cap_ms", "factor", "long_poll" }) do
      if op_retry[k] ~= nil then
        policy[k] = op_retry[k]
      end
    end
    policy.name = "default+operation"
  end
  if policy.budget == false then
    policy.budget = nil
  end
  return policy, settings
end

--- retry.backoff_delay(policy, n, err, bounded_hint_ms, cap_ms, random) -> ms | nil
-- Delay before retry n (0-based). nil when the server asked for a wait over the hint
-- cap: retrying earlier than the server asked would fail again (api.ts backoffDelay).
function retry.backoff_delay(p, n, err, bounded_hint_ms, hint_cap_ms, random)
  local throttling = errors.is_throttling(err)
  local base_ms, factor, cap_ms = p.base_ms or 0, p.factor or 1, p.cap_ms or 0
  local t
  if p.full_jitter then
    local base = (throttling and p.throttling_base_ms ~= nil) and p.throttling_base_ms or base_ms
    t = random() * math.min(base * factor ^ n, cap_ms)
  else
    local base = math.min(base_ms * factor ^ n, cap_ms)
    if p.min_throttle_ms ~= nil and base < p.min_throttle_ms and throttling then
      base = p.min_throttle_ms
    end
    t = base + random() * (p.jitter_ms or 0)
  end
  if not p.server_hint then
    return t
  end
  if bounded_hint_ms ~= nil then
    return math.min(math.max(bounded_hint_ms, t), t + retry.BOUNDED_HINT_MAX_EXTRA_MS)
  end
  local hint = type(err) == "table" and rawget(err, "retry_after") or nil
  if type(hint) ~= "number" or hint ~= hint then
    return t
  end
  local hint_ms = hint * 1000
  if hint_ms > hint_cap_ms then
    return nil
  end
  return math.max(t, hint_ms)
end

-- The server-hint cap in ms: the option, else DISTILLED_SERVER_RETRY_HINT_CAP_MS (a
-- non-negative finite number, truncated; invalid values are the default), else 60 s.
local function hint_cap_ms(opts, getenv)
  local s = opts.server_hint_cap_s
  if type(s) == "number" and s == s and s >= 0 and s < 1 / 0 then
    return floor(s * 1000)
  end
  local raw = getenv and getenv("DISTILLED_SERVER_RETRY_HINT_CAP_MS")
  if type(raw) == "string" and raw ~= "" then
    local n = js_number(raw)
    if n ~= nil and n >= 0 then
      return floor(n)
    end
  end
  return retry.DEFAULT_SERVER_HINT_CAP_S * 1000
end
retry._hint_cap_ms = hint_cap_ms

---------------------------------------------------------------------------------------
-- the run loop
---------------------------------------------------------------------------------------

local function round(x)
  return floor(x + 0.5)
end

-- a raise inside a user callback becomes an SdkError (the library never raises)
local function callback_error(what, raised)
  local message = type(raised) == "table" and rawget(raised, "message") or raised
  return errors.new("SdkError", {
    message = what .. " raised: " .. tostring(message),
    cause = raised,
  })
end

-- policy.when(err) -> boolean | nil, sdk_error
local function keep_going(policy, err)
  local when = policy.when
  if when == nil then
    return false
  end
  local ok, res = compat.pcall(when, err)
  if not ok then
    return nil, callback_error("the retry policy's `when`", res)
  end
  return res == true
end

-- tag of an error for attributes: err.tag, or "_OTHER" (Distilled's tagOf)
local function trace_tag(err)
  if type(err) == "table" and type(rawget(err, "tag")) == "string" then
    return err.tag
  end
  return "_OTHER"
end

local function run_attempt(fn, attempt, tracer)
  return tracer:with("distilled.attempt", {
    debug = true,
    attributes = {
      ["distilled.attempt"] = attempt.n,
      ["http.request.resend_count"] = attempt.n - 1,
    },
  }, function()
    return fn(attempt)
  end)
end

-- a successful response refills the budget of its host (retry-state.ts recordResponse)
local function record_success(budget, attempt)
  if budget and attempt.host and attempt.host ~= "" and attempt.status and attempt.status < 300 then
    budget:success(attempt.host)
  end
end

--- retry.run(fn, opts) -> value, nil, meta | nil, err, meta
-- opts = { policy, host, tracer, span, deadline_s, server_hint_cap_s }. The call runs once
-- with no retry bookkeeping; the policy is consulted only after a failure.
-- The operation span (opts.span) gets distilled.attempts, distilled.retry.errors and
-- distilled.retry.delay_ms (telemetry.ts `retried`), plus, when the loop stops early,
-- distilled.retry.stopped = "budget" | "deadline" | "hint_over_cap".
function retry.run(fn, opts)
  opts = opts or {}
  if type(fn) ~= "function" and not (type(fn) == "table" and getmetatable(fn)) then
    misuse("run expects a function")
  end
  local policy = opts.policy or retry.DEFAULT
  local host = opts.host or {}
  local tracer = opts.tracer or noop
  local span = opts.span or noop.NOOP_SPAN
  local now = host.now or os.time
  local deadline
  if opts.deadline_s ~= nil then
    deadline = now() + opts.deadline_s
  end
  local budget = policy.budget

  local attempt = { n = 1, timeout = opts.deadline_s }
  local value, err, meta = run_attempt(fn, attempt, tracer)
  record_success(budget, attempt)
  if value ~= nil or err == nil then
    return value, err, meta
  end

  local random = host.random or math.random
  local sleep = host.sleep
  local cap_ms = hint_cap_ms(opts, host.getenv)
  local retry_errors, total_ms = {}, 0
  local n = 0
  while true do
    local go, callback_err = keep_going(policy, err)
    if callback_err then
      return nil, callback_err, meta
    end
    if not go or (policy.max_retries ~= nil and n >= policy.max_retries) then
      return nil, err, meta
    end
    local ms = retry.backoff_delay(policy, n, err, attempt.hint_ms, cap_ms, random)
    if ms == nil then
      span:set("distilled.retry.stopped", "hint_over_cap")
      return nil, err, meta
    end
    if deadline ~= nil and now() + ms / 1000 > deadline then
      span:set("distilled.retry.stopped", "deadline")
      return nil, err, meta
    end
    -- no host: the request never went out through the protocol's send, so no success
    -- would refill a bucket; such calls are not budgeted (Distilled's rule)
    local key = attempt.host
    local budgeted = budget ~= nil and key ~= nil and key ~= ""
    local cost
    if budgeted then
      cost = budget:withdraw(key, errors.is_throttling(err))
      if cost == nil then
        span:set("distilled.retry.stopped", "budget")
        if policy.long_poll and sleep then
          -- a long-poll loop around the call must not spin: wait, then fail
          sleep(ms / 1000)
        end
        return nil, err, meta
      end
    end
    -- telemetry.ts retried(): the history on the operation span
    retry_errors[#retry_errors + 1] = trace_tag(err)
    total_ms = total_ms + ms
    span:set("distilled.attempts", n + 2)
    span:set("distilled.retry.errors", retry_errors)
    span:set("distilled.retry.delay_ms", round(total_ms))
    tracer:with("distilled.retry.backoff", {
      debug = true,
      attributes = {
        ["distilled.retry.attempt"] = n + 1,
        ["distilled.retry.delay_ms"] = round(ms),
        ["distilled.retry.reason"] = trace_tag(err),
      },
    }, function()
      if sleep then
        sleep(ms / 1000)
      end
    end)
    n = n + 1
    attempt = { n = n + 1 }
    if deadline ~= nil then
      attempt.timeout = deadline - now()
      if attempt.timeout <= 0 then
        span:set("distilled.retry.stopped", "deadline")
        return nil, err, meta
      end
    end
    value, err, meta = run_attempt(fn, attempt, tracer)
    record_success(budget, attempt)
    if value ~= nil or err == nil then
      if cost ~= nil then
        budget:refund(key, cost)
      end
      return value, err, meta
    end
  end
end

return retry
