-- Pagination: the seven modes of Distilled's pagination.ts, as iterator objects.
--
--   local it = paginate.pages(call, input, trait [, opts])   -- one value per page
--   local it = paginate.items(call, input, trait [, opts])   -- one value per item
--   for x in it do ... end ; if it.err then ... end
--   local list, err = it:collect([limit])
--   it:close()
--
-- call(input) -> page | nil, err, meta. `meta.headers` (the response headers, which the
-- REST protocol returns as a third value) is how `link` mode reads the Link header:
-- Distilled hands headers over through a fiber-local slot (recordPageHeaders); here the
-- page call returns them, so nothing global is needed.
--
-- trait = { mode, input_token, output_token, items, page_size, has_next_page } with
-- dot-separated paths into the decoded page (user names). Every stop condition below
-- beyond the obvious one exists because a real API looped forever without it; the
-- comments say which.
--
-- opts = { tracer, name, attributes, on_finish = fn(it) }. With a recording tracer the
-- traversal is one `distilled.pagination` span, parent of each page's operation span.
-- It is open across pulls but taken off the tracer's stack between them, so whatever
-- the caller does inside the `for` body is not parented to it, and an abandoned
-- iterator does not capture later spans (Lua 5.1 cannot see a `break`).
local compat = require("distilled.compat")
local errors = require("distilled.errors")
local json = require("distilled.json")
local secret = require("distilled.secret")
local url = require("distilled.url")

local paginate = {}

local null = json.null

paginate.MODES = {
  token = true,
  cursor = true,
  page = true,
  relay = true,
  link = true,
  keyset = true,
  single = true,
  -- a provider strategy (task 27): Scaleway's paginateByTotalCount
  total_count = true,
}

---------------------------------------------------------------------------------------
-- paths
---------------------------------------------------------------------------------------

local function split_path(path)
  local parts = {}
  for part in string.gmatch(path, "[^.]+") do
    parts[#parts + 1] = part
  end
  return parts
end

local function is_object_like(v)
  return type(v) == "table" and v ~= null and not secret.is(v) and not errors.is(v)
end

local function is_array(v)
  if type(v) ~= "table" or v == null then
    return false
  end
  if json.is_array(v) then
    return true
  end
  if getmetatable(v) ~= nil then
    return false
  end
  -- an unmarked table: a sequence, or empty (hand-built data; decoded data is marked)
  local n = #v
  local count = 0
  for _ in pairs(v) do
    count = count + 1
  end
  return count == n
end

--- paginate.get_path(value, "a.b.c") -> the value there, or nil (json.null is returned
-- as is when it is the last link)
function paginate.get_path(obj, path)
  local cur = obj
  for _, part in ipairs(split_path(path)) do
    if not is_object_like(cur) then
      return nil
    end
    cur = rawget(cur, part)
  end
  return cur
end
local get_path = paginate.get_path

--- paginate.get_items(value, "edges.node") -> list: every segment fans out over lists,
-- so a path may cross arrays; null and absent links are dropped, so a partially null
-- page still yields the items it has.
function paginate.get_items(obj, path)
  local current = { obj }
  for _, part in ipairs(split_path(path)) do
    local nxt = {}
    for _, value in ipairs(current) do
      if is_object_like(value) then
        local child = rawget(value, part)
        if is_array(child) then
          for i = 1, #child do
            nxt[#nxt + 1] = child[i]
          end
        elseif child ~= nil and child ~= null then
          nxt[#nxt + 1] = child
        end
      end
    end
    current = nxt
  end
  return current
end
local get_items = paginate.get_items

-- isTerminalToken: absent, null or "" means no more pages. "" is how several services
-- (SSM, CloudWatch Logs) mark the last page; treating it as a token re-requests the first
-- page forever.
local function is_terminal(token)
  return token == nil or token == null or token == ""
end
paginate.is_terminal_token = is_terminal

local function with_key(input, key, value)
  local out = {}
  for k, v in pairs(input) do
    out[k] = v
  end
  out[key] = value
  return out
end

-- setPath: input with the value at a dotted path replaced, copying each level
local function set_path(input, path, value)
  local parts = split_path(path)
  local root = {}
  for k, v in pairs(input) do
    root[k] = v
  end
  local cur = root
  for i = 1, #parts - 1 do
    local child = rawget(cur, parts[i])
    local copy = {}
    if is_object_like(child) then
      for k, v in pairs(child) do
        copy[k] = v
      end
    end
    cur[parts[i]] = copy
    cur = copy
  end
  cur[parts[#parts]] = value
  return root
end
paginate._set_path = set_path

---------------------------------------------------------------------------------------
-- Link headers (RFC 8288)
---------------------------------------------------------------------------------------

--- paginate.next_link(header) -> the URL of the rel="next" link, or nil
-- `<https://api.github.com/repositories/1/issues?page=2>; rel="next", <...>; rel="last"`.
-- rel may list several space-separated values and may be unquoted.
function paginate.next_link(header)
  if type(header) ~= "string" then
    return nil
  end
  local pos = 1
  while true do
    local lt = string.find(header, "<", pos, true)
    if not lt then
      return nil
    end
    local gt = string.find(header, ">", lt + 1, true)
    if not gt then
      return nil
    end
    local target = string.sub(header, lt + 1, gt - 1)
    -- the parameters run to the next "<" that follows a comma
    local next_lt = string.find(header, ",%s*<", gt + 1)
    local params = string.sub(header, gt + 1, next_lt and next_lt - 1 or #header)
    local rel = string.match(params, ';%s*[Rr][Ee][Ll]%s*=%s*"([^"]*)"')
      or string.match(params, ';%s*[Rr][Ee][Ll]%s*=%s*([^";,]*)')
    if rel then
      for word in string.gmatch(string.lower(rel), "%S+") do
        if word == "next" then
          return target
        end
      end
    end
    if not next_lt then
      return nil
    end
    pos = next_lt + 1
  end
end

local function hex_value(h)
  return string.char(tonumber(h, 16))
end

-- application/x-www-form-urlencoded decoding, as URLSearchParams does
local function form_decode(s)
  s = string.gsub(s, "+", " ")
  return (string.gsub(s, "%%(%x%x)", hex_value))
end

--- paginate.query_param(url, name) -> the first value of name in url's query, or nil
function paginate.query_param(target, name)
  local q = string.match(target, "^[^?#]*%?([^#]*)")
  if not q then
    return nil
  end
  for pair in string.gmatch(q, "[^&]+") do
    local eq = string.find(pair, "=", 1, true)
    local k = form_decode(eq and string.sub(pair, 1, eq - 1) or pair)
    if k == name then
      return form_decode(eq and string.sub(pair, eq + 1) or "")
    end
  end
  return nil
end

---------------------------------------------------------------------------------------
-- strategies: start(input, trait) -> state | nil, err ; step(state, call) -> page | nil, err
-- A step sets state.done and state.stop (the reason) when the page was the last.
---------------------------------------------------------------------------------------

local function missing(message)
  return nil, errors.new("SdkError", { message = message })
end

local strategies = {}

strategies.single = {
  start = function(input)
    return { request = input }
  end,
  step = function(state, call)
    local page, err, meta = call(state.request)
    state.done, state.stop = true, "single"
    return page, err, meta
  end,
}

strategies.token = {
  start = function(input, trait)
    if not trait.input_token or not trait.output_token then
      return missing("Token pagination requires input_token and output_token")
    end
    return { token = rawget(input, trait.input_token), input = input }
  end,
  step = function(state, call, trait)
    local request = state.input
    if state.token ~= nil then
      request = with_key(state.input, trait.input_token, state.token)
    end
    local page, err, meta = call(request)
    if page == nil then
      return nil, err, meta
    end
    local token = get_path(page, trait.output_token)
    state.token = token
    if is_terminal(token) then
      state.done, state.stop = true, "no_token"
    end
    return page, nil, meta
  end,
}

strategies.cursor = {
  start = function(input, trait)
    if not trait.input_token or not trait.output_token then
      return missing("Cursor pagination requires input_token and output_token")
    end
    local start = rawget(input, trait.input_token)
    -- cursor history belongs to this traversal
    return { cursor = type(start) == "string" and start or nil, input = input, requested = {} }
  end,
  step = function(state, call, trait)
    if state.cursor ~= nil then
      state.requested[state.cursor] = true
    end
    local request = state.input
    if state.cursor ~= nil and state.cursor ~= "" then
      request = with_key(state.input, trait.input_token, state.cursor)
    end
    local page, err, meta = call(request)
    if page == nil then
      return nil, err, meta
    end
    local cursor = get_path(page, trait.output_token)
    if cursor == null then
      cursor = nil
    end
    state.cursor = cursor
    if is_terminal(cursor) then
      state.done, state.stop = true, "no_token"
    elseif state.requested[cursor] then
      -- a cursor already requested would loop
      state.done, state.stop = true, "repeated_cursor"
    end
    -- empty pages still advance when they return a new cursor
    return page, nil, meta
  end,
}

strategies.page = {
  start = function(input, trait)
    if not trait.input_token or not trait.output_token then
      return missing("Page-number pagination requires input_token and output_token")
    end
    local start = rawget(input, trait.input_token)
    return { page = type(start) == "number" and start or 1, input = input }
  end,
  step = function(state, call, trait)
    local page, err, meta = call(with_key(state.input, trait.input_token, state.page))
    if page == nil then
      return nil, err, meta
    end
    local next_page = get_path(page, trait.output_token)
    -- Some APIs report the CURRENT page at output_token (Cloudflare's result_info.page);
    -- taking it as the next page re-requests the same page forever. Only an advancing
    -- number is accepted; otherwise advance by one and stop on an empty page.
    local items
    if trait.items then
      items = get_path(page, trait.items)
    end
    if type(next_page) == "number" and next_page > state.page then
      state.page = next_page
    else
      state.page = state.page + 1
    end
    if next_page == nil or next_page == null then
      state.done, state.stop = true, "no_token"
    elseif items == null then
      -- `result: null` is an empty page
      state.done, state.stop = true, "empty_page"
    elseif
      type(items) == "table"
      and (json.is_array(items) or next(items) == nil)
      and #items == 0
    then
      state.done, state.stop = true, "empty_page"
    end
    return page, nil, meta
  end,
}

-- total_count (Scaleway's paginateByTotalCount, scaleway/src/pagination.ts; the official
-- SDKs' fetchPaginated): request page, page+1, ... where output_token is the TOTAL item
-- count, never a page number. The page count is sized by the first page read
-- (ceil(total / its length): the server may cap page_size below what was asked); stop
-- after that page or on an empty page. A provider spec selects it with
-- `pagination = { modes = { page = "total_count" } }`.
strategies.total_count = {
  start = function(input, trait)
    if not trait.input_token or not trait.output_token or not trait.items then
      return missing("Total-count pagination requires input_token, output_token and items")
    end
    local start = rawget(input, trait.input_token)
    return { page = type(start) == "number" and start or 1, input = input }
  end,
  step = function(state, call, trait)
    local page, err, meta = call(with_key(state.input, trait.input_token, state.page))
    if page == nil then
      return nil, err, meta
    end
    local items = get_path(page, trait.items)
    local length = (type(items) == "table" and items ~= null and is_array(items)) and #items or 0
    if state.last_page == nil then
      local total = get_path(page, trait.output_token)
      if type(total) == "number" and length > 0 then
        state.last_page = math.ceil(total / length)
      else
        state.last_page = state.page
      end
    end
    if length == 0 then
      state.done, state.stop = true, "empty_page"
    elseif state.page >= state.last_page then
      state.done, state.stop = true, "last_page"
    end
    state.page = state.page + 1
    return page, nil, meta
  end,
}

strategies.relay = {
  start = function(input, trait)
    if not trait.input_token or not trait.output_token then
      return missing("Relay pagination requires input_token and output_token")
    end
    local start = rawget(input, trait.input_token)
    local has_next = trait.has_next_page
    if not has_next then
      -- pageInfo.endCursor -> pageInfo.hasNextPage
      local parts = split_path(trait.output_token)
      parts[#parts] = "hasNextPage"
      has_next = table.concat(parts, ".")
    end
    return { cursor = type(start) == "string" and start or nil, input = input, has_next = has_next }
  end,
  step = function(state, call, trait)
    local request = state.input
    if state.cursor ~= nil and state.cursor ~= "" then
      request = with_key(state.input, trait.input_token, state.cursor)
    end
    local page, err, meta = call(request)
    if page == nil then
      return nil, err, meta
    end
    local cursor = get_path(page, trait.output_token)
    if cursor == null then
      cursor = nil
    end
    -- the terminal page still carries an endCursor: only hasNextPage ends a connection
    local has_next = get_path(page, state.has_next) == true
    -- an empty page means the connection is exhausted whatever hasNextPage claims
    local empty = trait.items ~= nil and #get_items(page, trait.items) == 0
    -- the same endCursor with hasNextPage true (Railway `projects` did this) would loop
    local stuck = state.cursor ~= nil and cursor ~= nil and cursor == state.cursor
    if not has_next then
      state.done, state.stop = true, "no_next_page"
    elseif is_terminal(cursor) then
      state.done, state.stop = true, "no_token"
    elseif empty then
      state.done, state.stop = true, "empty_page"
    elseif stuck then
      state.done, state.stop = true, "stuck_cursor"
    end
    state.cursor = cursor
    return page, nil, meta
  end,
}

strategies.link = {
  start = function(input, trait)
    if not trait.input_token then
      return missing("Link pagination requires input_token")
    end
    return { token = rawget(input, trait.input_token), input = input }
  end,
  step = function(state, call, trait)
    local request = state.input
    if state.token ~= nil then
      request = with_key(state.input, trait.input_token, state.token)
    end
    local page, err, meta = call(request)
    if page == nil then
      return nil, err, meta
    end
    local headers = type(meta) == "table" and meta.headers or nil
    local nxt = paginate.next_link(headers and headers["link"])
    -- the token goes back as the query text it came as (page=2 -> "2")
    local token = nxt and paginate.query_param(nxt, trait.input_token) or nil
    if is_terminal(token) then
      state.done, state.stop = true, "no_next_link"
    elseif state.token ~= nil and token == url.text(state.token) then
      state.done, state.stop = true, "repeated_token"
    end
    state.token = token
    return page, nil, meta
  end,
}

strategies.keyset = {
  start = function(input, trait)
    if not trait.input_token or not trait.output_token or not trait.items then
      return missing("Keyset pagination requires input_token, output_token and items")
    end
    local limit = trait.page_size and get_path(input, trait.page_size) or nil
    return {
      request = input,
      key = get_path(input, trait.input_token),
      limit = type(limit) == "number" and limit or nil,
    }
  end,
  step = function(state, call, trait)
    local page, err, meta = call(state.request)
    if page == nil then
      return nil, err, meta
    end
    local list = get_items(page, trait.items)
    local key
    if #list > 0 then
      key = get_path(list[#list], trait.output_token)
    end
    if #list == 0 then
      state.done, state.stop = true, "empty_page"
    elseif is_terminal(key) then
      state.done, state.stop = true, "no_token"
    elseif key == state.key then
      state.done, state.stop = true, "key_not_advancing"
    elseif state.limit ~= nil and #list < state.limit then
      -- a page smaller than the requested size is the last one
      state.done, state.stop = true, "short_page"
    else
      state.request = set_path(state.request, trait.input_token, key)
      state.key = key
    end
    return page, nil, meta
  end,
}

-- Provider strategies: `trait.strategy = "<provider>"` picks strategies["<provider>.<mode>"]
-- when there is one, else the core mode (Distilled: a PaginationStrategy that dispatches on
-- the mode, falling back to paginateWithDefaults).

-- Cloudflare's page mode (packages/cloudflare/src/pagination.ts paginatePageByItems):
-- request page N and stop on the first page with no items; `result_info.page` reports the
-- CURRENT page, so there is no next token. A request schema without the page parameter
-- gets page 1 forever: when the server reports another page than the one asked for, stop
-- without emitting the duplicate. When result_info shows the listing is exhausted, stop
-- without asking for the empty page: total_pages says this was the last page, or the page
-- came back short of per_page (else the requested page size) and the items seen reach
-- total_count. A short page alone is not trusted (endpoints cap page sizes below what they
-- report), so the count check needs both signals.
strategies["cloudflare.page"] = {
  start = function(input, trait)
    if not trait.input_token then
      return missing("Cloudflare page pagination requires an input_token")
    end
    local start = rawget(input, trait.input_token)
    start = type(start) == "number" and start or 1
    local size = trait.page_size and rawget(input, trait.page_size) or nil
    return {
      page = start,
      start = start,
      seen = 0,
      input = input,
      page_size = type(size) == "number" and size or nil,
    }
  end,
  step = function(state, call, trait)
    local page, err, meta = call(with_key(state.input, trait.input_token, state.page))
    if page == nil then
      return nil, err, meta
    end
    local items = get_path(page, trait.items or "result")
    local reported = get_path(page, "result_info.page")
    if state.page ~= state.start and type(reported) == "number" and reported ~= state.page then
      -- the server ignored the page parameter: this page is a duplicate
      state.done, state.stop = true, "page_not_advancing"
      return false, nil, meta
    end
    local count = 0
    if type(items) == "table" and items ~= null then
      count = #items
    end
    local seen = state.seen + count
    local info = get_path(page, "result_info")
    if not is_object_like(info) then
      info = nil
    end
    local per_page = info and rawget(info, "per_page")
    if type(per_page) ~= "number" then
      per_page = state.page_size
    end
    local total_pages = info and rawget(info, "total_pages")
    local total_count = info and rawget(info, "total_count")
    local last = (type(total_pages) == "number" and state.page >= total_pages)
      or (
        type(total_count) == "number"
        and type(per_page) == "number"
        and count < per_page
        and seen >= total_count
      )
    state.page = state.page + 1
    state.seen = seen
    if count == 0 then
      state.done, state.stop = true, "empty_page"
    elseif last then
      state.done, state.stop = true, "last_page"
    end
    return page, nil, meta
  end,
}

---------------------------------------------------------------------------------------
-- the iterator object
---------------------------------------------------------------------------------------

local Iterator = {}
Iterator.__index = Iterator

-- the traversal span is current only while a page is fetched (tracer:attach/detach);
-- a tracer without that API (a caller's own tracer object) just keeps it current
local function attach(tracer, span)
  if tracer.attach then
    tracer:attach(span)
  end
end
local function detach(tracer, span)
  if tracer.detach then
    tracer:detach(span)
  end
end

local function new_iterator(kind, call, input, trait, opts)
  if type(call) ~= "function" and not (type(call) == "table" and getmetatable(call)) then
    compat.raise("paginate." .. kind .. ": call must be a function", 3)
  end
  if type(trait) ~= "table" then
    compat.raise("paginate." .. kind .. ": trait must be a table", 3)
  end
  if input == nil then
    input = {}
  end
  opts = opts or {}
  return setmetatable({
    kind = kind,
    err = nil,
    done = false,
    stop = nil,
    pages = 0,
    count = 0,
    _call = call,
    _input = input,
    _trait = trait,
    _opts = opts,
    _tracer = opts.tracer,
    _buffer = nil,
    _index = 0,
  }, Iterator)
end

function Iterator:_finish(stop, err)
  if self._finished then
    return
  end
  self._finished = true
  self.done = true
  self.stop = self.stop or stop
  local span = self._span
  if span then
    span:set("distilled.pagination.pages", self.pages)
    if self.kind == "items" then
      span:set("distilled.pagination.items", self.count)
    end
    span:set("distilled.pagination.stop", self.stop)
    if err then
      span:fail(err)
    end
    span:finish()
  end
  if self._opts.on_finish then
    self._opts.on_finish(self)
  end
end

function Iterator:_fail(err)
  self.err = err
  self:_finish("error", err)
  return nil
end

-- the next page, or nil (end or failure)
function Iterator:_next_page()
  if self.done then
    return nil
  end
  local trait = self._trait
  if not self._state then
    local mode = trait.mode or "token"
    local strategy = (trait.strategy and strategies[trait.strategy .. "." .. mode])
      or strategies[mode]
    if not strategy then
      return self:_fail(
        errors.new("SdkError", { message = "unknown pagination mode " .. tostring(mode) })
      )
    end
    if type(self._input) ~= "table" or self._input == null then
      return self:_fail(errors.new("InvalidInput", { message = "the input must be a table" }))
    end
    local state, err = strategy.start(self._input, trait)
    if not state then
      return self:_fail(err)
    end
    self._strategy, self._state = strategy, state
    local tracer = self._tracer
    if tracer and tracer.level ~= "off" then
      local attributes = {}
      for k, v in pairs(self._opts.attributes or {}) do
        attributes[k] = v
      end
      attributes["distilled.pagination.mode"] = mode
      attributes["distilled.pagination.kind"] = self.kind
      if self._opts.name then
        attributes["distilled.pagination.operation"] = self._opts.name
      end
      local span = tracer:start("distilled.pagination", { attributes = attributes })
      if span.recording then
        self._span = span
        detach(tracer, span)
      end
    end
  end
  local state = self._state
  if state.done then
    self.stop = state.stop
    self:_finish(state.stop)
    return nil
  end
  local tracer, span = self._tracer, self._span
  local function step()
    return self._strategy.step(state, self._call, trait)
  end
  local page, err
  if span then
    attach(tracer, span)
    local r = compat.pack(compat.pcall(step))
    detach(tracer, span)
    if not r[1] then
      error(r[2], 0)
    end
    page, err = r[2], r[3]
  else
    page, err = step()
  end
  if page == false then
    -- the strategy ended the traversal without a page (a duplicate it will not emit)
    self.stop = state.stop
    self:_finish(state.stop)
    return nil
  end
  if page == nil then
    return self:_fail(err or errors.new("SdkError", { message = "a page call returned nothing" }))
  end
  self.pages = self.pages + 1
  if state.done then
    self.stop = state.stop
  end
  return page
end

-- the items of a page: the trait's items path, or the page itself when it is a list,
-- else the page as one item (a trait without items: Distilled's `.items()` is then the
-- pages, api.ts `if (!p.items) return pagesOf(...)`; GCP list responses, task 21)
local function items_of(page, trait)
  if trait.items then
    return get_items(page, trait.items)
  end
  if is_array(page) then
    return page
  end
  if type(page) == "table" and page ~= null then
    return { page }
  end
  return {}
end

--- it() -> the next page (pages) or item (items); nil at the end or on failure
function Iterator:__call()
  if self._finished then
    return nil
  end
  if self.kind == "pages" then
    local page = self:_next_page()
    if page == nil then
      return nil
    end
    if self._state.done then
      -- the last page: finish now, so the traversal span ends with it
      self:_finish(self._state.stop)
    end
    self.count = self.count + 1
    return page
  end
  while true do
    local buffer = self._buffer
    if buffer and self._index < #buffer then
      self._index = self._index + 1
      self.count = self.count + 1
      return buffer[self._index]
    end
    if self._state and self._state.done then
      self:_finish(self._state.stop)
      return nil
    end
    local page = self:_next_page()
    if page == nil then
      return nil
    end
    self._buffer, self._index = items_of(page, self._trait), 0
  end
end

--- it:collect([limit]) -> list | nil, err. With limit, stops fetching pages once limit
-- values are collected (the list holds at most limit).
function Iterator:collect(limit)
  if limit ~= nil and (type(limit) ~= "number" or limit < 0) then
    compat.raise("collect: limit must be a non-negative number", 2)
  end
  local list = json.array({})
  if limit == 0 then
    self:close()
    return list
  end
  while true do
    local v = self()
    if v == nil then
      break
    end
    list[#list + 1] = v
    if limit ~= nil and #list >= limit then
      self.stop = self.stop or "limit"
      self:close("limit")
      break
    end
  end
  if self.err then
    return nil, self.err
  end
  return list
end

--- it:close(): stop fetching; ends the traversal span. Idempotent.
function Iterator:close(reason)
  self:_finish(reason or "closed")
end

--- paginate.pages(call, input, trait [, opts]) -> iterator over pages
function paginate.pages(call, input, trait, opts)
  return new_iterator("pages", call, input, trait, opts)
end

--- paginate.items(call, input, trait [, opts]) -> iterator over items
function paginate.items(call, input, trait, opts)
  return new_iterator("items", call, input, trait, opts)
end

paginate._strategies = strategies

return paginate
