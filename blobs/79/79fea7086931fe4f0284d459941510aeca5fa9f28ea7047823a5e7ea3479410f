-- Server-sent events (text/event-stream) framing, as the HTML living standard parses
-- them: lines `field: value` (one optional space after the colon), `data` lines joined
-- with "\n", a blank line dispatches the event, lines starting with ":" are comments,
-- an event with no data is not dispatched. A frame is { event = "message" | name,
-- data = text, id = last id | nil, retry = ms | nil }; the protocol decodes `data`.
local M = {}

M.CONTENT_TYPE = "text/event-stream"

--- sse.frames(reader) -> frames: frames:next() -> event | nil, nil | nil, err
function M.frames(reader)
  local frames = {}
  local last_id
  function frames.next()
    local data, event, retry
    while true do
      local line, err = reader:read_line()
      if line == nil then
        -- at EOF an unterminated event is dropped (the standard's rule)
        return nil, err
      end
      if line == "" then
        if data ~= nil then
          return { event = event or "message", data = data, id = last_id, retry = retry }
        end
        event = nil
      elseif string.sub(line, 1, 1) ~= ":" then
        local field, value = string.match(line, "^([^:]*):(.*)$")
        if not field then
          field, value = line, ""
        elseif string.sub(value, 1, 1) == " " then
          value = string.sub(value, 2)
        end
        if field == "data" then
          data = data and (data .. "\n" .. value) or value
        elseif field == "event" then
          event = value
        elseif field == "id" then
          if not string.find(value, "%z") then
            last_id = value
          end
        elseif field == "retry" then
          if string.find(value, "^%d+$") then
            retry = tonumber(value)
          end
        end
      end
    end
  end
  return frames
end

return M
