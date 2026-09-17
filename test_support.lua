-- Shared helpers for the luci-app-daed host-side tests.
--
-- The stubs deliberately avoid regex-based "parsing": a real JSON parser is
-- used so fixtures exercise the same shapes the daemon (and luci.jsonc on the
-- device) see. Otherwise a regex stub can accept payloads the real parser
-- rejects, and the tests would pass while the feature is broken.

local M = {}

-- parse_json(s) -> value | nil, error  (objects, arrays, strings, numbers,
-- booleans, null; \u escapes are decoded as "?" since no fixture needs them)
function M.parse_json(s)
	if type(s) ~= "string" then
		return nil, "not a string"
	end

	local function skip(i)
		local _, j = s:find("^[ \t\r\n]*", i)
		return j + 1
	end

	local parse_value

	local function parse_string(i)
		local out, j = {}, i + 1
		while j <= #s do
			local c = s:sub(j, j)
			if c == '"' then
				return table.concat(out), j + 1
			elseif c == "\\" then
				local esc = s:sub(j + 1, j + 1)
				local map = { n = "\n", t = "\t", r = "\r", ["\\"] = "\\", ['"'] = '"', ["/"] = "/", b = "\b", f = "\f" }
				if esc == "u" then
					out[#out + 1] = "?"
					j = j + 6
				else
					out[#out + 1] = map[esc] or esc
					j = j + 2
				end
			else
				out[#out + 1] = c
				j = j + 1
			end
		end
		return nil, nil, "unterminated string"
	end

	local function parse_array(i)
		local arr, j = {}, skip(i + 1)
		if s:sub(j, j) == "]" then
			return arr, j + 1
		end
		while true do
			local v, nj, err = parse_value(j)
			if err then return nil, nil, err end
			arr[#arr + 1] = v
			j = skip(nj)
			local c = s:sub(j, j)
			if c == "," then
				j = skip(j + 1)
			elseif c == "]" then
				return arr, j + 1
			else
				return nil, nil, "expected , or ]"
			end
		end
	end

	local function parse_object(i)
		local obj, j = {}, skip(i + 1)
		if s:sub(j, j) == "}" then
			return obj, j + 1
		end
		while true do
			if s:sub(j, j) ~= '"' then return nil, nil, "expected key" end
			local key, nj, err = parse_string(j)
			if err then return nil, nil, err end
			j = skip(nj)
			if s:sub(j, j) ~= ":" then return nil, nil, "expected :" end
			local v, nj2, err2 = parse_value(skip(j + 1))
			if err2 then return nil, nil, err2 end
			obj[key] = v
			j = skip(nj2)
			local c = s:sub(j, j)
			if c == "," then
				j = skip(j + 1)
			elseif c == "}" then
				return obj, j + 1
			else
				return nil, nil, "expected , or }"
			end
		end
	end

	parse_value = function(i)
		local c = s:sub(i, i)
		if c == "{" then return parse_object(i) end
		if c == "[" then return parse_array(i) end
		if c == '"' then return parse_string(i) end
		local num = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i)
		if num and num ~= "" and num ~= "-" then return tonumber(num), i + #num end
		if s:sub(i, i + 3) == "true" then return true, i + 4 end
		if s:sub(i, i + 4) == "false" then return false, i + 5 end
		if s:sub(i, i + 3) == "null" then return nil, i + 4 end
		return nil, nil, "unexpected token"
	end

	local v, _, err = parse_value(skip(1))
	if err then
		return nil, err
	end
	return v
end

-- jsonc_stub() -> a luci.jsonc replacement backed by parse_json.
function M.jsonc_stub()
	return { parse = M.parse_json }
end

-- Escapes a payload for embedding as a JSON string (test fixtures).
function M.json_string(s)
	return (s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t"))
end

return M
