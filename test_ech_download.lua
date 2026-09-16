-- Functional test for the ECH gist download endpoint (action_ech_download).
-- Stubs the LuCI runtime, simulates wget/uclient-fetch writing a gist API
-- response, and asserts the drop-in file and JSON feedback.

-- ── stubs ────────────────────────────────────────────────────────────────

local writes = {}        -- path -> content
local sys_calls = {}
local form = {}          -- formvalue() results
local json_out = nil     -- captured write_json payload
local wget_payload = nil -- body the fake downloader writes

local sys = {
	call = function(cmd)
		sys_calls[#sys_calls + 1] = cmd
		-- Simulate the downloader: when a command writes a file with -O,
		-- materialise the configured payload there.
		local dest = cmd:match("%-O%s+'([^']+)'")
		if dest and wget_payload ~= nil then
			writes[dest] = wget_payload
			return 0
		end
		if dest then
			return 1 -- downloader failed
		end
		return 0
	end,
	exec = function() return "" end,
}

local real_open = io.open
io.open = function(path, mode)
	if mode == "w" then
		local buf = {}
		return {
			write = function(self, ...) buf[#buf + 1] = table.concat({...}) end,
			close = function(self) writes[path] = table.concat(buf) end,
		}
	end
	if mode == "r" then
		if writes[path] then
			local i = 0
			local body = writes[path]
			return {
				read = function(self, _) i = i + 1; if i == 1 then return body end; return nil end,
				seek = function(self, _) return #body end,
				close = function() end,
			}
		end
		return nil
	end
	return real_open(path, mode)
end

local http = {
	formvalue = function(name) return form[name] end,
	prepare_content = function() end,
	write_json = function(t) json_out = t end,
}

-- Minimal luci.jsonc stub: enough for the fixtures below.
local jsonc = {
	parse = function(s)
		local nodes = {}
		for name in s:gmatch('"name"%s*:%s*"([^"]*)"') do
			nodes[#nodes + 1] = { name = name }
		end
		if #nodes == 0 and not s:match('"nodes"%s*:%s*%[') then
			return nil, "parse error"
		end
		return { nodes = nodes, files = json_files }
	end,
}

json_files = nil -- set per test: files table returned by the "API" parse

-- luci.i18n stub
local i18n_stub = {
	translate = function(s) return s end,
	translatef = function(f, ...) return f:format(...) end,
}

package.preload["luci.sys"] = function() return sys end
package.preload["luci.http"] = function() return http end
package.preload["nixio.fs"] = function() return {} end
package.preload["nixio"] = function() return {} end
package.preload["luci.i18n"] = function() return i18n_stub end
package.preload["luci.jsonc"] = function() return jsonc end
package.preload["luci.model.uci"] = function()
	return { cursor = function() return { get = function() return nil end } end }
end
package.preload["luci.dispatcher"] = function()
	return { build_url = function() return "/cgi-bin/luci/admin/services/daed/ech_download" end }
end

-- Lua 5.5 removed module(); shim it by rebinding the chunk _ENV so that
-- function definitions land in package.loaded[name] like LuCI expects.
module = function(name)
	local m = package.loaded[name]
	if not m then
		m = {}
		package.loaded[name] = m
	end
	local info = debug.getinfo(2, "f")
	if info and info.func then
		local env = setmetatable({}, {
			__index = function(_, k)
				local v = m[k]
				if v ~= nil then return v end
				return _G[k]
			end,
			__newindex = function(_, k, v) m[k] = v end,
		})
		debug.setupvalue(info.func, 1, env)
	end
	return m
end

-- Load the controller: functions register into package.loaded.
dofile("luci-app-daed/luasrc/controller/daed.lua")

local function call_action(name)
	local mod = package.loaded["luci.controller.daed"]
	if mod and mod[name] then
		return mod[name]()
	end
	error("action not found: " .. name)
end

-- ── assertions ───────────────────────────────────────────────────────────

local failures = 0
local function check(cond, msg)
	if cond then
		print("  PASS: " .. msg)
	else
		print("  FAIL: " .. msg)
		failures = failures + 1
	end
end

local function reset()
	writes, sys_calls, json_out, json_files = {}, {}, nil, nil
end

print("== invalid gist id ==")
reset()
form = { gist_id = "bad id!", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == false, "rejected invalid gist id")
check(json_out.error == "Invalid Gist ID", "error message is about the gist id")

print("== invalid tag ==")
reset()
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "bad tag" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == false, "rejected invalid tag")

print("== download failure ==")
reset()
wget_payload = nil -- downloader always fails
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == false, "reported download failure")
check(json_out.error:match("GitHub API") ~= nil, "error mentions the GitHub API")

print("== successful download ==")
reset()
json_files = {
	["nodes.json"] = { content = "PLACEHOLDER" },
}
-- The API response body must parse into files{} with the content inline; the
-- stub returns json_files directly, so mirror the real shape.
local api_body = "{\"files\":{\"nodes.json\":{\"content\":\"NODESJSON\"}}}"
wget_payload = api_body
-- The controller writes the API body to the gist.json temp file and then
-- parses it; make the stub return the files table with the real content.
jsonc.parse = function(s)
	if s:match('"files"') then
		return {
			files = {
				["nodes.json"] = { content = "{\"nodes\":[{\"name\":\"台湾-联通-a\"},{\"name\":\"日本-联通-b\"}]}" },
			},
		}
	end
	local nodes = {}
	for name in s:gmatch('"name"%s*:%s*"([^"]*)"') do
		nodes[#nodes + 1] = { name = name }
	end
	return { nodes = nodes }
end

form = { gist_id = "abc123", token = "tok", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == true, "download reported success")
check(json_out.count == 2, "counted 2 nodes (got " .. tostring(json_out and json_out.count) .. ")")
check(json_out.names[1] == "台湾-联通-a", "first node name comes from the name field")
check(json_out.file == "/etc/daed/nodes.d/ech_nodes.json",
	"drop-in path is the nodes.d directory (" .. tostring(json_out.file) .. ")")
local written = writes["/etc/daed/nodes.d/ech_nodes.json"]
check(written ~= nil, "drop-in file written")
check(written and written:match('"name":"台湾%-联通%-a"') ~= nil, "drop-in holds the raw nodes.json payload")

print("")
if failures == 0 then
	print("ALL DOWNLOAD CHECKS PASSED")
	os.exit(0)
else
	print(failures .. " CHECKS FAILED")
	os.exit(1)
end
