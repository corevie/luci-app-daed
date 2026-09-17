-- Functional test for the ECH gist download path:
--   controller action_ech_download -> luci.model.daed_gist.sync()
-- The real share module is loaded (via package.preload, since luasrc/ installs
-- to /usr/lib/lua/luci/ on the device); only the LuCI runtime
-- (sys/http/fs/jsonc/uci) is stubbed. JSON parsing is the real recursive
-- descent parser from test_support.lua, so the fixtures exercise the shapes
-- the daemon sees instead of being matched by regexes.

-- The share module under test: luasrc/ installs to /usr/lib/lua/luci/ on the
-- device, so map the require name to the repo path explicitly.
package.preload["luci.model.daed_gist"] = function()
	return dofile("luci-app-daed/luasrc/model/daed_gist.lua")
end

-- ── stubs ────────────────────────────────────────────────────────────────

local writes = {}        -- path -> content
local sys_calls = {}
local form = {}          -- formvalue() results
local json_out = nil     -- captured write_json payload
local api_body = nil     -- body the fake downloader writes for the gist API
local raw_body = nil     -- body for raw_url fallback
local fs_files = {}      -- path -> { size = n, mtime = n }
local uci_get = function() return nil end

local sys = {
	call = function(cmd)
		sys_calls[#sys_calls + 1] = cmd
		-- Downloader simulation: honour -O <dest> by materialising a body.
		local dest = cmd:match("%-O%s+'([^']+)'")
		if dest then
			if cmd:match("api%.github%.com") and api_body ~= nil then
				writes[dest] = api_body
				return 0
			end
			if cmd:match("raw") and raw_body ~= nil then
				writes[dest] = raw_body
				return 0
			end
			return 1 -- downloader failed
		end
		-- Atomic replace of the drop-in.
		local from, to = cmd:match("^mv %-f '([^']+)' '([^']+)'$")
		if from then
			writes[to] = writes[from]
			writes[from] = nil
			fs_files[to] = fs_files[from]
			fs_files[from] = nil
			return 0
		end
		return 0
	end,
	exec = function(cmd)
		sys_calls[#sys_calls + 1] = cmd
		if cmd:match("^ls %-1") then
			local names = {}
			for path in pairs(writes) do
				local name = path:match("([^/]+)$")
				if name then names[#names+1] = name end
			end
			return table.concat(names, "\n")
		end
		return ""
	end,
}

local real_open = io.open
io.open = function(path, mode)
	if mode == "w" then
		local buf = {}
		return {
			write = function(_, ...) buf[#buf + 1] = table.concat({...}) end,
			close = function()
				writes[path] = table.concat(buf)
				fs_files[path] = { size = #writes[path], mtime = 1700000000 }
			end,
		}
	end
	if mode == "r" then
		if writes[path] then
			local body, i = writes[path], 0
			return {
				read = function() i = i + 1; if i == 1 then return body end; return nil end,
				seek = function() return #body end,
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

local fs = {
	access = function(path) return writes[path] ~= nil or fs_files[path] ~= nil end,
	readfile = function(path) return writes[path] end,
	stat = function(path) return fs_files[path] end,
}

-- Real JSON parsing is shared with the other suites (see test_support.lua).
local jsonc = dofile("test_support.lua").jsonc_stub()

local i18n_stub = {
	translate = function(s) return s end,
	translatef = function(f, ...) return f:format(...) end,
}

package.preload["luci.sys"] = function() return sys end
package.preload["luci.http"] = function() return http end
package.preload["nixio.fs"] = function() return fs end
package.preload["nixio"] = function() return {} end
package.preload["luci.i18n"] = function() return i18n_stub end
package.preload["luci.jsonc"] = function() return jsonc end
package.preload["luci.model.uci"] = function()
	return { cursor = function() return { get = function(_, c, s, o) return uci_get(c, s, o) end } end }
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
	writes, sys_calls, json_out, fs_files = {}, {}, nil, {}
	api_body, raw_body = nil, nil
end

local function restarted()
	for _, c in ipairs(sys_calls) do
		if c:match("/etc/init%.d/daed restart") then return true end
	end
	return false
end

local CFMAC = '{"nodes":[{"id":"a","name":"台湾-联通-a","wssAddr":"e.workers.dev:443/","token":"t1"},' ..
	'{"id":"b","name":"日本-b","wssAddr":"e.workers.dev:443/","token":"t2"}]}'
local gist_api = function(content)
	return '{"files":{"nodes.json":{"content":"' .. dofile("test_support.lua").json_string(content) .. '"}}}'
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
check(writes["/etc/daed/nodes.d/bad tag.json"] == nil, "nothing written for an invalid tag")

print("== downloader failure ==")
reset()
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == false, "reported download failure")
check(json_out.error:match("GitHub API") ~= nil, "error mentions the GitHub API")

print("== HTML payload is refused (would replace good nodes) ==")
reset()
api_body = gist_api("<html><body>404</body></html>")
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == false, "rejected an HTML payload")
check(json_out.error:match("HTML") ~= nil, "error explains the payload is HTML")
check(writes["/etc/daed/nodes.d/ech_nodes.json"] == nil, "no drop-in written")

print("== unrecognised JSON is refused ==")
reset()
api_body = '{"files":{"nodes.json":{"content":"{\\"message\\":\\"Bad credentials\\"}"}}}'
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == false, "rejected a non-node JSON payload")

print("== cfMac nodes.json ==")
reset()
api_body = gist_api(CFMAC)
form = { gist_id = "abc123", token = "tok", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out ~= nil and json_out.ok == true, "download reported success")
check(json_out.kind == "cfmac", "kind reported as cfmac (got " .. tostring(json_out.kind) .. ")")
check(json_out.count == 2, "counted 2 nodes (got " .. tostring(json_out.count) .. ")")
check(json_out.names[1] == "台湾-联通-a", "node names come from the name field")
check(json_out.changed == true, "first write reported as changed")
check(json_out.file == "/etc/daed/nodes.d/ech_nodes.json", "drop-in path is nodes.d/<tag>.json")
check(writes["/etc/daed/nodes.d/ech_nodes.json"] ~= nil, "drop-in written")
check(writes["/etc/daed/nodes.d/ech_nodes.json.tmp"] == nil, "tmp file was renamed, not left behind")
for _, c in ipairs(sys_calls) do
	if c:match("chmod 600 '/etc/daed/nodes.d/ech_nodes.json.tmp'") then
		check(true, "mode 600 applied before the rename")
		break
	end
end
check(restarted(), "daemon restart triggered")

print("== unchanged payload does not restart daed ==")
local kept = writes["/etc/daed/nodes.d/ech_nodes.json"]
reset()
writes["/etc/daed/nodes.d/ech_nodes.json"] = kept
api_body = gist_api(CFMAC)
form = { gist_id = "abc123", token = "tok", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out.ok == true and json_out.changed == false, "unchanged payload recognised")
check(not restarted(), "no restart for an unchanged payload")

print("== SIP008 accepted (daemon can import it) ==")
reset()
api_body = gist_api('{"version":1,"servers":[{"remarks":"hk-1","server":"a.example","server_port":443},' ..
	'{"remarks":"jp-1","server":"b.example","server_port":443}]}')
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out.ok == true and json_out.kind == "sip008", "SIP008 accepted (kind=" .. tostring(json_out and json_out.kind) .. ")")
check(json_out.count == 2, "SIP008 node count reported")
check(json_out.names[1] == "hk-1", "SIP008 remarks used as names")

print("== plain link list accepted ==")
reset()
api_body = gist_api("socks5://127.0.0.1:1080#local\nsocks5://127.0.0.1:1081#local2\n")
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out.ok == true and json_out.kind == "links", "link list accepted (kind=" .. tostring(json_out and json_out.kind) .. ")")
check(json_out.count == 2, "link count reported")

print("== base64 subscription accepted ==")
reset()
api_body = gist_api("c29ja3M1Oi8vMTI3LjAuMC4xOjEwODAjbG9jYWwK")
form = { gist_id = "abc123", token = "", gist_file = "nodes.json", sub_tag = "ech_nodes" }
call_action("action_ech_download")
check(json_out.ok == true and json_out.kind == "base64", "base64 accepted (kind=" .. tostring(json_out and json_out.kind) .. ")")
check(json_out.changed == true, "base64 payload written")

print("")
if failures == 0 then
	print("ALL DOWNLOAD CHECKS PASSED")
	os.exit(0)
else
	print(failures .. " CHECKS FAILED")
	os.exit(1)
end
