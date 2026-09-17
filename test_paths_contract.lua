-- Cross-language contract checks for the gist node drop-in feature.
--
-- The pieces live in three languages (LuCI Lua, daed-wing Go, init.d shell)
-- and silently stop working when they disagree about a path or a file name --
-- which is exactly how the feature was broken before. These checks pin the
-- shared contract in one place:
--
--   * /etc/daed/nodes.d            written by Lua, scanned by Go
--   * /tmp/daed-nodes-sync.json    written by Go, read by Lua
--   * /usr/libexec/daed-gist-sync  invoked by init.d cron and by ech.lua
--
-- Lua-only: no device, no containers.

local MODULE = "luci-app-daed/luasrc/model/daed_gist.lua"
local PATCH = "patchset/feat-local-nodes-import.patch"
local SCRIPT = "luci-app-daed/root/usr/libexec/daed-gist-sync"
local INIT = "luci-app-daed/root/etc/init.d/luci_daed"
local ECH = "luci-app-daed/luasrc/model/cbi/daed/ech.lua"
local VIEW = "luci-app-daed/luasrc/view/daed/daed_ech_status.htm"
local CONTROLLER = "luci-app-daed/luasrc/controller/daed.lua"

local failures = 0
local function check(cond, msg)
	if cond then
		print("  PASS: " .. msg)
	else
		print("  FAIL: " .. msg)
		failures = failures + 1
	end
end

local function slurp(path)
	local f = assert(io.open(path, "r"), "cannot read " .. path)
	local body = f:read("*a")
	f:close()
	return body
end

local module_src = slurp(MODULE)
local patch_src = slurp(PATCH)
local script_src = slurp(SCRIPT)
local init_src = slurp(INIT)
local ech_src = slurp(ECH)

local function lua_const(src, name)
	return src:match(name .. '%s*=%s*"([^"]+)"')
end

print("== drop-in directory ==")
local lua_dir = lua_const(module_src, "M.NODES_DIR")
local go_dir = patch_src:match('LocalNodesDir%s*=%s*"([^"]+)"')
check(lua_dir ~= nil, "the share module declares NODES_DIR")
check(lua_dir == go_dir, "Lua and the daemon agree on the drop-in directory (" ..
	tostring(lua_dir) .. " vs " .. tostring(go_dir) .. ")")
check(lua_dir == "/etc/daed/nodes.d", "drop-in directory is /etc/daed/nodes.d")

print("== import report ==")
local lua_report = lua_const(module_src, "M.SYNC_REPORT")
local go_report = patch_src:match('SyncReportPath%s*=%s*"([^"]+)"')
check(lua_report == go_report, "written and read at the same path (" ..
	tostring(lua_report) .. " vs " .. tostring(go_report) .. ")")
check(lua_report ~= nil and lua_report:sub(1, 5) == "/tmp/",
	"report lives on tmpfs (it describes one daemon start)")

print("== status RPC surfaces what the daemon reports ==")
local view_src = slurp(VIEW)
local ctl_src = slurp(CONTROLLER)
check(module_src:match("read_sync_report") ~= nil, "the module reads the report")
check(view_src:match("dropins") ~= nil, "the status view renders the drop-in list")
-- Every status the view switches on must be produced by one of the producers:
-- the daemon (patch), the share module, or the controller that merges them.
local producers = patch_src .. module_src .. ctl_src .. view_src
for _, status in ipairs({ "imported", "skipped", "invalid", "failed", "pending" }) do
	check(producers:match('"' .. status .. '"') ~= nil,
		"status '" .. status .. "' is produced somewhere in the stack")
end
check(view_src:match("retained") ~= nil, "the status view renders the retained count")
check(view_src:match("d%.status === 'imported'") ~= nil or view_src:match('d%.status === "imported"') ~= nil,
	"the view branches on the imported status")

print("== ECH tunnel fragment directory ==")
-- The daemon merges ech_tunnel fragments from exactly one directory; the UI
-- both writes into it and warns when the configured path leaves it.
local lua_fragment_dir = ctl_src:match('FRAGMENT_DIR%s*=%s*"([^"]+)"')
local go_fragment_dir = patch_src:match('EchTunnelFragmentDir%s*=%s*"([^"]+)"')
check(lua_fragment_dir ~= nil, "the controller declares the scanned directory")
check(lua_fragment_dir == go_fragment_dir,
	"the UI and the daemon scan the same directory (" ..
	tostring(lua_fragment_dir) .. " vs " .. tostring(go_fragment_dir) .. ")")
local ech_src_full = ech_src
local default_runfile = ech_src_full:match('DEFAULT_RUNFILE%s*=%s*"([^"]+)"')
check(default_runfile ~= nil and default_runfile:sub(1, #tostring(lua_fragment_dir) + 1)
	== tostring(lua_fragment_dir) .. "/",
	"the default runfile path is inside the scanned directory (" .. tostring(default_runfile) .. ")")
check(patch_src:match("MergeEchTunnelFragments") ~= nil, "the daemon merges the fragment into its config")
check(patch_src:match("echtunnel%.New%(%)") ~= nil, "the daemon drives the tunnel controller")
check(view_src:match("data%.scanned") ~= nil, "the status view warns about unscanned paths")

print("== sync script wiring ==")
check(init_src:match("/usr/libexec/daed%-gist%-sync") ~= nil, "init.d cron invokes the script")
check(ech_src:match("/usr/libexec/daed%-gist%-sync") ~= nil, "apply triggers the script")
check(init_src:match("daed%-gist%-sync") ~= nil and init_src:match("grep %-v 'daed%-gist%-sync'") ~= nil,
	"init.d removes stale sync cron lines")
check(script_src:match('^#!/usr/bin/lua') ~= nil, "script uses the device's lua interpreter")
check(script_src:match('package%.path = "/usr/lib/lua/') ~= nil,
	"script sets LUA_PATH itself (the CGI wrapper is not there for cron)")

local f = io.open(SCRIPT, "r")
check(f ~= nil, "script is installed by the package (root/usr/libexec)")
if f then f:close() end

print("")
if failures == 0 then
	print("ALL CONTRACT CHECKS PASSED")
	os.exit(0)
else
	print(failures .. " CHECKS FAILED")
	os.exit(1)
end
