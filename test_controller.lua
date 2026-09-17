-- Regression tests for the LuCI controller/UI integration fixes:
--   * log file path matches /etc/init.d/daed --logfile
--   * config editor whitelist and no-validator feedback on the wing build
--   * ech_status probes IPv6 with inet6 and IPv4 with inet
--   * basic settings refresh the subscription cron on apply

local CONTROLLER = "luci-app-daed/luasrc/controller/daed.lua"
local BASIC = "luci-app-daed/luasrc/model/cbi/daed/basic.lua"
local INIT = "daed/files/daed.init"

local failures = 0
json_out = nil
local function check(cond, msg)
	if cond then
		print("  PASS: " .. msg)
	else
		print("  FAIL: " .. msg)
		failures = failures + 1
	end
end

-- ── shared stubs ─────────────────────────────────────────────────────────

local sys_calls = {}
local http_writes = {}
local form = {}
local file_writes = {}
local fs_access = {}
local fs_stat = {}       -- path -> { size, mtime }
local dropins = {}       -- stubbed `ls -1 nodes.d` listing entries
local sync_report = nil  -- stubbed daemon import report (JSON text)

local sys = {
	call = function(cmd)
		sys_calls[#sys_calls + 1] = cmd
		if cmd:match("pidof daed") then return 0 end
		if cmd:match("validate") then return 0 end
		return 0
	end,
	exec = function(cmd)
		sys_calls[#sys_calls + 1] = cmd
		if cmd:match("^cat ") then return "log-content\n" end
		if cmd:match("^ls %-1 '/etc/daed/nodes.d'") then
			local names = {}
			for _, d in ipairs(dropins) do
				names[#names + 1] = d.file:match("([^/]+)$")
			end
			return table.concat(names, "\n")
		end
		if cmd:match("^ls -1 /etc/daed") then return "ech_tunnel.dae\n" end
		return ""
	end,
}

local http = {
	formvalue = function(name) return form[name] end,
	prepare_content = function() end,
	write = function(s) http_writes[#http_writes + 1] = s end,
	write_json = function(t) json_out = t end,
}

local fs = {
	access = function(path) return fs_access[path] end,
	readfile = function(path) return "content" end,
	writefile = function(path, content) file_writes[path] = content end,
	stat = function(path) return fs_stat[path] end,
}

-- The daemon's import report is read through io.open by luci.model.daed_gist.
local real_open = io.open
io.open = function(path, mode)
	if mode == "r" and path == "/tmp/daed-nodes-sync.json" then
		if not sync_report then
			return nil
		end
		local body, i = sync_report, 0
		return {
			read = function() i = i + 1; if i == 1 then return body end; return nil end,
			close = function() end,
		}
	end
	return real_open(path, mode)
end

-- The share module under test: luasrc/ installs to /usr/lib/lua/luci/ on the
-- device, so map the require name to the repo path explicitly.
package.preload["luci.model.daed_gist"] = function()
	return dofile("luci-app-daed/luasrc/model/daed_gist.lua")
end

local uci_get = function() return nil end
local uci_cursor = {
	get = function(self, config, section, option) return uci_get(config, section, option) end,
	set = function() end,
}

local i18n_stub = {
	translate = function(s) return s end,
	translatef = function(f, ...) return f:format(...) end,
}

package.preload["luci.sys"] = function() return sys end
package.preload["luci.http"] = function() return http end
package.preload["nixio.fs"] = function() return fs end
package.preload["nixio"] = function()
	local families = {}
	local sockets = {}
	return {
		socket = function(family, kind)
			families[#families + 1] = family
			local s = {
				settimeout = function() end,
				connect = function() return true end,
				close = function() end,
			}
			sockets[#sockets + 1] = s
			return s
		end,
		get_families = function() return families end,
	}
end
package.preload["luci.i18n"] = function() return i18n_stub end
package.preload["luci.jsonc"] = function() return dofile("test_support.lua").jsonc_stub() end
package.preload["luci.model.uci"] = function() return { cursor = function() return uci_cursor end } end
package.preload["luci.dispatcher"] = function()
	return { build_url = function() return "/cgi-bin/luci/admin/services/daed/editor_save" end }
end
package.preload["luci.util"] = function() return { pcdata = function(s) return s end } end
package.preload["luci.template"] = function() return { render_string = function() end } end
package.preload["luci.ip"] = function() return { new = function() return true end } end

luci = {
	http = http,
	sys = sys,
	model = { uci = { cursor = function() return uci_cursor end } },
	dispatcher = { build_url = function() return "/cgi-bin/luci/admin/services/daed/editor_save" end },
	util = { pcdata = function(s) return s end },
	template = { render_string = function() end },
}

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

dofile(CONTROLLER)
local mod = package.loaded["luci.controller.daed"]

-- ── log path ─────────────────────────────────────────────────────────────

print("== log path ==")
sys_calls = {}
http_writes = {}
mod.get_log()
local cat_cmd = nil
for _, c in ipairs(sys_calls) do
	if c:match("^cat ") then cat_cmd = c end
end
local init_log = nil
for line in io.lines(INIT) do
	local l = line:match('^LOG="(.+)"')
	if l then init_log = l end
end
check(cat_cmd ~= nil and cat_cmd == "cat " .. init_log,
	"get_log reads the same path as daed.init (" .. tostring(init_log) .. ")")

sys_calls = {}
mod.clear_log()
local clear_seen = false
for _, c in ipairs(sys_calls) do
	if c == "true > " .. init_log then clear_seen = true end
end
check(clear_seen, "clear_log truncates the same path as daed.init")

-- ── editor whitelist and validation feedback ─────────────────────────────

print("== editor ==")
fs_access = {}
file_writes = {}
fs_access["/usr/bin/dae"] = nil -- wing build: no standalone dae validator
fs_access["/etc/daed/ech_tunnel.dae"] = true
form = { file = "ech_tunnel.dae", content = "ech_tunnel { server: 'x:443' }" }
http_writes = {}
mod.action_editor_save()
local saved = file_writes["/etc/daed/ech_tunnel.dae"]
check(saved ~= nil, "editor saves a whitelisted ech_tunnel.dae")
check(http_writes[1] ~= nil and http_writes[1]:match("no validator"),
	"editor reports no-validator instead of OK on the wing build")

form = { file = "config.dae", content = "x" }
http_writes = {}
mod.action_editor_save()
check(http_writes[1] ~= nil and http_writes[1]:match("file not allowed"),
	"editor rejects the legacy fake config.dae name")

-- ── ech_status IPv6/IPv4 probing ─────────────────────────────────────────

print("== ech_status family selection ==")
local nixio = require "nixio"
local function reset_ech(listen)
	fs_access = {}
	fs_access[listen] = true
	uci_get = function(config, section, option)
		if section == "ech" then
			if option == "enabled" then return "1" end
			if option == "listen" then return listen end
			if option == "config_file" then return listen end
		end
		return nil
	end
	http_writes = {}
	nixio.get_families_clear = true
	-- reset recorded families by swapping the inner table
	local prev = nixio.get_families()
	for i = #prev, 1, -1 do prev[i] = nil end
end

reset_ech("127.0.0.1:1080")
mod.act_ech_status()
local fam4 = nixio.get_families()
check(#fam4 == 1 and fam4[1] == "inet", "IPv4 listen probed with inet only")

reset_ech("[2606:4700::1]:1080")
mod.act_ech_status()
local fam6 = nixio.get_families()
check(fam6[1] == "inet6", "IPv6 listen tries inet6 first (" .. tostring(fam6[1]) .. ")")
check(json_out ~= nil, "ech_status returns JSON")

-- ── ech_status gist sync reporting ───────────────────────────────────────
-- The status RPC lists every drop-in under nodes.d and merges the daemon's
-- import report, so "written" and "actually imported" are distinguishable.
reset_ech("127.0.0.1:1080")
uci_get = function(config, section, option)
	if section == "gist" then
		if option == "enabled" then return "1" end
		if option == "sub_tag" then return "ech_nodes" end
	end
	if section == "ech" then
		if option == "enabled" then return "1" end
		if option == "listen" then return "127.0.0.1:1080" end
	end
	return nil
end
fs_access["/etc/daed/nodes.d"] = true
dropins = {
	{ tag = "ech_nodes", file = "/etc/daed/nodes.d/ech_nodes.json", size = 1234, mtime = 1700000000 },
	{ tag = "manual", file = "/etc/daed/nodes.d/manual.txt", size = 42, mtime = 1700000001 },
}
sync_report = [[{"generatedAt":1700000002,"entries":[
	{"tag":"ech_nodes","file":"/etc/daed/nodes.d/ech_nodes.json","status":"imported","nodes":246,"retained":0},
	{"tag":"manual","file":"/etc/daed/nodes.d/manual.txt","status":"skipped","nodes":0,"retained":0,
	 "error":"the tag is already used by subscription https://example.com/sub"}
]}]]
mod.act_ech_status()
check(json_out.gist ~= nil, "ech_status reports the gist sync block")
check(json_out.gist.enabled == true, "gist enabled flag surfaced")
check(json_out.gist.tag == "ech_nodes", "gist subscription tag surfaced")
check(json_out.gist.dropin == true, "configured tag's drop-in presence surfaced")
check(json_out.gist.report_at == 1700000002, "daemon report timestamp surfaced")
check(#json_out.gist.dropins == 2, "every drop-in listed (" .. #json_out.gist.dropins .. ")")
check(json_out.gist.dropins[1].tag == "ech_nodes" and json_out.gist.dropins[1].status == "imported"
	and json_out.gist.dropins[1].nodes == 246, "imported drop-in merged with the report")
check(json_out.gist.dropins[2].status == "skipped"
	and json_out.gist.dropins[2].error:match("already used") ~= nil,
	"tag conflict surfaced with its reason")
check(json_out.gist.nodes == 246, "node count for the configured tag surfaced")

-- Without a report (daemon not restarted yet) the drop-ins are still listed,
-- flagged as pending instead of silently vanishing.
sync_report = nil
mod.act_ech_status()
check(#json_out.gist.dropins == 2 and json_out.gist.dropins[1].pending == true,
	"drop-ins reported as pending while the daemon has not scanned them")
check(json_out.gist.report_at == nil, "no report timestamp when there is no report")

-- Retained (pinned) leftovers are surfaced too.
sync_report = [[{"generatedAt":1700000003,"entries":[
	{"tag":"ech_nodes","file":"/etc/daed/nodes.d/ech_nodes.json","status":"imported","nodes":2,"retained":1}
]}]]
mod.act_ech_status()
check(json_out.gist.dropins[1].retained == 1, "retained stale-node count surfaced")

-- ── basic.lua cron refresh ───────────────────────────────────────────────

print("== basic settings apply ==")
local apply_hook = nil
local option_store = {}
Map = function(config)
	return {
		config = config,
		apply_on_parse = false,
		sections = {},
		section = function(self, class, name, title)
			local s = { name = name, options = {} }
			s.option = function(self, oclass, oname, otitle)
				local o = { class = oclass, name = oname, title = otitle, option_store = option_store }
				table.insert(self.options, o)
				return o
			end
			table.insert(self.sections, s)
			return s
		end,
		append = function() end,
	}
end
SimpleSection = function() return {} end
TypedSection = function() return { addremove = false, anonymous = true } end
Flag = "Flag"
Value = "Value"
translate = function(s) return s end

local basic = dofile(BASIC)
if basic and basic.on_after_apply then
	sys_calls = {}
	basic.on_after_apply(basic, nil)
	local cron_refresh = false
	local daed_restart = false
	for _, c in ipairs(sys_calls) do
		if c:match("luci_daed restart") then cron_refresh = true end
		if c:match("/etc/init%.d/daed restart$") or c == "/etc/init.d/daed restart" then daed_restart = true end
	end
	check(cron_refresh, "saving basic settings refreshes the subscription cron (luci_daed restart)")
	check(daed_restart, "saving basic settings still restarts daed")
else
	check(false, "basic.lua loaded with on_after_apply")
end

-- ── weekday cron field validation ────────────────────────────────────────
local week_opt
for _, s in ipairs(basic.sections or {}) do
	for _, o in ipairs(s.options or {}) do
		if o.name == "subscribe_update_week_time" then week_opt = o end
	end
end
check(week_opt ~= nil and type(week_opt.validate) == "function",
	"weekday field carries a validate function")
if week_opt and week_opt.validate then
	local ok, err = week_opt.validate(week_opt, "1,3,5", nil)
	check(ok == "1,3,5", "weekday accepts a cron list")
	ok, err = week_opt.validate(week_opt, "0-6", nil)
	check(ok == "0-6", "weekday accepts a range")
	ok, err = week_opt.validate(week_opt, "", nil)
	check(ok == "*", "empty weekday falls back to *")
	ok, err = week_opt.validate(week_opt, "abc", nil)
	check(ok == nil and err ~= nil, "weekday rejects letters")
	ok, err = week_opt.validate(week_opt, "1; rm -rf /", nil)
	check(ok == nil and err ~= nil, "weekday rejects shell metacharacters")
	ok, err = week_opt.validate(week_opt, "8", nil)
	check(ok == nil and err ~= nil, "weekday rejects out-of-range values")
end

print("")
if failures == 0 then
	print("ALL CONTROLLER CHECKS PASSED")
	os.exit(0)
else
	print(failures .. " CHECKS FAILED")
	os.exit(1)
end
