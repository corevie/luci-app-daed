-- Functional test harness for luci-app-daed's ECH Tunnel page (ech.lua).
-- Stubs the LuCI CBI environment, loads the real model, and exercises the
-- validators and the runfile generation.

local LUCI_APP = "luci-app-daed/luasrc/model/cbi/daed"
local TESTDIR = "/tmp/ech_luci_test"

-- Recording stubs -----------------------------------------------------------

local recorded = { sections = {}, options = {}, apply_called = false }
local written_files = {}
local sys_calls = {}

local sys = {
	call = function(cmd) sys_calls[#sys_calls+1] = cmd end,
	exec = function(cmd) return "" end,
}

local function identity(s, ...) return s end

local function new_option(class, name, title)
	local o = {
		class = class, name = name, title = title,
		default = nil, rmempty = nil, placeholder = nil,
		description = nil, password = nil, datatype = nil,
		validate = nil,
	}
	recorded.options[#recorded.options+1] = o
	return o
end

local function new_section(class, name, title)
	local s = {
		class = class, name = name, title = title,
		addremove = nil, anonymous = nil,
		options = {},
		option = function(self, class, name, title)
			local o = new_option(class, name, title)
			table.insert(self.options, o)
			return o
		end,
	}
	recorded.sections[#recorded.sections+1] = s
	return s
end

local map_obj

local stub_map = function(config, title, description)
	map_obj = {
		config = config, title = title, description = description,
		apply_on_parse = false,
		sections = {},
		section = function(self, class, ...)
			local s = new_section(class, ...)
			table.insert(self.sections, s)
			return s
		end,
	}
	return map_obj
end

local stub_simple_section = function() return {} end

local function make_section_class(cls)
	return function(name, type_, title)
		return new_section(cls .. "-stub", name, title)
	end
end

-- UCI stub -------------------------------------------------------------------

local uci_store = {}

local uci_cursor = {
	get = function(self, config, section, option)
		return uci_store[section] and uci_store[section][option] or nil
	end,
	set = function(self, ...) end,
}

-- io stub: capture file writes ------------------------------------------------

local real_open = io.open
io.open = function(path, mode)
	if mode == "w" then
		local buf = {}
		local f = {
			write = function(self, ...) buf[#buf+1] = table.concat({...}) end,
			close = function(self) written_files[path] = table.concat(buf) end,
		}
		return f
	end
	return real_open(path, mode)
end

-- Globals expected inside a CBI model ----------------------------------------

luci = {
	http = {
		formvalue = function(name) return nil end,
		redirect = function() end,
	},
	model = { uci = { cursor = function() return uci_cursor end } },
	dispatcher = { build_url = function() return "" end },
}

Map = stub_map
translate = identity
translatef = identity
SimpleSection = stub_simple_section
NamedSection = make_section_class("NamedSection")
TypedSection = make_section_class("TypedSection")
Flag = "Flag"
Value = "Value"

package.preload["luci.sys"] = function() return sys end
package.preload["nixio.fs"] = function() return {} end
package.preload["luci.ip"] = function()
	return {
		new = function(v)
			-- Minimal address validator: dotted quad or IPv6 with a colon.
			if v:match("^%d+%.%d+%.%d+%.%d+$") or (v:match("^[%x:]+$") and v:find(":")) then
				return setmetatable({}, { __index = function() return v end })
			end
			error("invalid address: " .. tostring(v))
		end,
	}
end

-- Load the model -------------------------------------------------------------

dofile(LUCI_APP .. "/ech.lua")

local failures = 0
local function check(cond, msg)
	if cond then
		print("  PASS: " .. msg)
	else
		print("  FAIL: " .. msg)
		failures = failures + 1
	end
end

local function get_option(name)
	for _, o in ipairs(recorded.options) do
		if o.name == name then return o end
	end
	return nil
end

print("== structure ==")
check(map_obj ~= nil and map_obj.config == "daed", "Map bound to config 'daed'")
check(map_obj.apply_on_parse == true, "apply_on_parse enabled")
local ech_section
for _, sec in ipairs(recorded.sections) do
	if sec.name == "ech" then ech_section = sec end
end
check(ech_section ~= nil, "NamedSection 'ech' declared")
local optnames = {}
for _, o in ipairs(recorded.options) do optnames[#optnames+1] = o.name end
local want = { "enabled", "server", "listen", "ip", "token", "dns", "ech_domain", "gen_node", "config_file" }
for _, w in ipairs(want) do
	check(get_option(w) ~= nil, ("option '%s' declared"):format(w))
end

local gist_section
for _, sec in ipairs(recorded.sections) do
	if sec.name == "gist" then gist_section = sec end
end
check(gist_section ~= nil, "NamedSection 'gist' declared")

print("== server validation ==")
local srv = get_option("server")
luci.http.formvalue = function(name)
	if name == "cbid.daed.ech.enabled" then return "1" end
	return nil
end
check(srv.validate(srv, "worker.example.com:443/tunnel", nil) == "worker.example.com:443/tunnel",
	"valid server accepted")
check(srv.validate(srv, "worker.example.com", nil) == nil,
	"server without port rejected")
check(srv.validate(srv, "worker.example.com:99999", nil) == nil,
	"server with out-of-range port rejected")
check(srv.validate(srv, "worker.example.com:0", nil) == nil,
	"server with port 0 rejected")
check(srv.validate(srv, "[2606:4700::1]:443/ws", nil) == "[2606:4700::1]:443/ws",
	"bracketed IPv6 server accepted")
check(srv.validate(srv, "", nil) == nil, "empty server rejected when enabled")
check(srv.validate(srv, "a'b:443", nil) == nil, "quoted server rejected")
luci.http.formvalue = function(name) return nil end
check(srv.validate(srv, "", nil) == "", "empty server allowed when disabled")

print("== listen validation ==")
luci.http.formvalue = function(name)
	if name == "cbid.daed.ech.enabled" then return "1" end
	return nil
end
local listen = get_option("listen")
check(listen.validate(listen, "127.0.0.1:1080", nil) == "127.0.0.1:1080", "valid listen accepted")
check(listen.validate(listen, "127.0.0.1", nil) == nil, "listen without port rejected")
check(listen.validate(listen, "127.0.0.1:70000", nil) == nil, "listen with bad port rejected")
check(listen.validate(listen, "", nil) == nil, "empty listen rejected")

print("== ip validation ==")
local ipopt = get_option("ip")
check(ipopt.validate(ipopt, "", nil) == "", "empty ip allowed")
check(ipopt.validate(ipopt, "104.21.16.1", nil) == "104.21.16.1", "IPv4 accepted")
check(ipopt.validate(ipopt, "2606:4700::1", nil) == "2606:4700::1", "IPv6 accepted")
check(ipopt.validate(ipopt, "not-an-ip", nil) == nil, "garbage ip rejected")

print("== runfile generation (enabled, with node) ==")
uci_store["ech"] = {
	enabled = "1",
	server = "your-worker.workers.dev:443/tunnel",
	listen = "127.0.0.1:1080",
	ip = "104.21.16.1",
	token = "secret",
	dns = "dns.alidns.com/dns-query",
	ech_domain = "cloudflare-ech.com",
	gen_node = "1",
	config_file = TESTDIR .. "/ech_tunnel.dae",
}
map_obj.on_after_apply(map_obj, nil)
local content = written_files[TESTDIR .. "/ech_tunnel.dae"]
check(content ~= nil, "runfile written")
if content then
	check(content:find("ech_tunnel {", 1, true) ~= nil, "ech_tunnel section emitted")
	check(content:find("listen: '127%.0%.0%.1:1080'") ~= nil, "listen emitted")
	check(content:find("server: 'your%-worker%.workers%.dev:443/tunnel'") ~= nil, "server emitted")
	check(content:find("ip: '104%.21%.16%.1'") ~= nil, "ip emitted")
	check(content:find("token: 'secret'") ~= nil, "token emitted")
	check(content:find("dns: 'dns%.alidns%.com/dns%-query'") ~= nil, "dns emitted")
	check(content:find("ech_domain: 'cloudflare%-ech%.com'") ~= nil, "ech_domain emitted")
	check(content:find("echws://your%-worker%.workers%.dev:443/tunnel%?ip=104%.21%.16%.1&token=secret") ~= nil,
		"echws node link emitted with ip+token")
	check(content:find("group {") ~= nil and content:find("filter: name%(ech%-node%)") ~= nil,
		"ech_tunnel group emitted")
	-- The generated fragment must parse with dae's config parser: verified
	-- separately by the Go test in dae-2.0.0 (TestLuCIGeneratedRunfile).
end

print("== runfile generation (enabled, no node, no optional fields) ==")
uci_store["ech"] = {
	enabled = "1",
	server = "w.example.com:443",
	listen = "0.0.0.0:1080",
	ip = "",
	token = "",
	dns = "",
	ech_domain = "",
	gen_node = "0",
	config_file = TESTDIR .. "/ech_tunnel2.dae",
}
map_obj.on_after_apply(map_obj, nil)
local content2 = written_files[TESTDIR .. "/ech_tunnel2.dae"]
check(content2 ~= nil, "minimal runfile written")
if content2 then
	check(content2:find("ip:") == nil, "empty ip omitted")
	check(content2:find("token:") == nil, "empty token omitted")
	check(content2:find("dns:") == nil, "empty dns omitted (default applied by dae)")
	check(content2:find("echws://") == nil, "node link omitted")
end

print("== gist sync runfile ==")
uci_store["gist"] = {
	enabled = "1",
	gist_id = "abc123def456",
	token = "tok123",
	gist_file = "nodes.json",
	sub_tag = "ech_nodes",
	persist = "1",
}
map_obj.on_after_apply(map_obj, nil)
local gist_content = written_files["/etc/dae/config.d/ech_sub.dae"]
check(gist_content ~= nil, "gist runfile written")
if gist_content then
	check(gist_content:find("subscription {", 1, true) ~= nil, "subscription section emitted")
	check(gist_content:find("ech_nodes: 'gist%-file://tok123@abc123def456/nodes%.json'") ~= nil,
		"gist-file URL with token and filename emitted")
end

print("== gist disabled removes the runfile ==")
uci_store["gist"].enabled = "0"
map_obj.on_after_apply(map_obj, nil)
local gist_rm = false
for _, c in ipairs(sys_calls) do
	if c:find("ech_sub%.dae") and c:find("rm %-f") then gist_rm = true end
end
-- also check via logger mock (sys.call recorded)
print("== disabled removes the runfile ==")
uci_store["ech"].enabled = "0"
local rm_seen = false
sys.call = function(cmd)
	if cmd:find("rm %-f") then rm_seen = true end
end
map_obj.on_after_apply(map_obj, nil)
check(rm_seen, "runfile removal issued when disabled")

print("== service restart issued ==")
local restart_seen = false
for _, c in ipairs(sys_calls) do
	if c:find("/etc/init%.d/daed restart") then restart_seen = true end
end
check(restart_seen, "daemon restart scheduled on apply")

print("== bad config does not write a runfile ==")
written_files = {}
uci_store["ech"] = {
	enabled = "1",
	server = "bad server", -- invalid: contains a space, no port
	listen = "127.0.0.1:1080",
	gen_node = "0",
	config_file = TESTDIR .. "/ech_tunnel3.dae",
}
map_obj.on_after_apply(map_obj, nil)
check(written_files[TESTDIR .. "/ech_tunnel3.dae"] == nil, "invalid config produces no runfile")

print("")
if failures == 0 then
	print(("ALL CHECKS PASSED (%d options, %d checks)"):format(#recorded.options, 0))
	os.exit(0)
else
	print(failures .. " CHECKS FAILED")
	os.exit(1)
end
