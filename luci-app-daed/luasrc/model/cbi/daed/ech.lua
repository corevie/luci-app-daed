-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
--
-- ECH Tunnel (ech-workers) configuration page.
--
-- The form stores its options in the UCI section "ech" of /etc/config/daed
-- and generates a dae runfile (ech_tunnel.dae) consumed by dae-2.0.0:
--   * section "ech_tunnel" with the standalone local SOCKS5/HTTP proxy;
--   * optionally an echws:// node + group, so routing rules can use it.

local m, s, o
local sys = require "luci.sys"

-- Where the generated dae fragment is written (UCI option config_file).
local DEFAULT_RUNFILE = "/etc/daed/ech_tunnel.dae"

m = Map("daed")
m.title = translate("ECH Tunnel")
m.description = translate(
	"Relay traffic through a wss tunnel server using TLS 1.3 Encrypted Client Hello (ECH). " ..
	"The tunnel can serve a local SOCKS5/HTTP proxy and/or be used as an echws:// node in dae routing.")

m:section(SimpleSection).template = "daed/daed_ech_status"

s = m:section(NamedSection, "ech", "ech", translate("ECH Tunnel Settings"))
s.addremove = false

-- Validation helpers ---------------------------------------------------------

-- "host:port" or "host:port/path" of the tunnel server. IPv6 hosts must be
-- wrapped in brackets, e.g. [2606:4700::1]:443/tunnel.
local function validate_server(value)
	if value == nil or value == "" then
		return nil, translate("Server is required when ECH tunnel is enabled")
	end
	if value:find("['\"\\%c]") then
		return nil, translate("Server must not contain quotes or control characters")
	end
	-- Split off an optional path (Lua patterns have no optional groups, so
	-- capture up to the first slash instead).
	local hostport = value:match("^([^/]+)")
	if not hostport then
		return nil, translate("Invalid server, expected host:port[/path]")
	end
	local host, port = hostport:match("^%[?([%w%.%-:]+)%]?:([0-9]+)$")
	if not host then
		return nil, translate("Invalid server, expected host:port[/path]")
	end
	local portn = tonumber(port)
	if portn < 1 or portn > 65535 then
		return nil, translate("Port must be within 1..65535")
	end
	return value
end

-- "host:port" of the local SOCKS5/HTTP proxy.
local function validate_listen(value)
	if value == nil or value == "" then
		return nil, translate("Listen address is required")
	end
	local host, port = value:match("^(%[?[%w%.%-:]+%]?):([0-9]+)$")
	if not host then
		return nil, translate("Invalid listen address, expected host:port (e.g. 127.0.0.1:1080)")
	end
	local portn = tonumber(port)
	if portn < 1 or portn > 65535 then
		return nil, translate("Port must be within 1..65535")
	end
	return value
end

-- Optional fixed IP toward the tunnel server.
local function validate_ip(value)
	if value == nil or value == "" then
		return value
	end
	local ip = require "luci.ip"
	local ok = pcall(function() ip.new(value) end)
	if ok then
		return value
	end
	return nil, translate("Invalid IP address")
end

local function shell_safe(v)
	return v and v:find("['\"\\\r\n]") == nil
end

local function esc(v)
	return (v:gsub("['\"\\\r\n]", ""))
end


-- Options --------------------------------------------------------------------

o = s:option(Flag, "enabled", translate("Enable"))
o.default = 0
o.rmempty = false
o.description = translate(
	"When enabled, the ech_tunnel runfile is generated and the daemon is restarted. Turning it off removes the runfile. " ..
	"The dashboard daemon merges the fragment's ech_tunnel section on every config load; the runfile path must stay " ..
	"inside /etc/daed for that to happen.")

o = s:option(Value, "server", translate("Tunnel Server"))
o.placeholder = "your-worker.workers.dev:443/tunnel"
o.rmempty = false
o.description = translate("The wss tunnel server in host:port[/path] form, e.g. your-worker.workers.dev:443/tunnel")
function o.validate(self, value, section)
	local enabled = luci.http.formvalue("cbid.daed.ech.enabled")
	if not enabled and (value == nil or value == "") then
		return "" -- allowed while the tunnel is disabled
	end
	return validate_server(value)
end

o = s:option(Value, "listen", translate("Local Proxy Listen Address"))
o.placeholder = "127.0.0.1:1080"
o.default = "127.0.0.1:1080"
o.rmempty = false
o.description = translate("Local SOCKS5/HTTP proxy address. Both protocols share this port; SOCKS5 UDP is supported for DNS only (answered via DoH over ECH).")
function o.validate(self, value, section)
	local enabled = luci.http.formvalue("cbid.daed.ech.enabled")
	if not enabled and (value == nil or value == "") then
		return ""
	end
	return validate_listen(value)
end

o = s:option(Value, "ip", translate("Fixed Server IP (optional)"))
o.placeholder = "104.21.16.1"
o.rmempty = true
o.description = translate("Pin the TCP connection to this IP while keeping the TLS SNI of the server, e.g. a Cloudflare anycast IP.")
function o.validate(self, value, section)
	return validate_ip(value)
end

o = s:option(Value, "token", translate("Auth Token (optional)"))
o.password = true
o.rmempty = true
o.description = translate("Sent as the websocket subprotocol for authentication.")

o = s:option(Value, "dns", translate("DoH Server for ECH Config"))
o.placeholder = "dns.alidns.com/dns-query"
o.default = "dns.alidns.com/dns-query"
o.rmempty = false
o.description = translate("DoH server used to fetch the ECH config (HTTPS DNS record).")

o = s:option(Value, "ech_domain", translate("ECH Config Domain"))
o.placeholder = "cloudflare-ech.com"
o.default = "cloudflare-ech.com"
o.rmempty = false
o.description = translate("Domain queried for its HTTPS (type 65) record carrying the ECH config list.")

o = s:option(Flag, "gen_node", translate("Also Generate echws:// Node"))
o.default = 0
o.rmempty = false
o.description = translate(
	"Additionally write an echws:// node and an \"ech_tunnel\" group into the runfile, " ..
	"so routing rules can use the outbound ech_tunnel (e.g. fallback: ech_tunnel).")

o = s:option(Value, "config_file", translate("Generated Runfile Path"))
o.placeholder = DEFAULT_RUNFILE
o.default = DEFAULT_RUNFILE
o.rmempty = false
o.description = translate(
	"Path of the generated dae config fragment. The dashboard daemon merges the ech_tunnel section of every " ..
	"*.dae in /etc/daed on each config load, so keep the default (or any other path inside /etc/daed) for daed. " ..
	"A path outside /etc/daed (e.g. /etc/dae/config.d/ech_tunnel.dae) only takes effect in the standalone dae " ..
	"build, which reads it through an include directive.")
function o.validate(self, value, section)
	if value == nil or value == "" then
		return nil, translate("Runfile path is required")
	end
	if not value:match("^/") or not shell_safe(value) then
		return nil, translate("Runfile path must be absolute and must not contain quotes")
	end
	return value
end


-- Gist 同步（cfMac nodes.json）------------------------------------------------

local gs = m:section(NamedSection, "gist", "gist", translate("Gist Sync (cfMac nodes.json)"))
gs.addremove = false

o = gs:option(Flag, "enabled", translate("Enable Gist Sync"))
o.default = 0
o.rmempty = false
o.description = translate(
	"Run the download below on a schedule: the gist is fetched into /etc/daed/nodes.d/<subscription tag>.json " ..
	"and daed is restarted, so the nodes stay in sync without clicking the button. " ..
	"Every node becomes an echws:// outbound (name, token, preferred IPs, ECH DoH are all mapped).")

o = gs:option(Value, "gist_id", translate("Gist ID"))
o.placeholder = "abc123def456..."
o.rmempty = false
o.description = translate("The gist holding nodes.json (the ID from its URL).")
function o.validate(self, value, section)
	local enabled = luci.http.formvalue("cbid.daed.gist.enabled")
	if not enabled and (value == nil or value == "") then
		return ""
	end
	if value == nil or value == "" then
		return nil, translate("Gist ID is required when Gist sync is enabled")
	end
	if not value:match("^[%w%-]+$") then
		return nil, translate("Invalid Gist ID")
	end
	return value
end

o = gs:option(Value, "token", translate("GitHub Token (for private gists)"))
o.password = true
o.rmempty = true
o.description = translate(
	"Personal access token with the gist scope. Leave empty for public gists. " ..
	"The token is stored in plaintext in /etc/config/daed; the fetched node links (which carry the " ..
	"tunnel token) are stored in /etc/daed/nodes.d/<tag>.json with mode 0600. Do not reuse a " ..
	"high-privilege token.")

o = gs:option(Value, "gist_file", translate("Gist Filename"))
o.placeholder = "nodes.json"
o.default = "nodes.json"
o.rmempty = false
o.description = translate("File name inside the gist.")

o = gs:option(Value, "sub_tag", translate("Subscription Tag"))
o.placeholder = "ech_nodes"
o.default = "ech_nodes"
o.rmempty = false
o.description = translate(
	"Name of the drop-in file (/etc/daed/nodes.d/<tag>.json). The daemon imports it as a subscription " ..
	"with this tag plus a group of the same name, so routing rules can reference the group (e.g. fallback: ech_nodes).")

-- The button renders its own template (button + result area + hint).
o = gs:option(DummyValue, "download")
o.template = "daed/ech_download"

-- Runfile generation ---------------------------------------------------------

local function build_runfile(cfg)
	local lines = {}
	lines[#lines+1] = "# Generated by luci-app-daed (ECH Tunnel). Do not edit manually."
	lines[#lines+1] = ""
	lines[#lines+1] = "ech_tunnel {"
	lines[#lines+1] = string.format("    listen: '%s'", esc(cfg.listen))
	lines[#lines+1] = string.format("    server: '%s'", esc(cfg.server))
	if cfg.ip and cfg.ip ~= "" then
		lines[#lines+1] = string.format("    ip: '%s'", esc(cfg.ip))
	end
	if cfg.token and cfg.token ~= "" then
		lines[#lines+1] = string.format("    token: '%s'", esc(cfg.token))
	end
	if cfg.dns and cfg.dns ~= "" then
		lines[#lines+1] = string.format("    dns: '%s'", esc(cfg.dns))
	end
	if cfg.ech_domain and cfg.ech_domain ~= "" then
		lines[#lines+1] = string.format("    ech_domain: '%s'", esc(cfg.ech_domain))
	end
	lines[#lines+1] = "}"
	if cfg.gen_node == "1" then
		lines[#lines+1] = ""
		lines[#lines+1] = "node {"
		-- The node link only carries token/ip; the rest is already covered
		-- by the ech_tunnel section and the node defaults.
		local params = {}
		if cfg.ip and cfg.ip ~= "" then
			params[#params+1] = "ip=" .. esc(cfg.ip)
		end
		if cfg.token and cfg.token ~= "" then
			params[#params+1] = "token=" .. esc(cfg.token)
		end
		local link = "echws://" .. esc(cfg.server)
		if #params > 0 then
			link = link .. "?" .. table.concat(params, "&")
		end
		lines[#lines+1] = string.format("    ech-node: '%s'", link)
		lines[#lines+1] = "}"
		lines[#lines+1] = ""
		lines[#lines+1] = "group {"
		lines[#lines+1] = "    ech_tunnel {"
		lines[#lines+1] = "        filter: name(ech-node)"
		lines[#lines+1] = "        policy: min_moving_avg"
		lines[#lines+1] = "    }"
		lines[#lines+1] = "}"
	end
	lines[#lines+1] = ""
	return table.concat(lines, "\n")
end

local function read_ech_config()
	local uci = luci.model.uci.cursor()
	local cfg = {}
	for _, opt in ipairs({ "enabled", "server", "listen", "ip", "token", "dns", "ech_domain", "gen_node", "config_file" }) do
		cfg[opt] = uci:get("daed", "ech", opt) or ""
	end
	return cfg
end

local function write_runfile(cfg)
	local path = cfg.config_file
	if not path or path == "" then
		path = DEFAULT_RUNFILE
	end
	local content = build_runfile(cfg)
	local dir = path:match("^(.*/)") or "/tmp"
	sys.call(string.format("mkdir -p %q", dir))
	local f = io.open(path, "w")
	if not f then
		sys.call(string.format("logger -t luci-app-daed 'failed to write ECH tunnel runfile: %s'", path))
		return nil
	end
	f:write(content)
	f:close()
	-- dae refuses config files writable by group/others.
	sys.call(string.format("chmod 600 %q", path))
	sys.call(string.format("logger -t luci-app-daed 'generated ECH tunnel runfile: %s'", path))
	return path
end

local function remove_runfile(cfg)
	local path = cfg.config_file
	if not path or path == "" then
		path = DEFAULT_RUNFILE
	end
	if path:match("^/") and shell_safe(path) then
		sys.call(string.format("rm -f %q", path))
	end
end

m.apply_on_parse = true
m.on_after_apply = function(self, map)
	local cfg = read_ech_config()
	if cfg.enabled == "1"
		and validate_server(cfg.server)
		and validate_listen(cfg.listen)
		and validate_ip(cfg.ip) then
		write_runfile(cfg)
	else
		remove_runfile(cfg)
	end

	-- Gist sync: the nodes live as a daemon drop-in (nodes.d/<tag>.json) and
	-- the cron entry maintained by /etc/init.d/luci_daed keeps it fresh, so
	-- only a first fetch is triggered here; the script restarts daed itself.
	local uci = luci.model.uci.cursor()
	local gcfg = {}
	for _, opt in ipairs({ "enabled", "gist_id", "token", "gist_file", "sub_tag" }) do
		gcfg[opt] = uci:get("daed", "gist", opt) or ""
	end
	if gcfg.enabled == "1" and gcfg.gist_id ~= "" then
		sys.call("/usr/libexec/daed-gist-sync >/dev/null 2>&1 &")
	end

	sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
end

return m
