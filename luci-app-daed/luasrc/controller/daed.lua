local sys  = require "luci.sys"
local http = require "luci.http"
local fs   = require "nixio.fs"
local gist = require "luci.model.daed_gist"

module("luci.controller.daed", package.seeall)

-- Editable config files (whitelist).
local CONFIG_DIR = "/etc/daed"
local CONFIG_ENTRY = "/etc/daed/ech_tunnel.dae"
-- Must match the --logfile passed by /etc/init.d/daed.
local DAED_LOG_FILE = "/var/log/daed/daed.log"

-- Node drop-ins, the gist sync and its import report all live in
-- luci.model.daed_gist (shared with /usr/libexec/daed-gist-sync).
--
-- The daemon merges ech_tunnel fragments only from this directory (see
-- EchTunnelFragmentDir in the wing patch): a runfile written anywhere else is
-- read by the standalone dae build alone, so the UI has to say so.
local FRAGMENT_DIR = "/etc/daed"

function index()
	if not nixio.fs.access("/etc/config/daed") then
		return
	end

	entry({"admin",  "services", "daed"}, alias("admin", "services", "daed", "setting"),_("DAED"), 58).dependent = true
	entry({"admin", "services", "daed", "setting"}, cbi("daed/basic"), _("Base Setting"), 1).leaf=true
	entry({"admin", "services", "daed", "daed"}, template("daed/daed"), _("Dashboard"), 2).leaf = true
	entry({"admin", "services", "daed", "log"}, cbi("daed/log"), _("Logs"), 3).leaf = true
	entry({"admin", "services", "daed", "ech"}, cbi("daed/ech"), _("ECH Tunnel"), 4).leaf = true
	entry({"admin", "services", "daed", "editor"}, call("action_editor"), _("Config Files"), 5).leaf = true
	entry({"admin", "services", "daed", "editor_save"}, post("action_editor_save")).leaf = true
	entry({"admin", "services", "daed", "ech_download"}, post("action_ech_download")).leaf = true
	entry({"admin", "services", "daed", "status"}, call("act_status")).leaf = true
	entry({"admin", "services", "daed", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", "daed", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", "daed", "ech_status"}, call("act_ech_status")).leaf = true
end

function act_status()
	local sys  = require "luci.sys"
	local e = { }
	e.running = sys.call("pidof daed >/dev/null") == 0
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

function get_log()
	http.write(sys.exec("cat " .. DAED_LOG_FILE))
end

function clear_log()
	sys.call("true > " .. DAED_LOG_FILE)
end

-- ECH tunnel (ech-workers) status: runfile presence, daemon state, and
-- whether the local proxy port is accepting connections.
function act_ech_status()
	local uci = require "luci.model.uci".cursor()
	local e = { }

	local enabled = uci:get("daed", "ech", "enabled") or "0"
	local listen = uci:get("daed", "ech", "listen") or "127.0.0.1:1080"
	local config_file = uci:get("daed", "ech", "config_file") or "/etc/daed/ech_tunnel.dae"

	e.enabled = (enabled == "1")
	e.listen = listen
	e.config_file = config_file
	e.generated = fs.access(config_file) ~= nil
	-- Whether the daemon will actually pick the runfile up (it scans
	-- FRAGMENT_DIR/*.dae on every config load).
	e.scanned = config_file:sub(1, #FRAGMENT_DIR + 1) == FRAGMENT_DIR .. "/"
	e.daed_running = sys.call("pidof daed >/dev/null") == 0

	-- Gist sync state: the drop-in files present under nodes.d (each becomes a
	-- subscription named after its file), merged with the daemon's import
	-- report so the UI can tell "written" from "actually imported".
	local g_enabled = uci:get("daed", "gist", "enabled") or "0"
	local g_tag = uci:get("daed", "gist", "sub_tag") or "ech_nodes"
	local report = gist.read_sync_report()
	local by_tag = {}
	local report_time = nil
	if report then
		report_time = report.generatedAt
		for _, entry in ipairs(report.entries) do
			if type(entry) == "table" and type(entry.tag) == "string" then
				by_tag[entry.tag] = entry
			end
		end
	end
	e.gist = {
		enabled = (g_enabled == "1"),
		tag = g_tag,
		report_at = report_time,
		dropins = {},
	}
	local dropin_files = gist.list_dropins()
	for _, dropin in ipairs(dropin_files) do
		local entry = by_tag[dropin.tag]
		dropin.status = entry and entry.status or "pending"
		dropin.nodes = entry and entry.nodes or 0
		dropin.retained = entry and entry.retained or 0
		dropin.error = entry and entry.error or nil
		dropin.pending = (entry == nil)
		e.gist.dropins[#e.gist.dropins+1] = dropin
		if dropin.tag == g_tag then
			e.gist.dropin = true
		end
	end
	if by_tag[g_tag] then
		e.gist.nodes = by_tag[g_tag].nodes or 0
		e.gist.status = by_tag[g_tag].status
	else
		e.gist.nodes = 0
	end

	-- Probe the local proxy port with a short TCP connect.
	e.listening = false
	if e.enabled then
		local host, port = listen:match("^(%[?[%w%.%-:]+%]?):([0-9]+)$")
		if host and port then
			if host:match(":") then
				host = host:gsub("^%[", ""):gsub("%]$", "")
			end
			local nixio = require "nixio"
			for _, family in ipairs(host:match(":") and { "inet6", "inet" } or { "inet" }) do
				local ok, sock = pcall(nixio.socket, family, "stream")
				if ok and sock then
					sock:settimeout(1000)
					local connected = sock:connect(host, port)
					sock:close()
					if connected then
						e.listening = true
						break
					end
				end
			end
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

-- ── ECH tunnel: gist node download ──────────────────────────────────────
-- The fetch/validate/write logic lives in luci.model.daed_gist because
-- /usr/libexec/daed-gist-sync (the scheduled sync) shares it verbatim.

function action_ech_download()
	http.prepare_content("application/json")

	local result = gist.sync({
		gist_id = http.formvalue("gist_id") or "",
		token = http.formvalue("token") or "",
		gist_file = http.formvalue("gist_file") or "",
		sub_tag = http.formvalue("sub_tag") or "",
	})
	if not result.ok then
		http.write_json({ ok = false, error = result.error })
		return
	end
	http.write_json({
		ok = true,
		count = result.count,
		names = result.names,
		kind = result.kind,
		changed = result.changed,
		file = result.file,
		note = result.note,
	})
end

-- ── Config file editor ──────────────────────────────────────────────────

local function editable_files()
	local files, seen = {}, {}
	local function add(path, name, desc)
		if path and not seen[path] then
			seen[path] = true
			table.insert(files, { path = path, name = name, desc = desc or "" })
		end
	end
	add(CONFIG_ENTRY, "ech_tunnel.dae", "generated")
	local list = {}
	for name in (sys.exec("ls -1 " .. CONFIG_DIR .. " 2>/dev/null") or ""):gmatch("[^\r\n]+") do
		if name:match("%.dae$") then
			table.insert(list, name)
		end
	end
	table.sort(list)
	for _, name in ipairs(list) do
		add(CONFIG_DIR .. "/" .. name, name)
	end
	return files
end

local function safe_path(name)
	for _, f in ipairs(editable_files()) do
		if f.name == name then
			return f.path
		end
	end
	return nil
end

function action_editor()
	local name = http.formvalue("file") or "ech_tunnel.dae"
	local path = safe_path(name)
	if not path then
		name, path = "ech_tunnel.dae", CONFIG_ENTRY
	end
	local content = ""
	if path and fs.access(path) then
		content = fs.readfile(path) or ""
	end

	local files = editable_files()
	local html = {}
	html[#html+1] = '<%+header%>'
	html[#html+1] = '<div class="cbi-map">'
	html[#html+1] = '<h2 name="content"><%:Config Files%></h2>'
	html[#html+1] = '<p><%:Edit the dae runfiles under /etc/daed/ (e.g. ECH tunnel fragments). The daemon restarts on save. In the dashboard build, wing.db is authoritative for nodes/subscriptions/routing; these files are the ECH/gist bridge.%></p>'
	html[#html+1] = '<ul style="margin:0 0 10px 20px">'
	for _, f in ipairs(files) do
		local link = luci.dispatcher.build_url("admin/services/daed/editor") .. "?file=" .. f.name
		local css = (f.name == name) and ' style="font-weight:bold"' or ""
		html[#html+1] = string.format('<li%s><a href="%s">%s%s</a></li>', css, link, f.name,
			f.desc ~= "" and (' <em>(' .. f.desc .. ')</em>') or "")
	end
	html[#html+1] = '</ul>'
	html[#html+1] = '<textarea id="cfg" style="width:100%;height:60vh;min-height:380px;font-family:monospace" spellcheck="false" class="cbi-input-textarea" data-update="change" rows="5" wrap="off">'
	html[#html+1] = luci.util.pcdata(content)
	html[#html+1] = '</textarea><br />'
	html[#html+1] = '<input type="button" class="cbi-button cbi-button-apply" style="margin-top:10px" value="<%:Save & Apply%>" onclick="save_cfg(this)" />'
	html[#html+1] = '<span id="save_result" style="margin-left:10px"></span>'
	html[#html+1] = [[<script type="text/javascript">
function save_cfg(btn) {
	var ta = document.getElementById('cfg');
	var name = ']] .. name .. [[';
	var result = document.getElementById('save_result');
	result.textContent = '...';
	var fd = new FormData();
	fd.append('file', name);
	fd.append('content', ta.value);
	fetch(']] .. luci.dispatcher.build_url("admin/services/daed/editor_save") .. [[', {
		method: 'POST',
		body: fd,
		headers: {'X-Requested-With': 'XMLHttpRequest'}
	}).then(function(r) {
		if (!r.ok) { throw new Error('HTTP ' + r.status); }
		return r.text();
	}).then(function(t) {
		result.textContent = t;
	}).catch(function(e) {
		result.textContent = '<%:Save failed%>: ' + e + ' — <%:check the network and retry%>';
	});
}
</script>]]
	html[#html+1] = '</div>'
	html[#html+1] = '<%+footer%>'

	local tpl = require "luci.template"
	tpl.render_string(table.concat(html, "\n"))
end

function action_editor_save()
	local name = http.formvalue("file") or ""
	local content = http.formvalue("content") or ""
	local path = safe_path(name)
	http.prepare_content("text/plain")

	if not path then
		http.write("ERROR: file not allowed")
		return
	end
	if content:find("\r\n") then
		content = content:gsub("\r\n", "\n")
	end
	fs.writefile(path, content)
	sys.call("chmod 600 " .. path)

	-- Validate with the real parser before applying (standalone dae only;
	-- the dashboard build has no /usr/bin/dae, its config lives in wing.db).
	if fs.access("/usr/bin/dae") then
		local ok = sys.call("dae validate -c %q >/dev/null 2>&1" % path)
		if ok ~= 0 then
			http.write("SAVED, but 'dae validate' reported problems — check the log")
			return
		end
		sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
		http.write("OK: saved, restarting daemon")
	else
		sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
		http.write("SAVED (no validator on this build): daemon restarting, check Logs for errors")
	end
end
