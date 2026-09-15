local sys  = require "luci.sys"
local http = require "luci.http"
local fs   = require "nixio.fs"

module("luci.controller.daed", package.seeall)

-- Editable config files (whitelist).
local CONFIG_DIR = "/etc/dae/config.d"
local CONFIG_ENTRY = "/etc/dae/config.dae"

function index()
	if not nixio.fs.access("/etc/config/daed") then
		return
	end

	entry({"admin",  "services", "daed"}, alias("admin", "services", "daed", "setting"),_("DAED"), 58).dependent = true
	entry({"admin", "services", "daed", "setting"}, cbi("daed/basic"), _("Base Setting"), 1).leaf=true
	entry({"admin", "services", "daed", "log"}, cbi("daed/log"), _("Logs"), 3).leaf = true
	entry({"admin", "services", "daed", "ech"}, cbi("daed/ech"), _("ECH Tunnel"), 4).leaf = true
	entry({"admin", "services", "daed", "editor"}, call("action_editor"), _("Config Files"), 5).leaf = true
	entry({"admin", "services", "daed", "editor_save"}, post("action_editor_save")).leaf = true
	entry({"admin", "services", "daed_status"}, call("act_status"))
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
	http.write(sys.exec("cat /var/log/dae/dae.log"))
end

function clear_log()
	sys.call("true > /var/log/dae/dae.log")
end

-- ECH tunnel (ech-workers) status: runfile presence, daemon state, and
-- whether the local proxy port is accepting connections.
function act_ech_status()
	local uci = require "luci.model.uci".cursor()
	local e = { }

	local enabled = uci:get("daed", "ech", "enabled") or "0"
	local listen = uci:get("daed", "ech", "listen") or "127.0.0.1:1080"
	local config_file = uci:get("daed", "ech", "config_file") or "/etc/dae/config.d/ech_tunnel.dae"

	e.enabled = (enabled == "1")
	e.listen = listen
	e.config_file = config_file
	e.generated = fs.access(config_file) ~= nil
	e.daed_running = sys.call("pidof daed >/dev/null") == 0

	-- Probe the local proxy port with a short TCP connect.
	e.listening = false
	if e.enabled then
		local host, port = listen:match("^(%[?[%w%.%-:]+%]?):([0-9]+)$")
		if host and port then
			if host:match(":") then
				host = host:gsub("^%[", ""):gsub("%]$", "")
			end
			local nixio = require "nixio"
			local sock = nixio.socket("inet", "stream")
			sock:settimeout(1000)
			if sock:connect(host, port) then
				e.listening = true
			end
			sock:close()
		end
	end

	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

-- ── Config file editor ──────────────────────────────────────────────────

local function editable_files()
	local files = {}
	table.insert(files, { path = CONFIG_ENTRY, name = "config.dae", desc = "main" })
	local list = {}
	for name in (sys.exec("ls -1 " .. CONFIG_DIR .. " 2>/dev/null") or ""):gmatch("[^\r\n]+") do
		if name:match("%.dae$") then
			table.insert(list, name)
		end
	end
	table.sort(list)
	for _, name in ipairs(list) do
		table.insert(files, { path = CONFIG_DIR .. "/" .. name, name = name, desc = "" })
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
	local name = http.formvalue("file") or "config.dae"
	local path = safe_path(name)
	if not path then
		name, path = "config.dae", CONFIG_ENTRY
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
	html[#html+1] = '<p><%:Edit the dae runfiles under /etc/dae/. Changes apply after "Save & Apply" (hot reload).%></p>'
	html[#html+1] = '<ul style="margin:0 0 10px 20px">'
	for _, f in ipairs(files) do
		local link = luci.dispatcher.build_url("admin/services/daed/editor") .. "?file=" .. f.name
		local css = (f.name == name) and ' style="font-weight:bold"' or ""
		html[#html+1] = string.format('<li%s><a href="%s">%s%s</a></li>', css, link, f.name,
			f.desc ~= "" and (' <em>(' .. f.desc .. ')</em>') or "")
	end
	html[#html+1] = '</ul>'
	html[#html+1] = '<textarea id="cfg" style="width:100%;height:520px;font-family:monospace" spellcheck="false" class="cbi-input-textarea" data-update="change" rows="5" wrap="off">'
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
	}).then(function(r) { return r.text() }).then(function(t) {
		result.textContent = t;
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

	-- Validate with the real parser before applying.
	local ok = sys.call("dae validate -c %q >/dev/null 2>&1" % path)
	if ok ~= 0 then
		http.write("SAVED, but 'dae validate' reported problems — check the log")
		return
	end
	sys.call("/etc/init.d/dae hot_reload >/dev/null 2>&1 &")
	http.write("OK: saved and reloaded")
end
