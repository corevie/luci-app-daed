local sys  = require "luci.sys"
local http = require "luci.http"
local fs   = require "nixio.fs"
local jsonc = require "luci.jsonc"
local i18n = require "luci.i18n"

module("luci.controller.daed", package.seeall)

-- Editable config files (whitelist).
local CONFIG_DIR = "/etc/daed"
local CONFIG_ENTRY = "/etc/daed/ech_tunnel.dae"

-- Drop-in directory scanned by daed at startup: every <tag>.json /
-- <tag>.txt file becomes a subscription named after its file name, and a
-- group with the same name is bound to it.
local NODES_DROPIN_DIR = "/etc/daed/nodes.d"

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
	local config_file = uci:get("daed", "ech", "config_file") or "/etc/daed/ech_tunnel.dae"

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

-- ── ECH tunnel: gist node download ──────────────────────────────────────
-- Downloads nodes.json from the configured GitHub gist, converts nothing
-- locally: the raw payload is written to the daed drop-in directory where
-- the daemon's subscription importer resolves it (cfMac nodes.json -> one
-- echws:// node per entry, named after the "name" field).

local function shell_quote(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

-- http_download fetches url into dest, optionally with a bearer token.
-- It tries wget first and falls back to uclient-fetch; both ship with
-- OpenWrt. Returns true when a non-empty file was written.
local function http_download(url, dest, token)
	local attempts = {}
	local headers = {}
	if token and token ~= "" then
		headers[#headers+1] = "Authorization: Bearer " .. token
	end
	for _, tool in ipairs({ "wget", "uclient-fetch" }) do
		local cmd = tool .. " -q -T 20"
		for _, h in ipairs(headers) do
			cmd = cmd .. " --header=" .. shell_quote(h)
		end
		cmd = cmd .. " -O " .. shell_quote(dest) .. " " .. shell_quote(url)
		attempts[#attempts+1] = cmd
	end
	for _, cmd in ipairs(attempts) do
		if sys.call(cmd) == 0 then
			local f = io.open(dest, "r")
			if f then
				local size = f:seek("end")
				f:close()
				if size and size > 0 then
					return true
				end
			end
		end
	end
	return false
end

local function read_file(path)
	local f = io.open(path, "r")
	if not f then
		return nil
	end
	local body = f:read("*a")
	f:close()
	return body
end

-- gist_fetch downloads the requested file payload from a GitHub gist.
-- The GitHub API is used so that private gists (token) work; when the file
-- content is omitted (large file), its raw_url is fetched instead.
-- Returns content, filename or nil, error.
local function gist_fetch(gist_id, token, wanted, tmpdir)
	local api_file = tmpdir .. "/gist.json"
	if not http_download("https://api.github.com/gists/" .. gist_id, api_file, token) then
		return nil, i18n.translate("Cannot reach the GitHub API (check the network, Gist ID and token)")
	end
	local body = read_file(api_file)
	local obj = body and jsonc.parse(body)
	if type(obj) ~= "table" or type(obj.files) ~= "table" then
		return nil, i18n.translate("Unexpected GitHub API response (check the Gist ID and token)")
	end

	local filename, entry
	if wanted ~= "" and obj.files[wanted] then
		filename, entry = wanted, obj.files[wanted]
	else
		-- Fall back to nodes.json, then any *.json file.
		for name, candidate in pairs(obj.files) do
			if name == "nodes.json" then
				filename, entry = name, candidate
				break
			elseif name:match("%.json$") and not entry then
				filename, entry = name, candidate
			end
		end
	end
	if not entry then
		return nil, i18n.translatef("Gist has no such file: %s", wanted ~= "" and wanted or "*.json")
	end

	if type(entry.content) == "string" and entry.content ~= "" then
		return entry.content, filename
	end
	if type(entry.raw_url) == "string" and entry.raw_url ~= "" then
		local raw_file = tmpdir .. "/raw.json"
		if not http_download(entry.raw_url, raw_file, token) then
			return nil, i18n.translate("Failed to download the gist raw file")
		end
		local content = read_file(raw_file)
		if not content or content == "" then
			return nil, i18n.translate("The gist raw file is empty")
		end
		return content, filename
	end
	return nil, i18n.translate("The gist file has neither content nor a raw_url")
end

function action_ech_download()
	http.prepare_content("application/json")

	local function fail(msg)
		http.write_json({ ok = false, error = msg })
	end

	local gist_id = (http.formvalue("gist_id") or ""):gsub("%s", "")
	local token = (http.formvalue("token") or ""):gsub("^%s+", ""):gsub("%s+$", "")
	local wanted = (http.formvalue("gist_file") or ""):gsub("%s", "")
	local tag = (http.formvalue("sub_tag") or ""):gsub("%s", "")
	if wanted == "" then
		wanted = "nodes.json"
	end
	if tag == "" then
		tag = "ech_nodes"
	end
	if not gist_id:match("^[%w%-]+$") then
		return fail(i18n.translate("Invalid Gist ID"))
	end
	if not tag:match("^[%w_%-%.]+$") then
		return fail(i18n.translate("Invalid subscription tag"))
	end

	local tmpdir = "/tmp/daed-ech-" .. tostring(os.time())
	sys.call("rm -rf " .. shell_quote(tmpdir) .. " && mkdir -p " .. shell_quote(tmpdir))

	local content, filename = gist_fetch(gist_id, token, wanted, tmpdir)
	sys.call("rm -rf " .. shell_quote(tmpdir))
	if not content then
		return fail(filename)
	end

	-- Collect the node names for feedback and make sure it looks like a
	-- cfMac node library before it replaces the drop-in.
	local parsed = jsonc.parse(content)
	local names, count = {}, 0
	if type(parsed) == "table" and type(parsed.nodes) == "table" then
		count = #parsed.nodes
		for i, node in ipairs(parsed.nodes) do
			if i > 5 then
				break
			end
			if type(node) == "table" and type(node.name) == "string" then
				names[#names+1] = node.name
			end
		end
	end
	if count == 0 then
		return fail(i18n.translatef("Gist file %s contains no nodes", filename or wanted))
	end

	sys.call("mkdir -p " .. shell_quote(NODES_DROPIN_DIR))
	local dest = NODES_DROPIN_DIR .. "/" .. tag .. ".json"
	local f = io.open(dest, "w")
	if not f then
		return fail(i18n.translatef("Cannot write %s", dest))
	end
	f:write(content)
	f:close()
	sys.call("chmod 600 " .. shell_quote(dest))
	sys.call("logger -t luci-app-daed " .. shell_quote(
		string.format("ECH gist download: %d nodes from %s -> %s", count, filename or wanted, dest)))

	local note = ""
	if sys.call("pidof daed >/dev/null") == 0 then
		sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
		note = i18n.translate("daed is restarting; the nodes will appear in the dashboard shortly")
	else
		note = i18n.translate("daed is not running; the nodes will be imported on next start")
	end

	http.write_json({
		ok = true,
		count = count,
		names = names,
		file = dest,
		note = note,
	})
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
	html[#html+1] = '<p><%:Edit the dae runfiles under /etc/daed/ (e.g. ECH tunnel fragments). The daemon restarts on save.%></p>'
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

	-- Validate with the real parser before applying (standalone dae only;
	-- the dashboard build has no /usr/bin/dae, its config lives in wing.db).
	if fs.access("/usr/bin/dae") then
		local ok = sys.call("dae validate -c %q >/dev/null 2>&1" % path)
		if ok ~= 0 then
			http.write("SAVED, but 'dae validate' reported problems — check the log")
			return
		end
	end
	sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
	http.write("OK: saved, restarting daemon")
end
