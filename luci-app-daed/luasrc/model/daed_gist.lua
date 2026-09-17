-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
--
-- Shared gist -> node drop-in logic for luci-app-daed.
--
-- The daed (dae-wing) build imports every /etc/daed/nodes.d/<tag>.json|.txt
-- at daemon startup: each file becomes a subscription (tag = file name) and a
-- group of the same name, so its nodes show up in the dashboard and can be
-- used by routing rules.
--
-- Both consumers share this module:
--   * luci.controller.daed         (the "Download & Update Nodes" button and
--                                   the ECH status RPC)
--   * /usr/libexec/daed-gist-sync  (cron-driven sync while Gist sync is on)

local sys   = require "luci.sys"
local fs    = require "nixio.fs"
local jsonc = require "luci.jsonc"
local i18n  = require "luci.i18n"

local M = {}

M.NODES_DIR = "/etc/daed/nodes.d"
-- Per-startup import report written by the daemon (dae-wing patch). It tells
-- the UI what actually happened to each drop-in: imported / skipped (tag
-- owned by another subscription) / failed, plus the retained stale-node count.
M.SYNC_REPORT = "/tmp/daed-nodes-sync.json"

local function shell_quote(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
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

-- download fetches url into dest, optionally with a bearer token. It tries
-- wget first and falls back to uclient-fetch; both ship with OpenWrt.
-- Returns true when a non-empty file was written.
function M.download(url, dest, token)
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

-- fetch_gist downloads the requested file payload from a GitHub gist.
-- The GitHub API is used so that private gists (token) work; when the file
-- content is omitted (large file), its raw_url is fetched instead.
-- Returns content, filename or nil, error.
function M.fetch_gist(gist_id, token, wanted, tmpdir)
	local api_file = tmpdir .. "/gist.json"
	if not M.download("https://api.github.com/gists/" .. gist_id, api_file, token) then
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
		if not M.download(entry.raw_url, raw_file, token) then
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

-- analyze classifies a payload the same way the daemon does (cfMac nodes.json
-- first, then SIP008, then base64 / plain link lists) so the UI never accepts
-- something the importer would reject, and reports what it found.
-- Returns a table: { kind, count, names }
--   kind: "cfmac" | "sip008" | "links" | "base64" | "html" | "unknown"
function M.analyze(content)
	local result = { kind = "unknown", count = 0, names = {} }
	if type(content) ~= "string" or content:match("^%s*$") then
		return result
	end

	local parsed = jsonc.parse(content)
	if type(parsed) == "table" then
		if type(parsed.nodes) == "table" then
			result.kind = "cfmac"
			result.count = #parsed.nodes
			for i, node in ipairs(parsed.nodes) do
				if i > 5 then
					break
				end
				if type(node) == "table" and type(node.name) == "string" then
					result.names[#result.names+1] = node.name
				end
			end
			return result
		end
		if type(parsed.servers) == "table" then
			result.kind = "sip008"
			result.count = #parsed.servers
			for i, server in ipairs(parsed.servers) do
				if i > 5 then
					break
				end
				if type(server) == "table" and type(server.remarks) == "string" then
					result.names[#result.names+1] = server.remarks
				end
			end
			return result
		end
		-- Valid JSON but not a node library (e.g. a GitHub API error body).
		return result
	end

	-- Not JSON: a plain link list, or a base64-encoded subscription.
	if content:match("<%s*[Hh][Tt][Mm][Ll]") or content:match("^%s*<") then
		result.kind = "html"
		return result
	end
	for rawline in content:gmatch("[^\r\n]+") do
		local line = rawline:gsub("^%s+", ""):gsub("%s+$", "")
		if line:find("://", 1, true) then
			result.count = result.count + 1
			if #result.names < 5 then
				result.names[#result.names+1] = line
			end
		end
	end
	if result.count > 0 then
		result.kind = "links"
		return result
	end
	local stripped = content:gsub("%s", "")
	if #stripped >= 16 and stripped:match("^[%w%+/%=-]+$") then
		result.kind = "base64"
	end
	return result
end

-- write_dropin writes the payload atomically (tmp file + rename) so a daemon
-- started concurrently never reads a half-written file.
-- Returns path or nil, error.
function M.write_dropin(tag, content)
	if not tag or not tag:match("^[%w_%-%.]+$") then
		return nil, i18n.translate("Invalid subscription tag")
	end
	sys.call("mkdir -p " .. shell_quote(M.NODES_DIR))
	local dest = M.NODES_DIR .. "/" .. tag .. ".json"
	local tmp = dest .. ".tmp"
	local f = io.open(tmp, "w")
	if not f then
		return nil, i18n.translatef("Cannot write %s", dest)
	end
	f:write(content)
	f:close()
	sys.call("chmod 600 " .. shell_quote(tmp))
	sys.call("mv -f " .. shell_quote(tmp) .. " " .. shell_quote(dest))
	return dest
end

-- list_dropins reports the drop-in files present, using stat only (cheap
-- enough for the 5s status poll).
function M.list_dropins()
	local dropins = {}
	if not fs.access(M.NODES_DIR) then
		return dropins
	end
	local listing = sys.exec("ls -1 " .. shell_quote(M.NODES_DIR) .. " 2>/dev/null") or ""
	for name in listing:gmatch("[^\r\n]+") do
		if name:match("%.json$") or name:match("%.txt$") then
			local path = M.NODES_DIR .. "/" .. name
			local stat = fs.stat(path)
			local tag = name:gsub("%.json$", ""):gsub("%.txt$", "")
			dropins[#dropins+1] = {
				tag = tag,
				file = path,
				size = stat and stat.size or 0,
				mtime = stat and stat.mtime or 0,
			}
		end
	end
	table.sort(dropins, function(a, b) return a.tag < b.tag end)
	return dropins
end

-- read_sync_report returns the daemon's import report (or nil when the
-- daemon has not scanned the drop-ins since the last boot).
function M.read_sync_report()
	local body = read_file(M.SYNC_REPORT)
	local parsed = body and jsonc.parse(body)
	if type(parsed) == "table" and type(parsed.entries) == "table" then
		return parsed
	end
	return nil
end

-- sync fetches the configured gist and, when the payload changed, writes the
-- drop-in and restarts daed so the daemon imports it.
-- opts: { gist_id, token, gist_file, sub_tag, restart = true }
-- Returns a table: { ok = true, count, names, kind, file, changed, note }
--              or: { ok = false, error }
function M.sync(opts)
	local gist_id = (opts.gist_id or ""):gsub("%s", "")
	local token = (opts.token or ""):gsub("^%s+", ""):gsub("%s+$", "")
	local wanted = (opts.gist_file or ""):gsub("%s", "")
	local tag = (opts.sub_tag or ""):gsub("%s", "")
	local function fail(msg)
		return { ok = false, error = msg }
	end

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

	-- A random suffix keeps concurrent runs (cron + the button) apart.
	local tmpdir = string.format("/tmp/daed-gist-%d-%d", os.time(), math.random(100000, 999999))
	sys.call("rm -rf " .. shell_quote(tmpdir) .. " && mkdir -p " .. shell_quote(tmpdir))
	local content, filename = M.fetch_gist(gist_id, token, wanted, tmpdir)
	sys.call("rm -rf " .. shell_quote(tmpdir))
	if not content then
		return fail(filename)
	end

	local info = M.analyze(content)
	if info.kind == "html" then
		return fail(i18n.translate("The gist file is an HTML page, not a node library (check the Gist ID and token)"))
	end
	if info.kind == "unknown" then
		return fail(i18n.translatef("Gist file %s is not a node library the daemon can import (cfMac nodes.json, SIP008, base64 or link list)", filename or wanted))
	end

	local dest = M.NODES_DIR .. "/" .. tag .. ".json"
	local changed = (read_file(dest) ~= content)
	local path, werr = M.write_dropin(tag, content)
	if not path then
		return fail(werr)
	end
	sys.call("logger -t luci-app-daed " .. shell_quote(string.format(
		"gist sync: %s (%s, %d nodes) from %s -> %s",
		changed and "updated" or "unchanged", info.kind, info.count, filename or wanted, path)))

	local note
	if opts.restart == false then
		note = i18n.translate("daed restarts on the next scheduled update; the nodes appear then")
	elseif sys.call("pidof daed >/dev/null") == 0 then
		if changed then
			sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
			note = i18n.translate("daed is restarting; the nodes will appear in the dashboard shortly")
		else
			note = i18n.translate("Nodes are already up to date; daed was not restarted")
		end
	else
		note = i18n.translate("daed is not running; the nodes will be imported on next start")
	end

	return {
		ok = true,
		count = info.count,
		names = info.names,
		kind = info.kind,
		file = path,
		changed = changed,
		note = note,
	}
end

return M
