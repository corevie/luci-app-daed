-- Tests for /usr/libexec/daed-gist-sync: the cron-driven entry point that
-- makes "Enable Gist Sync" actually do something in the dashboard build.
-- It must read the same UCI options the LuCI page writes, do nothing while the
-- feature is off, and surface failures instead of failing silently.

local SCRIPT = "luci-app-daed/root/usr/libexec/daed-gist-sync"

local failures = 0
local function check(cond, msg)
	if cond then
		print("  PASS: " .. msg)
	else
		print("  FAIL: " .. msg)
		failures = failures + 1
	end
end

-- ── stubs ────────────────────────────────────────────────────────────────

local uci_store = {}
local sync_calls = {}
local sync_result = { ok = true, count = 3, names = { "a" }, kind = "cfmac", file = "/etc/daed/nodes.d/ech_nodes.json", changed = true }
local logged = {}
local exit_code = nil

package.preload["luci.model.uci"] = function()
	return {
		cursor = function()
			return {
				get = function(_, config, section, option)
					return (uci_store[section] or {})[option]
				end,
			}
		end,
	}
end

package.preload["luci.model.daed_gist"] = function()
	return {
		sync = function(opts)
			sync_calls[#sync_calls + 1] = opts
			return sync_result
		end,
	}
end

-- os.exit would tear the harness down; record the code and unwind instead.
local real_exit = os.exit
os.exit = function(code)
	exit_code = code or 0
	error({ exit = true }, 0)
end
local real_execute = os.execute
os.execute = function(cmd)
	logged[#logged + 1] = cmd
	return 0
end

-- ── load the script ──────────────────────────────────────────────────────

local chunk, load_err = loadfile(SCRIPT)
if not chunk then
	print("  FAIL: cannot load " .. SCRIPT .. ": " .. tostring(load_err))
	os.exit(1)
end

local function run_script()
	exit_code, sync_calls, logged = nil, {}, {}
	local ok, err = pcall(chunk)
	if not ok and (type(err) ~= "table" or not err.exit) then
		error(err)
	end
	-- The script calls os.exit, which unwinds; exit_code is then set.
	if exit_code == nil then
		exit_code = 0 -- fell off the end
	end
	return exit_code
end

local function logged_text()
	return table.concat(logged, "\n")
end

-- ── assertions ───────────────────────────────────────────────────────────

print("== disabled gist sync does nothing ==")
uci_store = { gist = { enabled = "0", gist_id = "abc123" } }
check(run_script() == 0, "exits 0 when disabled")
check(#sync_calls == 0, "no fetch attempted")

print("== enabled without a gist id does nothing ==")
uci_store = { gist = { enabled = "1", gist_id = "" } }
check(run_script() == 0, "exits 0 without a gist id")
check(#sync_calls == 0, "no fetch attempted")

print("== enabled passes the UCI values through ==")
uci_store = {
	gist = {
		enabled = "1",
		gist_id = "abc123def456",
		token = "tok123",
		gist_file = "nodes.json",
		sub_tag = "ech_nodes",
	},
}
check(run_script() == 0, "exits 0 on success")
check(#sync_calls == 1, "sync called once")
local opts = sync_calls[1] or {}
check(opts.gist_id == "abc123def456", "gist_id passed (got " .. tostring(opts.gist_id) .. ")")
check(opts.token == "tok123", "token passed")
check(opts.gist_file == "nodes.json", "gist_file passed")
check(opts.sub_tag == "ech_nodes", "sub_tag passed")

print("== failures are reported, not swallowed ==")
sync_result = { ok = false, error = "Cannot reach the GitHub API" }
check(run_script() == 1, "exits 1 when the sync fails")
check(logged_text():match("gist sync failed") ~= nil, "failure logged to syslog")
check(logged_text():match("GitHub API") ~= nil, "reason included in the log line")

print("== a missing module is reported too ==")
sync_result = { ok = true }
package.loaded["luci.model.daed_gist"] = nil
package.preload["luci.model.daed_gist"] = function()
	error("boom")
end
check(run_script() == 1, "exits 1 when the share module cannot be loaded")
check(logged_text():match("cannot load") ~= nil, "load failure logged")

os.exit = real_exit
os.execute = real_execute

print("")
if failures == 0 then
	print("ALL GIST SYNC SCRIPT CHECKS PASSED")
	os.exit(0)
else
	print(failures .. " CHECKS FAILED")
	os.exit(1)
end
