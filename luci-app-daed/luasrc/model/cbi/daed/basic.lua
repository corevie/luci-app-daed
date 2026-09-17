local m, s ,o

m = Map("daed")
m.title = translate("DAED")
m.description = translate("DAE is a Linux high-performance transparent proxy solution based on eBPF, And DAED is a modern dashboard for dae.")

m:section(SimpleSection).template = "daed/daed_status"

s = m:section(TypedSection, "daed", translate("Global Settings"))
s.addremove = false
s.anonymous = true

o = s:option(Flag,"enabled",translate("Enable"))
o.default = 0

o = s:option(Value, "log_maxbackups", translate("Logfile retention count"))
o.default = 1

o = s:option(Value, "log_maxsize", translate("Logfile Max Size (MB)"))
o.default = 5

o = s:option(Value, "listen_addr",translate("Set the DAED listen address"))
o.default = '0.0.0.0:2023'

o = s:option(Value, "dashboard_port", translate("Dashboard Access Port"))
o.placeholder = translate("Leave empty to use listen port")
o.datatype = "range(1,65535)"
o.description = translate("Only for external port mapping / reverse proxy scenarios: the daemon itself does NOT listen on this port. Leave empty to use the port from listen address.")

o = s:option(Flag, "subscribe_auto_update", translate("Enable Subscription Auto Update"))
o.default = 0
o.rmempty = false
o.description = translate("Periodically restart daed so subscriptions (e.g. the ECH nodes gist) are re-fetched.")

o = s:option(Value, "subscribe_update_day_time", translate("Update Time (Every Day)"))
o.default = 4
o.datatype = "range(0,23)"
o.rmempty = false

o = s:option(Value, "subscribe_update_week_time", translate("Update Cycle (Weekday)"))
o.default = "*"
o.rmempty = false
function o.validate(self, value, section)
	if value == nil or value == "" then
		return "*"
	end
	-- Cron weekday field: digits 0-7, lists, ranges and steps only.
	if not value:match("^[0-7%*,%-/]+$") then
		return nil, translate("Invalid weekday, expected 0-7 with optional , - * / (e.g. * or 1,3,5)")
	end
	return value
end

m.apply_on_parse = true
m.on_after_apply = function(self,map)
	luci.sys.exec("/etc/init.d/luci_daed restart >/dev/null 2>&1")
	luci.sys.exec("/etc/init.d/daed restart")
end

return m
