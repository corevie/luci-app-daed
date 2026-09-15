local m, s ,o

m = Map("daed")
m.title = translate("DAED")
m.description = translate("dae is a Linux high-performance transparent proxy solution based on eBPF. This build ships the standalone dae binary (runfiles mode, /etc/dae).")

m:section(SimpleSection).template = "daed/daed_status"

s = m:section(NamedSection, "config", "daed", translate("Global Settings"))
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable"))
o.default = 0

o = s:option(Value, "config_file", translate("Config Entry File"))
o.default = "/etc/dae/config.dae"
o.rmempty = false
o.description = translate("Main dae config file (include-style). Fragments under /etc/dae/config.d/ are merged automatically; edit them on the Config Files page.")

o = s:option(Value, "log_maxbackups", translate("Logfile retention count"))
o.default = 1

o = s:option(Value, "log_maxsize", translate("Logfile Max Size (MB)"))
o.default = 5

o = s:option(Flag, "subscribe_auto_update", translate("Enable Subscription Auto Update"))
o.default = 0
o.description = translate("Periodically hot-reload dae so subscriptions (e.g. the ECH nodes gist) are re-fetched.")

o = s:option(Value, "subscribe_update_day_time", translate("Update Time (Every Day)"))
o.default = 4
o.datatype = "range(0,23)"
o.description = translate("Hour of day (0-23) for the auto update. Leave default for 4 AM.")

o = s:option(Value, "subscribe_update_week_time", translate("Update Cycle (Weekday)"))
o.default = "*"
o.description = translate("Cron weekday: * = every day, 1-5 = Mon-Fri, 0/7 = Sunday.")

m.apply_on_parse = true
m.on_after_apply = function(self,map)
	luci.sys.call("/etc/init.d/daed restart >/dev/null 2>&1 &")
end

return m
