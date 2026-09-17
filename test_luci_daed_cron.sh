#!/bin/sh
# Tests for update_cron() in /etc/init.d/luci_daed: which cron lines are
# written, that stale ones are cleaned up, and that malformed UCI values cannot
# reach the crontab. Runs the real function from the init script against stub
# `uci`/`crontab` binaries -- no OpenWrt required.

set -u

INIT="luci-app-daed/root/etc/init.d/luci_daed"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
failures=0

check() {
	if [ "$1" = "0" ]; then
		printf '  PASS: %s\n' "$2"
	else
		printf '  FAIL: %s\n' "$2"
		failures=$((failures + 1))
	fi
}

mkdir -p "$TMP/bin"

# Stub uci: reads "<section>.<option>=<value>" lines from $UCI_FILE.
cat > "$TMP/bin/uci" <<'EOF'
#!/bin/sh
# only "uci -q get a.b.c" is used
opt="${3##*.}"
sect="${3%.*}"
sect="${sect##*.}"
sed -n "s/^${sect}\.${opt}=//p" "$UCI_FILE"
EOF

# Stub crontab: `crontab <file>` copies the file aside for inspection.
cat > "$TMP/bin/crontab" <<'EOF'
#!/bin/sh
case "$1" in
	-*) exit 0 ;;   # -l / -u ... : not used by the script
	*) cp "$1" "$CRON_OUT" ;;
esac
EOF

chmod +x "$TMP/bin/uci" "$TMP/bin/crontab"
PATH="$TMP/bin:$PATH"
export PATH
export UCI_FILE="$TMP/uci.txt"
export CRON_OUT="$TMP/crontab.txt"
: > "$CRON_OUT"

# shellcheck disable=SC1090
. "./$INIT"

reset_uci() {
	cat > "$UCI_FILE" <<EOF
$1
EOF
	: > "$CRON_OUT"
}

printf '== subscription auto update only ==\n'
reset_uci "config.subscribe_auto_update=1
config.subscribe_update_day_time=4
config.subscribe_update_week_time=*"
update_cron add
grep -q '/etc/init.d/daed restart' "$CRON_OUT" && check 0 "restart cron written" || check 1 "restart cron written"
grep -q 'daed-gist-sync' "$CRON_OUT" && check 1 "no gist sync line when gist is off" || check 0 "no gist sync line when gist is off"

printf '== gist sync only ==\n'
reset_uci "config.subscribe_auto_update=0
config.subscribe_update_day_time=5
config.subscribe_update_week_time=1,3,5
gist.enabled=1
gist.gist_id=abc123"
update_cron add
grep -q '^[0-9]* 5 \* \* 1,3,5 /usr/libexec/daed-gist-sync' "$CRON_OUT" \
	&& check 0 "gist sync cron uses the configured schedule" \
	|| check 1 "gist sync cron uses the configured schedule"
grep -q '/etc/init.d/daed restart' "$CRON_OUT" && check 1 "no restart line when auto update is off" || check 0 "no restart line when auto update is off"

printf '== both enabled ==\n'
reset_uci "config.subscribe_auto_update=1
config.subscribe_update_day_time=6
config.subscribe_update_week_time=*
gist.enabled=1
gist.gist_id=abc123"
update_cron add
check "$(grep -c . "$CRON_OUT" | grep -q '^2$' && echo 0 || echo 1)" "exactly two cron lines"

printf '== enabled but without a gist id ==\n'
reset_uci "config.subscribe_auto_update=0
gist.enabled=1
gist.gist_id="
update_cron add
grep -q 'daed-gist-sync' "$CRON_OUT" && check 1 "no sync line without a gist id" || check 0 "no sync line without a gist id"

printf '== stale lines are cleaned up ==\n'
# Run a copy of the init script whose crontab path points into the sandbox,
# so the seeding actually takes effect (and the repo file stays untouched).
sed "s#/etc/crontabs/root#$TMP/etc/crontabs/root#" "./$INIT" > "$TMP/luci_daed"
mkdir -p "$TMP/etc/crontabs"
cat > "$TMP/etc/crontabs/root" <<'EOF'
0 1 * * * /etc/init.d/daed restart >/dev/null 2>&1
5 1 * * * /usr/libexec/daed-gist-sync >/dev/null 2>&1
30 2 * * * /usr/bin/keepme
EOF
reset_uci "config.subscribe_auto_update=0
gist.enabled=0"
# shellcheck disable=SC1090
. "$TMP/luci_daed"
update_cron add
grep -q 'daed restart' "$CRON_OUT" && check 1 "stale restart line removed" || check 0 "stale restart line removed"
grep -q 'daed-gist-sync' "$CRON_OUT" && check 1 "stale sync line removed" || check 0 "stale sync line removed"
grep -q '/usr/bin/keepme' "$CRON_OUT" && check 0 "unrelated cron lines preserved" || check 1 "unrelated cron lines preserved"

printf '== malformed values cannot inject ==\n'
reset_uci "config.subscribe_auto_update=1
config.subscribe_update_day_time=7; reboot
config.subscribe_update_week_time=0 0 * * * reboot
gist.enabled=1
gist.gist_id=abc123"
update_cron add
if grep -qE 'reboot' "$CRON_OUT"; then
	check 1 "injected payload did not reach the crontab"
else
	check 0 "injected payload did not reach the crontab"
fi
# The minute field is intentionally random, so match it loosely.
grep -qE '^[0-9]+ \* \* \* \* /usr/libexec/daed-gist-sync' "$CRON_OUT" \
	&& check 0 "malformed schedule falls back to *" \
	|| check 1 "malformed schedule falls back to *"

printf '\n'
if [ "$failures" = "0" ]; then
	printf 'ALL CRON CHECKS PASSED\n'
	exit 0
fi
printf '%s CHECKS FAILED\n' "$failures"
exit 1
