#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.." || exit 1

THRESHOLD="${COVERAGE_MIN:-54}"
COV="${COV_BUILD:-build/cov}"
EXE="$COV/netsim"

rm -rf "$COV"
JOBS="${JOBS:-4}"
if ! make BUILD="$COV" TARGET="$EXE" COVERAGE=1 -j"$JOBS" >/tmp/yn_cov_build.log 2>&1; then
    echo "coverage: build failed"
    tail -20 /tmp/yn_cov_build.log
    exit 1
fi

run() {
    [ -e "$1" ] || return 0
    timeout 30 "$EXE" "$1" >/dev/null 2>&1 || true
}

for t in tests/*.txt tests/*.lua tests/config.yn; do
    run "$t"
done
printf 'demo\nstate\nquit\n' | timeout 30 "$EXE" >/dev/null 2>&1 || true
bash tests/cli_test.sh >/dev/null 2>&1 || true
"$EXE" --json tests/auto_ping.txt >/dev/null 2>&1 || true
"$EXE" --log /tmp/yn_cov_log.jsonl tests/auto_ping.txt >/dev/null 2>&1 || true

mkdir -p "$COV"
if g++ -std=c++17 -O0 -g --coverage -I. \
        tests/unit/unit_tests.cpp \
        "$COV"/obj/core/*.o "$COV"/obj/device/*.o "$COV"/obj/device/end/*.o "$COV"/obj/device/router/*.o "$COV"/obj/link/*.o \
        "$COV"/obj/engine/*.o "$COV"/obj/topo/*.o "$COV"/obj/netstack/*.o \
        -o "$COV"/cov_unit --coverage -lm >/tmp/yn_cov_unit.log 2>&1; then
    ./"$COV"/cov_unit >/dev/null 2>&1 || true
else
    echo "coverage: unit binary build failed"
    tail -15 /tmp/yn_cov_unit.log
    make clean >/dev/null 2>&1
    exit 1
fi

rm -f ./*.gcov
( cd "$COV" && gcov obj/core/*.gcno obj/device/*.gcno obj/device/end/*.gcno obj/device/router/*.gcno obj/link/*.gcno obj/engine/*.gcno obj/topo/*.gcno obj/netstack/*.gcno ) >/tmp/yn_gcov.txt 2>&1 || true

awk -v THRESH="$THRESHOLD" '
  /Lines executed:/ {
    p=$2; sub(/.*:/,"",p); sub(/%/,"",p); t=$4+0;
    executed += (p+0)*t/100.0; total += t;
  }
  END {
    if(total == 0) { print "coverage: no data"; exit 1; }
    pct = executed*100.0/total;
    printf "coverage: %.1f%% (%d/%d lines), threshold %s%%\n", pct, int(executed+0.5), total, THRESH;
    if(pct+0 < THRESH+0) exit 1;
  }
' /tmp/yn_gcov.txt

rc=$?
rm -f tests/netsim_test.pcap tests/netsim_tcp_test.pcap tests/netsim_saved.yn tests/netsim_ipv6_saved.yn tests/netsim_acl_saved.yn tests/netsim_acl6_saved.yn tests/netsim_nat_saved.yn tests/netsim_span_saved.yn tests/netsim_bgp_saved.yn
exit "$rc"
