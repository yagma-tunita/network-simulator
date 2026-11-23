#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.." || exit 1

THRESHOLD="${COVERAGE_MIN:-54}"

make clean >/dev/null 2>&1
JOBS="${JOBS:-4}"
if ! make COVERAGE=1 -j"$JOBS" >/tmp/yn_cov_build.log 2>&1; then
    echo "coverage: build failed"
    tail -20 /tmp/yn_cov_build.log
    exit 1
fi

run() {
    [ -e "$1" ] || return 0
    timeout 30 ./netsim "$1" >/dev/null 2>&1 || true
}

for t in tests/*.txt tests/*.lua tests/config.yn; do
    run "$t"
done
printf 'demo\nstate\nquit\n' | timeout 30 ./netsim >/dev/null 2>&1 || true
bash tests/cli_test.sh >/dev/null 2>&1 || true
./netsim --json tests/auto_ping.txt >/dev/null 2>&1 || true
./netsim --log /tmp/yn_cov_log.jsonl tests/auto_ping.txt >/dev/null 2>&1 || true

mkdir -p build
if g++ -std=c++17 -O0 -g --coverage -I. \
        tests/unit/unit_tests.cpp \
        build/obj/core/*.o build/obj/device/*.o build/obj/link/*.o \
        build/obj/engine/*.o build/obj/topo/*.o build/obj/netstack/*.o \
        -o build/cov_unit --coverage -lm >/tmp/yn_cov_unit.log 2>&1; then
    ./build/cov_unit >/dev/null 2>&1 || true
else
    echo "coverage: unit binary build failed"
    tail -15 /tmp/yn_cov_unit.log
    make clean >/dev/null 2>&1
    exit 1
fi

rm -f ./*.gcov
gcov build/obj/core/*.gcno build/obj/device/*.gcno build/obj/link/*.gcno build/obj/engine/*.gcno build/obj/topo/*.gcno build/obj/netstack/*.gcno >/tmp/yn_gcov.txt 2>&1 || true

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
make clean >/dev/null 2>&1
exit "$rc"
