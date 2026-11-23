#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.." || exit 1

make >/dev/null 2>&1 || { echo "perf: build failed"; exit 1; }

printf 'bench 500000\n' > /tmp/yn_perf.txt
out=$(./netsim /tmp/yn_perf.txt 2>&1 || true)
rate=$(printf '%s' "$out" | awk '/events\/s/{for(i=1;i<=NF;i++) if($i=="events/s") print $(i-1)}')
if [ -z "$rate" ]; then
    echo "perf: no rate reported"
    printf '%s\n' "$out" | tail -5
    exit 1
fi

awk -v r="$rate" -v min="200000" 'BEGIN {
    if (r+0 < min+0) { printf "perf: FAIL %.0f < %.0f events/s\n", r, min; exit 1 }
    printf "perf: ok %.0f events/s (floor %.0f)\n", r, min
}'
