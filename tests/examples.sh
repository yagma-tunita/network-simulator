#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

if [ ! -x ./netsim ]; then
    echo "examples: netsim not built"
    exit 1
fi

RUN=""
if command -v timeout >/dev/null 2>&1; then
    RUN="timeout 30"
fi

status=0
for f in examples/*.txt examples/*.lua examples/*.yn; do
    [ -e "$f" ] || continue
    if $RUN ./netsim -q "$f" >/dev/null 2>&1; then
        echo "PASS  example $f"
    else
        echo "FAIL  example $f"
        status=1
    fi
done

exit "$status"
