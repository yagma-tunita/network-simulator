#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

make >/dev/null

RUN=""
if command -v timeout >/dev/null 2>&1; then
    RUN="timeout 30"
fi

status=0

check() {
    local t="$1"
    local name="${t%.*}"
    local want out
    want="$(cat "${name}.want")"
    out="$($RUN ./netsim "$t" 2>&1)" || true
    if printf '%s' "$out" | grep -qF "$want" && ! printf '%s' "$out" | grep -qF 'fatal:'; then
        echo "PASS  ${t}"
    else
        echo "FAIL  ${t}  (want: ${want})"
        printf '%s\n' "$out" | sed 's/^/    /'
        status=1
    fi
}

for t in tests/*.txt; do
    check "$t"
done

if ./netsim --features 2>/dev/null | grep -q 'lua'; then
    for t in tests/*.lua; do
        [ -e "$t" ] || continue
        check "$t"
    done
fi

if [ -x ./netsim ]; then
    bash tests/cli_test.sh || status=1
fi

make clean >/dev/null
exit "$status"
