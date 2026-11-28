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
    out="$($RUN ./netsim -q "$t" 2>&1)" || true
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
    bash tests/examples.sh || status=1
fi

rm -f tests/netsim_test.pcap tests/netsim_tcp_test.pcap tests/netsim_saved.yn tests/netsim_ipv6_saved.yn tests/netsim_acl_saved.yn tests/netsim_acl6_saved.yn tests/netsim_nat_saved.yn tests/netsim_span_saved.yn tests/netsim_bgp_saved.yn tests/netsim_bgp_filter_saved.yn tests/netsim_bgp_asf_saved.yn tests/netsim_bgp_prepend_saved.yn tests/netsim_bgp_comm_saved.yn tests/netsim_bgp_max_saved.yn
exit "$status"
