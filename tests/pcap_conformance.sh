#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

CAP=tests/netsim_tcp_test.pcap
rm -f "$CAP"
./netsim -q tests/tcp_pcap.txt >/dev/null
./build/ynpcap -q "$CAP"
rm -f "$CAP"
echo "pcap conformance: ok"
