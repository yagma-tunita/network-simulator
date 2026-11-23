#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.." || exit 1

make >/dev/null 2>&1 || { echo "soak: build failed"; exit 1; }

cat > /tmp/yn_soak.txt <<'EOF'
add-device PC1 end
add-device PC2 end
add-device SW1 switch
add-device SW2 switch
add-device SW3 switch
add-port PC1 aa:aa:aa:aa:aa:01 192.168.1.1/24
add-port PC2 aa:aa:aa:aa:aa:02 192.168.1.2/24
add-port SW1 11:11:11:11:11:01
add-port SW1 11:11:11:11:11:02
add-port SW1 11:11:11:11:11:03
add-port SW2 22:22:22:22:22:01
add-port SW2 22:22:22:22:22:02
add-port SW3 33:33:33:33:33:01
add-port SW3 33:33:33:33:33:02
add-port SW3 33:33:33:33:33:03
connect PC1:0 SW1:0
connect SW1:1 SW2:0
connect SW2:1 SW3:0
connect SW3:1 SW1:2
connect PC2:0 SW3:2
set-stp SW1 on
set-stp SW2 on
set-stp SW3 on
run 200000
ping PC1 192.168.1.2
run 200000
set-link SW3:1 down
run 200000
ping PC1 192.168.1.2
run 200000
EOF

( ulimit -v 262144; timeout 30 ./netsim -q /tmp/yn_soak.txt ) >/tmp/yn_soak.out 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "soak: FAIL rc=$rc"
    tail -20 /tmp/yn_soak.out
    exit 1
fi

echo "soak: ok (bounded memory, reconvergence)"
