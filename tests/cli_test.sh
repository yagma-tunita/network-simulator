#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

status=0

out=$(./netsim --version 2>&1)
if printf '%s' "$out" | grep -q 'yanas net'; then echo "PASS  cli version"; else echo "FAIL  cli version"; status=1; fi

out=$(./netsim --help 2>&1)
if printf '%s' "$out" | grep -q 'Usage:'; then echo "PASS  cli help"; else echo "FAIL  cli help"; status=1; fi

./netsim --no-such-option >/dev/null 2>&1
if [ $? -eq 2 ]; then echo "PASS  cli usage-error"; else echo "FAIL  cli usage-error"; status=1; fi

./netsim tests/config.yn >/dev/null 2>&1
if [ $? -eq 0 ]; then echo "PASS  cli scene"; else echo "FAIL  cli scene"; status=1; fi

printf 'add-device\n' > /tmp/yn_bad.txt
out=$(./netsim /tmp/yn_bad.txt 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'yn_bad.txt:1: error:'; then
    echo "PASS  cli error-line"
else
    echo "FAIL  cli error-line"
    status=1
fi

out=$(./netsim -q tests/auto_ping.txt 2>&1)
if printf '%s' "$out" | grep -q '^done;'; then
    echo "FAIL  cli quiet"
    status=1
else
    echo "PASS  cli quiet"
fi

out=$(./netsim --no-lua tests/lua_ping.lua 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'Lua disabled'; then
    echo "PASS  cli no-lua"
else
    echo "FAIL  cli no-lua"
    status=1
fi

cat > /tmp/yn_edit.txt <<'EOF'
add-device PC1 end
add-port PC1 aa:aa:aa:aa:aa:01 10.0.0.2/24
rename-device PC1 HOST1
set-ip HOST1:0 10.0.0.9/24
state
EOF
out=$(./netsim /tmp/yn_edit.txt 2>&1)
if printf '%s' "$out" | grep -q '"name":"HOST1"' && \
   printf '%s' "$out" | grep -q '"ip":"10.0.0.9/24"' && \
   ! printf '%s' "$out" | grep -q '"name":"PC1"'; then
    echo "PASS  cli edit-state"
else
    echo "FAIL  cli edit-state"
    status=1
fi

cat > /tmp/yn_rm.txt <<'EOF'
add-device A end
add-device B end
add-port A aa:aa:aa:aa:aa:01 10.0.1.1/24
add-port B aa:aa:aa:aa:aa:02 10.0.1.2/24
connect A:0 B:0
disconnect A:0
remove-device B
state
EOF
out=$(./netsim /tmp/yn_rm.txt 2>&1)
if printf '%s' "$out" | grep -q '"name":"A"' && \
   ! printf '%s' "$out" | grep -q '"name":"B"' && \
   printf '%s' "$out" | grep -q '"links":\[\]'; then
    echo "PASS  cli remove-disconnect"
else
    echo "FAIL  cli remove-disconnect"
    status=1
fi

cat > /tmp/yn_show.txt <<'EOF'
add-device PC1 end
add-device R1 router
add-port PC1 aa:aa:aa:aa:aa:01 10.0.0.2/24
add-port R1 22:22:22:22:22:01 10.0.0.254/24
connect PC1:0 R1:0
devices
routes R1
links
EOF
out=$(./netsim /tmp/yn_show.txt 2>&1)
if printf '%s' "$out" | grep -q 'devices (2):' && \
   printf '%s' "$out" | grep -q '10.0.0.0/24 -> direct' && \
   printf '%s' "$out" | grep -q 'PC1:0 <-> R1:0 up'; then
    echo "PASS  cli show"
else
    echo "FAIL  cli show"
    status=1
fi

cat > /tmp/yn_export.txt <<'EOF'
add-device PC1 end
add-device SW1 switch
add-port PC1 aa:aa:aa:aa:aa:01 10.0.0.1/24
add-port SW1 11:11:11:11:11:01
connect PC1:0 SW1:0
export dot /tmp/yn_export.dot
export svg /tmp/yn_export.svg
EOF
out=$(./netsim /tmp/yn_export.txt 2>&1)
if printf '%s' "$out" | grep -q 'exported dot' && \
   grep -q 'graph' /tmp/yn_export.dot 2>/dev/null && \
   grep -q '<svg' /tmp/yn_export.svg 2>/dev/null; then
    echo "PASS  cli export"
else
    echo "FAIL  cli export"
    status=1
fi
rm -f /tmp/yn_export.dot /tmp/yn_export.svg

out=$(printf 'help ping\nquit\n' | ./netsim 2>&1)
if printf '%s' "$out" | grep -q 'usage: ping'; then
    echo "PASS  cli command-help"
else
    echo "FAIL  cli command-help"
    status=1
fi

exit "$status"
