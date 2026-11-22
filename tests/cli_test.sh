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

exit "$status"
