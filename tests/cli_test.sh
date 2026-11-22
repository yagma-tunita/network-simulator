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

exit "$status"
