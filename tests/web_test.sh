#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP  web (curl not available)"
    exit 0
fi

PORT=18080
./netsim --serve "$PORT" >/tmp/yanas_web.log 2>&1 &
PID=$!

cleanup() { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }
trap cleanup EXIT

ok=0
i=0
while [ "$i" -lt 50 ]; do
    if curl -s "http://127.0.0.1:$PORT/api/state" >/dev/null 2>&1; then ok=1; break; fi
    i=$((i + 1))
    sleep 0.1
done

if [ "$ok" != 1 ]; then
    echo "FAIL  web (server did not start)"
    exit 1
fi

status=0
check() {
    local p="$1"
    local want="$2"
    local out
    out=$(curl -s "http://127.0.0.1:$PORT$p" 2>/dev/null)
    if printf '%s' "$out" | grep -qF "$want"; then
        echo "PASS  web $p"
    else
        echo "FAIL  web $p"
        status=1
    fi
}

check /api/state '"name":"yanas net"'
check / 'yanas net'
check /style.css 'titlebar'
check /app.js 'apiPost'
check /logo.svg 'polygon'

curl -s -X POST --data 'add-device PC1 end' "http://127.0.0.1:$PORT/api/cmd" >/dev/null
check /api/state 'PC1'

exit "$status"
