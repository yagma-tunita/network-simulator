#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$(id -u)" -ne 0 ]; then
    echo "live_tap: requires root (TAP + ip address)"
    exit 77
fi
if [ ! -x ./netsim ] || [ ! -x ./build/ynbridge ]; then
    echo "live_tap: build first (make && make tools)"
    exit 1
fi

TAP="${TAP:-yntap0}"
LOSS="${LOSS:-0}"
DUP="${DUP:-0}"
SEED="${SEED:-1}"
SCENE="$(mktemp)"
LOG="$(mktemp)"
TMPD="$(mktemp -d)"

cat > "$SCENE" <<'EOF'
add-device PC1 end
add-port PC1 aa:aa:aa:aa:aa:01 10.0.0.1/24
tcp-listen PC1 on 80
EOF

cleanup() {
    if [ -n "${BRIDGE_PID:-}" ]; then
        kill "$BRIDGE_PID" 2>/dev/null || true
        wait "$BRIDGE_PID" 2>/dev/null || true
    fi
    ip link del "$TAP" 2>/dev/null || true
    rm -f "$SCENE" "$LOG" /tmp/yn_live_in.bin /tmp/yn_live_out.bin
    rm -rf "$TMPD"
}
trap cleanup EXIT

ip link del "$TAP" 2>/dev/null || true
./build/ynbridge -exe ./netsim -scene "$SCENE" -dev PC1:0 \
    -tap "$TAP" -addr 10.0.0.254/24 -loss "$LOSS" -dup "$DUP" -seed "$SEED" \
    >"$LOG" 2>&1 &
BRIDGE_PID=$!
sleep 2

ping -c 1 -W 2 10.0.0.1 >/dev/null

exec 3<>/dev/tcp/10.0.0.1/80
printf 'hello' >&3
OUT="$(timeout 5 dd bs=1 count=5 <&3 2>/dev/null)"
exec 3>&- 2>/dev/null || true
exec 3<&- 2>/dev/null || true

if [ "$OUT" != "hello" ]; then
    echo "live_tap: TCP echo mismatch: '$OUT'"
    cat "$LOG" >&2
    exit 1
fi

head -c 65536 /dev/urandom > /tmp/yn_live_in.bin
exec 3<>/dev/tcp/10.0.0.1/80
head -c 65536 /tmp/yn_live_in.bin >&3 &
WRITER=$!
timeout 15 head -c 65536 <&3 > /tmp/yn_live_out.bin
wait "$WRITER" 2>/dev/null || true
exec 3>&- 2>/dev/null || true
exec 3<&- 2>/dev/null || true

if ! cmp -s /tmp/yn_live_in.bin /tmp/yn_live_out.bin; then
    echo "live_tap: large TCP transfer mismatch"
    cat "$LOG" >&2
    exit 1
fi
rm -f /tmp/yn_live_in.bin /tmp/yn_live_out.bin

PIDS=""
for i in 1 2 3 4 5 6 7 8; do
    (
        exec 3<>/dev/tcp/10.0.0.1/80
        printf 'p%d' "$i" >&3
        dd bs=1 count=2 <&3 > "$TMPD/$i" 2>/dev/null
        exec 3>&- 2>/dev/null || true
        exec 3<&- 2>/dev/null || true
    ) &
    PIDS="$PIDS $!"
done
for p in $PIDS; do wait "$p"; done
for i in 1 2 3 4 5 6 7 8; do
    if [ "$(cat "$TMPD/$i")" != "p$i" ]; then
        echo "live_tap: concurrent echo $i mismatch"
        exit 1
    fi
done

if [ "$LOSS" = "0" ]; then
    set +e
    timeout 2 bash -c 'exec 3<>/dev/tcp/10.0.0.1/9999' 2>/dev/null
    RC=$?
    set -e
    if [ "$RC" -eq 0 ]; then
        echo "live_tap: closed port unexpectedly accepted"
        exit 1
    fi
    if [ "$RC" -eq 124 ]; then
        echo "live_tap: closed port timed out instead of returning RST"
        exit 1
    fi
fi

echo "live_tap: ping + echoes + 8 concurrent + RST check passed (loss=$LOSS dup=$DUP)"
