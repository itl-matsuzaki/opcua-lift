#!/usr/bin/env bash
# smoke-test.sh — prove the standalone build works end-to-end against a live
# OPC UA server you supply.
#
# Usage: ./smoke-test.sh <path-to-opcua-server-binary> [port]
#
# It starts the server, replays the bundled sample ReadRequest body through
# opcua-lift, then exercises --multi with the bundled sample scripts, and stops
# the server.  A working run prints AFLNet-style state codes (e.g. "0-0-")
# followed by the raw MSGF response bytes, then one decoded line per request of
# each --multi script, and exits 0.
#
# OPCUA_LIFT_ANON / OPCUA_LIFT_ANON_V14 / OPCUA_LIFT_TIMEOUT are inherited from
# your environment, so set them here too if your server needs them:
#   OPCUA_LIFT_ANON=1 ./smoke-test.sh /path/to/server 4840
set -uo pipefail

SERVER_BIN="${1:-}"
PORT="${2:-4840}"

if [ -z "$SERVER_BIN" ] || [ ! -x "$SERVER_BIN" ]; then
  echo "Usage: $0 <path-to-opcua-server-binary> [port]" >&2
  echo "  (server must listen on opc.tcp://127.0.0.1:<port>)" >&2
  exit 2
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
[ -x "$DIR/opcua-lift" ] || { echo "Build first: make" >&2; exit 1; }

echo "[smoke] starting server: $SERVER_BIN"
"$SERVER_BIN" >/tmp/opcua-smoke-srv.log 2>&1 &
SRVPID=$!
trap 'kill "$SRVPID" 2>/dev/null; wait "$SRVPID" 2>/dev/null' EXIT
sleep 1.2

if ! kill -0 "$SRVPID" 2>/dev/null; then
  echo "[smoke] server failed to start; log:" >&2
  tail -5 /tmp/opcua-smoke-srv.log >&2
  exit 1
fi

echo "[smoke] single service: replaying testcases/readrequest_body.raw (service=read) ..."
"$DIR/opcua-lift" "$DIR/testcases/readrequest_body.raw" "$PORT" 631 127.0.0.1
RC=$?
echo ""
echo "[smoke] opcua-lift exit=$RC  (0 = handshake completed + MSG sent + response received)"
[ "$RC" -eq 0 ] || exit "$RC"

# --- multi-service mode -----------------------------------------------------
# Decoding the framed output needs python3.  It is a convenience, not a build
# dependency: skip the decode rather than fail the smoke test without it.
if command -v python3 >/dev/null 2>&1; then
  DECODE=("python3" "$DIR/multi.py" "decode" "-")
else
  echo "[smoke] python3 not found — running --multi without decoding the output"
  DECODE=("wc" "-c")
fi

for SCRIPT in multi_read3 multi_browse_next; do
  echo ""
  echo "[smoke] multi service: $SCRIPT.script ..."
  "$DIR/opcua-lift" --multi "$DIR/testcases/$SCRIPT.script" "$PORT" 127.0.0.1 2>/dev/null \
    | "${DECODE[@]}"
  MRC=${PIPESTATUS[0]}
  if [ "$MRC" -ne 0 ]; then
    echo "[smoke] --multi $SCRIPT failed (exit=$MRC)" >&2
    exit "$MRC"
  fi
done

echo ""
echo "[smoke] all modes OK"
echo "[smoke] expected in multi_browse_next: BrowseNext results[0]=0x00000000 Good."
echo "[smoke] 0x804A0000 there means the continuationPoint was not carried over."
exit 0
