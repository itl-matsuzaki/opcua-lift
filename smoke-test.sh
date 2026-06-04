#!/usr/bin/env bash
# smoke-test.sh — prove the standalone build works end-to-end against a live
# OPC UA server you supply.
#
# Usage: ./smoke-test.sh <path-to-opcua-server-binary> [port]
#
# It starts the server, replays the bundled sample ReadRequest body through
# opcua-lift, then stops the server.  A working run prints AFLNet-style state
# codes (e.g. "0-0-") followed by the raw MSGF response bytes, and exits 0.
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

echo "[smoke] replaying testcases/readrequest_body.raw (service=read) ..."
"$DIR/opcua-lift" "$DIR/testcases/readrequest_body.raw" "$PORT" 631 127.0.0.1
RC=$?
echo ""
echo "[smoke] opcua-lift exit=$RC  (0 = handshake completed + MSG sent + response received)"
exit "$RC"
