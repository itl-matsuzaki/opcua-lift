#!/usr/bin/env bash
# replay.sh — convenience wrapper around opcua-lift.
#
# Maps a human service name to the OPC UA service NodeId that opcua-lift frames
# the corpus body with, then replays one raw corpus entry against a live server.
#
# Usage: ./replay.sh <corpus_file> <port> [service] [host]
#   service: read | write | browse | call   (default: read)
#   host:    target host                     (default: 127.0.0.1)
#
# NodeId map (open62541 v1.3.x binary service request TypeIds):
#   read=631  write=673  browse=527  call=713
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ $# -lt 2 ]; then
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

CORPUS_FILE="$1"
PORT="$2"
SERVICE="${3:-read}"
HOST="${4:-127.0.0.1}"

case "$SERVICE" in
  read)   NODE_ID=631 ;;
  write)  NODE_ID=673 ;;
  browse) NODE_ID=527 ;;
  call)   NODE_ID=713 ;;
  *) echo "[replay] Unsupported service: $SERVICE (use read|write|browse|call)" >&2; exit 2 ;;
esac

DIR="$(cd "$(dirname "$0")" && pwd)"
LIFT_BIN="${LIFT_BIN:-$DIR/opcua-lift}"

if [ ! -x "$LIFT_BIN" ]; then
  echo "[replay] opcua-lift not built. Run 'make' first." >&2
  exit 1
fi

exec "$LIFT_BIN" "$CORPUS_FILE" "$PORT" "$NODE_ID" "$HOST"
