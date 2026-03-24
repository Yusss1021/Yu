#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_NAME="${1:-demo_lab_scan}"
RUN_DIR="$ROOT_DIR/lab/run"
mkdir -p "$RUN_DIR"

SSH_PID=""
REDIS_PID=""

cleanup() {
  if [[ -n "$SSH_PID" ]] && kill -0 "$SSH_PID" 2>/dev/null; then
    kill "$SSH_PID" || true
  fi
  if [[ -n "$REDIS_PID" ]] && kill -0 "$REDIS_PID" 2>/dev/null; then
    kill "$REDIS_PID" || true
  fi
}
trap cleanup EXIT

python3 "$ROOT_DIR/lab/mock_ssh.py" --host 127.0.0.1 --port 2222 >"$RUN_DIR/mock_ssh.log" 2>&1 &
SSH_PID=$!
python3 "$ROOT_DIR/lab/mock_redis.py" --host 127.0.0.1 --port 6379 >"$RUN_DIR/mock_redis.log" 2>&1 &
REDIS_PID=$!

sleep 0.5
if ! kill -0 "$SSH_PID" 2>/dev/null; then
  echo "mock_ssh start failed, check $RUN_DIR/mock_ssh.log"
  exit 1
fi
if ! kill -0 "$REDIS_PID" 2>/dev/null; then
  echo "mock_redis start failed, check $RUN_DIR/mock_redis.log"
  exit 1
fi

python3 "$ROOT_DIR/main.py" scan \
  --target 127.0.0.1/32 \
  --methods icmp,syn \
  --ports 2222,6379 \
  --name "$SCAN_NAME"
