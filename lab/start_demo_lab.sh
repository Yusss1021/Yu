#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/lab/run"
mkdir -p "$RUN_DIR"

start_service() {
  local name="$1"
  shift

  local pid_file="$RUN_DIR/${name}.pid"
  local log_file="$RUN_DIR/${name}.log"

  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid="$(cat "$pid_file")"
    if kill -0 "$old_pid" 2>/dev/null; then
      echo "$name already running with PID $old_pid"
      return
    fi
    rm -f "$pid_file"
  fi

  nohup "$@" >"$log_file" 2>&1 < /dev/null &
  local new_pid=$!
  echo "$new_pid" >"$pid_file"
  sleep 0.2

  if ! kill -0 "$new_pid" 2>/dev/null; then
    echo "failed to start $name, check log: $log_file"
    exit 1
  fi
  echo "started $name (PID $new_pid), log: $log_file"
}

start_service mock_ssh python3 "$ROOT_DIR/lab/mock_ssh.py" --host 127.0.0.1 --port 2222
start_service mock_redis python3 "$ROOT_DIR/lab/mock_redis.py" --host 127.0.0.1 --port 6379

echo "demo lab is ready."
echo "run scan command:"
echo "  python3 main.py scan --target 127.0.0.1/32 --methods icmp,syn --ports 2222,6379 --name demo_lab_scan"
