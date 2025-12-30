#!/usr/bin/env bash
set -euo pipefail

CYAN=$'\033[36m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'

./psa_tls_server -p 11111 2>&1 | sed "s/^/${CYAN}[SERVER] ${RESET}/" &
SERVER_PID=$!

trap 'kill '"$SERVER_PID"' >/dev/null 2>&1 || true; wait '"$SERVER_PID"' >/dev/null 2>&1 || true' EXIT

sleep 0.2

./psa_tls_client -h 127.0.0.1 -p 11111 -l ECDHE-ECDSA-AES128-GCM-SHA256 -d \
  2>&1 | sed "s/^/${YELLOW}[CLIENT] ${RESET}/"

wait "$SERVER_PID"
