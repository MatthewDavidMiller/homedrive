#!/bin/bash
# What the sync client costs on real Windows and NTFS: memory and CPU across
# a first sync, an idle daemon, and small changes.
#
# Usage: make bench-windows      (from WSL, after make windows)
#        HD_BENCH_FILES=N HD_BENCH_IDLE=SECONDS ./scripts/bench-windows.sh [homedrive.exe]
#
# The client runs on Windows from a folder of its own. The server runs in the
# toolbox, reached through WSL's port forwarding, so its disk is not NTFS and
# transfer rates here say little; the client's own figures are the point.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
command -v powershell.exe >/dev/null || {
    echo "ERROR: run this from WSL, where Windows programs can be started" >&2
    exit 1
}
EXE="$(realpath "${1:-dist/homedrive.exe}")"
FILES="${HD_BENCH_FILES:-20000}"
IDLE="${HD_BENCH_IDLE:-320}"
PORT=18081
WORK=target/bench-windows

./scripts/toolbox.sh cargo build --release -p hd-server >/dev/null 2>&1

rm -rf "${WORK}"
mkdir -p "${WORK}/store"
cat >"${WORK}/users.json" <<EOF
{"version":1,"users":[{"name":"bench","password":"a bench password","admin":true,"quota_gb":100}]}
EOF

WIN_TEMP="$(cd /mnt/c && cmd.exe /c 'echo %TEMP%' 2>/dev/null | tr -d '\r')"
RUN_DIR="$(wslpath -u "${WIN_TEMP}")/homedrive-bench"
mkdir -p "${RUN_DIR}"
trap 'kill "${server}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "${RUN_DIR}"' EXIT
cp "${EXE}" "${RUN_DIR}/homedrive.exe"
cp contrib/windows/bench-daemon.ps1 "${RUN_DIR}/"

HD_DATA_DIR="${PWD}/${WORK}/store" HD_USERS_FILE="${PWD}/${WORK}/users.json" \
    HD_LISTEN="0.0.0.0:${PORT}" HD_SECURE_COOKIES=false HD_MIN_FREE_GB=0 \
    ./scripts/toolbox.sh --publish "${PORT}" sh -c \
    'target/release/hd-server init >/dev/null && exec target/release/hd-server' \
    >"${WORK}/server.log" 2>&1 &
server=$!
until curl -fs "http://127.0.0.1:${PORT}/healthz" >/dev/null; do sleep 0.5; done

(cd "${RUN_DIR}" && powershell.exe -NoProfile -ExecutionPolicy Bypass -File bench-daemon.ps1 \
    -Exe "${WIN_TEMP}\\homedrive-bench\\homedrive.exe" -Server "http://127.0.0.1:${PORT}" \
    -Files "${FILES}" -Idle "${IDLE}" </dev/null | tr -d '\r')
