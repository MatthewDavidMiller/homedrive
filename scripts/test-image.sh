#!/bin/bash
# Build the runtime image and test it the way VM1 runs it.
#
# Usage: make test-image   (runs on the host; needs rootless Podman)
#
# 1. Builds the image from the Containerfile.
# 2. Starts the server with VM1's flags -- read-only root, every capability
#    dropped, no-new-privileges, a memory cap with no swap, a pids limit, a
#    noexec tmpfs /tmp, and the store on its own volume -- and checks it
#    becomes healthy, runs as uid 10001, cannot write its root filesystem,
#    and stops promptly on SIGTERM.
#
# Later milestones add a WebDAV round trip, an API commit, and the refusal
# to start on a store without its sentinel (docs/PLAN.md).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
IMAGE="localhost/homedrive:test"
NAME="hd-image-test-$$"
DATA="hd-image-test-data-$$"
PORT="${HD_TEST_PORT:-18082}"

cleanup() {
    podman rm -f "${NAME}" >/dev/null 2>&1 || true
    podman volume rm -f "${DATA}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The flags roles/homedrive uses on VM1.
# shellcheck disable=SC2054 # the commas are inside mount option lists
SECURITY=(
    --read-only
    --cap-drop=ALL
    --security-opt=no-new-privileges:true
    --memory=1g
    --memory-swap=1g
    --pids-limit=200
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777
)

echo "== build image"
podman build --format docker --platform linux/amd64 -q -f Containerfile -t "${IMAGE}" . >/dev/null

echo "== static binary"
podman run --rm --entrypoint sh "${IMAGE}" -c \
    'test "$(head -c 4 /usr/local/bin/hd-server | od -An -c | tr -d " ")" = "177ELF"'
podman run --rm --entrypoint sh "${IMAGE}" -c \
    '! ldd /usr/local/bin/hd-server 2>&1 | grep -q "=>"' || { echo "FAIL: not static" >&2; exit 1; }

echo "== smoke: start with VM1 flags"
podman run -d --name "${NAME}" "${SECURITY[@]}" \
    -v "${DATA}:/var/lib/homedrive" \
    -p "127.0.0.1:${PORT}:8080" \
    "${IMAGE}" >/dev/null
for _ in $(seq 1 30); do
    podman exec "${NAME}" hd-server healthcheck 2>/dev/null && break
    sleep 1
done
podman exec "${NAME}" hd-server healthcheck
[[ "$(podman exec "${NAME}" id -u)" == 10001 ]] || { echo "FAIL: not uid 10001" >&2; exit 1; }
if podman exec "${NAME}" sh -c 'touch /usr/local/bin/x' 2>/dev/null; then
    echo "FAIL: the root filesystem is writable" >&2
    exit 1
fi
curl -fsS "http://127.0.0.1:${PORT}/healthz" | grep -qx ok || { echo "FAIL: /healthz" >&2; exit 1; }
# SIGTERM must stop it promptly (PID 1 ignores unhandled signals).
started="$(date +%s)"
podman stop -t 20 "${NAME}" >/dev/null
(( $(date +%s) - started < 5 )) || { echo "FAIL: SIGTERM did not stop the server" >&2; exit 1; }
podman logs "${NAME}" 2>&1 | grep -q "stopping" || { echo "FAIL: no clean stop" >&2; exit 1; }
echo "Image checks passed."
