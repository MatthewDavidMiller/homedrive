#!/bin/bash
# Build the runtime image and test it the way VM1 runs it.
#
# Usage: make test-image   (runs on the host; needs rootless Podman)
#
# 1. Builds the image from the Containerfile.
# 2. Starts the server with VM1's flags -- read-only root, every capability
#    dropped, no-new-privileges, a memory cap with no swap, a pids limit, a
#    noexec tmpfs /tmp, and the store on its own volume -- and checks it
#    refuses to start on a volume that is not a store (an unmounted disk
#    looks like that), and once `hd-server init` has made it one, becomes
#    healthy, runs as uid 10001, cannot write its root filesystem, and stops
#    promptly on SIGTERM.
# 3. Proves a backup restores: a file-level copy of the running store (as
#    borg takes it) goes through `restore-drill` in a one-off container with
#    no network, its plain files pass `sha256sum -c`, and `drill-compare`
#    finds the copy complete; backup reports reach the admin's status.
#
# Later milestones add a WebDAV round trip and an API commit (docs/PLAN.md).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
IMAGE="localhost/homedrive:test"
NAME="hd-image-test-$$"
DATA="hd-image-test-data-$$"
BACKUP="hd-image-test-backup-$$"
PLAIN="hd-image-test-plain-$$"
USERS_SECRET="hd-image-test-users-$$"
PORT="${HD_TEST_PORT:-18082}"
WORK="$(mktemp -d)"

cleanup() {
    podman rm -f "${NAME}" >/dev/null 2>&1 || true
    podman volume rm -f "${DATA}" "${BACKUP}" "${PLAIN}" >/dev/null 2>&1 || true
    podman secret rm "${USERS_SECRET}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
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

printf '%s' '{"version":1,"users":[{"name":"admin","password":"image-test-pw","admin":true,"quota_gb":1}]}' > "${WORK}/users.json"
podman secret create "${USERS_SECRET}" "${WORK}/users.json" >/dev/null
USERS=(--secret "${USERS_SECRET},target=/run/secrets/homedrive_users,uid=10001,gid=10001,mode=0400")

echo "== refuses a volume that is not a store"
if out="$(podman run --rm "${SECURITY[@]}" "${USERS[@]}" -v "${DATA}:/var/lib/homedrive" "${IMAGE}" 2>&1)"; then
    echo "FAIL: the server started without a store" >&2
    exit 1
fi
grep -q "refusing to start" <<<"${out}" || { echo "FAIL: unexpected refusal: ${out}" >&2; exit 1; }

echo "== init"
podman run --rm "${SECURITY[@]}" -v "${DATA}:/var/lib/homedrive" "${IMAGE}" init
if podman run --rm "${SECURITY[@]}" -v "${DATA}:/var/lib/homedrive" "${IMAGE}" init 2>/dev/null; then
    echo "FAIL: init ran twice" >&2
    exit 1
fi

echo "== smoke: start with VM1 flags"
podman run -d --name "${NAME}" "${SECURITY[@]}" "${USERS[@]}" \
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
base="http://127.0.0.1:${PORT}"
curl -fsS "${base}/healthz" | grep -qx ok || { echo "FAIL: /healthz" >&2; exit 1; }
echo "== API: register a device, upload and fetch a file"
token="$(curl -fsS -u admin:image-test-pw -d '{"name":"image-test"}' "${base}/api/v1/devices" |
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[[ "${token}" == hd1_* ]] || { echo "FAIL: no device token" >&2; exit 1; }
printf 'hello from the image test\n' > "${WORK}/f"
id="$(sha256sum "${WORK}/f" | cut -d' ' -f1)"
curl -fsS -H "Authorization: Bearer ${token}" -T "${WORK}/f" "${base}/api/v1/chunks/${id}" >/dev/null
curl -fsS -H "Authorization: Bearer ${token}" \
    -d "{\"path\":\"t.txt\",\"base\":\"absent\",\"size\":26,\"sha256\":\"${id}\",\"mtime_ms\":0,\"chunks\":[[\"${id}\",26]]}" \
    "${base}/api/v1/commit" | grep -q '"conflict":false' || { echo "FAIL: commit" >&2; exit 1; }
curl -fsS -H "Authorization: Bearer ${token}" "${base}/api/v1/file?path=t.txt" | cmp - "${WORK}/f" ||
    { echo "FAIL: download differs" >&2; exit 1; }
echo "== admin socket: import through podman exec, as backup scripts do"
head -c 3000000 /dev/urandom > "${WORK}/backup.bin"
podman exec -i "${NAME}" hd-server import --user admin --dest backups/test/backup.bin < "${WORK}/backup.bin" >/dev/null
curl -fsS -H "Authorization: Bearer ${token}" "${base}/api/v1/file?path=backups/test/backup.bin" | cmp - "${WORK}/backup.bin" ||
    { echo "FAIL: imported file differs" >&2; exit 1; }
podman exec "${NAME}" hd-server fsck --deep | grep -q clean || { echo "FAIL: fsck" >&2; exit 1; }
podman exec "${NAME}" hd-server checkpoint | grep -q "snapshot" || { echo "FAIL: checkpoint" >&2; exit 1; }
echo "== restore drill: a backup copy restores to plain files that match the drive"
podman volume create "${BACKUP}" >/dev/null
podman volume create "${PLAIN}" >/dev/null
# A file-level copy, as borg takes it: without the socket or history.id.
podman run --rm -v "${DATA}:/src:ro" -v "${BACKUP}:/dst" --entrypoint sh "${IMAGE}" -c \
    'tar -C /src --exclude=./admin.sock --exclude=./history.id -cf - . | tar -C /dst -xf -'
drill="$(podman run --rm "${SECURITY[@]}" --network=none \
    -v "${BACKUP}:/var/lib/homedrive" -v "${PLAIN}:/restore" "${IMAGE}" restore-drill --to /restore)" ||
    { echo "FAIL: restore-drill: ${drill}" >&2; exit 1; }
grep -qx "USER admin 2 3000026" <<<"${drill}" || { echo "FAIL: drill restored: ${drill}" >&2; exit 1; }
podman run --rm -v "${PLAIN}:/restore:ro" --entrypoint sh "${IMAGE}" -c \
    'cd /restore/admin && sha256sum -c ../admin.sha256' >/dev/null ||
    { echo "FAIL: the restored files do not pass sha256sum -c" >&2; exit 1; }
podman run --rm -v "${PLAIN}:/restore:ro" --entrypoint cat "${IMAGE}" /restore/admin.sha256 > "${WORK}/admin.sha256"
taken="$(sed -n 's/^TAKEN_MS //p' <<<"${drill}")"
podman exec -i "${NAME}" hd-server drill-compare --user admin --taken-ms "${taken}" < "${WORK}/admin.sha256" >/dev/null ||
    { echo "FAIL: drill-compare" >&2; exit 1; }
podman exec "${NAME}" hd-server report-backup --kind drill --ok --message "image test"
podman exec "${NAME}" hd-server report-backup --kind local --failed --message "image test failure"
curl -fsS -H "Authorization: Bearer ${token}" "${base}/api/v1/status" | grep -q "local backup failed" ||
    { echo "FAIL: a failed backup did not reach the admin" >&2; exit 1; }
# SIGTERM must stop it promptly (PID 1 ignores unhandled signals).
started="$(date +%s)"
podman stop -t 20 "${NAME}" >/dev/null
(( $(date +%s) - started < 5 )) || { echo "FAIL: SIGTERM did not stop the server" >&2; exit 1; }
# Captured first: grep -q would close the pipe early, and pipefail would
# report podman's SIGPIPE as a failure.
logs="$(podman logs "${NAME}" 2>&1)"
grep -q "opened store" <<<"${logs}" || { echo "FAIL: no store opened" >&2; exit 1; }
grep -q "stopping" <<<"${logs}" || { echo "FAIL: no clean stop" >&2; exit 1; }
echo "Image checks passed."
