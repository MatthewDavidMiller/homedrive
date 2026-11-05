#!/bin/bash
# Runs the sync client's test suites on real Windows and NTFS.
#
# Usage: ./scripts/test-windows.sh [test name filter]
#
# Run it from WSL: the tests are cross-built in the Windows builder image,
# copied to the Windows temporary folder, and started through WSL's Windows
# interop. Each test starts its own server on loopback, so nothing else is
# needed. Everything they make stays under that folder.
#
# They are built with the windows-test profile (see Cargo.toml): optimized,
# because Microsoft Defender removes unoptimized test programs at times,
# but with symbols, line tables and debug assertions kept.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
command -v cmd.exe >/dev/null || {
    echo "ERROR: run this from WSL, where Windows programs can be started" >&2
    exit 1
}
DOCKERFILE=tools/windows/Dockerfile
TAG="homedrive-windows-builder:$(cat "${DOCKERFILE}" scripts/install-rust.sh | sha256sum | cut -c1-16)"

podman image inspect "${TAG}" >/dev/null 2>&1 ||
    podman build --format docker --platform linux/amd64 -f "${DOCKERFILE}" -t "${TAG}" .

BUILD_LOG="$(mktemp)"
trap 'rm -f "${BUILD_LOG}"' EXIT
PACKAGES=(-p hd-common -p hd-crypto -p hd-chunk -p hd-api -p hd-client)
podman run --rm --userns=keep-id --network=none \
    -v "${PROJECT_ROOT}:${PROJECT_ROOT}:Z" -w "${PROJECT_ROOT}" -e HOME=/build-home \
    "${TAG}" cargo test --no-run --locked --offline --profile windows-test \
    --target x86_64-pc-windows-gnu --target-dir target/windows-test "${PACKAGES[@]}" \
    2>&1 | tee "${BUILD_LOG}"

WIN_TEMP="$(cd /mnt/c && cmd.exe /c 'echo %TEMP%' 2>/dev/null | tr -d '\r')"
RUN_DIR="$(wslpath -u "${WIN_TEMP}")/homedrive-tests"
mkdir -p "${RUN_DIR}"

mapfile -t SUITES < <(grep -oE 'target/windows-test/[^)]*\.exe' "${BUILD_LOG}" | sort -u)
# hd-client alone has three end-to-end suites: fewer means something went
# wrong before any test ran, not that everything passed.
[[ "${#SUITES[@]}" -ge 8 ]] || {
    echo "ERROR: found only ${#SUITES[@]} test suites" >&2
    exit 1
}

# The end-to-end suites start the real program.
cp target/windows-test/x86_64-pc-windows-gnu/windows-test/homedrive.exe "${RUN_DIR}/homedrive.exe"

# A failing test shows where it failed, with file and line.
export RUST_BACKTRACE=1
export WSLENV="${WSLENV:+${WSLENV}:}RUST_BACKTRACE"

failed=0
for exe in "${SUITES[@]}"; do
    name="$(basename "${exe}")"
    cp "${exe}" "${RUN_DIR}/${name}"
    echo "== ${name}"
    # Windows programs read WSL's stdin, so it is closed. The working
    # directory is on NTFS: a WSL one would give the tests a network path.
    if ! (cd "${RUN_DIR}" && "./${name}" "$@" </dev/null | tr -d '\r'; exit "${PIPESTATUS[0]}"); then
        failed=1
    fi
done

# Each test leaves its small world behind in the temporary folder.
find "$(dirname "${RUN_DIR}")" -maxdepth 1 -type d -name 'hd-client-e2e-*' -exec rm -rf {} +

# The folder check, against folders damaged on purpose. PowerShell needs a
# Windows path, so it runs from the temporary folder too.
cp contrib/windows/compare-folders.ps1 contrib/windows/test-compare-folders.ps1 "${RUN_DIR}/"
echo "== compare-folders"
if ! (cd "${RUN_DIR}" && powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File test-compare-folders.ps1 </dev/null | tr -d '\r'; exit "${PIPESTATUS[0]}"); then
    failed=1
fi

if [[ "${failed}" -ne 0 ]]; then
    echo "FAILED: see the suites above" >&2
    exit 1
fi
echo "All ${#SUITES[@]} Windows suites and the folder check passed."
