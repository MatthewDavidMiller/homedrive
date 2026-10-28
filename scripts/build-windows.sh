#!/bin/bash
# Cross-build the Windows sync client, dist/homedrive.exe.
#
# Usage: ./scripts/build-windows.sh   (runs on the host; needs rootless Podman)
#
# The builder image (tools/windows/Dockerfile) carries mingw-w64 and a
# static OpenSSL for Windows, so the result is one self-contained .exe.
# It is not run here: test it on a Windows machine (docs/USAGE.md).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
DOCKERFILE=tools/windows/Dockerfile
TAG="homedrive-windows-builder:$(cat "${DOCKERFILE}" scripts/install-rust.sh | sha256sum | cut -c1-16)"

podman image inspect "${TAG}" >/dev/null 2>&1 ||
    podman build --format docker --platform linux/amd64 -f "${DOCKERFILE}" -t "${TAG}" .

podman run --rm --userns=keep-id --network=none \
    -v "${PROJECT_ROOT}:${PROJECT_ROOT}:Z" -w "${PROJECT_ROOT}" -e HOME=/build-home \
    "${TAG}" cargo build --release --locked --offline \
    --target x86_64-pc-windows-gnu -p hd-client --bin homedrive \
    --target-dir target/windows

mkdir -p dist
cp target/windows/x86_64-pc-windows-gnu/release/homedrive.exe dist/homedrive.exe
file dist/homedrive.exe 2>/dev/null || true
sha256sum dist/homedrive.exe
