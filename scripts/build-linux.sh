#!/bin/bash
# Build the Linux sync client, dist/homedrive: one static x86-64 file, with
# musl and OpenSSL linked in, so it runs on any Linux distribution.
#
# Usage: ./scripts/build-linux.sh   (runs on the host; needs rootless Podman)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
TAG="localhost/homedrive-client:build"

podman build --format docker --platform linux/amd64 -f Containerfile \
    --target build -t "${TAG}" .

container="$(podman create "${TAG}")"
trap 'podman rm "${container}" >/dev/null' EXIT
mkdir -p dist
podman cp "${container}:/homedrive" dist/homedrive
file dist/homedrive 2>/dev/null || true
sha256sum dist/homedrive
