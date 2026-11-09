#!/bin/bash
# Build, push, and publish a release of the runtime image.
#
# Usage: make release   (runs on the host)
#
# Requires a clean tree on main, `podman login ghcr.io` with a token that
# has write:packages, and an authenticated gh CLI. The version is the
# workspace version in Cargo.toml; bump it first. The script:
#
#   1. runs the full gate and the image tests,
#   2. builds the Linux and Windows sync clients and signs the Windows one
#      with the personal code-signing key (needs osslsigncode and the key in
#      ~/.config/code-signing),
#   3. builds and pushes ghcr.io/matthewdavidmiller/homedrive:<version>,
#   4. tags the commit v<version> and creates a prerelease on GitHub with the
#      clients and their checksums attached, and whose notes carry the pushed
#      digest -- the value ansible_playbooks pins.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
REPO="ghcr.io/matthewdavidmiller/homedrive"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
[[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: no version in Cargo.toml" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "ERROR: the tree is not clean" >&2; exit 1; }
[[ "$(git rev-parse --abbrev-ref HEAD)" == main ]] || { echo "ERROR: release from main" >&2; exit 1; }
if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
    echo "ERROR: v${VERSION} already exists; bump the version in Cargo.toml" >&2
    exit 1
fi

./scripts/toolbox.sh ./scripts/test-local.sh
./scripts/test-image.sh

# Before anything is published, so a client that will not build stops here.
./scripts/build-linux.sh
./scripts/build-windows.sh
[[ "$(dist/homedrive version)" == "homedrive ${VERSION}" ]] || {
    echo "ERROR: dist/homedrive is not version ${VERSION}" >&2
    exit 1
}
# Sign the Windows client with the personal code-signing key. This runs on the
# host because the key lives outside the repository and the toolbox never sees
# it. The signature is verified and timestamped before it replaces dist/.
command -v osslsigncode >/dev/null 2>&1 || {
    echo "ERROR: osslsigncode is required to sign the Windows client." >&2
    exit 1
}
./scripts/codesign.sh dist/homedrive.exe homedrive
assets="$(mktemp -d)"
trap 'rm -rf "${assets}"' EXIT
cp dist/homedrive "${assets}/homedrive-${VERSION}-linux-x86_64"
cp dist/homedrive.exe "${assets}/homedrive-${VERSION}-windows-x86_64.exe"
(cd "${assets}" && sha256sum homedrive-* > SHA256SUMS)

podman build --format docker --platform linux/amd64 -f Containerfile \
    --label "org.opencontainers.image.version=${VERSION}" \
    --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
    --label "org.opencontainers.image.source=https://github.com/MatthewDavidMiller/homedrive" \
    -t "${REPO}:${VERSION}" .
digestfile="$(mktemp)"
trap 'rm -rf "${assets}" "${digestfile}"' EXIT
podman push --digestfile "${digestfile}" "${REPO}:${VERSION}"
digest="$(cat "${digestfile}")"

git tag -a "v${VERSION}" -m "homedrive ${VERSION}"
git push origin "v${VERSION}"
gh release create "v${VERSION}" --prerelease --title "homedrive ${VERSION}" --notes "$(cat <<NOTES
Image: \`${REPO}:${VERSION}\`
Digest: \`${digest}\`

Pin it in ansible_playbooks with scripts/review_container_updates.sh.

The sync clients are attached, for x86-64 Linux and Windows. Check them
against SHA256SUMS.
NOTES
)" "${assets}"/*
echo "Released ${REPO}:${VERSION}@${digest}"
