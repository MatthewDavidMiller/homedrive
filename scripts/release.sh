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
#   2. builds and pushes ghcr.io/matthewdavidmiller/homedrive:<version>,
#   3. tags the commit v<version> and creates a GitHub release whose notes
#      carry the pushed digest -- the value ansible_playbooks pins.

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

podman build --format docker --platform linux/amd64 -f Containerfile \
    --label "org.opencontainers.image.version=${VERSION}" \
    --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
    --label "org.opencontainers.image.source=https://github.com/MatthewDavidMiller/homedrive" \
    -t "${REPO}:${VERSION}" .
digestfile="$(mktemp)"
trap 'rm -f "${digestfile}"' EXIT
podman push --digestfile "${digestfile}" "${REPO}:${VERSION}"
digest="$(cat "${digestfile}")"

git tag -a "v${VERSION}" -m "homedrive ${VERSION}"
git push origin "v${VERSION}"
gh release create "v${VERSION}" --title "homedrive ${VERSION}" --notes "$(cat <<NOTES
Image: \`${REPO}:${VERSION}\`
Digest: \`${digest}\`

Pin it in ansible_playbooks with scripts/review_container_updates.sh.
NOTES
)"
echo "Released ${REPO}:${VERSION}@${digest}"
