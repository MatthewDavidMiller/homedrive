#!/bin/bash
# Lint the shell scripts and the git hooks.
#
# Usage: ./scripts/lint.sh   (run through scripts/toolbox.sh)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "== shellcheck"
mapfile -t scripts < <(git ls-files --cached --others --exclude-standard -- '*.sh' '.githooks/*')
shellcheck --external-sources "${scripts[@]}"

echo "== base image pins"
# Every base image is an official image pinned by digest, and the toolbox and
# the shipped image share one Alpine digest so they cannot drift apart.
digests=()
for file in Containerfile tools/toolbox/Dockerfile; do
    while IFS= read -r line; do
        [[ "${line}" == *"@\${ALPINE_DIGEST}"* || "${line}" =~ @sha256:[0-9a-f]{64} ]] || {
            echo "ERROR: ${file}: unpinned base image: ${line}" >&2
            exit 1
        }
        [[ "${line}" == *"docker.io/library/"* ]] || {
            echo "ERROR: ${file}: base image is not an official docker.io/library image: ${line}" >&2
            exit 1
        }
    done < <(grep -E '^FROM ' "${file}")
    digests+=("$(sed -n 's/^ARG ALPINE_DIGEST=\(sha256:[0-9a-f]\{64\}\)$/\1/p' "${file}")")
done
[[ -n "${digests[0]}" && "${digests[0]}" == "${digests[1]}" ]] || {
    echo "ERROR: Containerfile and tools/toolbox/Dockerfile must pin the same ALPINE_DIGEST" >&2
    exit 1
}
