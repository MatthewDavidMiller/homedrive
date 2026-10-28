#!/bin/bash
# Point git at the tracked hooks in .githooks.
#
# Usage: ./scripts/setup-hooks.sh

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "${PROJECT_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "ERROR: not a git repository" >&2
    exit 1
}
chmod +x "${PROJECT_ROOT}/.githooks/pre-commit"
git -C "${PROJECT_ROOT}" config --local core.hooksPath .githooks
echo "Configured core.hooksPath=.githooks; the pre-commit hook runs 'make test'."
