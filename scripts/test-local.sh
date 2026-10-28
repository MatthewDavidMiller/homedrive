#!/bin/bash
# The full local gate the pre-commit hook runs: lint, then the Rust gate.
#
# Usage: ./scripts/test-local.sh   (run through scripts/toolbox.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/lint.sh"
"${SCRIPT_DIR}/check-rust.sh"
echo "All checks passed."
