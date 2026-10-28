#!/bin/bash
# Install the repository-pinned Rust toolchain after checksum verification.
#
# One toolchain, pinned to a dated stable release rather than a channel name,
# with the static x86_64 musl target the shipped binary is built for.
#
# rustup-init itself is pinned by SHA-256; rustup then verifies every
# component it downloads against the checksums in the dated channel manifest.
# rust-toolchain.toml names the same release, and scripts/check-rust.sh holds
# the two to one version.
#
# Usage: RUSTUP_HOME=... CARGO_HOME=... ./scripts/install-rust.sh [--build-only]
#   --build-only  skip clippy and rustfmt (the image's builder stage)

set -euo pipefail

RUSTUP_VERSION="1.29.1"
RUSTUP_LINUX_X86_64_SHA256="331228566cc931f32cd684f9bebc5956a5e5d7394c8d5de595f196a658ab98e6"
RUSTUP_LINUX_ARM64_SHA256="1ddf36182ac5d1782dbeefcb9bea7f5f9412d88f4a0d5047b1564a223624e8c6"
RUST_STABLE="1.98.1"
RUST_TARGET="x86_64-unknown-linux-musl"

: "${RUSTUP_HOME:?set RUSTUP_HOME to where the toolchain should live}"
: "${CARGO_HOME:?set CARGO_HOME to where the rustup proxies should live}"

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)
        host="x86_64-unknown-linux-musl"
        expected_sha256="${RUSTUP_LINUX_X86_64_SHA256}"
        ;;
    Linux/aarch64|Linux/arm64)
        host="aarch64-unknown-linux-musl"
        expected_sha256="${RUSTUP_LINUX_ARM64_SHA256}"
        ;;
    *)
        echo "ERROR: pinned Rust installation supports Linux x86_64 and arm64 only." >&2
        exit 1
        ;;
esac

components="clippy,rustfmt"
if [[ "${1:-}" == "--build-only" ]]; then
    components=""
fi

download_dir="$(mktemp -d)"
trap 'rm -rf "${download_dir}"' EXIT
installer="${download_dir}/rustup-init"

curl -fsSLo "${installer}" \
    "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${host}/rustup-init"
printf '%s  %s\n' "${expected_sha256}" "${installer}" | sha256sum -c -
chmod 0755 "${installer}"

args=(-y --no-modify-path --profile minimal
    --default-host "${host}" --default-toolchain "${RUST_STABLE}")
[[ -n "${components}" ]] && args+=(--component "${components}")
"${installer}" "${args[@]}"
"${CARGO_HOME}/bin/rustup" target add --toolchain "${RUST_STABLE}" "${RUST_TARGET}"
