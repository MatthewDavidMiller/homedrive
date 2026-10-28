#!/bin/bash
# The Rust gate: formatting, the first-party dependency graph, the unsafe
# allowlist, the toolchain pin, clippy, and the test suites.
#
# Usage: ./scripts/check-rust.sh   (run through scripts/toolbox.sh)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

for tool in cargo rustfmt; do
    command -v "${tool}" >/dev/null || { echo "ERROR: ${tool} is required" >&2; exit 1; }
done

echo "== toolchain pin"
pinned="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
installer="$(sed -n 's/^RUST_STABLE="\(.*\)"$/\1/p' scripts/install-rust.sh)"
workspace="$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)"
if [[ -z "${pinned}" || "${pinned}" != "${installer}" || "${pinned}" != "${workspace}" ]]; then
    echo "ERROR: rust-toolchain.toml (${pinned}), install-rust.sh (${installer})," \
        "and Cargo.toml rust-version (${workspace}) must name one release" >&2
    exit 1
fi

echo "== rustfmt"
cargo fmt --all -- --check

echo "== workspace-only dependency graph"
cargo generate-lockfile --offline >/dev/null
if grep -q '^source = ' Cargo.lock; then
    echo "ERROR: Cargo.lock names a package from outside the workspace:" >&2
    grep -B2 '^source = ' Cargo.lock >&2
    exit 1
fi
members="$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.lock | sort)"
expected="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -exec \
    awk -F'"' '/^\[/ { in_package = ($0 == "[package]") } in_package && /^name = / { print $2 }' {} \; |
    sort)"
if [[ "${members}" != "${expected}" ]]; then
    echo "ERROR: Cargo.lock packages differ from the workspace members" >&2
    diff <(echo "${expected}") <(echo "${members}") >&2 || true
    exit 1
fi

echo "== native library allowlist"
# libcrypto (and, for the sync client, libssl) is the one third-party
# library; pthread is the C library's, and the rest are the Windows system
# libraries a static OpenSSL needs there.
libraries="$(grep -rhoE 'rustc-link-lib=\{kind\}=[A-Za-z0-9_]+|rustc-link-lib=([a-z]+=)?[A-Za-z0-9_]+' crates --include='*.rs' |
    sed 's/.*=//' | sort -u)"
[[ -n "${libraries}" ]] || { echo "ERROR: no linked library found; the pattern no longer matches" >&2; exit 1; }
while IFS= read -r library; do
    [[ "${library}" =~ ^(crypto|ssl|pthread|ws2_32|crypt32|advapi32|user32|gdi32)$ ]] || { echo "ERROR: unexpected native library ${library}" >&2; exit 1; }
done <<<"${libraries}"
if grep -rn '#\[link(' crates --include='*.rs' >/dev/null; then
    echo "ERROR: link libraries through crates/hd-sys/build.rs, not #[link]" >&2
    exit 1
fi

echo "== unsafe allowlist"
UNSAFE_CRATES=(hd-sys)
for manifest in crates/*/Cargo.toml; do
    dir="$(dirname "${manifest}")"
    name="$(basename "${dir}")"
    allowed=false
    for a in "${UNSAFE_CRATES[@]}"; do [[ "${name}" == "${a}" ]] && allowed=true; done
    [[ "${allowed}" == true ]] && continue
    while IFS= read -r root; do
        grep -q '^#!\[forbid(unsafe_code)\]' "${root}" || {
            echo "ERROR: ${root} must forbid unsafe_code" >&2
            exit 1
        }
    done < <(find "${dir}/src" -maxdepth 2 \( -name lib.rs -o -name main.rs -o -path '*/bin/*.rs' \))
done

# Shipped code is every source line before a file's `#[cfg(test)]` module;
# integration tests and test-only fixture modules are not shipped.
shipped_lines() {
    local pattern="$1" file
    while IFS= read -r file; do
        [[ "${file}" == */testutil.rs ]] && continue
        awk -v f="${file}" -v pat="${pattern}" '
            /^#\[cfg\(test\)\]/ { exit }
            /^[[:space:]]*\/\// { next }
            $0 ~ pat { print f ":" FNR ": " $0 }
        ' "${file}" || { echo "ERROR: cannot scan ${file}" >&2; exit 1; }
    done < <(find crates/*/src -name '*.rs' | sort)
}

# Patterns are awk regular expressions passed through -v, which consumes one
# level of backslashes, so a literal parenthesis or dot is written [(] or [.].
#
# Allows the matches listed in a pattern's allowlist (files) and fails on
# any other.
require_only_in() {
    local what="$1" pattern="$2"
    shift 2
    local hits line file allowed a
    hits="$(shipped_lines "${pattern}")"
    while IFS= read -r line; do
        [[ -n "${line}" ]] || continue
        file="${line%%:*}"
        allowed=false
        for a in "$@"; do [[ "${file}" == "${a}" ]] && allowed=true; done
        [[ "${allowed}" == true ]] || {
            echo "ERROR: ${what}: ${line}" >&2
            exit 1
        }
    done <<<"${hits}"
}

echo "== no subprocesses"
# homedrive starts no programs at all.
require_only_in "only tests may start a process" 'Command::new[(]|process_group[(]|pre_exec[(]'

echo "== durable writes"
# Every file the server or client writes goes through hd-common's fsio
# helpers, which stage, fsync, rename without replacing, and fsync the
# directory. A bare write or rename elsewhere is how acknowledged data gets
# lost in a crash.
require_only_in "write files through hd_common::fsio" \
    'fs::write[(]|File::create[(]|fs::rename[(]|fs::copy[(]|[.]create[(]true[)]|[.]truncate[(]true[)]' \
    crates/hd-common/src/fsio.rs

echo "== deletion allowlist"
# Content is only ever destroyed by the garbage collector after its grace
# periods, by the client's own trash expiry, and by fsio's cleanup of its
# own staging files.
require_only_in "only GC and the client trash may delete" \
    'remove_file[(]|remove_dir[(]|remove_dir_all[(]|set_len[(]' \
    crates/hd-common/src/fsio.rs crates/hd-store/src/gc.rs crates/hd-client/src/trash.rs

echo "== clippy"
cargo clippy --workspace --all-targets --offline --locked -- -D warnings

echo "== Windows client (type-check and lint; scripts/build-windows.sh links it)"
cargo clippy -p hd-client --lib --bins --target x86_64-pc-windows-gnu --offline --locked -- -D warnings

echo "== tests"
cargo test --workspace --offline --locked
