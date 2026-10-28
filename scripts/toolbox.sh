#!/bin/bash
# Run a gate command inside the toolbox image.
#
# Usage: ./scripts/toolbox.sh <command> [args...]
#        ./scripts/toolbox.sh --build          Build (or rebuild) the image only
#        ./scripts/toolbox.sh --shell          Interactive shell in the toolbox
#        ./scripts/toolbox.sh --publish PORT <command> [args...]
#                                              As the first form, with the
#                                              container's PORT published on
#                                              127.0.0.1:PORT (make dev)
#
# Rootless Podman is the only thing this needs from the host. Every compiler,
# linter, and test tool the gates call lives in tools/toolbox.
#
# The repository is bind-mounted at the same absolute path it occupies on the
# host, so paths in compiler output and test failures match the host's tree.

set -euo pipefail

# Already inside the toolbox: run the command rather than nesting a container.
if [[ -n "${HD_IN_TOOLBOX:-}" && "${1:-}" != "--build" ]]; then
    [[ $# -gt 0 ]] || { echo "Usage: $0 <command> [args...]" >&2; exit 2; }
    exec "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${PROJECT_ROOT}/tools/toolbox/Dockerfile"
HOME_VOLUME="${HD_TOOLBOX_HOME_VOLUME:-homedrive-toolbox-home}"
TOOLBOX_REPO=homedrive-toolbox

command -v podman >/dev/null || { echo "ERROR: podman is required" >&2; exit 1; }
if [[ "$(id -u)" -eq 0 ]]; then
    echo "ERROR: run the toolbox as a regular user (rootless Podman)" >&2
    exit 1
fi

# The tag is the digest of everything that determines what lands in the
# image, so a changed pin names a different image and the rebuild happens on
# the next gate run rather than whenever somebody remembers to force one.
toolbox_tag() {
    local digest
    digest="$(cat "${DOCKERFILE}" "${PROJECT_ROOT}/scripts/install-rust.sh" |
        sha256sum | cut -c1-16)"
    printf '%s:%s\n' "${TOOLBOX_REPO}" "${digest}"
}

# Drop the builds this one replaces; content-hash tags otherwise strand every
# superseded image. A failure means a gate is still using it, and it is
# collected on the next build.
prune_superseded_toolboxes() {
    local keep="$1" image
    while read -r image; do
        [[ -n "${image}" && "${image}" != "${keep}" ]] || continue
        podman rmi "${image}" >/dev/null 2>&1 || true
    done < <(podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null |
        sed 's|^localhost/||' | grep "^${TOOLBOX_REPO}:" || true)
}

build_toolbox() {
    local tag="$1"
    echo "=== Building toolbox image ${tag} ===" >&2
    # The platform is explicit because the base is pinned by manifest digest,
    # and Podman resolves a digest to whatever variant it already holds
    # locally: an arm64 copy pulled by another project would otherwise yield
    # an emulated arm64 toolbox.
    local platform
    case "$(uname -m)" in
        x86_64 | amd64) platform="linux/amd64" ;;
        aarch64 | arm64) platform="linux/arm64" ;;
        *) echo "ERROR: unsupported workstation architecture $(uname -m)" >&2; return 1 ;;
    esac
    podman build --format docker --platform "${platform}" \
        -f "${DOCKERFILE}" -t "${tag}" "${PROJECT_ROOT}"
    prune_superseded_toolboxes "${tag}"
}

main() {
    local tag mode="run" publish=""
    if [[ "${1:-}" == "--publish" ]]; then
        publish="${2:?--publish needs a port}"
        [[ "${publish}" =~ ^[0-9]+$ ]] || { echo "ERROR: --publish needs a port number" >&2; exit 2; }
        shift 2
    fi
    case "${1:-}" in
        --build) mode="build"; shift ;;
        --shell) mode="shell"; shift ;;
        -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}"; exit 0 ;;
        "") echo "Usage: $0 <command> [args...]" >&2; exit 2 ;;
    esac

    tag="$(toolbox_tag)"
    if [[ "${mode}" == "build" ]]; then
        build_toolbox "${tag}"
        exit 0
    fi
    podman image inspect "${tag}" >/dev/null 2>&1 || build_toolbox "${tag}"

    local -a args=(
        run --rm
        --userns=keep-id
        -v "${PROJECT_ROOT}:${PROJECT_ROOT}:Z"
        -v "${HOME_VOLUME}:/toolbox-home"
        -w "${PROJECT_ROOT}"
        -e HOME=/toolbox-home
    )
    if [[ -n "${publish}" ]]; then
        # Loopback only: the development server is never reachable from
        # another machine.
        args+=(-p "127.0.0.1:${publish}:${publish}")
        [[ -t 0 ]] && args+=(-it)
        for name in "${!HD_@}"; do
            [[ "${name}" == HD_IN_TOOLBOX ]] || args+=(-e "${name}")
        done
    else
        # No crate ever comes from a registry, so the gates need no network.
        args+=(--network=none)
    fi
    if [[ "${mode}" == "shell" ]]; then
        args+=(-it "${tag}" bash)
    else
        args+=("${tag}" "$@")
    fi
    exec podman "${args[@]}"
}

main "$@"
