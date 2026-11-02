# The gate toolbox: the compiler, linters, and test tools every gate depends
# on, so a workstation needs nothing but rootless Podman. scripts/toolbox.sh
# builds this image and runs the gates inside it.
#
# The base is the official Alpine image pinned by digest, the same release the
# shipped image (Containerfile) runs on, so the gates and the product resolve
# one musl and one OpenSSL rather than two that may drift.
#
# This image is a developer tool, not a shipped artifact: it is never
# published, never serves traffic, and only runs this repository's gates. It
# declares no USER on purpose: scripts/toolbox.sh maps the invoking user in
# with --userns=keep-id, so a gate leaves no root-owned files in the tree.

ARG ALPINE_DIGEST=sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

FROM docker.io/library/alpine:3.23.5@${ALPINE_DIGEST}

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# build-base and musl-dev are the C toolchain and libc the Rust linker
# drives. openssl-dev and openssl-libs-static are the libcrypto hd-sys binds,
# linked statically into the shipped binary. coreutils, findutils, gawk,
# grep, and sed replace busybox's applets with the GNU ones the scripts are
# written against. rclone is a test-only tool: the WebDAV interop test
# drives the real client against the server (it is not in the shipped
# image).
RUN apk add --no-cache \
        bash \
        build-base \
        coreutils \
        curl \
        diffutils \
        file \
        findutils \
        gawk \
        git \
        grep \
        make \
        musl-dev \
        openssl \
        openssl-dev \
        openssl-libs-static \
        pkgconf \
        python3 \
        rclone \
        sed \
        shellcheck \
        tar

ENV RUSTUP_HOME=/opt/rustup
ENV PATH="/opt/cargo/bin:${PATH}"
COPY scripts/install-rust.sh /tmp/installers/
RUN CARGO_HOME=/opt/cargo /tmp/installers/install-rust.sh \
    && chmod -R a+rX /opt/rustup /opt/cargo \
    && rm -rf /tmp/installers

# scripts/toolbox.sh runs a command directly when it sees this rather than
# starting another container, so gates that call each other do not nest.
ENV HD_IN_TOOLBOX=1
# The rclone interop test fails rather than skips when rclone is missing here.
ENV HD_REQUIRE_RCLONE=1

# Cargo and the gates want a writable HOME. The container runs as whichever
# uid invoked it, so this is world-writable with the sticky bit.
RUN mkdir -p /toolbox-home \
    && chmod 1777 /toolbox-home \
    && git config --system --add safe.directory '*'

WORKDIR /work
