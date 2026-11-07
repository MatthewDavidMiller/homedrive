# The homedrive server runtime image.
#
# Both stages start from the official Alpine image pinned by digest -- the
# same release and digest as the toolbox (tools/toolbox/Dockerfile) -- so the
# binary is built against the musl and libcrypto it ships with. The builder
# installs the repository-pinned Rust toolchain through the same
# checksum-verified installer the gates use, rather than trusting a second
# base image for the compiler.
#
# The build stage also makes the Linux sync client for releases, which
# `scripts/build-linux.sh` takes from it. It is a build of its own, so libssl,
# which only the client's feature pulls in, stays out of the server, and the
# runtime stage never copies it.
#
# The binary is fully static (musl, static-pie, libcrypto linked in), so the
# runtime stage adds no package: Alpine is there for its shell and tools when
# an operator runs `podman exec`, not for anything the server loads.
#
# Run it read-only, as the non-root user it declares, with the store on its
# own volume and the users file as a Podman secret; see docs/DEPLOYMENT.md.

ARG ALPINE_DIGEST=sha256:5c216c9767869f6ec7c4718977601d52f087c5c7bf2fdfb198e403f6b48ec40d

FROM docker.io/library/alpine:3.23.8@${ALPINE_DIGEST} AS build

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# Upgrade first: the pinned base ships whatever was current when it was
# built, and the static libcrypto linked into the binary should be the
# newest fixed release, not that snapshot.
RUN apk upgrade --no-cache \
    && apk add --no-cache bash build-base curl musl-dev openssl-dev openssl-libs-static

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH="/opt/cargo/bin:${PATH}"
COPY scripts/install-rust.sh /tmp/install-rust.sh
RUN /tmp/install-rust.sh --build-only

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml LICENSE ./
COPY .cargo .cargo
COPY crates crates

# static-pie against musl with libcrypto linked in; RUSTFLAGS replaces the
# development crt-static=off setting in .cargo/config.toml.
RUN HD_OPENSSL_STATIC=1 \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie" \
    cargo build --release --locked --offline --target x86_64-unknown-linux-musl \
        -p hd-server --bin hd-server \
    && install -m 0755 target/x86_64-unknown-linux-musl/release/hd-server /hd-server

RUN HD_OPENSSL_STATIC=1 \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie" \
    cargo build --release --locked --offline --target x86_64-unknown-linux-musl \
        -p hd-client --bin homedrive \
    && install -m 0755 target/x86_64-unknown-linux-musl/release/homedrive /homedrive


FROM docker.io/library/alpine:3.23.8@${ALPINE_DIGEST}

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# apk upgrade brings the packages preinstalled in the pinned base to their
# fixed releases, which the lock review's scan reports otherwise.
RUN apk upgrade --no-cache

COPY --from=build /hd-server /usr/local/bin/hd-server
COPY crates/hd-server/THIRD_PARTY_NOTICES.txt /usr/share/doc/homedrive/THIRD_PARTY_NOTICES.txt

RUN addgroup -S -g 10001 homedrive \
    && adduser -S -D -H -u 10001 -G homedrive -h /var/lib/homedrive -s /sbin/nologin homedrive \
    && install -d -m 0700 -o homedrive -g homedrive /var/lib/homedrive /srv/exports

ENV PATH="/usr/local/bin:/usr/bin:/bin" \
    HD_LISTEN=0.0.0.0:8080 \
    HD_DATA_DIR=/var/lib/homedrive

USER 10001:10001
WORKDIR /var/lib/homedrive
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/usr/local/bin/hd-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hd-server"]
CMD ["serve"]
