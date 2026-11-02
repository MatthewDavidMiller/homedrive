# The Windows sync client's cross-build: mingw-w64 and a static OpenSSL
# for Windows, built from source checked against its published SHA-256.
# scripts/build-windows.sh runs it and writes dist/homedrive.exe.
#
# The base is the same official Alpine image, pinned by the same digest,
# as the toolbox and the runtime image.

ARG ALPINE_DIGEST=sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

FROM docker.io/library/alpine:3.23.5@${ALPINE_DIGEST}

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN apk add --no-cache bash build-base curl linux-headers make mingw-w64-gcc perl

# OpenSSL 3.5.9, the release the toolbox's Alpine ships. The checksum is
# the one openssl.org and the GitHub release both publish.
ARG OPENSSL_VERSION=3.5.9
ARG OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
RUN curl -fsSLo /tmp/openssl.tar.gz \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && printf '%s  %s\n' "${OPENSSL_SHA256}" /tmp/openssl.tar.gz | sha256sum -c - \
    && mkdir /tmp/openssl && tar -C /tmp/openssl --strip-components=1 -xzf /tmp/openssl.tar.gz \
    && cd /tmp/openssl \
    && ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- \
        no-shared no-tests no-docs --prefix=/opt/openssl-win --libdir=lib \
    && make -j"$(nproc)" >/dev/null \
    && make install_sw >/dev/null \
    && rm -rf /tmp/openssl /tmp/openssl.tar.gz

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH="/opt/cargo/bin:${PATH}"
COPY scripts/install-rust.sh /tmp/install-rust.sh
RUN /tmp/install-rust.sh && chmod -R a+rX /opt/rustup /opt/cargo && rm /tmp/install-rust.sh

ENV CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    HD_OPENSSL_STATIC=1 \
    HD_OPENSSL_LIB_DIR=/opt/openssl-win/lib

RUN mkdir -p /build-home && chmod 1777 /build-home
WORKDIR /work
