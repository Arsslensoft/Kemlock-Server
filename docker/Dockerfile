# syntax=docker/dockerfile:1.18
#
# Kemlock Server: one static musl binary per architecture on a distroless static base.
#
#   docker buildx build -f docker/Dockerfile --platform linux/amd64,linux/arm64 -t kemlock-server .
#   docker buildx build -f docker/Dockerfile --target binaries --output type=local,dest=out .
#
# Why cargo-zigbuild. aws-lc-rs compiles C and assembly (aws-lc-sys), so a musl build needs a C
# cross toolchain for every target. Zig's `zig cc` is one pinned download that targets musl on
# amd64, arm64, arm/v7, arm/v6, 386, ppc64le, s390x and riscv64 from one build host, with its own
# musl and no sysroots to install. The alternatives were musl.cc or distro cross-gcc packages (one
# toolchain per architecture, unpinned apt packages, so builds drift) and building each
# architecture under QEMU (about ten times slower, and no better pinned). The builder runs on the
# build platform, so nothing here runs under emulation; QEMU is used only to start the finished
# images in CI.
#
# Reproducible: every base image is named by digest, the Zig tarball by SHA-256, cargo-zigbuild by
# version with --locked, and the build uses `cargo build --locked`, --remap-path-prefix and
# SOURCE_DATE_EPOCH. tools/verify.sh rebuilds a tag this way and compares the binaries.

ARG RUST_IMAGE=rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea
ARG NODE_IMAGE=node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# ---------------------------------------------------------------------------------------------
# The two WebAssembly modules the web vault loads (web/scripts/build-wasm.sh): wasm-pack and
# binaryen's wasm-opt pinned by checksum, the Rust toolchain pinned above.
# ---------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS wasm
ARG BUILDARCH
ARG WASM_PACK_VERSION=0.13.1
ARG WASM_PACK_SHA256_AMD64=c539d91ccab2591a7e975bcf82c82e1911b03335c80aa83d67ad25ed2ad06539
ARG WASM_PACK_SHA256_ARM64=2e65038769f8bbaa5fc237ad4bb523e692df99458cbd3e3d92525b89d8762379
ARG BINARYEN_VERSION=123
ARG BINARYEN_SHA256_AMD64=e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe
ARG BINARYEN_SHA256_ARM64=4b6bd61ba6cd3b18c993b4657d93426c782f9b91b74be0d38018cd8be1319376
RUN set -eu;     case "${BUILDARCH}" in       amd64) arch=x86_64; wp="${WASM_PACK_SHA256_AMD64}"; bn="${BINARYEN_SHA256_AMD64}" ;;       arm64) arch=aarch64; wp="${WASM_PACK_SHA256_ARM64}"; bn="${BINARYEN_SHA256_ARM64}" ;;       *) echo "unsupported build host: ${BUILDARCH}" >&2; exit 1 ;;     esac;     curl -fsSL -o /tmp/wasm-pack.tar.gz       "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-${arch}-unknown-linux-musl.tar.gz";     echo "${wp}  /tmp/wasm-pack.tar.gz" | sha256sum -c -;     tar -xzf /tmp/wasm-pack.tar.gz -C /tmp;     install -m 0755 "/tmp/wasm-pack-v${WASM_PACK_VERSION}-${arch}-unknown-linux-musl/wasm-pack" /usr/local/bin/;     curl -fsSL -o /tmp/binaryen.tar.gz       "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-${arch}-linux.tar.gz";     echo "${bn}  /tmp/binaryen.tar.gz" | sha256sum -c -;     tar -xzf /tmp/binaryen.tar.gz -C /opt;     ln -s "/opt/binaryen-version_${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt;     rm -rf /tmp/wasm-pack* /tmp/binaryen.tar.gz;     rustup target add wasm32-unknown-unknown
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked     --mount=type=cache,target=/src/target,id=kemlock-wasm-target     set -eu;     web/scripts/build-wasm.sh;     mkdir -p /pkg;     cp -a web/src/crypto/pkg /pkg/crypto;     cp -a web/src/import/pkg /pkg/import

# Only the two packages, for web development without Rust:
#   docker build --target wasm-out --output web/wasm-pkg -f docker/Dockerfile .
FROM scratch AS wasm-out
COPY --from=wasm /pkg /

# ---------------------------------------------------------------------------------------------
# The web vault. `web/` has not landed yet, so WITH_WEB=auto builds it only when web/package-lock.json
# exists; `true` makes a missing web/ an error (use it for releases), `false` skips it.
# ---------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
ARG WITH_WEB=auto
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} NODE_ENV=production
RUN --mount=type=bind,source=.,target=/src,rw \
    --mount=type=bind,from=wasm,source=/pkg,target=/wasm \
    --mount=type=cache,target=/root/.npm \
    set -eu; \
    mkdir -p /out; \
    if [ "${WITH_WEB}" != "false" ] && [ -f /src/web/package-lock.json ]; then \
      cd /src/web; \
      rm -rf src/crypto/pkg src/import/pkg; \
      cp -a /wasm/crypto src/crypto/pkg; \
      cp -a /wasm/import src/import/pkg; \
      npm ci --include=dev --ignore-scripts --no-audit --no-fund; \
      npm run build; \
      cp -a dist/. /out/; \
    elif [ "${WITH_WEB}" = "true" ]; then \
      echo "WITH_WEB=true but web/package-lock.json is missing" >&2; exit 1; \
    else \
      echo "web/ has not landed: building the API without the web vault" >&2; \
    fi

# ---------------------------------------------------------------------------------------------
# The C and Rust toolchain: Zig pinned by checksum, cargo-zigbuild pinned by version.
# ---------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS toolchain
ARG BUILDARCH
ARG ZIG_VERSION=0.15.2
ARG ZIG_SHA256_AMD64=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239
ARG ZIG_SHA256_ARM64=958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f
ARG CARGO_ZIGBUILD_VERSION=0.24.1
# xz-utils only unpacks Zig; it does not end up in any build output.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends xz-utils; \
    rm -rf /var/lib/apt/lists/*; \
    case "${BUILDARCH}" in \
      amd64) zig_arch=x86_64; zig_sha="${ZIG_SHA256_AMD64}" ;; \
      arm64) zig_arch=aarch64; zig_sha="${ZIG_SHA256_ARM64}" ;; \
      *) echo "unsupported build host: ${BUILDARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz"; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/zig; \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1; \
    rm /tmp/zig.tar.xz
ENV PATH=/opt/zig:${PATH}
RUN cargo install --locked --version "${CARGO_ZIGBUILD_VERSION}" cargo-zigbuild

# ---------------------------------------------------------------------------------------------
# The binaries, for the platform being built (TARGETPLATFORM), cross-compiled on the build host.
# ---------------------------------------------------------------------------------------------
FROM toolchain AS build
ARG TARGETARCH
ARG TARGETVARIANT
ARG SOURCE_DATE_EPOCH=0
# Where the server's build expects the web vault. Change it with the build that embeds it.
ARG WEB_DIST_DIR=web/dist
# The commit the binary reports on /kem/v1/config and links the source to (AGPL-3.0 section 13).
# The build context has no .git, so the caller passes it; empty leaves it out.
ARG KEMLOCK_GIT_COMMIT=
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} TZ=UTC KEMLOCK_GIT_COMMIT=${KEMLOCK_GIT_COMMIT}
WORKDIR /src
COPY . .
COPY --from=web /out/ /src/${WEB_DIST_DIR}/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/cache/target,id=kemlock-target-${TARGETARCH}${TARGETVARIANT} \
    --mount=type=cache,target=/cache/zig,id=kemlock-zig \
    set -eux; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64)    rust_target=x86_64-unknown-linux-musl ;; \
      arm64)    rust_target=aarch64-unknown-linux-musl ;; \
      armv7)    rust_target=armv7-unknown-linux-musleabihf ;; \
      armv6)    rust_target=arm-unknown-linux-musleabihf ;; \
      386)      rust_target=i686-unknown-linux-musl ;; \
      ppc64le)  rust_target=powerpc64le-unknown-linux-musl ;; \
      s390x)    rust_target=s390x-unknown-linux-musl ;; \
      riscv64)  rust_target=riscv64gc-unknown-linux-musl ;; \
      *) echo "no Rust target for ${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${rust_target}"; \
    # The Pi Zero and the first Pi are ARMv6: keep aws-lc's C and assembly at that level.
    export CFLAGS_arm_unknown_linux_musleabihf="-mcpu=arm1176jzf_s"; \
    export CARGO_TARGET_DIR=/cache/target \
           ZIG_GLOBAL_CACHE_DIR=/cache/zig/global \
           ZIG_LOCAL_CACHE_DIR=/cache/zig/local \
           CARGO_INCREMENTAL=0 \
           CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
           CARGO_PROFILE_RELEASE_LTO=fat \
           CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
           CARGO_PROFILE_RELEASE_STRIP=symbols \
           RUSTFLAGS="--remap-path-prefix=/src=/kemlock --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup"; \
    # The web vault goes into the binary when the web stage built one (rust-embed needs web/dist).
    features=""; \
    if [ -f "/src/${WEB_DIST_DIR}/index.html" ]; then features="--features kemlock-server/web"; fi; \
    cargo zigbuild --release --locked --target "${rust_target}" -p kemlock-server -p kemlock-cli ${features}; \
    mkdir -p /out; \
    cp "/cache/target/${rust_target}/release/kemlock-server" "/cache/target/${rust_target}/release/kemlock-cli" /out/; \
    # An empty /data to copy into the final image with the right owner: distroless has no shell.
    mkdir -p /rootfs/data

# `--target binaries` writes just the executables, one folder per platform: what the release
# archives and tools/verify.sh use, built by the same stage as the image.
FROM scratch AS binaries
COPY --from=build /out/ /
# ---------------------------------------------------------------------------------------------
# The licence notices every image carries (/usr/share/doc/kemlock-server). THIRD-PARTY-NOTICES.txt
# is generated, not committed: release.yml runs tools/third-party-notices.sh before the build, and
# a local `docker build` needs the same first. The `binaries` target does not need it.
# ---------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS notices
WORKDIR /src
COPY LICENSE NOTICE ./
# A glob, so a missing file is caught by the check below with a message instead of a COPY error.
COPY THIRD-PARTY-NOTICES.tx[t] ./
RUN set -eu; \
    test -s THIRD-PARTY-NOTICES.txt || { \
      echo "THIRD-PARTY-NOTICES.txt is missing: run tools/third-party-notices.sh before docker build" >&2; \
      exit 1; }; \
    mkdir -p /out; \
    cp LICENSE NOTICE THIRD-PARTY-NOTICES.txt /out/

# ---------------------------------------------------------------------------------------------
# What every image shares. Distroless static is scratch plus CA roots, tzdata and a nonroot user
# (65532).
# ---------------------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS base
LABEL org.opencontainers.image.title="Kemlock Server" \
      org.opencontainers.image.description="Self-hosted vault server for Kemlock, Amethystora Vault and Bitwarden apps" \
      org.opencontainers.image.source="https://github.com/arsslensoft/kemlock-server" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build --chown=65532:65532 /rootfs/data /data
# The licence texts the binary and the web vault require to travel with them.
COPY --from=notices /out/ /usr/share/doc/kemlock-server/
# Everything the server writes is under /data (database, server.key, attachments, backups), so
# the root filesystem can be read-only. Vaultwarden's DATA_FOLDER name is the one it reads.
ENV DATA_FOLDER=/data
WORKDIR /data
VOLUME ["/data"]
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM
# The image has no shell and no curl: the server asks its own /alive over loopback and exits 0 or 1.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/kemlock-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/kemlock-server"]

# ---------------------------------------------------------------------------------------------
# `--target tools`: the image plus kemlock-cli (restore, the restore drill, import-vaultwarden,
# migrate), for one-off runs:
#   docker run --rm -v ./kemlock-data:/data --entrypoint /usr/local/bin/kemlock-cli <tools> restore ...
# The CLI links the whole server library, so shipping it in the default image doubled its size.
# ---------------------------------------------------------------------------------------------
FROM base AS tools
COPY --from=build /out/kemlock-server /out/kemlock-cli /usr/local/bin/

# ---------------------------------------------------------------------------------------------
# The image: the server binary and nothing else. Last, so a plain `docker build` makes it.
# ---------------------------------------------------------------------------------------------
FROM base AS image
COPY --from=build /out/kemlock-server /usr/local/bin/
