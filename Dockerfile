# syntax=docker/dockerfile:1
#
# keychute: secrets storage and delivery broker for AI agents.
# See docs/DESIGN.md §7 for how this image is deployed.
#
# The image ships BOTH binaries:
#   /usr/local/bin/keychute-server  — the broker (ENTRYPOINT)
#   /usr/local/bin/keychute         — the client CLI
# The CLI rides along on purpose: DESIGN §7 has the k8s-agent image pull the
# `keychute` CLI out of this image (renovate-pinned ref, exactly like the
# sudo-service CLI), so there is one artifact to build and one digest to pin.

# ---------------------------------------------------------------------------
# Base build environment.
#
# Pinned to the runner's native platform and cross-compiled to TARGETPLATFORM,
# so multi-arch builds need no QEMU emulation: every stage that executes a
# command is pinned to $BUILDPLATFORM, and the one per-target stage (runtime)
# runs nothing at all — it is COPY-only. Unlike the Go services here, the
# build is NOT CGO-free:
# aws-lc-sys (pulled in by rustls via axum-server/reqwest) is a cmake + C
# project, so the builder carries cmake and, when cross-compiling, a GNU cross
# toolchain. aws-lc-sys ships pre-generated bindings for both target triples we
# build, so no bindgen/libclang is required.
#
# Digest-pinned, like every action in .github/workflows and the chart's own app
# image: the monthly scheduled rebuild pushes its result straight into
# values.yaml, so a floating base tag would let an unreviewed base-image change
# roll out on a timer. The tag is kept in the reference for human readability;
# the digest is what actually resolves. Bump both together.
FROM --platform=$BUILDPLATFORM rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS chef
WORKDIR /app

# cargo-chef lets the (very expensive: aws-lc-sys, ring, sqlx, axum) dependency
# build live in its own layer keyed only on Cargo.toml/Cargo.lock, so ordinary
# source edits reuse it. Deliberately no BuildKit --mount=type=cache anywhere in
# this file: cache mounts are not exported by `cache-to type=gha|registry`, so
# in CI everything worth keeping has to be an actual layer.
#
# Installed before anything reads TARGETPLATFORM so the layer is shared by both
# per-arch builds instead of being compiled twice.
RUN cargo install cargo-chef --locked --version 0.1.77

ARG BUILDPLATFORM
ARG TARGETPLATFORM

# Resolve TARGETPLATFORM -> Rust target triple once and stash it for the later
# stages; every RUN below reads /rust-target rather than re-deriving it.
#
# The GNU cross packages are only installed when the target arch differs from
# the build arch — building natively, plain gcc already answers to the
# <arch>-linux-gnu-* tool names via Debian's multiarch aliases (and the cross
# package for the host's own arch does not exist).
RUN set -eux; \
    case "$TARGETPLATFORM" in \
      linux/arm64) triple=aarch64-unknown-linux-gnu; cross_pkgs="gcc-aarch64-linux-gnu g++-aarch64-linux-gnu" ;; \
      linux/amd64) triple=x86_64-unknown-linux-gnu;  cross_pkgs="gcc-x86-64-linux-gnu g++-x86-64-linux-gnu" ;; \
      *) echo "unsupported TARGETPLATFORM: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac; \
    echo "$triple" > /rust-target; \
    if [ "$BUILDPLATFORM" = "$TARGETPLATFORM" ]; then cross_pkgs=""; fi; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      cmake ninja-build $cross_pkgs; \
    rm -rf /var/lib/apt/lists/*; \
    cc="$(echo "$triple" | sed 's/-unknown-linux-gnu$/-linux-gnu-gcc/')"; \
    command -v "$cc" >/dev/null || { echo "missing C compiler $cc for $triple" >&2; exit 1; }; \
    rustup target add "$triple"

# Cross-compilation wiring for cargo/cc/cmake. Both triples are configured
# unconditionally — the entries for the arch we are not building are inert.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
    CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++ \
    AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar

# Strip via cargo rather than binutils: the host `strip` cannot touch a
# cross-built aarch64 binary. Set here (not on the final build) so `chef cook`
# and `cargo build` agree on the profile and nothing is recompiled.
ENV CARGO_PROFILE_RELEASE_STRIP=symbols

# ---------------------------------------------------------------------------
# Recipe: the dependency graph, distilled from the manifests.
FROM chef AS planner
COPY . .
# e2e/ is a test-only crate (it needs a live Postgres and prebuilt binaries) and
# .dockerignore keeps its sources out of the context — but it is a workspace
# member, so cargo still needs its manifest plus *a* lib target to resolve the
# workspace at all. A stub is enough; nothing ever builds it.
RUN mkdir -p e2e/src && : > e2e/src/lib.rs
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------
# Build.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Dependencies only — cached until Cargo.lock or a manifest changes.
RUN cargo chef cook --release --target "$(cat /rust-target)" \
      -p keychute-server -p keychute-cli --recipe-path recipe.json

COPY . .
RUN mkdir -p e2e/src && : > e2e/src/lib.rs
# migrations/ must be present: server/ embeds it at compile time via
# sqlx::migrate!("../migrations"), so a missing directory is a build failure,
# not a runtime one.
RUN set -eux; \
    triple="$(cat /rust-target)"; \
    cargo build --release --locked --target "$triple" \
      -p keychute-server -p keychute-cli; \
    mkdir -p /out; \
    cp "target/${triple}/release/keychute-server" /out/keychute-server; \
    cp "target/${triple}/release/keychute" /out/keychute

# ---------------------------------------------------------------------------
# Runtime rootfs prep.
#
# Everything the runtime image needs beyond the two binaries — the CA bundle
# and the unprivileged account — is produced here, on $BUILDPLATFORM, so the
# per-target runtime stage below can be COPY-only and the whole multi-arch
# build stays free of QEMU. All three artifacts are architecture-independent
# text: /etc/passwd and /etc/group are byte-identical across the arches of
# this same base image apart from the two entries added here, and the
# ca-certificates payload is PEM.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS rootfs
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 65532 keychute; \
    useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin keychute

# ---------------------------------------------------------------------------
# Runtime.
#
# debian-slim rather than distroless/static: the binaries are glibc-linked
# (gnu triples, matching the bookworm builder).
#
# The system CA bundle is shipped but is NOT what the binaries currently trust:
# reqwest is built with `rustls-tls` and sqlx with `tls-rustls`, both of which
# resolve to the compiled-in webpki-roots set (Cargo.lock has webpki-roots and
# no rustls-native-certs), so the brokered proxy and the Pushover notifier
# verify against bundled roots. /etc/ssl/certs is kept as a cheap hedge — it is
# what any later switch to native roots, or any added tool, would look for —
# and costs one COPY of arch-independent PEM. Internal-CA trust for upstream
# origins is a separate, explicit path: config `upstream_ca_path`, loaded in
# server/src/state.rs.
#
# No RUN in this stage: it is the only per-target stage, and keeping it
# COPY-only is what lets the arm64 leg build on an amd64 runner without QEMU.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime
COPY --from=rootfs /etc/passwd /etc/passwd
COPY --from=rootfs /etc/group /etc/group
COPY --from=rootfs /usr/share/ca-certificates /usr/share/ca-certificates
COPY --from=rootfs /etc/ssl/certs /etc/ssl/certs

COPY --from=builder /out/keychute-server /usr/local/bin/keychute-server
COPY --from=builder /out/keychute /usr/local/bin/keychute

USER 65532:65532
# Documentation only — the actual bind address comes from the config file
# (listen_addr); the chart owns the real port.
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/keychute-server"]
