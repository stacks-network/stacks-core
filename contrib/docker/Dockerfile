# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.98.0
ARG DISTROLESS_TAG=nonroot
FROM rust:${RUST_VERSION}-slim-trixie AS chef
ARG RUST_VERSION
ENV RUSTUP_TOOLCHAIN=${RUST_VERSION}

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential mold pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY rust-toolchain.toml ./
# FROM cannot read the checkout; reject an outdated default or an incorrect override.
RUN set -eu; \
    toolchain=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml); \
    if [ "$RUST_VERSION" != "$toolchain" ]; then \
    echo "Pass --build-arg RUST_VERSION=$toolchain to match rust-toolchain.toml" >&2; \
    exit 1; \
    fi; \
    rustup show

ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold"
ARG CARGO_BUILD_JOBS
RUN cargo install cargo-chef --locked --version 0.1.78

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS dependencies
ARG TARGETARCH
ARG CARGO_PROFILE=release-lite
COPY --from=planner /src/recipe.json ./recipe.json

# cargo-chef normalizes workspace versions; its generated lockfile must adjust.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    set -eu; \
    case "$TARGETARCH" in \
    amd64|arm64) ;; \
    *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    case "$CARGO_PROFILE" in \
    release|release-lite) ;; \
    *) echo "Unsupported profile: $CARGO_PROFILE (use release or release-lite)" >&2; exit 1 ;; \
    esac; \
    cargo chef cook --profile "$CARGO_PROFILE" --workspace --features monitoring_prom,slog_json --recipe-path recipe.json

FROM dependencies AS build
COPY . .
# Apply revision metadata after dependency caching.
ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
# Empty means clean, + means modified, and ? means unavailable.
ARG GIT_TREE_CLEAN=?

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    set -eu; \
    cargo build --locked --profile "$CARGO_PROFILE" --workspace --features monitoring_prom,slog_json; \
    mkdir -p /out; \
    find "target/$CARGO_PROFILE" -maxdepth 1 -type f -executable -exec cp '{}' /out/ ';'

RUN install -d -m 0755 -o 65532 -g 65532 /data

FROM gcr.io/distroless/cc-debian13:${DISTROLESS_TAG} AS runtime

COPY --from=build --chown=65532:65532 /data/ /data/
WORKDIR /data
USER 65532:65532

ARG GIT_COMMIT=unknown
ARG STACKS_VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/stacks-network/stacks-core" \
    org.opencontainers.image.revision="$GIT_COMMIT" \
    org.opencontainers.image.version="$STACKS_VERSION"

# Build only this runtime image with --target signer.
FROM runtime AS signer
COPY --from=build /out/stacks-signer /usr/local/bin/
CMD ["/usr/local/bin/stacks-signer", "run", "--config", "/signer-config.toml"]

# The default runtime image contains only the node.
FROM runtime AS node
COPY --from=build /out/stacks-node /usr/local/bin/
CMD ["/usr/local/bin/stacks-node", "mainnet"]
