# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.91
FROM rust:${RUST_VERSION}-alpine AS build

# Install musl tools for static build
RUN apk add --no-cache build-base git openssl-dev pkgconfig sqlite-dev

WORKDIR /app

# Set a dedicated target directory for stacks-bench artifacts
ENV CARGO_TARGET_DIR=/app/target
# Optional: speed up incremental builds
ENV CARGO_INCREMENTAL=0
# Ensure reproducible builds by stripping symbols
ENV RUSTFLAGS="-C strip=symbols"
# Explicit (these are defaults in rust image, but set to be clear)
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup

# Copy workspace manifest files first (cache dependency resolution)
COPY Cargo.toml Cargo.lock ./
COPY clarity/Cargo.toml clarity/Cargo.toml
COPY clarity-types/Cargo.toml clarity-types/Cargo.toml
COPY stackslib/Cargo.toml stackslib/Cargo.toml
COPY stacks-common/Cargo.toml stacks-common/Cargo.toml
COPY stacks-codec/Cargo.toml stacks-codec/Cargo.toml
COPY stacks-profiler/Cargo.toml stacks-profiler/Cargo.toml
COPY stacks-profiler-macros/Cargo.toml stacks-profiler-macros/Cargo.toml
COPY contrib/stacks-bench/Cargo.toml contrib/stacks-bench/Cargo.toml
COPY libstackerdb/Cargo.toml libstackerdb/Cargo.toml
COPY libsigner/Cargo.toml libsigner/Cargo.toml
COPY stx-genesis/Cargo.toml stx-genesis/Cargo.toml
COPY pox-locking/Cargo.toml pox-locking/Cargo.toml
COPY stacks-signer/Cargo.toml stacks-signer/Cargo.toml
COPY stacks-node/Cargo.toml stacks-node/Cargo.toml
COPY contrib/clarity-cli/Cargo.toml contrib/clarity-cli/Cargo.toml
COPY contrib/stacks-inspect/Cargo.toml contrib/stacks-inspect/Cargo.toml
COPY contrib/stacks-cli/Cargo.toml contrib/stacks-cli/Cargo.toml

# Dummy targets for all workspace members
RUN mkdir -p contrib/stacks-bench/src && echo "// dummy" > contrib/stacks-bench/src/lib.rs && echo 'fn main(){}' > contrib/stacks-bench/src/main.rs && \
    for c in clarity clarity-types stackslib stacks-common stacks-codec stacks-profiler stacks-profiler-macros libstackerdb libsigner stx-genesis pox-locking stacks-signer stacks-node contrib/clarity-cli contrib/stacks-inspect contrib/stacks-cli; do \
      mkdir -p "$c/src"; [ -f "$c/src/lib.rs" ] || echo "// dummy" > "$c/src/lib.rs"; \
    done

# Fetch & build dependency graph (cached)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    cargo fetch

# Now copy full source (respects .dockerignore, i.e. no .git, target, etc.)
COPY . .

# Build only stacks-bench (release, cached)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/app/target \
    cargo build -p stacks-bench --bin stacks-bench --release && \
    install -D /app/target/release/stacks-bench /out/stacks-bench

# Final runtime image
FROM alpine:3.22 AS runtime
RUN apk add --no-cache libssl3 libcrypto3 sqlite-libs
WORKDIR /app
# Copy binary from build stage
COPY --from=build /out/stacks-bench /usr/local/bin/stacks-bench

ENTRYPOINT ["/usr/local/bin/stacks-bench"]
