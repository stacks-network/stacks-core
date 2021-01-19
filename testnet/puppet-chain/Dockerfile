FROM rust:stretch as builder

WORKDIR /src
COPY . .

RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y musl-tools

RUN CC=musl-gcc \
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --target x86_64-unknown-linux-musl

FROM alpine
WORKDIR /
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/bitcoin-neon-controller /bin/
COPY config.toml.default /etc/bitcoin-neon-controller/Config.toml
EXPOSE 3000
CMD ["/bin/bitcoin-neon-controller", "/etc/bitcoin-neon-controller/Config.toml"]
