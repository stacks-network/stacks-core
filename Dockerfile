FROM rust:stretch as build

WORKDIR /src

COPY . .

RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y musl-tools

RUN CC=musl-gcc \
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --target x86_64-unknown-linux-musl --workspace=./

RUN cd /src/target/x86_64-unknown-linux-musl/release && \
    mkdir /out && \
    cp blockstack-core /out && cp blockstack-cli /out && cp clarity-cli /out && cp stacks-node /out

FROM alpine

COPY --from=build /out/ /bin/

CMD ["stacks-node", "neon"]