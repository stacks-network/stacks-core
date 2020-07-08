FROM rust:stretch as build

WORKDIR /src

COPY . .

RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y git musl-tools

ENV CC musl-gcc
ENV CC_x86_64_unknown_linux_musl musl-gcc
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER musl-gcc

RUN mkdir /out

RUN cd testnet/stacks-node && cargo build --features "monitoring_prom" --release --target x86_64-unknown-linux-musl
RUN cd testnet/bitcoin-neon-controller && cargo build --release --target x86_64-unknown-linux-musl

RUN cp target/x86_64-unknown-linux-musl/release/stacks-node /out
RUN cp target/x86_64-unknown-linux-musl/release/bitcoin-neon-controller /out

FROM alpine

COPY --from=build /out/ /bin/

CMD ["stacks-node", "argon"]