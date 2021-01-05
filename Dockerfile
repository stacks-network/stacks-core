FROM rust:alpine as build

ARG CARGO_PKG_VERSION

ENV CARGO_PKG_NAME=stacks-blockchain \
    CARGO_PKG_VERSION=${CARGO_PKG_VERSION}

WORKDIR /src

COPY . .

RUN apk add --no-cache musl-dev

RUN mkdir /out

RUN cd testnet/stacks-node && cargo build --features monitoring_prom,slog_json --release
RUN cd testnet/bitcoin-neon-controller && cargo build --release

RUN cp target/release/stacks-node /out
RUN cp target/release/bitcoin-neon-controller /out

FROM alpine

COPY --from=build /out/ /bin/

CMD ["stacks-node", "xenon"]
