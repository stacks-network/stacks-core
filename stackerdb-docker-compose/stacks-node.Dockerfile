FROM rust:alpine as build

RUN apk add --no-cache musl-dev git

RUN git clone https://github.com/stacks-network/stacks-blockchain.git

WORKDIR /stacks-blockchain

RUN git checkout feat/stackerdb-sync

RUN mkdir /out

RUN cd testnet/stacks-node && cargo build --features monitoring_prom,slog_json --release

RUN cp target/release/stacks-node /out

FROM alpine

COPY --from=build /out/ /bin/

CMD ["stacks-node", "start", "--config=/bin/config/stacks.toml"]
