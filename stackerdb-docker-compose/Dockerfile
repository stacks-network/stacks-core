FROM rust as build

RUN git clone https://github.com/stacks-network/stacks-blockchain.git

WORKDIR /stacks-blockchain

RUN cd testnet/stacks-node && cargo build --features monitoring_prom,slog_json --release

RUN ls /stacks-blockchain/target/release

FROM alpine

COPY --from=build /stacks-blockchain/target/release/stacks-node /bin/

CMD ["stacks-node", "start", "--config=/bin/config/stacks.toml"]
