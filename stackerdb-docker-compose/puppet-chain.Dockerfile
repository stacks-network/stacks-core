FROM rust as build

RUN git clone https://github.com/stacks-network/stacks-blockchain.git

WORKDIR /stacks-blockchain

RUN cd contrib/tools/puppet-chain && cargo build --release

FROM debian

COPY --from=build /stacks-blockchain/contrib/tools/puppet-chain/target/release /bin/

CMD ["puppet-chain", "/config/puppet.toml"]
