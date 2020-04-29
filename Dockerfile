FROM rust:latest as build

WORKDIR /src

COPY . .

RUN cargo build --release --workspace=./
RUN cd /src/target/release && \
    mkdir /out && \
    cp blockstack-core /out && cp blockstack-cli /out && cp clarity-cli /out && cp stacks-node /out

FROM debian:stable-slim

COPY --from=build /out/ /bin/

CMD ["stacks-node", "neon"]