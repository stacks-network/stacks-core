FROM rust:latest

WORKDIR /src/blockstack-core

COPY . .

RUN cargo build --release
RUN cargo install --path .

CMD ["blockstack-core"]
