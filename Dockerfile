FROM rust:latest

WORKDIR /src/

# Hacks to cache the build dependencies.

RUN USER=root cargo new --bin blockstack-core
WORKDIR /src/blockstack-core

COPY ./Cargo.toml ./Cargo.toml

RUN cargo build --release
RUN rm src/*.rs
RUN rm ./target/release/deps/blockstack_core*

# copy your source tree
COPY . .

RUN cargo build --release
RUN cargo install --path .

CMD ["blockstack-core"]
