FROM rust:latest as build

WORKDIR /src/blockstack-core

COPY . .

RUN cargo install --path . --root .

FROM debian:stable-slim
COPY --from=build /src/blockstack-core/bin /bin

CMD ["blockstack-core"]
