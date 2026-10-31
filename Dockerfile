FROM rust:bookworm AS build

ARG STACKS_NODE_VERSION="No Version Info"
ARG CUSTOM_VERSION_STRING
ARG GIT_BRANCH='No Branch Info'
ARG GIT_COMMIT='No Commit Info'

WORKDIR /src
COPY . .
RUN mkdir /out
RUN rustup toolchain install stable
RUN cargo build --locked --features monitoring_prom,slog_json --release
RUN cp -R target/release/. /out

FROM debian:bookworm-slim
COPY --from=build /out/stacks-node /out/stacks-signer /out/stacks-inspect /bin/
CMD ["stacks-node", "mainnet"]
