FROM rust:alpine as build

ARG STACKS_NODE_VERSION="No Version Info"
ARG GIT_BRANCH='No Branch Info'
ARG GIT_COMMIT='No Commit Info'

WORKDIR /src

COPY . .

RUN apk add --no-cache musl-dev

RUN mkdir /out

RUN cd testnet/stacks-node && cargo build --release --bin mempool-analyzer

RUN cp target/release/mempool-analyzer /out

FROM alpine

COPY --from=build /out/ /bin/

CMD ["mempool-analyzer", "/hirosystems/data", "600000"]
