FROM rust as builder
WORKDIR /src/bitcoin-neon-controller
COPY . .
RUN cd /src/bitcoin-neon-controller && cargo build --target x86_64-unknown-linux-gnu --release
RUN cargo install --target x86_64-unknown-linux-gnu --path /src/bitcoin-neon-controller

FROM alpine
ARG GLIBC_VERSION="2.31-r0"
ARG GLIBC_URL="https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-${GLIBC_VERSION}.apk"
ARG GLIBC_BIN_URL="https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-bin-${GLIBC_VERSION}.apk"
ARG GLIBC_I18N_URL="https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-i18n-${GLIBC_VERSION}.apk"
WORKDIR /
RUN apk --no-cache add --update ca-certificates curl libgcc \
    && curl -L -s -o /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && curl -L -s -o /tmp/glibc-${GLIBC_VERSION}.apk ${GLIBC_URL} \
    && curl -L -s -o /tmp/glibc-bin-${GLIBC_VERSION}.apk ${GLIBC_BIN_URL} \
    && curl -L -s -o /tmp/glibc-i18n-${GLIBC_VERSION}.apk ${GLIBC_I18N_URL} \
    && apk --no-cache add /tmp/glibc-${GLIBC_VERSION}.apk /tmp/glibc-bin-${GLIBC_VERSION}.apk /tmp/glibc-i18n-${GLIBC_VERSION}.apk \
    && /usr/glibc-compat/sbin/ldconfig /usr/lib /lib \
    && rm /tmp/glibc-${GLIBC_VERSION}.apk /tmp/glibc-bin-${GLIBC_VERSION}.apk /tmp/glibc-i18n-${GLIBC_VERSION}.apk
COPY --from=builder /usr/local/cargo/bin/bitcoin-neon-controller /usr/local/bin/bitcoin-neon-controller
COPY config.toml.default /etc/bitcoin-neon-controller/Config.toml
EXPOSE 3000
CMD ["/usr/local/bin/bitcoin-neon-controller /etc/bitcoin-neon-controller/Config.toml"]
