# Dockerfile used to build an image with all glibc binaries
FROM alpine AS builder

ARG TARGETPLATFORM
ENV ARCHIVE_ROOT="/release"

# Upload the release artifacts downloaded to ./release to /release in the build stage, then extract the binary needed for the target platform
COPY ./release/ $ARCHIVE_ROOT

RUN case ${TARGETPLATFORM} in \
    linux/amd64*) ARCHIVE=${ARCHIVE_ROOT}/linux-glibc-x64.zip ;; \
    linux/arm64*) ARCHIVE=${ARCHIVE_ROOT}/linux-glibc-arm64.zip ;; \
    *) exit 1 ;; \
    esac \
    && unzip "$ARCHIVE" -d /out

FROM debian:stable-slim
COPY --from=builder /out/* /bin/
CMD ["/bin/stacks-node", "mainnet"]
