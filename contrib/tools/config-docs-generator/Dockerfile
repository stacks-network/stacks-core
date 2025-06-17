# Use a specific nightly toolchain for reproducible builds
FROM rustlang/rust@sha256:04690ffa09cddd358b349272173155319f384e57816614eea0840ec7f9422862

RUN apt-get update -y \
 && apt-get install -y --no-install-recommends \
    jq \
 && rm -rf /var/lib/apt/lists/*

# Set the working directory for building
WORKDIR /build

# Copy the entire project root to preserve structure
# Copy from three levels up (project root) to maintain the directory structure
COPY ../../../ /build

RUN useradd -ms /bin/bash docs-builder
RUN chown docs-builder -R /build
USER docs-builder

# Pre-build the config-docs-generator binaries during image build
RUN cargo build --package config-docs-generator --release

# Set the working directory where the project will be mounted at runtime
WORKDIR /project_root

# Set environment variables for generate-config-docs.sh
ENV PROJECT_ROOT=/project_root \
    CARGO_TARGET_DIR=/tmp/stacks-config-docs/target \
    TEMP_DIR=/tmp/stacks-config-docs/doc-generation \
    EXTRACT_DOCS_BIN=/build/target/release/extract-docs \
    GENERATE_MARKDOWN_BIN=/build/target/release/generate-markdown \
    OUTPUT_DIR=/project_root/target/generated-docs \
    SKIP_BUILD=true

# Create the Docker-specific temp directory
RUN mkdir -p /tmp/stacks-config-docs

ENTRYPOINT ["/build/generate-config-docs.sh"]
