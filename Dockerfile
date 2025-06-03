# Use a specific nightly toolchain for reproducible builds
FROM rustlang/rust@sha256:04690ffa09cddd358b349272173155319f384e57816614eea0840ec7f9422862

# Set the working directory for building
WORKDIR /build

# Copy the entire project to build the binaries
COPY . .

# Pre-build the config-docs-generator binaries during image build
RUN cargo build --package config-docs-generator --release

# Set the working directory where the project will be mounted at runtime
WORKDIR /project_root

# Set environment variables for generate-config-docs.sh
ENV PROJECT_ROOT=/project_root
ENV BUILD_ROOT=/build
ENV CARGO_HOME=/project_root/.cargo
ENV EXTRACT_DOCS_BIN=/build/target/release/extract-docs
ENV GENERATE_MARKDOWN_BIN=/build/target/release/generate-markdown
ENV SKIP_BUILD=true

# Set the entrypoint to run the config docs generation script
ENTRYPOINT ["/build/contrib/tools/config-docs-generator/generate-config-docs.sh"]
