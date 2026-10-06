# Build Docker images from source

Run from the repository root with Bash, awk and Docker with BuildKit enabled:

```bash
./contrib/docker/build.sh
```

This builds `stacks-core:<version>` and `stacks-signer:<version>`, using the workspace
version in `Cargo.toml` and Rust version in `rust-toolchain.toml`. Git supplies
revision metadata when available. Version output includes the full commit SHA,
with `+` for a modified checkout (including staged or untracked changes), `?` when
Git status is unavailable, and no suffix for a clean checkout. No host Rust
installation is needed.

The builder uses `rust:<rust-version>-slim-trixie`, locked dependencies, the
`release-lite` profile and `monitoring_prom,slog_json`, linked with mold. The node
image contains only `stacks-node`; the signer image contains only `stacks-signer`.
Both use `gcr.io/distroless/cc-debian13:nonroot` at runtime.

## Build options

Arguments to the wrapper apply to both images:

```bash
./contrib/docker/build.sh --platform linux/amd64
```

Supported platforms are `linux/amd64` and `linux/arm64`; the default is the builder's
platform. Foreign-platform builds require emulation or a matching native builder.
Both use Rust's default CPU baseline for their target.

The default `release-lite` profile uses thin LTO. For CI's fat-LTO release profile,
pass `--build-arg CARGO_PROFILE=release`. Cargo chooses concurrency from available
CPUs; on memory-constrained builders, limit it with `--build-arg CARGO_BUILD_JOBS=1`.
Cargo-chef caches compiled dependencies in a separate Docker layer, reused when
source changes leave the dependency recipe, toolchain and build settings unchanged.
Workspace crates and final linking still rebuild. The final build uses the checkout's
`Cargo.lock` with `--locked`; Cargo downloads are also cached.

To build a single image directly and choose its tag:

```bash
docker build -f contrib/docker/Dockerfile -t stacks-core:local .
docker build -f contrib/docker/Dockerfile --target signer -t stacks-signer:local .
```

Direct builds use the Dockerfile's Rust version default. If it differs from
`rust-toolchain.toml`, the build fails and requests the matching
`--build-arg RUST_VERSION=...`. Unlike the wrapper, direct builds require explicit
`GIT_COMMIT`, `GIT_BRANCH` and `STACKS_VERSION` build arguments for source metadata
and version labels; their defaults are `unknown`. `GIT_TREE_CLEAN` defaults to `?`;
pass `--build-arg GIT_TREE_CLEAN=` for verified clean sources or
`--build-arg GIT_TREE_CLEAN=+` for modified sources. Base images and OS packages
are not pinned to immutable versions. Pass `--pull` to refresh base images.

## Run a node

The examples below use workspace version `4.0.3`; substitute your built tag.
The default command starts a mainnet node. To supply your own configuration:

```bash
docker run --rm \
  --mount type=bind,src="$PWD/node.toml",dst=/node.toml,readonly \
  --mount type=volume,src=stacks-data,dst=/data \
  -p 20443:20443 -p 20444:20444 \
  stacks-core:4.0.3 /usr/local/bin/stacks-node start --config /node.toml
```

Create `node.toml` for your network and include these settings:

```toml
[node]
working_dir = "/data"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
```

Bitcoin and peer endpoints must be reachable from the container; `127.0.0.1`
refers to the container itself. For signet launch parameters, see
[Bitcoin signet setup](../../docs/bitcoin-signet.md).

## Run a signer

Create `signer.toml` from the [signer configuration template](../../sample/conf/signer/mainnet-signer-conf.toml)
and fill in the required fields for your network. Set `db_path` under `/data`,
`endpoint = "0.0.0.0:30000"` and a container-reachable `node_host`. Configure the node's event observer to reach the signer's published
port and match the authentication settings described in the template.

```bash
docker run --rm \
  --mount type=bind,src="$PWD/signer.toml",dst=/signer-config.toml,readonly \
  --mount type=volume,src=signer-data,dst=/data \
  -p 30000:30000 \
  stacks-signer:4.0.3
```

## Data permissions

Both images default to UID/GID `65532:65532`, which owns `/data` with mode `0755`.
Configuration files must be readable and mounted data writable by the runtime
user. Docker initializes a new local data volume from the image; existing volumes
must already have suitable permissions.

For a host bind mount, replace the data-volume mount with
`--mount type=bind,src="$PWD/data",dst=/data`. Create that directory first and
select its owner's UID/GID with `--user`, for example `--user 5555:6666`.

`--user` changes the process identity, not ownership. A bind mount hides the
image's `/data`, so the host directory's permissions apply. Without a mount,
another unprivileged UID cannot write to `/data`; named volumes also need their
ownership prepared for a custom UID/GID.

Matching host IDs assumes Linux Docker without user-namespace remapping.
[Rootless Docker](https://docs.docker.com/engine/security/rootless/) and
`userns-remap` translate container IDs to host IDs; mount permissions must account
for that mapping. In Kubernetes, use `runAsUser`/`runAsGroup` and, where supported
by the volume, `fsGroup`.

## Troubleshooting

Check the binaries without starting a node or signer:

```bash
docker run --rm stacks-core:4.0.3 /usr/local/bin/stacks-node version
docker run --rm stacks-signer:4.0.3 /usr/local/bin/stacks-signer --version
```

[Distroless](https://github.com/GoogleContainerTools/distroless) has no shell or
package manager. For an interactive BusyBox shell, build a separate debug image:

```bash
docker build -f contrib/docker/Dockerfile \
  --build-arg DISTROLESS_TAG=debug-nonroot -t stacks-core:debug .
docker run --rm -it --entrypoint /busybox/sh stacks-core:debug
```
