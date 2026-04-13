# marf-squash

Offline CLI for producing Genesis State Snapshots (GSS) from a Stacks node's
chainstate. Squashes the three MARFs (Clarity, Index, Sortition), copies
canonical block data and Bitcoin auxiliary files, generates a manifest with
SHA-256 checksums for fixed artifacts plus one aggregate hash for the epoch-2
block archive.

## Build

From the repository root:

```bash
cargo build -p marf-squash --release
```

## Usage

### Produce a full GSS

```bash
marf-squash squash \
  --chainstate /data/mainnet \
  --out-dir /tmp/gss \
  --tenure-start-bitcoin-height 880000 \
  --all
```

`--all` squashes all three MARFs, copies canonical block data, copies Bitcoin
auxiliary files, and generates a `GSS_manifest.toml` with SHA-256 checksums for
the fixed artifacts plus one aggregate hash for the epoch-2 block archive under
`chainstate/blocks/`.

Individual MARFs can be squashed selectively with `--clarity`, `--index`, or
`--sortition`. `--blocks` copies block data and requires `--index` (or `--all`).
`--bitcoin` copies Bitcoin auxiliary files and requires `--sortition` (or
`--all`).

## GSS output layout

A full GSS (`--all`) mirrors the node's working directory structure:

```
/tmp/gss/
├── chainstate/
│   ├── vm/
│   │   ├── clarity/
│   │   │   ├── marf.sqlite
│   │   │   └── marf.sqlite.blobs
│   │   ├── index.sqlite
│   │   └── index.sqlite.blobs
│   └── blocks/
│       ├── nakamoto.sqlite
│       └── {XX}/{YY}/{hash}... # Epoch 2.x blocks
├── burnchain/
│   ├── sortition/
│   │   ├── marf.sqlite
│   │   └── marf.sqlite.blobs
│   └── burnchain.sqlite
├── headers.sqlite
└── GSS_manifest.toml
```

## Using a GSS to bootstrap a node

1. Produce or download a GSS directory
2. Set `[node].working_dir` in your Stacks config to the **parent** of the GSS directory (e.g. `/data/my-node`)
3. Start the node normally

The node is unaware it is running from a GSS.

## Trust model

- **WSCP (Weak-Subjectivity Checkpoint)** authenticates the three squashed MARFs
  via their recomputed content hashes. These are the trust anchor.
- **Manifest checksums** verify artifact integrity: file-level SHA-256 for the
  fixed artifacts and one aggregate hash for the epoch-2 block archive. The
  manifest itself is part of the untrusted artifact - it is NOT authenticated by
  the WSCP.
