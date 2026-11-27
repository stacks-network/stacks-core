# marf-squash

Offline CLI for producing Pruned Chainstate Snapshots (PCS) from a Stacks node's
chainstate. Squashes the three MARFs (Clarity, Index, Sortition), copies
canonical block data and Bitcoin auxiliary files, and generates a self-describing
manifest with SHA-256 checksums for the fixed artifacts plus one aggregate hash
for the epoch-2 block archive.

This crate *produces* a PCS; it does not verify one. Offline verification of a
PCS against a trusted checkpoint is a separate tool, not provided here.

## Build

From the repository root:

```bash
cargo build -p marf-squash --release
```

## Usage

```bash
marf-squash squash \
  --chainstate /data/mainnet \
  --out-dir /data/pcs \
  --tenure-start-bitcoin-height 943334 \
  --all
```

`--all` squashes all three MARFs, copies canonical block data, copies Bitcoin
auxiliary files, and generates a `PCS_manifest.toml` with SHA-256 checksums for
the fixed artifacts plus one aggregate hash for the epoch-2 block archive under
`chainstate/blocks/`.

Individual MARFs can be squashed selectively with `--clarity`, `--index`, or
`--sortition`. `--blocks` requires `--index` (or `--all`); `--bitcoin` requires
`--sortition` (or `--all`). A node config can be supplied with `--config`.

Run the squash against a stopped node: the tool reads the source chainstate
directly and is meant to be run offline.

### Choosing `--tenure-start-bitcoin-height`

The squash anchors at the first Nakamoto block of the tenure that started at
this Bitcoin height. State as of that point is kept; historical MARF data
before it is dropped.

- **Minimum.** The height must be in epoch 3.4 or later. On mainnet the tool
  enforces a minimum of `943334`, the first tenure of epoch 3.4 (3.4 activated
  at Bitcoin height 943333, which had no sortition). On other networks the
  minimum is epoch 3.4's `start_height` from the node config passed with
  `--config`. Lower values are rejected.
- **Must start a tenure.** The Bitcoin block must have a sortition
  (`sortition=true`). If it does not, the tool exits with an error listing
  nearby heights that do; pick one of those (often the height minus 1 works).
- **Stay well below the tip.** As a precaution around reward-cycle
  boundaries, choose a height at least ~2100 Bitcoin blocks below the current
  burnchain tip.
- **Trade-off.** A higher height squashes more history, so the resulting
  snapshot is smaller, but more historical data is discarded. Nothing is lost
  by picking a conservative height now: a PCS can be squashed again later at a
  higher height. There is currently no automatic/continuous squashing.

### Disk space, memory and duration

- **Put `--out-dir` on a real disk with plenty of free space.** Do not use a
  RAM-backed `tmpfs` such as `/tmp` on many Linux distributions: it is
  typically capped at half the machine's RAM and a mainnet squash will not fit.
- **Scratch space lives in the output directory.** While collecting trie
  nodes, each MARF squash writes a hidden spill file
  `.squash_nodes_<pid>_<nanos>.tmp` next to its destination `marf.sqlite` /
  `index.sqlite`. It holds every node reachable from the squash tip and is
  only deleted after the squashed `.blobs` file has been written, so peak
  usage is roughly the spill file plus the squashed output. For the mainnet
  Clarity MARF (tens of millions of nodes) the spill file alone exceeds 4 GB.
- **On failure, space is released silently.** If the squash fails (for
  example with `No space left on device (os error 28)`), the spill file is
  deleted on exit, so `df` afterwards may show the output filesystem as
  nearly empty. Only small partial `marf.sqlite` / `.blobs` files remain;
  remove the output directory before retrying, as the tool refuses to
  overwrite existing destinations.
- **Size of the result.** The PCS is much smaller than the archival
  chainstate, since only the state at the squash tip is kept; its exact size
  depends on the chosen height. As a conservative rule of thumb, have free
  space at least comparable to the source chainstate available on the output
  filesystem.
- **Duration.** A full `--all` squash rebuilds the entire chainstate and can
  take a long time on mainnet - plan for hours rather than minutes, and keep
  in mind that the node (and any signer relying on it) stays down meanwhile.
  Progress is logged per step (`[1/8]` ... `[8/8]`) for each MARF, including
  periodic `Trie DFS: N nodes ...` lines during node collection.

## PCS output layout

A full PCS (`--all`) mirrors the node's working directory structure:

```
/data/pcs/
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
└── PCS_manifest.toml
```

## The PCS manifest

`PCS_manifest.toml` is a self-describing record of the snapshot: the three MARFs'
squash root node hashes and archival MARF root hashes, the block range, and
SHA-256 checksums (file-level for the fixed artifacts, one aggregate hash for the
epoch-2 block archive). It is written by `squash` for a full PCS (`--all`).

Nothing in this crate reads it back - it is the artifact format consumed by an
external/offline verifier. The squash root node hashes are the intended trust
anchor: a verifier authenticates them against an independently published
checkpoint. The manifest itself is part of the untrusted artifact and is not
authenticated.

## Using a PCS to bootstrap a node

1. Produce or download a PCS directory.
2. (Recommended) Verify it against a trusted checkpoint with the offline verifier
   - a separate tool, not provided by this crate.
3. Set `[node].working_dir` in your Stacks config to the **parent** of the PCS
   directory (e.g. `/data/my-node`).
4. Start the node normally.

The node is unaware it is running from a PCS.
