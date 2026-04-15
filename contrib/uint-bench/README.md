# uint-bench

Criterion benchmarks comparing `stacks-common::util::uint` operations between
the current in-tree implementation and the implementation at commit
[`eef1647d90c0c78d06c12277d931a8976bd819f3`](https://github.com/stacks-network/stacks-core/tree/eef1647d90c0c78d06c12277d931a8976bd819f3).

Both versions of `stacks-common` are pulled in as dependencies (renamed via
`package = "stacks-common"` so they coexist):

- `stacks-common-new` — local path dependency on the in-tree crate
- `stacks-common-old` — git dependency pinned at the comparison commit

This package is excluded from the workspace because the workspace already
contains the local `stacks-common`; making this a workspace member would
collide with the second copy fetched from git.

## Operations benchmarked

`Uint256`: `+`, `-`, `*`, `<<`, `>>`
`Uint512`: `<<`, `>>`

(`Uint512` arithmetic operators didn't exist in the old commit, so only
shifts are compared for it.)

## Running

```sh
cd contrib/uint-bench
cargo bench
```

Reports are written to `target/criterion/`. Within each benchmark group the
`new` and `old` benches are reported side-by-side.
