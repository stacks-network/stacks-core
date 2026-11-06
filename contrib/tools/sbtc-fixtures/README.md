# sBTC v2 deposit fixtures

This standalone tool generates `stackslib/src/chainstate/stacks/fixtures/sbtc-v2.json`
from the sBTC crate at commit `6ec5dbeecb606fc2e921661ec9b43a6ad3545e6e`.

From the repository root, run:

```sh
cargo run --locked --manifest-path contrib/tools/sbtc-fixtures/Cargo.toml -- \
  stackslib/src/chainstate/stacks/fixtures/sbtc-v2.json
cargo test -p stackslib chainstate::stacks::sbtc::tests --lib -- --test-threads=1
```

`inputs.json` contains only case names, descriptions and inputs. Every expected
value is rebuilt by calling upstream `SignerKeySet::derive`,
`SignerKeySet::signing_script`, `SignerKeySet::script_pubkey`,
`DepositScriptInputsV2::deposit_script`, `ReclaimScriptInputs::reclaim_script`,
`to_v2_taproot` and `to_v2_script_pubkey`. Leaf hashes are obtained from
rust-bitcoin, the same library used by sBTC. The generator contains no local
implementation of signer derivation, deposit encoding, or the taproot tree.

To check reproducibility without changing the checked-in file:

```sh
cargo run --locked --manifest-path contrib/tools/sbtc-fixtures/Cargo.toml -- /tmp/sbtc-v2.json
cmp /tmp/sbtc-v2.json stackslib/src/chainstate/stacks/fixtures/sbtc-v2.json
```

The seven cases cover the PoX-5 mainnet and testnet recipients, upstream's
2-of-3, 11-of-15 and 1-of-1 signer sets, a standard principal, a 16-key set,
and reversed input order with duplicate keys.

The `Checks: sBTC Fixtures` workflow runs the locked regeneration and byte-for-byte
comparison for pull requests changing the generator, fixtures, derivation code,
constants, or build configuration, and for merge queues and manual runs. It
follows the repository's CI enablement setting. This verifies the pinned upstream
revision; updating sBTC requires updating the pin and regenerating the fixtures.
The node's existing sBTC unit tests separately check its implementation against
these fixtures, including the v2 NUMS constant.
