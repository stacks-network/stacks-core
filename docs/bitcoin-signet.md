# Bitcoin signet

Stacks nodes support Bitcoin Core's public signet and custom signets through
`burnchain.mode = "signet"`. Omit `signet_challenge` for public signet; set it to
the exact hex script used by Core's `signetchallenge` for a custom signet.

This selects the Bitcoin backing network. It does not create a Stacks network,
join the existing Stacks testnet, or supply miners, signers, initial balances,
or sBTC contracts. All Stacks participants must share those launch parameters.

## Bitcoin Core

Run an operator-controlled Core node with RPC and inbound P2P available to Stacks.
Core validates the signet challenge solution; Stacks validates the header chain,
proof of work, retargets, and its own burn operations. This retains Stacks' SPV
trust model: connect to a trusted, fully validating Core peer. Stacks does not
independently execute BIP 325 challenge scripts.

Example public-signet `bitcoin.conf`:

```ini
signet=1
server=1
txindex=1

[signet]
listen=1
rpcbind=127.0.0.1
rpcuser=stacks-signet
rpcpassword=replace-with-a-local-password
```

For custom signet, add `signetchallenge=<hex-script>` before `[signet]` and
configure your Bitcoin peers. The same challenge is required on every Bitcoin
and Stacks participant. A private block producer must satisfy that challenge;
Stacks does not produce Bitcoin signet signatures. `51` (`OP_TRUE`) is useful
only for disposable local testing because anyone can satisfy it. Even this
challenge requires actual signet proof of work, unlike regtest.

Wait for Core's `getblockchaininfo` to report `chain: "signet"` and
`initialblockdownload: false`. Keep historical blocks available for Stacks
bootstrap; an unpruned Core node avoids missing-block problems. Core's public
signet ports are 38333 (P2P) and 38332 (RPC).

## Stacks configuration

Start from [the follower template](../sample/conf/signet-follower-conf.toml),
then add your Stacks network's peers and agreed launch configuration.

```toml
[node]
working_dir = "/absolute/path/to/stacks-signet"
rpc_bind = "127.0.0.1:20443"
p2p_bind = "127.0.0.1:20444"
miner = false

[burnchain]
mode = "signet"
peer_host = "127.0.0.1"
peer_port = 38333
rpc_port = 38332
username = "stacks-signet"
password = "replace-with-a-local-password"
# Custom signet only; omit for public signet:
# signet_challenge = "51"
```

Signet defaults to Stacks chain ID `0x80000001` (`2147483649`), distinct from
mainnet (`0x00000001`) and testnet/regtest (`0x80000000`). Nodes advertise this ID
in `/v2/info` as `network_id` and reject transactions and P2P messages for other
IDs. Independent deployments should override `[burnchain].chain_id` with their
own agreed ID; the Bitcoin signet challenge does not assign a Stacks chain ID.

Configure signers with `network = "signet"` to use the same default. If the node
uses a custom chain ID, set the signer's `chain_id` to that value too. Wallets,
transaction builders, and PoX signing tools must use the deployment's chain ID,
including when signing PoX authorizations; selecting an ordinary testnet client
alone is insufficient.

Signet retains testnet's Stacks address prefixes, transaction version, peer
protocol version, genesis data, and boot contracts. No new genesis package is
required. Launch with fresh chainstate when changing the chain ID; existing
pre-default signet deployments can explicitly retain `chain_id = 0x80000000` in
both node and signer configurations.

`magic_bytes` sets Stacks' **two-byte burn-operation prefix**, default `S2`.
All participants in a Stacks network must use the same prefix. Bitcoin's separate
four-byte P2P magic is derived from the signet challenge. Signet addresses use
testnet's legacy prefixes and `tb` SegWit/Taproot encoding. An address alone cannot
distinguish signet from testnet.

Use a dedicated `node.working_dir` for each Stacks deployment. Changing the
signet challenge requires a new working directory; reusing existing data across
signets is unsupported. Chain data lives under `<working_dir>/signet/`, and the
pending observer queue remains at `<working_dir>/event_observers.sqlite`.
Independent Stacks deployments on the same Bitcoin signet also need separate
working directories and agreed Stacks chain IDs, operation prefixes, genesis
state, and peer configuration.

## Launch epochs and PoX

The defaults target a **fresh custom signet launched from Bitcoin genesis**:

| Epoch | First Bitcoin height |
| ---- | ---- |
| 1.0 / 2.0 | 0 / 0 |
| 2.05 / 2.1 / 2.2 / 2.3 / 2.4 | 1 / 2 / 3 / 4 / 5 |
| 2.5 / 3.0 / 3.1 | 201 / 231 / 241 |
| 3.2 / 3.3 / 3.4 | 251 / 252 / 253 |
| 4.0 | 262 |
| 4.1 | Inactive |

PoX cycles contain 20 Bitcoin blocks, including a five-block prepare phase.
For each miner, set `burnchain.wallet_name` to a precreated Bitcoin Core
watch-only descriptor wallet and import its mining addresses before funding.
Use `miner.segwit = true` for P2WPKH funding; legacy and Nakamoto mining keys
must both have spendable outputs if they differ. Stacks loads an existing wallet
but does not create it or automatically import signet addresses.
Set `burnchain.burn_fee_cap` high enough that each PoX output clears Core's dust
policy; the commitment is divided between its reward outputs.

Fund Bitcoin mining keys with mature outputs, produce legacy Stacks blocks,
and register/stack the signer set before Nakamoto. Before Epoch 4.0, deploy the
agreed sBTC token and registry contracts and configure
`node.pox_5_sbtc_contract` and `node.pox_5_sbtc_registry_contract` consistently.
PoX-5 signer registration and staking must continue across reward cycles.

For a new Stacks chain on an existing public or private signet, coordinate a
recent Bitcoin anchor (`first_burn_block_height`, `first_burn_block_hash`,
`first_burn_block_timestamp`) and an explicit `[[burnchain.epochs]]` schedule.
The epoch 2.0 start must equal the anchor height. Initial mining rewards
also start at that anchor; preceding Bitcoin history earns no Stacks rewards.
Include all preceding epochs when overriding later ones, preserve valid
reward/prepare-phase boundaries,
and allow time for funding, contract deployment, and signer enrollment. Do not
reuse the genesis-height development schedule for a new public launch.

## Integration tests

Use the repository's Rust toolchain, `cargo-nextest`, and native Bitcoin Core
`bitcoind` on `PATH` (tested with Core 31.1). Run one signer integration test at a
time because the harness uses a shared event observer.

Routine CI checks custom-signet startup, rejection of testnet transactions, a
new signed tenure, successful STX transfer execution, and agreement between two
miners backed by five signers.
It uses a shorter test-only epoch schedule with mature Bitcoin funding and
inherits the standard CI timeout and retry settings:

```bash
BITCOIND_TEST=1 cargo nextest run -p stacks-node --locked \
  --config-file .github/nextest/ci-nextest.toml --profile ci-sequential \
  --run-ignored only --no-capture -E 'test(signet_signed_transfer_smoke)'
```

Run the full PoX-5 qualification explicitly. Its `ci_skip` tag excludes it from
the routine Bitcoin CI matrix; it remains available through this command:

```bash
BITCOIND_TEST=1 cargo nextest run -p stackslib -p stacks-node --locked \
  --run-ignored only --no-capture \
  -E 'test(signet_pox5_epoch40_stability_and_restart)'
```

This test mines real custom-signet PoW, runs two Stacks miners and five signers,
bootstraps PoX-4 and PoX-5 through transactions, and checks three complete PoX-5
cycles in Epoch 4.0. It checks signed block progress, transfers, node agreement,
and restart/catch-up after one miner is offline for three burn blocks. The test
uses sBTC token and registry stubs; external sBTC services and custody flows are
outside its scope. The harness shuts down its processes when the test completes.

Focused offline checks:

```bash
cargo nextest run -p stackslib -p stacks-node -p stacks-signer --locked \
  -E 'test(signet) | test(test_network_identity_defaults)'
```

Opt-in public/private P2P tests against your already synchronized local
Core peer (set the challenge only for a custom signet):

```bash
STACKS_SIGNET_PORT=38333 STACKS_SIGNET_HEIGHT=4033 \
  cargo nextest run -p stackslib -p stacks-node --locked \
  --run-ignored only -E 'test(signet_live_header_sync)'
```

`STACKS_SIGNET_TIP_HASH` optionally checks the expected block hash at the requested
height. The existing sync API can fetch beyond that height to the peer's tip.

## References

The implementation follows [BIP 325](https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki)
and [Bitcoin Core's chain parameters](https://github.com/bitcoin/bitcoin/blob/v31.1/src/kernel/chainparams.cpp).
