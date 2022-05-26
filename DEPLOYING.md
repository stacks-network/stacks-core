## 1. Getting Testnet STX

```bash
./target/debug/blockstack-cli generate-sk --testnet
{ 
  "publicKey": "02c3c7ab279c5637ea5f024f8036c5218b6d1e71518adba0693c3dcc7bead92305",
  "stacksAddress": "STFTX3F4XCY7RS5VRHXP2SED0WC0YRKNWTNXD74P"
}
```

```bash
curl -X POST "https://stacks-node-api.testnet.stacks.co/extended/v1/faucets/stx?address=STFTX3F4XCY7RS5VRHXP2SED0WC0YRKNWTNXD74P&stacking=true"
```

## 2. Spin up testnet `stacks-node`


```toml
[node]
working_dir = "/var/testnet-stacks-node"
rpc_bind = "127.0.0.1:20443"
p2p_bind = "0.0.0.0:20444"
bootstrap_node = "047435c194e9b01b3d7f7a2802d6684a3af68d05bbf4ec8f17021980d777691f1d51651f7f1d566532c804da506c117bbf79ad62eea81213ba58f8808b4d9504ad@testnet.stacks.co:20444"

[burnchain]
chain = "bitcoin"
mode = "xenon"
peer_host = "bitcoind.testnet.stacks.co"
username = "blockstack"
password = "blockstacksystem"
rpc_port = 18332
peer_port = 18333

# Used for sending events to a local stacks-blockchain-api service
# [[events_observer]]
# endpoint = "localhost:3700"
# retry_count = 255
# events_keys = ["*"]

[[ustx_balance]]
address = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2"
amount = 10000000000000000

[[ustx_balance]]
address = "ST319CF5WV77KYR1H3GT0GZ7B8Q4AQPY42ETP1VPF"
amount = 10000000000000000

[[ustx_balance]]
address = "ST221Z6TDTC5E0BYR2V624Q2ST6R0Q71T78WTAX6H"
amount = 10000000000000000

[[ustx_balance]]
address = "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B"
amount = 10000000000000000
```


```bash
./target/release/stacks-node start --config=/var/devel/stacks-hyperchains/contrib/conf/stacks-l1-testnet.toml 2>&1 | tee -i /tmp/stacks-testnet-0426-1055.log
```

Note: You can use an existing testnet chain state if you have one available.
I used `cp /root/stacks-node/` on one of the Hiro deployed xenon followers.
The first bootup did not work: I `CTRL-C`'d the execution, which triggered a panic,
but on the next start, the node booted fine.

## 3. Launch the contract

Collect the contracts:

```bash
mkdir my-hyperchain/
mkdir my-hyperchain/contracts
cp stacks-hyperchains/core-contracts/contracts/hyperchains.clar my-hyperchain/contracts/
cp stacks-hyperchains/core-contracts/contracts/helper/ft-trait-standard.clar my-hyperchain/contracts/
cp stacks-hyperchains/core-contracts/contracts/helper/nft-trait-standard.clar my-hyperchain/contracts/
```

Set the miners list to contain the address generated in Step 1:

```bash
sed -ie "s#^(define-constant miners.*#(define-constant miners (list \'STFTX3F4XCY7RS5VRHXP2SED0WC0YRKNWTNXD74P))#" my-hyperchain/contracts/hyperchains.clar
```

Make the transactions -- you will need to set the private key of the contract publisher as an env var:

```bash
export SENDER_KEY=<PRIVATEKEY>
```

This is the private key from the first step.

```bash
mkdir my-hyperchain/scripts
cp stacks-hyperchains/contrib/scripts/* my-hyperchain/scripts/
cd my-hyperchain/scripts/
npm i @stacks/network
npm i @stacks/transactions
mkdir ../transactions/
node ./publish_tx.js ft-trait-standard ../contracts/ft-trait-standard.clar 0 > ../transactions/ft-publish.hex
node ./publish_tx.js nft-trait-standard ../contracts/nft-trait-standard.clar 1 > ../transactions/nft-publish.hex
node ./publish_tx.js hc-alpha ../contracts/hyperchains.clar 2 > ../transactions/hc-publish.hex
```

Submit the transactions:

```bash
$ node ./broadcast_tx.js ../transactions/ft-publish.hex
{
  txid: '93cae889b9382c512e55715e5357b388734c0448643e2cc35d2a1aab90dcf61a'
}

$ node ./broadcast_tx.js ../transactions/nft-publish.hex
{
  txid: '9752954c5d3303a20ceede5638d65aab8b8aa999d52aa0edb7321ceb7fba3c09'
}

$ node ./broadcast_tx.js ../transactions/hc-publish.hex
{
  txid: '8c457091916a7f57b487162e0692c2cd28e71dd0b2dc9a9dfad73f93babe1dfd'
}
```

## 4. Configure the HC miner

Create a `toml` configuration for the hyperchains miner.  Importantly,
you should set the `contract_identifier` to the contract published in
Steps 3 (e.g., `STFTX3F4XCY7RS5VRHXP2SED0WC0YRKNWTNXD74P.hc-alpha`).

```toml
[node]
working_dir = "/var/my-hyperchain/hc-alpha"
rpc_bind = "127.0.0.1:80443"
p2p_bind = "127.0.0.1:80444"
mining_key = "<FILL HERE>"
miner = true
wait_time_for_microblocks = 50_000

[miner]
first_attempt_time_ms = 60_000
subsequent_attempt_time_ms = 60_000
microblock_attempt_time_ms = 30_000

[burnchain]
chain = "stacks_layer_1"
mode = "xenon"
first_burn_header_height = 46_721
first_burn_header_hash = "9ba2f357115308fb1c503715f3a1b0cb3e8fdbe6baea7e7634635affdf675501"
contract_identifier = "<CONTRACT_NAME_HERE>"
peer_host = "127.0.0.1"
rpc_port = 20443
peer_port = 20444
rpc_ssl = false

[[ustx_balance]]
address = "STFTX3F4XCY7RS5VRHXP2SED0WC0YRKNWTNXD74P"
amount = 10000000000000000
```

Add to L1 node config:
```
[[events_observer]]
endpoint = "localhost:50303"
retry_count = 255
events_keys = ["*"]
```

## 5. Start the nodes

The `hyperchain-node` must be started before the `stacks-node`:

```bash
./target/release/hyperchain-node start --config=/var/my-hyperchain/configs/hc-miner.toml 2>&1 | tee /var/my-hyperchain/hc-miner.log
```

The `stacks-node` must be started from a state _before_ the
`first_burn_header_height` and `first_burn_header_hash` configured
in the hyperchain node's TOML.

```bash
./target/release/stacks-node start --config=/var/stacks-hyperchains/contrib/conf/stacks-l1-testnet.toml 2>&1 | tee -i /tmp/stacks-testnet.log
```
