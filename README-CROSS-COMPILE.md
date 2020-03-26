# Cross-Compiling Stacks 2.0 for Raspberry Pi

## Notice

The instructions below describe how to build the Blockstack Stacks v2.0 Blockchain for Raspberry Pi 2, 3, or the 1GB RAM model Pi 4, with `cross`. Raspberry Pi 1 and Raspberry Pi Zero are not supported by these instructions. Note also that by default the build is a developer-mode build.

For instructions on building directly on Raspberry Pi 4, with >= 2GB of RAM, see the [README.md](README.md).

More about cross: https://github.com/rust-embedded/cross

## Getting started

### Configure local environment

The first step is to ensure that you have Rust and the support software installed.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cross
```

Follow the instructions for installing Docker, including post-install steps:

##### Install Docker

https://docs.docker.com/install/

##### Docker Post-install

https://docs.docker.com/install/linux/linux-postinstall/

### Download and build stacks-blockchain

From there, you can clone this repository:

```bash
git clone https://github.com/blockstack/stacks-blockchain.git

cd stacks-blockchain
```

Then build the project:

#### Build with cross

```bash
cross build --target arm-unknown-linux-gnueabihf
```

You now have binaries that will run on Raspberry pi in your "target" directory. Copy the `stacks-blockchain/target/arm-unknown-linux-gnueabihf/debug` directory to your Raspberry Pi before continuing.

## On your Raspberry Pi

```bash
cd <your debug directory>
```

### Encode and sign transactions

Let's start by generating a keypair, that will be used for signing the upcoming transactions:

```bash
./blockstack-cli generate-sk --testnet

# Output
# {
#  secretKey: "b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001",
#  publicKey: "02781d2d3a545afdb7f6013a8241b9e400475397516a0d0f76863c6742210539b5",
#  stacksAddress: "ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH"
# }
```

We will interact with the following simple contract `kv-store`. In our examples, we will assume this contract is saved to `./kv-store.clar`:

```scheme
(define-map store ((key (buff 32))) ((value (buff 32))))

(define-public (get-value (key (buff 32)))
    (match (map-get? store ((key key)))
        entry (ok (get value entry))
        (err 0)))

(define-public (set-value (key (buff 32)) (value (buff 32)))
    (begin
        (map-set store ((key key)) ((value value)))
        (ok 'true)))
```

We want to publish this contract on chain, then issue some transactions that interact with it by setting some keys and getting some values, so we can observe read and writes.

Our first step is to generate and sign, using your private key, the transaction that will publish the contract `kv-store`.
To do that, we will use the subcommand:

```bash
./blockstack-cli publish --help
```

With the following arguments:

```bash
./blockstack-cli publish b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 0 kv-store ./kv-store.clar --testnet
```

This command will output the **binary format** of the transaction. In our case, we want to pipe this output and dump it to a file that will be used later in this tutorial.

```bash
./blockstack-cli publish b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 0 kv-store ./kv-store.clar --testnet | xxd -r -p > tx1.bin
```

### Run the testnet

You can observe the state machine in action locally by running:

```bash
./blockstack-core testnet
```

In your console, you should observe an output with a similar:

```bash
*** mempool path: /tmp/stacks-testnet-5fc814cf78dc0636/L1/mempool
```

The testnet is watching this directory, decoding and ingesting the transactions materialized as files. This mechanism is a shortcut for simulating a mempool. A RPC server will soon be integrated.

### Publish your contract

Assuming that the testnet is running, we can publish our `kv-store` contract.

In another terminal (or file explorer), you can move the `tx1.bin` generated earlier, to the mempool:

```bash
cp ./tx1.bin /tmp/stacks-testnet-5fc814cf78dc0636/L1/mempool
```

In the terminal window running the testnet, you can observe the state machine's reactions.

### Reading from / Writing to the contract

Now that our contract has been published on chain, let's try to submit some read / write transactions.
We will start by trying to read the value associated with the key `foo`.

To do that, we will use the subcommand:

```bash
./blockstack-cli contract-call --help
```

With the following arguments:

```bash
./blockstack-cli contract-call b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 1 ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH kv-store get-value -e \"foo\" --testnet | xxd -r -p > tx2.bin
```

`contract-call` generates and signs a contract-call transaction.
Note: the third argument `1` is a nonce, that must be increased monotonically with each new transaction.

We can submit the transaction by moving it to the mempool path:

```bash
cp ./tx2.bin /tmp/stacks-testnet-5fc814cf78dc0636/L1/mempool
```

Similarly, we can generate a transaction that would be setting the key `foo` to the value `bar`:

```bash
./blockstack-cli contract-call b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 2 ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH kv-store set-value -e \"foo\" -e \"bar\" --testnet | xxd -r -p > tx3.bin
```

And submit it by moving it to the mempool path:

```bash
cp ./tx3.bin /tmp/stacks-testnet-5fc814cf78dc0636/L1/mempool
```

Finally, we can issue a third transaction, reading the key `foo` again, for ensuring that the previous transaction has successfully updated the state machine:

```bash
./blockstack-cli contract-call b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 3 ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH kv-store get-value -e \"foo\" --testnet | xxd -r -p > tx4.bin
```

And submit this last transaction by moving it to the mempool path:

```bash
cp ./tx4.bin /tmp/stacks-testnet-5fc814cf78dc0636/L1/mempool
```

Congratulations, you can now [write your own smart contracts with Clarity](https://docs.blockstack.org/core/smart/overview.html). See the [README](https://github.com/blockstack/stacks-blockchain/blob/master/README.md#community) for further documentation and options community links.
