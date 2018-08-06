## Hardware and OS requirements

* A 64-bit CPU running at at least 1 GHz is *highly* recommended (but not strictly required)
* You will need ~250MB RAM and ~10 GB disk free.  Do **not** attempt to use a network-attached disk for this.
* You should have at least 30,000 inodes free in your filesystem.  Unless you are using a very small VM image, you almost certainly have enough (you can check with `df -i`).
* TCP port 6264 should be open and support bidirectional traffic.  If you want to use SSL, then port 6263 should be open.
* A reliable Internet connection of DSL-like quality or higher

## Deployment
### The Easy Way
* Install from `pip`, source code, or Docker
* Run `blockstack-core fast_sync`
* Run `blockstack-core start`

### The Less Easy Way
* Install from `pip`, source code, or Docker
* Run `blockstack-core start`
* Wait a few days

#### Best Practices for the Less Easy Way
* Take a `blockstack-server.snapshots` database from a known-good node and pass `--expected_snapshots=/path/to/blockstack-server.snapshots`.  This will force your bootstrapping node to verify that it reaches the same sequence of consensus hashes as it bootstraps (i.e. your node will detect any divergence from Blockstack's name history and abort early, instead of wasting your time).
* Make sure you're in a position to leave the node online at 100% CPU use for the duration of its bootstrapping period

### The Hard Way
* Install `bitcoind` (version 0.16.x is recommended for now)
* Start `bitcoind` as `bitcoind -daemon -txindex=1`
* Wait for `bitcoind` to download the entire blockchain.  This can take between 1 hour and 1 day.
* Install `blockstack-core` from source, `pip`, or Docker
* Run `blockstack-core configure` and enter your `bitcoind` node's IP address, port, RPC username, and RPC password when prompted
* Run `blockstack-core start`
* Wait a few days

#### Best Practices for the Hard Way
* You're going to need ~500 GB of space for the Bitcoin blockchain state
* You can safely store its chain state on a network-attached disk, if you're doing this in a cloud-hosted environment
* Your `bitcoind` host will need TCP:8332-8333 open for bidirectional traffic

## Troubleshooting
### The node stops responding to TCP:6264
* Check `dmesg` for TCP SYN flooding.  The solution here is to kill and restart the node.
* To mitigate, install a rate-limiting proxy HTTP server in front of the node.  We have a sample config for `nginx` [here](https://github.com/blockstack/atlas/blob/master/public_fleet/node/default).

### No other Blockstack nodes contact my node
* Verify that your IP address is publicly-routable, and that peers can communicate on TCP:6264

### People are attacking my Bitcoin node
* Stick an `nginx` reverse proxy in front of your `bitcoind` node, and use our [nginx](https://github.com/blockstack/atlas/tree/master/public_fleet/bitcoind) scripts to limit APi access to only the JSON-RPC methods Blockstack actually needs.  Better yet, do what we do---build a statically-linked `bitcoind` binary from source that simply omits all of the RPC methods except the ones listed in the linked config file.
