FROM rust:bullseye

### Install Node.js
RUN apt-get update
RUN curl -sL https://deb.nodesource.com/setup_15.x | bash -
RUN apt-get install -y nodejs
RUN node --version

### Checkout Stacks 2.0 src
ARG STACKS_V2_BRANCH
RUN git clone --depth 1 --branch $STACKS_V2_BRANCH https://github.com/blockstack/stacks-blockchain.git /stacks2.0
WORKDIR /stacks2.0/testnet/stacks-node
RUN cargo fetch

### Install Stacks 1.0
RUN git clone --depth 1 --branch v1-migration https://github.com/blockstack/stacks-blockchain.git /stacks1.0
RUN python --version
RUN apt-get install -y python-setuptools python-pip rng-tools libgmp3-dev
RUN pip install pyparsing
WORKDIR /stacks1.0
RUN python ./setup.py build
RUN python ./setup.py install
RUN blockstack-core version

### Sync Stacks 1.0 chain
RUN blockstack-core fast_sync --working-dir /stacks1.0-chain

# Use sqlite cli to mark the chain as exported/frozen so Stacks 1.0 does not process new transactions
RUN apt-get install -y sqlite3
RUN sqlite3 /stacks1.0-chain/blockstack-server.db 'UPDATE v2_upgrade_signal SET threshold_block_id = 1 WHERE id = 1'
RUN sqlite3 /stacks1.0-chain/blockstack-server.db 'UPDATE v2_upgrade_signal SET import_block_id = 1 WHERE id = 1'

# Perform fast sync snapshot
RUN blockstack-core fast_sync_snapshot 0 /stacks1.0-snapshot --working-dir /stacks1.0-chain > fast_sync_snapshot.log

# Extract the snapshotted block height and consensus hash
RUN cat fast_sync_snapshot.log | grep "consensus hash" | tail -1 | sed "s/.*at block \(.*\) with consensus hash \(.*\).*/\1/" > export_block
RUN cat fast_sync_snapshot.log | grep "consensus hash" | tail -1 | sed "s/.*at block \(.*\) with consensus hash \(.*\).*/\2/" > consensus_hash
RUN echo "Block $(cat export_block) hash $(cat consensus_hash)"

# Generate a chainstate export from the snapshot
RUN blockstack-core export_migration_json /stacks1.0-snapshot $(cat export_block) $(cat consensus_hash) /stacks1.0-export --working-dir /stacks1.0-chain

# Copy exported data into Stacks 2.0 src
RUN cp /stacks1.0-export/chainstate.txt /stacks2.0/stx-genesis/chainstate.txt
RUN cp /stacks1.0-export/chainstate.txt.sha256 /stacks2.0/stx-genesis/chainstate.txt.sha256

# Build Stacks 2.0 with exported data
WORKDIR /stacks2.0/testnet/stacks-node
RUN cargo build --release
RUN cp /stacks2.0/target/release/stacks-node /bin/stacks-node
RUN stacks-node version

# Dump 1000 high activity / balance addresses
WORKDIR /test
RUN echo "select address, (cast(credit_value as integer) - cast(debit_value as integer)) as amount from ( \
            select * \
            from accounts \
            where type = \"STACKS\" \
            group by address \
            having block_id = max(block_id) and vtxindex = max(vtxindex) \
            order by block_id DESC, vtxindex DESC \
            ) amounts \
        order by amount DESC, address \
        limit 1000" | sqlite3 /stacks1.0-chain/blockstack-server.db > check_addrs.txt
RUN cat check_addrs.txt

# Dump ~1000 randomly sampled vesting schedules
RUN echo "\
        SELECT address, vesting_value, block_id FROM account_vesting \
        WHERE address IN (SELECT address FROM account_vesting ORDER BY RANDOM() LIMIT 35) \
        ORDER BY address, block_id \
    " | sqlite3 /stacks1.0-chain/blockstack-server.db > check_lockups.txt
RUN cat check_lockups.txt

# Run the js test script
COPY test ./
RUN npm i
RUN npm test
