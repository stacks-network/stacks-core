FROM rust:buster

### Install Stacks 2.0
RUN git clone --depth 1 --branch v24.2.1.0-xenon https://github.com/blockstack/stacks-blockchain.git /stacks2.0
WORKDIR /stacks2.0/testnet/stacks-node
RUN cargo fetch
RUN cargo build --release
RUN cp /stacks2.0/target/release/stacks-node /bin/stacks-node
RUN stacks-node version

### Install Node.js
RUN apt-get update
RUN curl -sL https://deb.nodesource.com/setup_15.x | bash -
RUN apt-get install -y nodejs
RUN node --version

### Install Stacks 1.0
RUN git clone --depth 1 --branch v1-migration https://github.com/blockstack/stacks-blockchain.git /stacks1.0
RUN python --version
RUN apt-get install -y python-setuptools python-pip rng-tools libgmp3-dev
RUN pip install pyparsing
WORKDIR /stacks1.0
RUN python ./setup.py build
RUN python ./setup.py install
# RUN python ./bin/blockstack-core version
RUN blockstack-core version

### Sync Stacks 1.0 chain
RUN blockstack-core fast_sync --working-dir /stacks1.0-chain
# use sqlite cli to set get_v2_upgrade_threshold_block
RUN apt-get install -y sqlite3
RUN sqlite3 /stacks1.0-chain/blockstack-server.db 'UPDATE v2_upgrade_signal SET threshold_block_id = 1 WHERE id = 1'
RUN sqlite3 /stacks1.0-chain/blockstack-server.db 'UPDATE v2_upgrade_signal SET import_block_id = 1 WHERE id = 1'
RUN blockstack-core fast_sync_snapshot 0 /stacks1.0-snapshot --working-dir /stacks1.0-chain > fast_sync_snapshot.log
# Fast-sync-snapshot completed at block 662399 with consensus hash bf81462f58d511cb2ab9d9752d745af8

# RUN blockstack-core start --working-dir /stacks1.0-export

RUN cat fast_sync_snapshot.log | grep "consensus hash" | tail -1 | sed "s/.*at block \(.*\) with consensus hash \(.*\).*/\1/" > export_block
RUN cat fast_sync_snapshot.log | grep "consensus hash" | tail -1 | sed "s/.*at block \(.*\) with consensus hash \(.*\).*/\2/" > consensus_hash

RUN echo "Block $(cat export_block) hash $(cat consensus_hash)"

# RUN cat fast_sync_snapshot.log | grep "consensus hash" | tail -1 | sed -e 's/.*block \([^"]*\)with.*/\1/' > export_block
# RUN curl -s https://core.blockstack.org/v1/blockchains/bitcoin/consensus/$(cat export_block) | jq '.consensus_hash' -r > consensus_hash

# RUN sed 's/.*block//; s/with.*//'
# RUN sed -e 's/.*block\(.*\)with.*/\1/'
# RUN sed -e 's/.*block\([^"]*\)with.*/\1/'

# RUN curl https://core.blockstack.org/v1/blockchains/bitcoin/consensus/662399
# RUN curl https://core.blockstack.org/v1/blockchains/bitcoin/consensus-block/bf81462f58d511cb2ab9d9752d745af8
# RUN curl http://localhost:6270/v1/info

RUN rm -rf /stacks1.0-chain

# RUN blockstack-core export_migration_json /stacks1.0-snapshot $(cat export_block) $(cat consensus_hash) --working-dir /stacks1.0-export
RUN blockstack-core export_migration_json /stacks1.0-snapshot $(cat export_block) $(cat consensus_hash) /stacks1.0-export --working-dir /stacks1.0-chain
RUN ls -al /stacks1.0-export
RUN cp /stacks1.0-export/chainstate.txt /stacks2.0/stx-genesis/chainstate.txt
RUN cp /stacks1.0-export/chainstate.txt.sha256 /stacks2.0/stx-genesis/chainstate.txt.sha256

WORKDIR /stacks2.0/testnet/stacks-node
RUN cargo build --release
RUN cp /stacks2.0/target/release/stacks-node /bin/stacks-node

# RUN blockstack-core start --working-dir /stacks1.0-chain && sleep 10 && curl --max-time 2 --retry 200 http://localhost:6270/v1/info

WORKDIR /test
COPY test ./
RUN npm i
RUN npm test