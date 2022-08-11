// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::HashMap;
use std::{fs, io};

use rusqlite::{
    types::ToSql, Connection, OpenFlags, OptionalExtension, Row, Transaction, NO_PARAMS,
};
use serde_json;

use crate::burnchains::Txid;
use crate::burnchains::{Burnchain, BurnchainBlock, BurnchainBlockHeader, Error as BurnchainError};
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::util_lib::db::{
    query_row, query_rows, sql_pragma, sqlite_open, tx_begin_immediate, tx_busy_handler,
    u64_to_sql, Error as DBError, FromColumn, FromRow,
};

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use stacks_common::types::chainstate::BurnchainHeaderHash;

pub struct BurnchainDB {
    conn: Connection,
}

struct BurnchainDBTransaction<'a> {
    sql_tx: Transaction<'a>,
}

pub struct BurnchainBlockData {
    pub header: BurnchainBlockHeader,
    pub ops: Vec<BlockstackOperationType>,
}

/// Apply safety checks on extracted blockstack transactions
/// - put them in order by vtxindex
/// - make sure there are no vtxindex duplicates
fn apply_blockstack_txs_safety_checks(
    block_height: u64,
    blockstack_txs: &mut Vec<BlockstackOperationType>,
) -> () {
    // safety -- make sure these are in order
    blockstack_txs.sort_by(|ref a, ref b| a.vtxindex().partial_cmp(&b.vtxindex()).unwrap());

    // safety -- no duplicate vtxindex (shouldn't happen but crash if so)
    if blockstack_txs.len() > 1 {
        for i in 0..blockstack_txs.len() - 1 {
            if blockstack_txs[i].vtxindex() == blockstack_txs[i + 1].vtxindex() {
                panic!(
                    "FATAL: BUG: duplicate vtxindex {} in block {}",
                    blockstack_txs[i].vtxindex(),
                    blockstack_txs[i].block_height()
                );
            }
        }
    }

    // safety -- block heights all match
    for tx in blockstack_txs.iter() {
        if tx.block_height() != block_height {
            panic!(
                "FATAL: BUG: block height mismatch: {} != {}",
                tx.block_height(),
                block_height
            );
        }
    }
}

impl FromRow<BurnchainBlockHeader> for BurnchainBlockHeader {
    fn from_row(row: &Row) -> Result<BurnchainBlockHeader, DBError> {
        let block_height = u64::from_column(row, "block_height")?;
        let block_hash = BurnchainHeaderHash::from_column(row, "block_hash")?;
        let timestamp = u64::from_column(row, "timestamp")?;
        let num_txs = u64::from_column(row, "num_txs")?;
        let parent_block_hash = BurnchainHeaderHash::from_column(row, "parent_block_hash")?;

        Ok(BurnchainBlockHeader {
            block_height,
            block_hash,
            timestamp,
            num_txs,
            parent_block_hash,
        })
    }
}

impl FromRow<BlockstackOperationType> for BlockstackOperationType {
    fn from_row(row: &Row) -> Result<BlockstackOperationType, DBError> {
        let serialized = row.get_unwrap::<_, String>("op");
        let deserialized = serde_json::from_str(&serialized)
            .expect("CORRUPTION: db store un-deserializable block op");

        Ok(deserialized)
    }
}

pub const BURNCHAIN_DB_VERSION: &'static str = "1";

const BURNCHAIN_DB_INITIAL_SCHEMA: &'static str = "
CREATE TABLE burnchain_db_block_headers (
    block_height INTEGER NOT NULL,
    block_hash TEXT UNIQUE NOT NULL,
    parent_block_hash TEXT NOT NULL,
    num_txs INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,

    PRIMARY KEY(block_hash)
);

CREATE TABLE burnchain_db_block_ops (
    block_hash TEXT NOT NULL,
    op TEXT NOT NULL,
    txid TEXT NOT NULL,
    FOREIGN KEY(block_hash) REFERENCES burnchain_db_block_headers(block_hash)
);

CREATE TABLE db_config(version TEXT NOT NULL);";

const BURNCHAIN_DB_INDEXES: &'static [&'static str] = &[
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_headers_height_hash ON burnchain_db_block_headers(block_height DESC, block_hash ASC);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_block_hash ON burnchain_db_block_ops(block_hash);",
    "CREATE INDEX IF NOT EXISTS index_burnchain_db_txid ON burnchain_db_block_ops(txid);",
];

impl<'a> BurnchainDBTransaction<'a> {
    fn store_burnchain_db_entry(
        &self,
        header: &BurnchainBlockHeader,
    ) -> Result<i64, BurnchainError> {
        let sql = "INSERT INTO burnchain_db_block_headers
                   (block_height, block_hash, parent_block_hash, num_txs, timestamp)
                   VALUES (?, ?, ?, ?, ?)";
        let args: &[&dyn ToSql] = &[
            &u64_to_sql(header.block_height)?,
            &header.block_hash,
            &header.parent_block_hash,
            &u64_to_sql(header.num_txs)?,
            &u64_to_sql(header.timestamp)?,
        ];

        match self.sql_tx.execute(sql, args) {
            Ok(_) => Ok(self.sql_tx.last_insert_rowid()),
            Err(e) => Err(BurnchainError::from(e)),
        }
    }

    fn store_blockstack_ops(
        &self,
        block_hash: &BurnchainHeaderHash,
        block_ops: &[BlockstackOperationType],
    ) -> Result<(), BurnchainError> {
        let sql = "INSERT INTO burnchain_db_block_ops
                   (block_hash, txid, op) VALUES (?, ?, ?)";
        let mut stmt = self.sql_tx.prepare(sql)?;
        for op in block_ops.iter() {
            let serialized_op =
                serde_json::to_string(op).expect("Failed to serialize parsed BlockstackOp");
            let args: &[&dyn ToSql] = &[block_hash, op.txid_ref(), &serialized_op];
            stmt.execute(args)?;
        }
        Ok(())
    }

    fn commit(self) -> Result<(), BurnchainError> {
        self.sql_tx.commit().map_err(BurnchainError::from)
    }
}

impl BurnchainDB {
    fn add_indexes(&mut self) -> Result<(), BurnchainError> {
        let db_tx = self.tx_begin()?;
        for index in BURNCHAIN_DB_INDEXES.iter() {
            db_tx.sql_tx.execute_batch(index)?;
        }
        db_tx.commit()?;
        Ok(())
    }

    pub fn connect(
        path: &str,
        first_block_height: u64,
        first_burn_header_hash: &BurnchainHeaderHash,
        first_burn_header_timestamp: u64,
        readwrite: bool,
    ) -> Result<BurnchainDB, BurnchainError> {
        let mut create_flag = false;
        let open_flags = match fs::metadata(path) {
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    // need to create
                    if readwrite {
                        create_flag = true;
                        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                    } else {
                        return Err(BurnchainError::from(DBError::NoDBError));
                    }
                } else {
                    return Err(BurnchainError::from(DBError::IOError(e)));
                }
            }
            Ok(_md) => {
                // can just open
                if readwrite {
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                } else {
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                }
            }
        };

        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if create_flag {
            let db_tx = db.tx_begin()?;
            db_tx.sql_tx.execute_batch(BURNCHAIN_DB_INITIAL_SCHEMA)?;

            db_tx.sql_tx.execute(
                "INSERT INTO db_config (version) VALUES (?1)",
                &[&BURNCHAIN_DB_VERSION],
            )?;

            let first_block_header = BurnchainBlockHeader {
                block_height: first_block_height,
                block_hash: first_burn_header_hash.clone(),
                timestamp: first_burn_header_timestamp,
                num_txs: 0,
                parent_block_hash: BurnchainHeaderHash::sentinel(),
            };

            db_tx.store_burnchain_db_entry(&first_block_header)?;
            db_tx.commit()?;
        }

        if readwrite {
            db.add_indexes()?;
        }
        Ok(db)
    }

    pub fn open(path: &str, readwrite: bool) -> Result<BurnchainDB, BurnchainError> {
        let open_flags = if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let conn = sqlite_open(path, open_flags, true)?;
        let mut db = BurnchainDB { conn };

        if readwrite {
            db.add_indexes()?;
        }
        Ok(db)
    }

    fn tx_begin<'a>(&'a mut self) -> Result<BurnchainDBTransaction<'a>, BurnchainError> {
        let sql_tx = tx_begin_immediate(&mut self.conn)?;
        Ok(BurnchainDBTransaction { sql_tx: sql_tx })
    }

    pub fn get_canonical_chain_tip(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height DESC, block_hash ASC LIMIT 1";
        let opt = query_row(&self.conn, qry, NO_PARAMS)?;
        opt.ok_or(BurnchainError::MissingParentBlock)
    }

    pub fn get_burnchain_block(
        &self,
        block: &BurnchainHeaderHash,
    ) -> Result<BurnchainBlockData, BurnchainError> {
        let block_header_qry =
            "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ? LIMIT 1";
        let block_ops_qry = "SELECT * FROM burnchain_db_block_ops WHERE block_hash = ?";

        let block_header = query_row(&self.conn, block_header_qry, &[block])?
            .ok_or_else(|| BurnchainError::UnknownBlock(block.clone()))?;
        let block_ops = query_rows(&self.conn, block_ops_qry, &[block])?;

        Ok(BurnchainBlockData {
            header: block_header,
            ops: block_ops,
        })
    }

    pub fn get_burnchain_op(&self, txid: &Txid) -> Option<BlockstackOperationType> {
        let qry = "SELECT op FROM burnchain_db_block_ops WHERE txid = ?";

        match query_row(&self.conn, qry, &[txid]) {
            Ok(res) => res,
            Err(e) => {
                warn!(
                    "BurnchainDB Error finding burnchain op: {:?}. txid = {}",
                    e, txid
                );
                None
            }
        }
    }

    /// Filter out the burnchain block's transactions that could be blockstack transactions.
    /// Return the ordered list of blockstack operations by vtxindex
    fn get_blockstack_transactions(
        &self,
        burnchain: &Burnchain,
        block: &BurnchainBlock,
        block_header: &BurnchainBlockHeader,
    ) -> Vec<BlockstackOperationType> {
        debug!(
            "Extract Blockstack transactions from block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let mut ops = Vec::new();
        let mut pre_stx_ops = HashMap::new();

        for tx in block.txs().iter() {
            let result =
                Burnchain::classify_transaction(burnchain, self, block_header, &tx, &pre_stx_ops);
            if let Some(classified_tx) = result {
                if let BlockstackOperationType::PreStx(pre_stx_op) = classified_tx {
                    pre_stx_ops.insert(pre_stx_op.txid.clone(), pre_stx_op);
                } else {
                    ops.push(classified_tx);
                }
            }
        }

        ops.extend(
            pre_stx_ops
                .into_iter()
                .map(|(_, op)| BlockstackOperationType::PreStx(op)),
        );

        ops.sort_by_key(|op| op.vtxindex());

        ops
    }

    pub fn store_new_burnchain_block(
        &mut self,
        burnchain: &Burnchain,
        block: &BurnchainBlock,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        let header = block.header();
        debug!("Storing new burnchain block";
              "burn_header_hash" => %header.block_hash.to_string());
        let mut blockstack_ops = self.get_blockstack_transactions(burnchain, block, &header);
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.tx_begin()?;

        db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(&header.block_hash, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(blockstack_ops)
    }

    #[cfg(test)]
    pub fn raw_store_burnchain_block(
        &mut self,
        header: BurnchainBlockHeader,
        mut blockstack_ops: Vec<BlockstackOperationType>,
    ) -> Result<(), BurnchainError> {
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.tx_begin()?;

        db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(&header.block_hash, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::chainstate::stacks::address::StacksAddressExtensions;
    use std::convert::TryInto;

    use crate::burnchains::bitcoin::address::*;
    use crate::burnchains::bitcoin::blocks::*;
    use crate::burnchains::bitcoin::*;
    use crate::burnchains::PoxConstants;
    use crate::burnchains::BLOCKSTACK_MAGIC_MAINNET;
    use crate::chainstate::burn::*;
    use crate::chainstate::stacks::address::PoxAddress;
    use crate::chainstate::stacks::*;
    use stacks_common::address::AddressHashMode;
    use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BtcTx;
    use stacks_common::deps_common::bitcoin::network::serialize::deserialize;
    use stacks_common::util::hash::*;

    use crate::types::chainstate::StacksAddress;

    use super::*;

    fn make_tx(hex_str: &str) -> BtcTx {
        let tx_bin = hex_bytes(hex_str).unwrap();
        deserialize(&tx_bin.to_vec()).unwrap()
    }

    #[test]
    fn test_store_and_fetch() {
        let first_bhh = BurnchainHeaderHash([0; 32]);
        let first_timestamp = 321;
        let first_height = 1;

        let mut burnchain_db =
            BurnchainDB::connect(":memory:", first_height, &first_bhh, first_timestamp, true)
                .unwrap();

        let mut burnchain = Burnchain::regtest(":memory:");
        burnchain.pox_constants = PoxConstants::test_default();

        let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
        assert_eq!(&first_block_header.block_hash, &first_bhh);
        assert_eq!(&first_block_header.block_height, &first_height);
        assert_eq!(&first_block_header.timestamp, &first_timestamp);
        assert_eq!(
            &first_block_header.parent_block_hash,
            &BurnchainHeaderHash::sentinel()
        );

        let canon_hash = BurnchainHeaderHash([1; 32]);

        let canonical_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            500,
            &canon_hash,
            &first_bhh,
            &vec![],
            485,
        ));
        let ops = burnchain_db
            .store_new_burnchain_block(&burnchain, &canonical_block)
            .unwrap();
        assert_eq!(ops.len(), 0);

        let vtxindex = 1;
        let noncanon_block_height = 400;
        let non_canon_hash = BurnchainHeaderHash([2; 32]);

        let fixtures = operations::leader_key_register::tests::get_test_fixtures(
            vtxindex,
            noncanon_block_height,
            non_canon_hash,
        );

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);
        let mut broadcast_ops = vec![];
        let mut expected_ops = vec![];

        for (ix, tx_fixture) in fixtures.iter().enumerate() {
            let tx = make_tx(&tx_fixture.txstr);
            let burnchain_tx = parser.parse_tx(&tx, ix + 1).unwrap();
            if let Some(res) = &tx_fixture.result {
                let mut res = res.clone();
                res.vtxindex = (ix + 1).try_into().unwrap();
                expected_ops.push(res.clone());
            }
            broadcast_ops.push(burnchain_tx);
        }

        let non_canonical_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            400,
            &non_canon_hash,
            &first_bhh,
            &broadcast_ops,
            350,
        ));

        let ops = burnchain_db
            .store_new_burnchain_block(&burnchain, &non_canonical_block)
            .unwrap();
        assert_eq!(ops.len(), expected_ops.len());
        for op in ops.iter() {
            let expected_op = expected_ops
                .iter()
                .find(|candidate| candidate.txid == op.txid())
                .expect("FAILED to find parsed op in expected ops");
            if let BlockstackOperationType::LeaderKeyRegister(op) = op {
                assert_eq!(op, expected_op);
            } else {
                panic!("EXPECTED to parse a LeaderKeyRegister");
            }
        }

        let BurnchainBlockData { header, ops } =
            burnchain_db.get_burnchain_block(&non_canon_hash).unwrap();
        assert_eq!(ops.len(), expected_ops.len());
        for op in ops.iter() {
            let expected_op = expected_ops
                .iter()
                .find(|candidate| candidate.txid == op.txid())
                .expect("FAILED to find parsed op in expected ops");
            if let BlockstackOperationType::LeaderKeyRegister(op) = op {
                assert_eq!(op, expected_op);
            } else {
                panic!("EXPECTED to parse a LeaderKeyRegister");
            }
        }
        assert_eq!(&header, &non_canonical_block.header());

        let looked_up_canon = burnchain_db.get_canonical_chain_tip().unwrap();
        assert_eq!(&looked_up_canon, &canonical_block.header());

        let BurnchainBlockData { header, ops } =
            burnchain_db.get_burnchain_block(&canon_hash).unwrap();
        assert_eq!(ops.len(), 0);
        assert_eq!(&header, &looked_up_canon);
    }

    #[test]
    fn test_classify_stack_stx() {
        let first_bhh = BurnchainHeaderHash([0; 32]);
        let first_timestamp = 321;
        let first_height = 1;

        let mut burnchain_db =
            BurnchainDB::connect(":memory:", first_height, &first_bhh, first_timestamp, true)
                .unwrap();

        let mut burnchain = Burnchain::regtest(":memory:");
        burnchain.pox_constants = PoxConstants::test_default();

        let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
        assert_eq!(&first_block_header.block_hash, &first_bhh);
        assert_eq!(&first_block_header.block_height, &first_height);
        assert_eq!(&first_block_header.timestamp, &first_timestamp);
        assert_eq!(
            &first_block_header.parent_block_hash,
            &BurnchainHeaderHash::sentinel()
        );

        let canon_hash = BurnchainHeaderHash([1; 32]);

        let canonical_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            500,
            &canon_hash,
            &first_bhh,
            &vec![],
            485,
        ));
        let ops = burnchain_db
            .store_new_burnchain_block(&burnchain, &canonical_block)
            .unwrap();
        assert_eq!(ops.len(), 0);

        // let's mine a block with a pre-stack-stx tx, and a stack-stx tx,
        //    the stack-stx tx should _fail_ to verify, because there's no
        //    corresponding pre-stack-stx.

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

        let pre_stack_stx_0_txid = Txid([5; 32]);
        let pre_stack_stx_0 = BitcoinTransaction {
            txid: pre_stack_stx_0_txid.clone(),
            vtxindex: 0,
            opcode: Opcodes::PreStx as u8,
            data: vec![0; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 1),
            }],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: BitcoinAddress {
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                },
            }],
        };

        // this one will not have a corresponding pre_stack_stx tx.
        let stack_stx_0 = BitcoinTransaction {
            txid: Txid([4; 32]),
            vtxindex: 1,
            opcode: Opcodes::StackStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 1),
            }],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: BitcoinAddress {
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                },
            }],
        };

        // this one will have a corresponding pre_stack_stx tx.
        let stack_stx_0_second_attempt = BitcoinTransaction {
            txid: Txid([4; 32]),
            vtxindex: 2,
            opcode: Opcodes::StackStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (pre_stack_stx_0_txid.clone(), 1),
            }],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: BitcoinAddress {
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([2; 20]),
                },
            }],
        };

        // this one won't have a corresponding pre_stack_stx tx.
        let stack_stx_1 = BitcoinTransaction {
            txid: Txid([3; 32]),
            vtxindex: 3,
            opcode: Opcodes::StackStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 1),
            }],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: BitcoinAddress {
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                },
            }],
        };

        // this one won't use the correct output
        let stack_stx_2 = BitcoinTransaction {
            txid: Txid([8; 32]),
            vtxindex: 4,
            opcode: Opcodes::StackStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (pre_stack_stx_0_txid.clone(), 2),
            }],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: BitcoinAddress {
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                },
            }],
        };

        let ops_0 = vec![pre_stack_stx_0, stack_stx_0];

        let ops_1 = vec![stack_stx_1, stack_stx_0_second_attempt, stack_stx_2];

        let block_height_0 = 501;
        let block_hash_0 = BurnchainHeaderHash([2; 32]);
        let block_height_1 = 502;
        let block_hash_1 = BurnchainHeaderHash([3; 32]);

        let block_0 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            block_height_0,
            &block_hash_0,
            &first_bhh,
            &ops_0,
            350,
        ));

        let block_1 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
            block_height_1,
            &block_hash_1,
            &block_hash_0,
            &ops_1,
            360,
        ));

        let processed_ops_0 = burnchain_db
            .store_new_burnchain_block(&burnchain, &block_0)
            .unwrap();

        assert_eq!(
            processed_ops_0.len(),
            1,
            "Only pre_stack_stx op should have been accepted"
        );

        let processed_ops_1 = burnchain_db
            .store_new_burnchain_block(&burnchain, &block_1)
            .unwrap();

        assert_eq!(
            processed_ops_1.len(),
            1,
            "Only one stack_stx op should have been accepted"
        );

        let expected_pre_stack_addr = StacksAddress::from_bitcoin_address(&BitcoinAddress {
            addrtype: BitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([1; 20]),
        });

        let expected_reward_addr = PoxAddress::Standard(
            StacksAddress::from_bitcoin_address(&BitcoinAddress {
                addrtype: BitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([2; 20]),
            }),
            Some(AddressHashMode::SerializeP2PKH),
        );

        if let BlockstackOperationType::PreStx(op) = &processed_ops_0[0] {
            assert_eq!(&op.output, &expected_pre_stack_addr);
        } else {
            panic!("EXPECTED to parse a pre stack stx op");
        }

        if let BlockstackOperationType::StackStx(op) = &processed_ops_1[0] {
            assert_eq!(&op.sender, &expected_pre_stack_addr);
            assert_eq!(&op.reward_addr, &expected_reward_addr);
            assert_eq!(op.stacked_ustx, u128::from_be_bytes([1; 16]));
            assert_eq!(op.num_cycles, 1);
        } else {
            panic!("EXPECTED to parse a stack stx op");
        }
    }
}
