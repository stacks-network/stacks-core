// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

use std::cmp;
use std::path::PathBuf;

use rusqlite::{params, Connection};
use stacks_common::address::AddressHashMode;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BtcTx;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::hash::*;

use super::*;
use crate::burnchains::bitcoin::address::*;
use crate::burnchains::bitcoin::blocks::*;
use crate::burnchains::bitcoin::*;
use crate::burnchains::db::apply_blockstack_txs_safety_checks;
use crate::burnchains::{Error as BurnchainError, PoxConstants, BLOCKSTACK_MAGIC_MAINNET};
use crate::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::tests::next_txid;
use crate::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::*;
use crate::core::{StacksEpochId, BITCOIN_REGTEST_FIRST_BLOCK_HASH};
use crate::util_lib::db::Error as DBError;

impl BurnchainDB {
    pub fn get_first_header(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height ASC, block_hash DESC LIMIT 1";
        let opt = query_row(&self.conn, qry, NO_PARAMS)?;
        opt.ok_or(BurnchainError::MissingParentBlock)
    }

    /// Get back all of the parsed burnchain operations for a given block.
    /// Used in testing to replay burnchain data.
    #[cfg(test)]
    pub fn get_burnchain_block_ops(
        &self,
        block_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        use rusqlite::params;

        let sql = "SELECT op FROM burnchain_db_block_ops WHERE block_hash = ?1";
        let args = params![block_hash];
        let mut ops: Vec<BlockstackOperationType> = query_rows(&self.conn, sql, args)?;
        ops.sort_by_key(|op| op.vtxindex());
        Ok(ops)
    }

    pub fn raw_store_burnchain_block<B: BurnchainHeaderReader>(
        &mut self,
        burnchain: &Burnchain,
        indexer: &B,
        header: BurnchainBlockHeader,
        mut blockstack_ops: Vec<BlockstackOperationType>,
    ) -> Result<(), BurnchainError> {
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.tx_begin()?;

        test_debug!(
            "Store raw block {},{} (parent {}) with {} ops",
            &header.block_hash,
            header.block_height,
            &header.parent_block_hash,
            blockstack_ops.len()
        );

        db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(&header, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(())
    }
}

impl BurnchainHeaderReader for Vec<BurnchainBlockHeader> {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError> {
        if start_height >= self.len() as u64 {
            return Ok(vec![]);
        }
        let end = cmp::min(end_height, self.len() as u64) as usize;
        Ok(self[(start_height as usize)..end].to_vec())
    }

    fn get_burnchain_headers_height(&self) -> Result<u64, DBError> {
        Ok(self.len() as u64)
    }

    fn find_burnchain_header_height(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        for hdr in self.iter() {
            if &hdr.block_hash == burn_header_hash {
                return Ok(Some(hdr.block_height));
            }
        }
        Ok(None)
    }
}

fn make_tx(hex_str: &str) -> BtcTx {
    let tx_bin = hex_bytes(hex_str).unwrap();
    deserialize(&tx_bin.to_vec()).unwrap()
}

#[test]
fn test_store_and_fetch() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    burnchain.pox_constants = PoxConstants::test_default();
    burnchain.pox_constants.sunset_start = 999;
    burnchain.pox_constants.sunset_end = 1000;

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(&first_block_header.block_height, &first_height);
    assert_eq!(&first_block_header.timestamp, &0);
    assert_eq!(
        &first_block_header.parent_block_hash,
        &BurnchainHeaderHash::sentinel()
    );

    let headers = vec![first_block_header];
    let canon_hash = BurnchainHeaderHash([1; 32]);

    let canonical_block =
        BurnchainBlock::Bitcoin(BitcoinBlock::new(500, &canon_hash, &first_bhh, vec![], 485));
    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &canonical_block,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();
    assert!(ops.is_empty());

    let vtxindex = 1;
    let noncanon_block_height = 400;
    let non_canon_hash = BurnchainHeaderHash([2; 32]);

    let fixtures = operations::leader_key_register::tests::get_test_fixtures(
        vtxindex,
        noncanon_block_height,
        non_canon_hash.clone(),
    );

    let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);
    let mut broadcast_ops = vec![];
    let mut expected_ops = vec![];

    for (ix, tx_fixture) in fixtures.iter().enumerate() {
        let tx = make_tx(&tx_fixture.txstr);
        let burnchain_tx = parser
            .parse_tx(&tx, ix + 1, StacksEpochId::Epoch2_05)
            .unwrap();
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
        broadcast_ops,
        350,
    ));

    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &non_canonical_block,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
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

    let BurnchainBlockData { header, ops, .. } =
        BurnchainDB::get_burnchain_block(burnchain_db.conn(), &non_canon_hash).unwrap();
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

    // when we get a block header by its height, it's canonical
    for (height, header) in headers.iter().enumerate() {
        let hdr = BurnchainDB::get_burnchain_header(burnchain_db.conn(), &headers, height as u64)
            .unwrap()
            .unwrap();
        assert!(headers.iter().find(|h| **h == hdr).is_some());
        assert_ne!(hdr, non_canonical_block.header());
    }

    let looked_up_canon = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&looked_up_canon, &canonical_block.header());

    let BurnchainBlockData { header, ops, .. } =
        BurnchainDB::get_burnchain_block(burnchain_db.conn(), &canon_hash).unwrap();
    assert!(ops.is_empty());
    assert_eq!(&header, &looked_up_canon);
}

#[test]
fn test_classify_stack_stx() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    burnchain.pox_constants = PoxConstants::test_default();
    burnchain.pox_constants.sunset_start = 999;
    burnchain.pox_constants.sunset_end = 1000;

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(&first_block_header.block_height, &first_height);
    assert_eq!(&first_block_header.timestamp, &0);
    assert_eq!(
        &first_block_header.parent_block_hash,
        &BurnchainHeaderHash::sentinel()
    );

    let mut headers = vec![first_block_header.clone()];
    let canon_hash = BurnchainHeaderHash([1; 32]);

    let canonical_block =
        BurnchainBlock::Bitcoin(BitcoinBlock::new(500, &canon_hash, &first_bhh, vec![], 485));
    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &canonical_block,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();
    assert!(ops.is_empty());

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
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    // this one will not have a corresponding pre_stack_stx tx.
    let stack_stx_0 = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 1,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    // this one will have a corresponding pre_stack_stx tx.
    let stack_stx_0_second_attempt = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 2,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_stack_stx_0_txid.clone(), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([2; 20]),
            }),
        }],
    };

    // this one won't have a corresponding pre_stack_stx tx.
    let stack_stx_1 = BitcoinTransaction {
        txid: Txid([3; 32]),
        vtxindex: 3,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    // this one won't use the correct output
    let stack_stx_2 = BitcoinTransaction {
        txid: Txid([8; 32]),
        vtxindex: 4,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_stack_stx_0_txid.clone(), 2),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    let ops_0 = vec![pre_stack_stx_0, stack_stx_0];

    let ops_1 = vec![stack_stx_1, stack_stx_0_second_attempt, stack_stx_2];

    let block_height_0 = 501;
    let block_hash_0 = BurnchainHeaderHash([2; 32]);
    let block_height_1 = 502;
    let block_hash_1 = BurnchainHeaderHash([3; 32]);

    let num_txs_ops_0: u64 = ops_0.len() as u64;
    let block_0 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_0,
        &block_hash_0,
        &first_bhh,
        ops_0,
        350,
    ));

    headers.push(BurnchainBlockHeader {
        block_height: first_block_header.block_height + 1,
        block_hash: block_hash_0.clone(),
        parent_block_hash: first_bhh.clone(),
        num_txs: num_txs_ops_0,
        timestamp: first_block_header.timestamp + 1,
    });

    let num_txs_ops_1: u64 = ops_1.len() as u64;
    let block_1 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_1,
        &block_hash_1,
        &block_hash_0,
        ops_1,
        360,
    ));

    headers.push(BurnchainBlockHeader {
        block_height: first_block_header.block_height + 2,
        block_hash: block_hash_1.clone(),
        parent_block_hash: block_hash_0.clone(),
        num_txs: num_txs_ops_1,
        timestamp: first_block_header.timestamp + 2,
    });

    let processed_ops_0 = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &block_0,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();

    assert_eq!(
        processed_ops_0.len(),
        1,
        "Only pre_stack_stx op should have been accepted"
    );

    let processed_ops_1 = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &block_1,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();

    assert_eq!(
        processed_ops_1.len(),
        1,
        "Only one stack_stx op should have been accepted"
    );

    let expected_pre_stack_addr =
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([1; 20]),
        });

    let expected_reward_addr = PoxAddress::Standard(
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
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

pub fn make_simple_block_commit(
    burnchain: &Burnchain,
    parent: Option<&LeaderBlockCommitOp>,
    burn_header: &BurnchainBlockHeader,
    block_hash: BlockHeaderHash,
) -> LeaderBlockCommitOp {
    let block_height = burn_header.block_height;
    let mut new_op = LeaderBlockCommitOp {
        sunset_burn: 0,
        treatment: vec![],
        block_header_hash: block_hash,
        new_seed: VRFSeed([1u8; 32]),
        parent_block_ptr: 0,
        parent_vtxindex: 0,
        key_block_ptr: 0,
        key_vtxindex: 0,
        memo: vec![0],

        commit_outs: vec![
            PoxAddress::standard_burn_address(false),
            PoxAddress::standard_burn_address(false),
        ],

        burn_fee: 10000,
        input: (next_txid(), 0),
        apparent_sender: BurnchainSigner::mock_parts(
            AddressHashMode::SerializeP2PKH,
            1,
            vec![StacksPublicKey::from_hex(
                "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
            )
            .unwrap()],
        ),

        txid: next_txid(),
        vtxindex: 0,
        block_height,
        burn_parent_modulus: ((block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
        burn_header_hash: burn_header.block_hash.clone(),
    };

    if burnchain.is_in_prepare_phase(block_height) {
        new_op.commit_outs = vec![PoxAddress::standard_burn_address(false)];
    }

    if let Some(op) = parent {
        new_op.parent_block_ptr = op.block_height as u32;
        new_op.parent_vtxindex = op.vtxindex as u16;
    };

    new_op
}

fn burn_db_test_pox() -> PoxConstants {
    PoxConstants::new(
        5,
        3,
        2,
        3,
        0,
        u64::MAX - 1,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    )
}

#[test]
fn test_get_commit_at() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 0;
    let first_height = 1;

    let mut burnchain = Burnchain::regtest(":memory");
    burnchain.pox_constants = burn_db_test_pox();
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let mut parent = None;
    let mut parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut cmts = vec![];

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 1,
            timestamp: i,
        };

        headers.push(block_header.clone());
        parent_block_header = Some(block_header);
    }

    for i in 0..5 {
        let block_header = &headers[i + 1];

        let cmt = make_simple_block_commit(
            &burnchain,
            parent.as_ref(),
            block_header,
            BlockHeaderHash([((i + 1) as u8) | 0x80; 32]),
        );
        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                block_header,
                &vec![BlockstackOperationType::LeaderBlockCommit(cmt.clone())],
            )
            .unwrap();

        cmts.push(cmt.clone());
        parent = Some(cmt);
    }

    for i in 0..5 {
        let cmt =
            BurnchainDB::get_commit_at(burnchain_db.conn(), &headers, (first_height + i) as u32, 0)
                .unwrap()
                .unwrap();
        assert_eq!(cmt, cmts[i as usize]);
    }

    let cmt = BurnchainDB::get_commit_at(burnchain_db.conn(), &headers, 5, 0)
        .unwrap()
        .unwrap();
    assert_eq!(cmt, cmts[4]);

    // fork off the last stored commit block
    let fork_hdr = BurnchainHeaderHash([90; 32]);
    let fork_block_header = BurnchainBlockHeader {
        block_height: 5,
        block_hash: fork_hdr.clone(),
        parent_block_hash: BurnchainHeaderHash([4; 32]),
        num_txs: 1,
        timestamp: 4,
    };

    let mut fork_cmt = cmts[4].clone();
    fork_cmt.burn_header_hash = fork_hdr.clone();
    fork_cmt.vtxindex += 1;

    let mut fork_headers = headers.clone();
    fork_headers[5] = fork_block_header.clone();

    burnchain_db
        .store_new_burnchain_block_ops_unchecked(
            &fork_block_header,
            &vec![BlockstackOperationType::LeaderBlockCommit(fork_cmt.clone())],
        )
        .unwrap();

    let cmt = BurnchainDB::get_commit_at(burnchain_db.conn(), &headers, 5, 0)
        .unwrap()
        .unwrap();
    assert_eq!(cmt, cmts[4]);

    let cmt = BurnchainDB::get_commit_at(burnchain_db.conn(), &fork_headers, 5, 1)
        .unwrap()
        .unwrap();
    assert_eq!(cmt, fork_cmt);
}

#[test]
fn test_get_set_check_anchor_block() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 0;
    let first_height = 1;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = burn_db_test_pox();
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let mut parent = None;
    let mut parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut cmts = vec![];

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 1,
            timestamp: i,
        };

        headers.push(block_header.clone());
        parent_block_header = Some(block_header);
    }

    for i in 0..5 {
        let block_header = &headers[i + 1];

        let cmt = make_simple_block_commit(
            &burnchain,
            parent.as_ref(),
            block_header,
            BlockHeaderHash([((i + 1) as u8) | 0x80; 32]),
        );
        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                block_header,
                &vec![BlockstackOperationType::LeaderBlockCommit(cmt.clone())],
            )
            .unwrap();

        cmts.push(cmt.clone());
        parent = Some(cmt);
    }

    assert!(!BurnchainDB::has_anchor_block(burnchain_db.conn(), 1).unwrap());

    {
        let tx = burnchain_db.tx_begin().unwrap();
        tx.set_anchor_block(&cmts[3], 1).unwrap();
        tx.commit().unwrap();
    }

    assert!(BurnchainDB::has_anchor_block(burnchain_db.conn(), 1).unwrap());
    assert_eq!(
        BurnchainDB::get_anchor_block_commit(burnchain_db.conn(), &cmts[3].burn_header_hash, 1)
            .unwrap()
            .unwrap()
            .0,
        cmts[3]
    );
    assert!(BurnchainDB::is_anchor_block(
        burnchain_db.conn(),
        &cmts[3].burn_header_hash,
        &cmts[3].txid
    )
    .unwrap());
}

#[test]
fn test_classify_delegate_stx() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 321;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    burnchain.pox_constants = PoxConstants::test_default();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(&first_block_header.block_height, &first_height);
    assert_eq!(
        &first_block_header.parent_block_hash,
        &BurnchainHeaderHash::sentinel()
    );

    let canon_hash = BurnchainHeaderHash([1; 32]);

    let canonical_block =
        BurnchainBlock::Bitcoin(BitcoinBlock::new(500, &canon_hash, &first_bhh, vec![], 485));
    let mut headers = vec![first_block_header, canonical_block.header()];

    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &canonical_block,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();
    assert!(ops.is_empty());

    // let's mine a block with a pre-stx tx, and an invalid delegate-stx tx,
    //    the delegate-stx tx should _fail_ to verify, because there's it
    //    doesn't set the txid of the pre-stx in its input.

    let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

    let pre_delegate_stx_0_txid = Txid([5; 32]);
    let pre_delegate_stx_0 = BitcoinTransaction {
        txid: pre_delegate_stx_0_txid.clone(),
        vtxindex: 0,
        opcode: Opcodes::PreStx as u8,
        data: vec![0; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    // Set up the data field for the delegate stx transactions
    let mut data = vec![1; 80];
    // Make it so that reward_addr_index = Some(1)
    for i in 17..20 {
        data[i] = 0;
    }

    // this one will not have a corresponding pre_stx tx.
    let delegate_stx_0 = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 1,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    // this one will have a corresponding pre_stx tx.
    let delegate_stx_0_second_attempt = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 2,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_delegate_stx_0_txid.clone(), 1),
        }
        .into()],
        outputs: vec![
            BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([2; 20]),
                }
                .into(),
            },
            BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                }
                .into(),
            },
        ],
    };

    // this one won't have a corresponding pre_stx tx.
    let delegate_stx_1 = BitcoinTransaction {
        txid: Txid([3; 32]),
        vtxindex: 3,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    // This one won't use the correct output from the pre stx transaction.
    // It tries to use the second output from the pre stx tx, which DNE.
    let delegate_stx_2 = BitcoinTransaction {
        txid: Txid([8; 32]),
        vtxindex: 4,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_delegate_stx_0_txid.clone(), 2),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    let ops_0 = vec![pre_delegate_stx_0, delegate_stx_0];

    let ops_1 = vec![
        delegate_stx_1,
        delegate_stx_0_second_attempt,
        delegate_stx_2,
    ];

    let block_height_0 = 501;
    let block_hash_0 = BurnchainHeaderHash([2; 32]);
    let block_height_1 = 502;
    let block_hash_1 = BurnchainHeaderHash([3; 32]);

    let ops_0_length = ops_0.len();
    let ops_1_length = ops_1.len();
    let block_0 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_0,
        &block_hash_0,
        &first_bhh,
        ops_0,
        350,
    ));

    let block_1 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_1,
        &block_hash_1,
        &block_hash_0,
        ops_1,
        360,
    ));

    headers.push(block_0.header());
    headers.push(block_1.header());

    test_debug!("store ops ({}) for block 0", ops_0_length);
    let processed_ops_0 = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &block_0,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();

    assert_eq!(
        processed_ops_0.len(),
        1,
        "Only pre_delegate_stx op should have been accepted"
    );

    test_debug!("store ops ({}) for block 1", ops_1_length);
    let processed_ops_1 = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &block_1,
            StacksEpochId::Epoch21,
            u64::MAX,
        )
        .unwrap();

    assert_eq!(
        processed_ops_1.len(),
        1,
        "Only one delegate_stx op should have been accepted"
    );

    let expected_pre_delegate_addr =
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([1; 20]),
        });

    let expected_delegate_addr = PoxAddress::Standard(
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([2; 20]),
        }),
        Some(AddressHashMode::SerializeP2PKH),
    );

    let expected_reward_addr = Some((
        1,
        PoxAddress::Standard(
            StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
            Some(AddressHashMode::SerializeP2PKH),
        ),
    ));

    if let BlockstackOperationType::PreStx(op) = &processed_ops_0[0] {
        assert_eq!(&op.output, &expected_pre_delegate_addr);
    } else {
        panic!("EXPECTED to parse a pre delegate stx op");
    }

    if let BlockstackOperationType::DelegateStx(op) = &processed_ops_1[0] {
        assert_eq!(&op.sender, &expected_pre_delegate_addr);
        assert_eq!(op.delegated_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(
            op.delegate_to,
            StacksAddress::new(22, Hash160([2u8; 20])).unwrap()
        );
        assert_eq!(&op.reward_addr, &expected_reward_addr);
        assert_eq!(op.until_burn_height, Some(u64::from_be_bytes([1; 8])));
    } else {
        panic!("EXPECTED to parse a delegate stx op");
    }
}

// Mock Burnchain for testing
fn mock_burnchain() -> Burnchain {
    let first_block_height = 100;
    Burnchain {
        pox_constants: PoxConstants::test_default(),
        peer_version: 0x012345678,
        network_id: 0x9abcdef0,
        chain_name: "bitcoin".to_string(),
        network_name: "testnet".to_string(),
        working_dir: "/nope".to_string(),
        consensus_hash_lifetime: 24,
        stable_confirmations: 7,
        first_block_height,
        initial_reward_start_block: first_block_height,
        first_block_timestamp: 0,
        first_block_hash: BurnchainHeaderHash::zero(),
        marf_opts: None,
    }
}

/// Create a temporary db path for testing purposes
pub fn tmp_db_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "burnchain-db-test-{}.sqlite",
        rand::random::<u64>()
    ))
}

#[test]
fn burnchain_db_migration_v2() -> Result<(), BurnchainError> {
    // Create an in-memory database
    let tmp_path = tmp_db_path();
    let conn = Connection::open(tmp_path.clone())?;

    // Initialize database with schema version 2 using SCHEMA_2
    for statement in SCHEMA_2.iter() {
        conn.execute_batch(statement)?;
    }

    // Insert sample data to verify data integrity post-migration
    let sample_block_hash = BurnchainHeaderHash([1u8; 32]);
    let sample_parent_block_hash = BurnchainHeaderHash([0u8; 32]);
    let sample_txid = "txid1".to_string();
    conn.execute(
            "INSERT INTO burnchain_db_block_headers (block_height, block_hash, parent_block_hash, num_txs, timestamp) VALUES (?, ?, ?, ?, ?)",
            params![1, &sample_block_hash, &sample_parent_block_hash, 1, 1234567890],
        )?;
    conn.execute(
        "INSERT INTO affirmation_maps (weight, affirmation_map) VALUES (?, ?)",
        params![1, "test_map"],
    )?;
    conn.execute(
            "INSERT INTO block_commit_metadata (burn_block_hash, txid, block_height, vtxindex, affirmation_id, anchor_block, anchor_block_descendant) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![&sample_block_hash, &sample_txid, 1, 0, 0, None::<i64>, None::<i64>],
        )?;

    // Create BurnchainDB using connect to trigger migration code
    let burnchain = mock_burnchain();
    let db = BurnchainDB::connect(tmp_path.to_str().unwrap(), &burnchain, true)?;

    // Verify schema version is updated to 3
    let mut stmt = conn.prepare("SELECT version FROM db_config")?;
    let version: u32 = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(Result::ok)
        .filter_map(|v| v.parse::<u32>().ok())
        .max()
        .expect("Expected db_config to have a version");
    assert_eq!(
        version,
        BurnchainDB::SCHEMA_VERSION,
        "Database version should be current after migration"
    );

    // Verify affirmation_maps table is dropped
    assert!(
        !table_exists(&db.conn, "affirmation_maps")?,
        "affirmation_maps table should be dropped"
    );

    // Verify affirmation_id column is dropped from block_commit_metadata
    let columns: Vec<String> = db
        .conn
        .prepare("PRAGMA table_info(block_commit_metadata)")?
        .query_map([], |row| row.get(1))?
        .collect::<Result<Vec<String>, _>>()?;
    assert!(
        !columns.contains(&"affirmation_id".to_string()),
        "affirmation_id column should be dropped"
    );

    // Verify other tables and data remain intact
    assert!(
        table_exists(&db.conn, "burnchain_db_block_headers")?,
        "burnchain_db_block_headers table should exist"
    );
    assert!(
        table_exists(&db.conn, "block_commit_metadata")?,
        "block_commit_metadata table should exist"
    );
    let header: Option<BurnchainBlockHeader> = query_row(
        &db.conn,
        "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ?",
        params![&sample_block_hash],
    )?;
    assert!(
        header.is_some(),
        "Sample block header should remain after migration"
    );
    let metadata: Option<String> = query_row(
        &db.conn,
        "SELECT txid FROM block_commit_metadata WHERE burn_block_hash = ?",
        params![&sample_block_hash],
    )?;
    assert_eq!(
        metadata,
        Some(sample_txid),
        "Sample block_commit_metadata should remain after migration"
    );

    // Verify indexes are still present
    let indexes: Vec<String> = db.conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'index_block_commit_metadata%'")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
    assert!(
        indexes.contains(&"index_block_commit_metadata_burn_block_hash_anchor_block".to_string()),
        "Expected index should still exist"
    );

    Ok(())
}

#[test]
fn burnchain_db_migration_v3() -> Result<(), BurnchainError> {
    // Create an in-memory database
    let tmp_path = tmp_db_path();
    let conn = Connection::open(tmp_path.clone())?;

    // Initialize database with schema version 3
    for statement in SCHEMA_2.iter().chain(SCHEMA_3.iter()) {
        conn.execute_batch(statement)?;
    }

    // Insert sample data to verify data integrity post-migration
    let sample_block_hash = BurnchainHeaderHash([1u8; 32]);
    let sample_parent_block_hash = BurnchainHeaderHash([0u8; 32]);
    let sample_txid = "txid1".to_string();
    conn.execute(
            "INSERT INTO burnchain_db_block_headers (block_height, block_hash, parent_block_hash, num_txs, timestamp) VALUES (?, ?, ?, ?, ?)",
            params![1, &sample_block_hash, &sample_parent_block_hash, 1, 1234567890],
        )?;
    conn.execute(
            "INSERT INTO block_commit_metadata (burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant) VALUES (?, ?, ?, ?, ?, ?)",
            params![&sample_block_hash, &sample_txid, 1, 0, None::<i64>, None::<i64>],
        )?;

    // Create BurnchainDB using connect to trigger migration code
    let burnchain = mock_burnchain();
    let db = BurnchainDB::connect(tmp_path.to_str().unwrap(), &burnchain, true)?;

    let mut stmt = conn.prepare("SELECT version FROM db_config")?;
    let version: u32 = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(Result::ok)
        .filter_map(|v| v.parse::<u32>().ok())
        .max()
        .expect("Expected db_config to have a version");
    assert_eq!(
        version,
        BurnchainDB::SCHEMA_VERSION,
        "Database version should be current after migration"
    );

    // Verify affirmation_maps table is dropped
    assert!(
        !table_exists(&db.conn, "affirmation_maps")?,
        "affirmation_maps table should be dropped"
    );

    // Verify affirmation_id column is dropped from block_commit_metadata
    let columns: Vec<String> = db
        .conn
        .prepare("PRAGMA table_info(block_commit_metadata)")?
        .query_map([], |row| row.get(1))?
        .collect::<Result<Vec<String>, _>>()?;
    assert!(
        !columns.contains(&"affirmation_id".to_string()),
        "affirmation_id column should be dropped"
    );

    // Verify other tables and data remain intact
    assert!(
        table_exists(&db.conn, "burnchain_db_block_headers")?,
        "burnchain_db_block_headers table should exist"
    );
    assert!(
        table_exists(&db.conn, "block_commit_metadata")?,
        "block_commit_metadata table should exist"
    );
    let header: Option<BurnchainBlockHeader> = query_row(
        &db.conn,
        "SELECT * FROM burnchain_db_block_headers WHERE block_hash = ?",
        params![&sample_block_hash],
    )?;
    assert!(
        header.is_some(),
        "Sample block header should remain after migration"
    );
    let metadata: Option<String> = query_row(
        &db.conn,
        "SELECT txid FROM block_commit_metadata WHERE burn_block_hash = ?",
        params![&sample_block_hash],
    )?;
    assert_eq!(
        metadata,
        Some(sample_txid),
        "Sample block_commit_metadata should remain after migration"
    );

    // Verify indexes are still present
    let indexes: Vec<String> = db.conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'index_block_commit_metadata%'")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
    assert!(
        indexes.contains(&"index_block_commit_metadata_burn_block_hash_anchor_block".to_string()),
        "Expected index should still exist"
    );

    Ok(())
}

#[test]
fn witness_script_hash_sql_roundtrip() {
    // Verify that ToSql and FromSql are inverses of each other through a real SQLite connection.
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (v TEXT NOT NULL)")
        .unwrap();

    let original = WitnessScriptHash([0xabu8; 32]);
    conn.execute("INSERT INTO t (v) VALUES (?1)", params![&original])
        .unwrap();
    let retrieved: WitnessScriptHash = conn
        .query_row("SELECT v FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(retrieved, original);
}

#[test]
fn witness_script_hash_from_sql_errors() {
    use rusqlite::types::{FromSql, ValueRef};

    // Valid 32-byte hex string parses correctly.
    let valid_hex = "ab".repeat(32);
    let result = WitnessScriptHash::column_result(ValueRef::Text(valid_hex.as_bytes()));
    assert!(
        result.is_ok(),
        "Valid 32-byte hex should parse successfully"
    );
    assert_eq!(result.unwrap().0, [0xabu8; 32]);

    // Non-hex characters must be rejected.
    let result = WitnessScriptHash::column_result(ValueRef::Text(b"zz_not_hex_at_all_zz"));
    assert!(result.is_err(), "Non-hex string should fail");

    // 31 bytes (62 hex chars) must be rejected.
    let short_hex = "ab".repeat(31);
    let result = WitnessScriptHash::column_result(ValueRef::Text(short_hex.as_bytes()));
    assert!(result.is_err(), "31-byte hash should fail length check");

    // 33 bytes (66 hex chars) must be rejected.
    let long_hex = "ab".repeat(33);
    let result = WitnessScriptHash::column_result(ValueRef::Text(long_hex.as_bytes()));
    assert!(result.is_err(), "33-byte hash should fail length check");
}

proptest! {
    /// Universal positive form of [`witness_script_hash_from_sql_errors`]:
    /// every 32-byte value, hex-encoded, parses back to the original bytes.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_witness_script_hash_from_sql_accepts_valid_hex(bytes in any::<[u8; 32]>()) {
        use rusqlite::types::{FromSql, ValueRef};
        let hex = to_hex(&bytes);
        let result = WitnessScriptHash::column_result(ValueRef::Text(hex.as_bytes()));
        prop_assert!(result.is_ok(), "len 64 hex must accept");
        prop_assert_eq!(result.unwrap().0, bytes);
    }

    /// Universal negative form: any byte string that is NOT exactly 64
    /// ASCII hex chars is rejected. Generator filters out the rare valid
    /// case so the negative branch is exercised on every iteration.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_witness_script_hash_from_sql_rejects_non_64_hex(
        raw in prop::collection::vec(any::<u8>(), 0..=200).prop_filter(
            "exclude valid 64-char hex",
            |v| !(v.len() == 64 && v.iter().all(|b| b.is_ascii_hexdigit())),
        ),
    ) {
        use rusqlite::types::{FromSql, ValueRef};
        let result = WitnessScriptHash::column_result(ValueRef::Text(&raw));
        prop_assert!(
            result.is_err(),
            "non-64-hex input of len {} accepted",
            raw.len()
        );
    }
}

#[test]
fn store_watched_outputs() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let burnchain = Burnchain::regtest(":memory:");
    let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let block_hash = BurnchainHeaderHash([1u8; 32]);
    let header = BurnchainBlockHeader {
        block_height: 1,
        block_hash: block_hash.clone(),
        parent_block_hash: first_bhh,
        num_txs: 0,
        timestamp: 1,
    };

    let outputs = vec![
        WatchedP2WSHOutput {
            txid: Txid([1u8; 32]),
            vout: 0,
            witness_script_hash: WitnessScriptHash([0xaau8; 32]),
            amount: 1_000,
        },
        WatchedP2WSHOutput {
            txid: Txid([2u8; 32]),
            vout: 0,
            witness_script_hash: WitnessScriptHash([0xbbu8; 32]),
            amount: 2_000,
        },
    ];

    let db_tx = db.tx_begin().unwrap();
    db_tx.store_burnchain_db_entry(&header).unwrap();
    db_tx.store_watched_outputs(&header, &outputs).unwrap();
    db_tx.commit().unwrap();

    // get_watched_outputs_at_block: both outputs are retrievable.
    let retrieved = BurnchainDB::get_watched_outputs_at_block(db.conn(), &block_hash).unwrap();
    assert_eq!(retrieved.len(), 2);
    assert!(retrieved.contains(&outputs[0]));
    assert!(retrieved.contains(&outputs[1]));

    // An unknown block hash returns an empty list.
    let unknown_hash = BurnchainHeaderHash([0xffu8; 32]);
    assert!(
        BurnchainDB::get_watched_outputs_at_block(db.conn(), &unknown_hash)
            .unwrap()
            .is_empty()
    );

    // empty-slice store is a no-op.
    let block_hash2 = BurnchainHeaderHash([2u8; 32]);
    let header2 = BurnchainBlockHeader {
        block_height: 2,
        block_hash: block_hash2.clone(),
        parent_block_hash: block_hash.clone(),
        num_txs: 0,
        timestamp: 2,
    };
    let db_tx = db.tx_begin().unwrap();
    db_tx.store_burnchain_db_entry(&header2).unwrap();
    db_tx.store_watched_outputs(&header2, &[]).unwrap();
    db_tx.commit().unwrap();
    assert!(
        BurnchainDB::get_watched_outputs_at_block(db.conn(), &block_hash2)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn prune_watched_outputs() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let burnchain = Burnchain::regtest(":memory:");
    let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    // With reward_cycle_length = 10, the retention window is (3 * 10) / 2 = 15 blocks.
    // Pruning against a tip at height 100 keeps outputs with block_height >= 85.
    let reward_cycle_length: u32 = 10;
    let window: u64 = (3 * u64::from(reward_cycle_length)) / 2; // 15
    let current_block_height: u64 = 100;
    let threshold = current_block_height - window; // 85

    let heights: &[u64] = &[1, 50, 80, 84, 85, 90, 100];
    let mut parent = first_bhh;
    for &height in heights {
        let hash_bytes = [(height as u8); 32];
        let block_hash = BurnchainHeaderHash(hash_bytes);
        let header = BurnchainBlockHeader {
            block_height: height,
            block_hash: block_hash.clone(),
            parent_block_hash: parent.clone(),
            num_txs: 0,
            timestamp: height,
        };
        let output = WatchedP2WSHOutput {
            txid: Txid(hash_bytes),
            vout: 0,
            witness_script_hash: WitnessScriptHash(hash_bytes),
            amount: height * 1_000,
        };
        let db_tx = db.tx_begin().unwrap();
        db_tx.store_burnchain_db_entry(&header).unwrap();
        db_tx.store_watched_outputs(&header, &[output]).unwrap();
        db_tx.commit().unwrap();
        parent = block_hash;
    }

    let db_tx = db.tx_begin().unwrap();
    db_tx
        .prune_watched_outputs(reward_cycle_length, current_block_height)
        .unwrap();
    db_tx.commit().unwrap();

    for &height in heights {
        let block_hash = BurnchainHeaderHash([(height as u8); 32]);
        let remaining = BurnchainDB::get_watched_outputs_at_block(db.conn(), &block_hash).unwrap();
        if height < threshold {
            assert!(
                remaining.is_empty(),
                "Expected outputs at height {height} to be pruned (threshold={threshold})"
            );
        } else {
            assert_eq!(
                remaining.len(),
                1,
                "Expected outputs at height {height} to survive (threshold={threshold})"
            );
        }
    }

    // When the tip is below the retention window, nothing should be pruned.
    let early_tip: u64 = 5;
    let db_tx = db.tx_begin().unwrap();
    db_tx
        .prune_watched_outputs(reward_cycle_length, early_tip)
        .unwrap();
    db_tx.commit().unwrap();

    for &height in heights.iter().filter(|&&h| h >= threshold) {
        let block_hash = BurnchainHeaderHash([(height as u8); 32]);
        let remaining = BurnchainDB::get_watched_outputs_at_block(db.conn(), &block_hash).unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "Expected outputs at height {height} to survive a below-window prune"
        );
    }
}

// Property tests for watched P2WSH outputs.

#[cfg(test)]
use proptest::prelude::*;

/// Deterministic 32-byte hash from `height`. Distinct heights map to distinct
/// hashes (heights always fit in 8 bytes).
#[cfg(test)]
fn height_hash(height: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&height.to_le_bytes());
    bytes
}

#[cfg(test)]
fn header_at_height(height: u64, parent: BurnchainHeaderHash) -> BurnchainBlockHeader {
    BurnchainBlockHeader {
        block_height: height,
        block_hash: BurnchainHeaderHash(height_hash(height)),
        parent_block_hash: parent,
        num_txs: 0,
        timestamp: height,
    }
}

#[cfg(test)]
fn output_for_height(height: u64) -> WatchedP2WSHOutput {
    WatchedP2WSHOutput {
        txid: Txid(height_hash(height)),
        vout: 0,
        witness_script_hash: WitnessScriptHash(height_hash(height)),
        amount: 1_000,
    }
}

/// Insert one watched output per height. Heights are inserted in sorted order
/// so the parent chain stays linear.
#[cfg(test)]
fn seed_outputs_at_heights(db: &mut BurnchainDB, heights: &[u64]) {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let mut parent = first_bhh;
    for &h in heights {
        let header = header_at_height(h, parent);
        let output = output_for_height(h);
        let db_tx = db.tx_begin().unwrap();
        db_tx.store_burnchain_db_entry(&header).unwrap();
        db_tx.store_watched_outputs(&header, &[output]).unwrap();
        db_tx.commit().unwrap();
        parent = header.block_hash;
    }
}

/// Joint strategy for `(reward_cycle_length, current_block_height)` such
/// that `current_block_height > window` by construction — i.e.,
/// `threshold = current - window >= 1` is guaranteed without a
/// `prop_assume!`. Conditional generation keeps shrinking deterministic
/// and ensures every iteration reaches the boundary code path being
/// asserted.
#[cfg(test)]
fn arb_rcl_and_current_above_window() -> impl proptest::strategy::Strategy<Value = (u32, u64)> {
    use proptest::prelude::*;
    (2u32..=10_000u32).prop_flat_map(|rcl| {
        let window = (3u64 * u64::from(rcl)) / 2;
        // Upper bound mirrors the original test ranges. `lower = window + 1`
        // guarantees `current > window`. We grow the upper bound with `rcl`
        // so large reward cycles still get a non-degenerate sampling band.
        let lower = window + 1;
        let upper = 1_000_000u64.max(lower + 1_000);
        (Just(rcl), lower..=upper)
    })
}

#[cfg(test)]
fn outputs_at_height(db: &BurnchainDB, height: u64) -> Vec<WatchedP2WSHOutput> {
    let block_hash = BurnchainHeaderHash(height_hash(height));
    BurnchainDB::get_watched_outputs_at_block(db.conn(), &block_hash).unwrap()
}

proptest! {
    /// Property 1: ToSql + FromSql round-trip any 32-byte witness script hash.
    ///
    /// Pins that the on-disk hex encoding is a strict, lossless inverse of the
    /// in-memory representation for every possible value. The hand-written test
    /// `witness_script_hash_sql_roundtrip` only covers `[0xab; 32]`.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_witness_script_hash_sql_roundtrip(bytes in any::<[u8; 32]>()) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (v TEXT NOT NULL)").unwrap();

        let original = WitnessScriptHash(bytes);
        conn.execute("INSERT INTO t (v) VALUES (?1)", params![&original]).unwrap();
        let retrieved: WitnessScriptHash = conn
            .query_row("SELECT v FROM t", [], |row| row.get(0))
            .unwrap();
        prop_assert_eq!(retrieved.0, bytes);
    }

    /// Property 2: After `prune_watched_outputs(R, H)`, every output stored at
    /// block height `h < threshold` is gone and every output at `h >= threshold`
    /// survives, where `threshold = H.saturating_sub(3 * R / 2)`.
    ///
    /// This is the universal claim behind the hand-written `prune_watched_outputs`
    /// example, generalized over arbitrary RCL/tip/height-set combinations.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_prune_deletes_below_threshold(
        reward_cycle_length in 1u32..=10_000,
        current_block_height in 0u64..=(i64::MAX as u64),
        heights in prop::collection::hash_set(0u64..=(i64::MAX as u64), 1..=10),
    ) {
        let window = (3u64 * u64::from(reward_cycle_length)) / 2;
        let threshold = current_block_height.saturating_sub(window);

        let burnchain = Burnchain::regtest(":memory:");
        let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

        let mut sorted: Vec<u64> = heights.into_iter().collect();
        sorted.sort();
        seed_outputs_at_heights(&mut db, &sorted);

        let db_tx = db.tx_begin().unwrap();
        db_tx.prune_watched_outputs(reward_cycle_length, current_block_height).unwrap();
        db_tx.commit().unwrap();

        for &h in &sorted {
            let remaining = outputs_at_height(&db, h);
            if h < threshold {
                prop_assert!(
                    remaining.is_empty(),
                    "height {} < threshold {} should be pruned", h, threshold
                );
            } else {
                prop_assert_eq!(
                    remaining.len(), 1,
                    "height {} >= threshold {} should survive", h, threshold
                );
            }
        }
    }

    /// Boundary property (a): an output at `block_height < threshold` is
    /// always pruned. Together with [`prop_prune_keeps_at_threshold`] and
    /// [`prop_prune_keeps_above_threshold`] this pins that the SQL is
    /// strict `<`, not `<=`.
    ///
    /// The `(rcl, current)` strategy is conditioned so `current > window`
    /// by construction — no `prop_assume!` needed.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_prune_strictly_below_threshold(
        (reward_cycle_length, current_block_height) in arb_rcl_and_current_above_window(),
    ) {
        let window = (3u64 * u64::from(reward_cycle_length)) / 2;
        let threshold = current_block_height - window;

        let burnchain = Burnchain::regtest(":memory:");
        let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();
        seed_outputs_at_heights(&mut db, &[threshold - 1]);

        let db_tx = db.tx_begin().unwrap();
        db_tx.prune_watched_outputs(reward_cycle_length, current_block_height).unwrap();
        db_tx.commit().unwrap();

        prop_assert!(outputs_at_height(&db, threshold - 1).is_empty());
    }

    /// Boundary property (b): an output at `block_height == threshold`
    /// survives. The SQL uses `<`, not `<=`.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_prune_keeps_at_threshold(
        (reward_cycle_length, current_block_height) in arb_rcl_and_current_above_window(),
    ) {
        let window = (3u64 * u64::from(reward_cycle_length)) / 2;
        let threshold = current_block_height - window;

        let burnchain = Burnchain::regtest(":memory:");
        let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();
        seed_outputs_at_heights(&mut db, &[threshold]);

        let db_tx = db.tx_begin().unwrap();
        db_tx.prune_watched_outputs(reward_cycle_length, current_block_height).unwrap();
        db_tx.commit().unwrap();

        prop_assert_eq!(outputs_at_height(&db, threshold).len(), 1);
    }

    /// Boundary property (c): an output at `block_height > threshold`
    /// survives.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_prune_keeps_above_threshold(
        (reward_cycle_length, current_block_height) in arb_rcl_and_current_above_window(),
    ) {
        let window = (3u64 * u64::from(reward_cycle_length)) / 2;
        let threshold = current_block_height - window;

        let burnchain = Burnchain::regtest(":memory:");
        let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();
        seed_outputs_at_heights(&mut db, &[threshold + 1]);

        let db_tx = db.tx_begin().unwrap();
        db_tx.prune_watched_outputs(reward_cycle_length, current_block_height).unwrap();
        db_tx.commit().unwrap();

        prop_assert_eq!(outputs_at_height(&db, threshold + 1).len(), 1);
    }

    /// Property 4: prune is idempotent. Running it twice with the same arguments
    /// is observationally identical to running it once.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_prune_idempotent(
        reward_cycle_length in 1u32..=10_000,
        current_block_height in 0u64..=(i64::MAX as u64),
        heights in prop::collection::hash_set(0u64..=(i64::MAX as u64), 1..=10),
    ) {
        let burnchain = Burnchain::regtest(":memory:");
        let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

        let mut sorted: Vec<u64> = heights.into_iter().collect();
        sorted.sort();
        seed_outputs_at_heights(&mut db, &sorted);

        let db_tx = db.tx_begin().unwrap();
        db_tx.prune_watched_outputs(reward_cycle_length, current_block_height).unwrap();
        db_tx.commit().unwrap();

        let snapshot_after_first: Vec<(u64, Vec<WatchedP2WSHOutput>)> = sorted
            .iter()
            .map(|&h| (h, outputs_at_height(&db, h)))
            .collect();

        let db_tx = db.tx_begin().unwrap();
        db_tx.prune_watched_outputs(reward_cycle_length, current_block_height).unwrap();
        db_tx.commit().unwrap();

        for (h, expected) in snapshot_after_first {
            let got = outputs_at_height(&db, h);
            prop_assert_eq!(got, expected, "prune at h={} not idempotent", h);
        }
    }

    /// A scriptpubkey of the canonical P2WSH shape `[0x00, 0x20, ..32]`
    /// maps to `SegwitBitcoinAddress::P2WSH` with hash equal to the
    /// 32 trailing bytes. The generator constructs only canonical scripts —
    /// there is no negative branch in this property.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_canonical_p2wsh_script_maps_to_p2wsh(
        witness_hash in any::<[u8; 32]>(),
    ) {
        let mut script = Vec::with_capacity(34);
        script.push(0x00);
        script.push(0x20);
        script.extend_from_slice(&witness_hash);

        let result = BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Mainnet, &script);
        match result {
            Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(_, hash))) => {
                prop_assert_eq!(hash, witness_hash);
            }
            other => prop_assert!(
                false, "canonical P2WSH script produced {:?}", other
            ),
        }
    }

    /// A scriptpubkey of any non-canonical shape does NOT produce a
    /// `SegwitBitcoinAddress::P2WSH`. It may produce a different variant
    /// (P2WPKH, P2TR, P2PKH, P2SH) or `None`, but never P2WSH.
    ///
    /// The generator filters out the canonical shape so the negative
    /// branch is exercised on every iteration.
    #[test]
    #[cfg_attr(test, pinny::tag(t_prop))]
    fn prop_non_canonical_script_never_maps_to_p2wsh(
        script in prop::collection::vec(any::<u8>(), 0..=100)
            .prop_filter(
                "exclude canonical P2WSH shape",
                |v| !(v.len() == 34 && v[0] == 0x00 && v[1] == 0x20),
            ),
    ) {
        let result = BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Mainnet, &script);
        prop_assert!(
            !matches!(
                result,
                Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(_, _)))
            ),
            "non-canonical script of len {} produced P2WSH", script.len()
        );
    }
}

/// Hand-computed (rcl, expected_window) oracle pairs. **Deliberately not**
/// derived from the production `(3 * rcl) / 2` formula — these are
/// independent values the test asserts against. If the production
/// formula drifts (say a rounding fix changes the window for odd RCLs),
/// this loop catches the drift even if a copied formula in the proptest
/// wouldn't.
#[test]
#[cfg_attr(test, pinny::tag(t_prop))]
fn prune_window_table_oracle() {
    // (reward_cycle_length, expected_window)
    let cases: &[(u32, u64)] = &[
        (1, 1),       // (3*1)/2 = 1
        (2, 3),       // (3*2)/2 = 3
        (3, 4),       // (3*3)/2 = 4
        (10, 15),
        (100, 150),
        (1000, 1500),
        (2016, 3024), // ~Bitcoin difficulty cycle
    ];

    for &(rcl, expected_window) in cases {
        let current_block_height: u64 = expected_window + 10; // ensure threshold > 0
        let expected_threshold = current_block_height - expected_window;

        let burnchain = Burnchain::regtest(":memory:");
        let mut db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();
        let triple = [
            expected_threshold - 1,
            expected_threshold,
            expected_threshold + 1,
        ];
        seed_outputs_at_heights(&mut db, &triple);

        let db_tx = db.tx_begin().unwrap();
        db_tx
            .prune_watched_outputs(rcl, current_block_height)
            .unwrap();
        db_tx.commit().unwrap();

        assert!(
            outputs_at_height(&db, expected_threshold - 1).is_empty(),
            "rcl={rcl} window={expected_window}: h<threshold not pruned"
        );
        assert_eq!(
            outputs_at_height(&db, expected_threshold).len(),
            1,
            "rcl={rcl} window={expected_window}: h==threshold pruned (SQL should be `<`, not `<=`)"
        );
        assert_eq!(
            outputs_at_height(&db, expected_threshold + 1).len(),
            1,
            "rcl={rcl} window={expected_window}: h>threshold pruned"
        );
    }
}
