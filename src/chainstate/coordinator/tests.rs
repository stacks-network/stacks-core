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

use std::cmp;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::sync_channel,
    Arc, RwLock,
};

use rusqlite::Connection;

use address;
use burnchains::{db::*, *};
use chainstate;
use chainstate::burn::db::sortdb::SortitionDB;
use chainstate::burn::operations::leader_block_commit::*;
use chainstate::burn::operations::*;
use chainstate::burn::*;
use chainstate::coordinator::{Error as CoordError, *};
use chainstate::stacks::db::{
    accounts::MinerReward, ClarityTx, StacksChainState, StacksHeaderInfo,
};
use chainstate::stacks::*;
use clarity_vm::clarity::ClarityConnection;
use core;
use core::*;
use monitoring::increment_stx_blocks_processed_counter;
use util::hash::{to_hex, Hash160};
use util::vrf::*;
use vm::{
    costs::{ExecutionCost, LimitedCostTracker},
    types::PrincipalData,
    types::QualifiedContractIdentifier,
    Value,
};

use crate::{types, util};
use chainstate::stacks::boot::COSTS_2_NAME;
use rand::RngCore;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, VRFSeed,
};
use util_lib::boot::boot_code_id;
use vm::clarity::TransactionConnection;
use vm::database::BurnStateDB;

lazy_static! {
    static ref BURN_BLOCK_HEADERS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    static ref TXIDS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    static ref MBLOCK_PUBKHS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
}

pub fn next_burn_header_hash() -> BurnchainHeaderHash {
    let cur = BURN_BLOCK_HEADERS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[0; 24]);
    BurnchainHeaderHash::from_bytes(&bytes).unwrap()
}

pub fn next_txid() -> Txid {
    let cur = TXIDS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[1; 24]);
    Txid::from_bytes(&bytes).unwrap()
}

pub fn next_hash160() -> Hash160 {
    let cur = MBLOCK_PUBKHS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[2; 12]);
    Hash160::from_bytes(&bytes).unwrap()
}

/// Produce a burn block, insert it into burnchain_db, and insert it into others as well
pub fn produce_burn_block<'a, I: Iterator<Item = &'a mut BurnchainDB>>(
    burnchain_db: &mut BurnchainDB,
    par: &BurnchainHeaderHash,
    mut ops: Vec<BlockstackOperationType>,
    others: I,
) -> BurnchainHeaderHash {
    let BurnchainBlockData {
        header: par_header, ..
    } = burnchain_db.get_burnchain_block(par).unwrap();
    assert_eq!(&par_header.block_hash, par);
    let block_height = par_header.block_height + 1;
    for op in ops.iter_mut() {
        op.set_block_height(block_height);
    }

    produce_burn_block_do_not_set_height(burnchain_db, par, ops, others)
}

fn produce_burn_block_do_not_set_height<'a, I: Iterator<Item = &'a mut BurnchainDB>>(
    burnchain_db: &mut BurnchainDB,
    par: &BurnchainHeaderHash,
    mut ops: Vec<BlockstackOperationType>,
    others: I,
) -> BurnchainHeaderHash {
    let BurnchainBlockData {
        header: par_header, ..
    } = burnchain_db.get_burnchain_block(par).unwrap();
    assert_eq!(&par_header.block_hash, par);
    let block_height = par_header.block_height + 1;
    let timestamp = par_header.timestamp + 1;
    let num_txs = ops.len() as u64;
    let block_hash = next_burn_header_hash();
    let header = BurnchainBlockHeader {
        block_height,
        timestamp,
        num_txs,
        block_hash: block_hash.clone(),
        parent_block_hash: par.clone(),
    };

    for op in ops.iter_mut() {
        op.set_burn_header_hash(block_hash.clone());
    }

    burnchain_db
        .raw_store_burnchain_block(header.clone(), ops.clone())
        .unwrap();

    for other in others {
        other
            .raw_store_burnchain_block(header.clone(), ops.clone())
            .unwrap();
    }

    block_hash
}

fn p2pkh_from(sk: &StacksPrivateKey) -> StacksAddress {
    let pk = StacksPublicKey::from_private(sk);
    StacksAddress::from_public_keys(
        chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &address::AddressHashMode::SerializeP2PKH,
        1,
        &vec![pk],
    )
    .unwrap()
}

pub fn setup_states(
    paths: &[&str],
    vrf_keys: &[VRFPrivateKey],
    committers: &[StacksPrivateKey],
    pox_consts: Option<PoxConstants>,
    initial_balances: Option<Vec<(PrincipalData, u64)>>,
    stacks_epoch_id: StacksEpochId,
) {
    let mut burn_block = None;
    let mut others = vec![];

    for path in paths.iter() {
        let burnchain = get_burnchain(path, pox_consts.clone());
        let epochs = StacksEpoch::unit_test(stacks_epoch_id, burnchain.first_block_height);
        let sortition_db = SortitionDB::connect(
            &burnchain.get_db_path(),
            burnchain.first_block_height,
            &burnchain.first_block_hash,
            burnchain.first_block_timestamp.into(),
            &epochs,
            true,
        )
        .unwrap();

        let burnchain_blocks_db = BurnchainDB::connect(
            &burnchain.get_burnchaindb_path(),
            burnchain.first_block_height,
            &burnchain.first_block_hash,
            burnchain.first_block_timestamp as u64,
            true,
        )
        .unwrap();

        if burn_block.is_none() {
            let first_sortition =
                SortitionDB::get_canonical_burn_chain_tip(sortition_db.conn()).unwrap();
            let first_consensus_hash = &first_sortition.consensus_hash;

            // build a bunch of VRF key registers

            let registers = vec![];

            burn_block.replace((
                burnchain_blocks_db,
                first_sortition.burn_header_hash,
                registers,
            ));
        } else {
            others.push(burnchain_blocks_db);
        }
    }

    let (mut burnchain_blocks_db, burn_header_hash, registers) = burn_block.take().unwrap();

    produce_burn_block(
        &mut burnchain_blocks_db,
        &burn_header_hash,
        registers,
        others.iter_mut(),
    );

    let initial_balances = initial_balances.unwrap_or(vec![]);
    for path in paths.iter() {
        let burnchain = get_burnchain(path, pox_consts.clone());

        let mut boot_data = ChainStateBootData::new(&burnchain, initial_balances.clone(), None);

        let post_flight_callback = move |clarity_tx: &mut ClarityTx| {
            let contract = boot_code_id("pox", false);
            let sender = PrincipalData::from(contract.clone());

            clarity_tx.connection().as_transaction(|conn| {
                conn.run_contract_call(
                    &sender,
                    &contract,
                    "set-burnchain-parameters",
                    &[
                        Value::UInt(burnchain.first_block_height as u128),
                        Value::UInt(0u128),
                        Value::UInt(0u128),
                        Value::UInt(0u128),
                    ],
                    |_, _| false,
                )
                .expect("Failed to set burnchain parameters in PoX contract");
            });
        };

        boot_data.post_flight_callback = Some(Box::new(post_flight_callback));

        let (chain_state_db, _) = StacksChainState::open_and_exec(
            false,
            0x80000000,
            &format!("{}/chainstate/", path),
            Some(&mut boot_data),
        )
        .unwrap();
    }
}

pub struct NullEventDispatcher;

impl BlockEventDispatcher for NullEventDispatcher {
    fn announce_block(
        &self,
        _block: StacksBlock,
        _metadata: StacksHeaderInfo,
        _receipts: Vec<StacksTransactionReceipt>,
        _parent: &StacksBlockId,
        _winner_txid: Txid,
        _rewards: Vec<MinerReward>,
        _rewards_info: Option<MinerRewardInfo>,
        _parent_burn_block_hash: BurnchainHeaderHash,
        _parent_burn_block_height: u32,
        _parent_burn_block_timestamp: u64,
        _anchor_block_cost: &ExecutionCost,
        _confirmed_mblock_cost: &ExecutionCost,
    ) {
        assert!(
            false,
            "We should never try to announce to the null dispatcher"
        );
    }

    fn announce_burn_block(
        &self,
        _burn_block: &BurnchainHeaderHash,
        _burn_block_height: u64,
        _rewards: Vec<(StacksAddress, u64)>,
        _burns: u64,
        _slot_holders: Vec<StacksAddress>,
    ) {
    }

    fn dispatch_boot_receipts(&mut self, _receipts: Vec<StacksTransactionReceipt>) {}
}

pub fn make_coordinator<'a>(
    path: &str,
    burnchain: Option<Burnchain>,
) -> ChainsCoordinator<'a, NullEventDispatcher, (), OnChainRewardSetProvider, (), ()> {
    let (tx, _) = sync_channel(100000);
    let burnchain = burnchain.unwrap_or_else(|| get_burnchain(path, None));
    ChainsCoordinator::test_new(&burnchain, 0x80000000, path, OnChainRewardSetProvider(), tx)
}

struct StubbedRewardSetProvider(Vec<StacksAddress>);

impl RewardSetProvider for StubbedRewardSetProvider {
    fn get_reward_set(
        &self,
        _current_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<Vec<StacksAddress>, chainstate::coordinator::Error> {
        Ok(self.0.clone())
    }
}

fn make_reward_set_coordinator<'a>(
    path: &str,
    addrs: Vec<StacksAddress>,
    pox_consts: Option<PoxConstants>,
) -> ChainsCoordinator<'a, NullEventDispatcher, (), StubbedRewardSetProvider, (), ()> {
    let (tx, _) = sync_channel(100000);
    ChainsCoordinator::test_new(
        &get_burnchain(path, pox_consts),
        0x80000000,
        path,
        StubbedRewardSetProvider(addrs),
        tx,
    )
}

pub fn get_burnchain(path: &str, pox_consts: Option<PoxConstants>) -> Burnchain {
    let mut b = Burnchain::regtest(&format!("{}/burnchain/db/", path));
    b.pox_constants = pox_consts.unwrap_or_else(|| PoxConstants::new(5));
    b
}

pub fn get_sortition_db(path: &str, pox_consts: Option<PoxConstants>) -> SortitionDB {
    let burnchain = get_burnchain(path, pox_consts);
    SortitionDB::open(&burnchain.get_db_path(), false).unwrap()
}

pub fn get_rw_sortdb(path: &str, pox_consts: Option<PoxConstants>) -> SortitionDB {
    let burnchain = get_burnchain(path, pox_consts);
    SortitionDB::open(&burnchain.get_db_path(), true).unwrap()
}

pub fn get_burnchain_db(path: &str, pox_consts: Option<PoxConstants>) -> BurnchainDB {
    let burnchain = get_burnchain(path, pox_consts);
    BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap()
}

pub fn get_chainstate_path_str(path: &str) -> String {
    format!("{}/chainstate/", path)
}

pub fn get_chainstate(path: &str) -> StacksChainState {
    let (chainstate, _) =
        StacksChainState::open(false, 0x80000000, &get_chainstate_path_str(path)).unwrap();
    chainstate
}

fn make_genesis_block(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    parent_block: &BlockHeaderHash,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
) -> (BlockstackOperationType, StacksBlock) {
    make_genesis_block_with_recipients(
        sort_db,
        state,
        parent_block,
        miner,
        my_burn,
        vrf_key,
        key_index,
        None,
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork.
fn make_genesis_block_with_recipients(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    parent_block: &BlockHeaderHash,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
) -> (BlockstackOperationType, StacksBlock) {
    let tx_auth = TransactionAuth::from_p2pkh(miner).unwrap();

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
    );
    tx.chain_id = 0x80000000;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(miner).unwrap();

    let coinbase_op = tx_signer.get_tx().unwrap();

    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

    let parent_stacks_header = StacksHeaderInfo::regtest_genesis();

    let proof = VRF::prove(vrf_key, sortition_tip.sortition_hash.as_bytes());

    let mut builder = StacksBlockBuilder::make_regtest_block_builder(
        &parent_stacks_header,
        proof.clone(),
        0,
        next_hash160(),
    )
    .unwrap();

    let iconn = sort_db.index_conn();
    let mut miner_epoch_info = builder.pre_epoch_begin(state, &iconn).unwrap();
    let mut epoch_tx = builder
        .epoch_begin(&iconn, &mut miner_epoch_info)
        .unwrap()
        .0;

    builder.try_mine_tx(&mut epoch_tx, &coinbase_op).unwrap();

    let block = builder.mine_anchored_block(&mut epoch_tx);
    builder.epoch_finish(epoch_tx);

    let commit_op = LeaderBlockCommitOp {
        block_header_hash: block.block_hash(),
        withdrawal_merkle_root: block.header.withdrawal_merkle_root,
        txid: next_txid(),
        burn_header_hash: BurnchainHeaderHash([0; 32]),
    };

    (BlockstackOperationType::LeaderBlockCommit(commit_op), block)
}

fn make_stacks_block(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
) -> (BlockstackOperationType, StacksBlock) {
    make_stacks_block_with_recipients(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        None,
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
fn make_stacks_block_with_recipients(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
) -> (BlockstackOperationType, StacksBlock) {
    make_stacks_block_with_recipients_and_sunset_burn(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        recipients,
        0,
        false,
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
fn make_stacks_block_with_recipients_and_sunset_burn(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
    sunset_burn: u64,
    post_sunset_burn: bool,
) -> (BlockstackOperationType, StacksBlock) {
    make_stacks_block_with_input(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        recipients,
        sunset_burn,
        post_sunset_burn,
        (Txid([0; 32]), 0),
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
fn make_stacks_block_with_input(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
    sunset_burn: u64,
    post_sunset_burn: bool,
    input: (Txid, u32),
) -> (BlockstackOperationType, StacksBlock) {
    let tx_auth = TransactionAuth::from_p2pkh(miner).unwrap();

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
    );
    tx.chain_id = 0x80000000;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(miner).unwrap();

    let coinbase_op = tx_signer.get_tx().unwrap();

    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    let parents_sortition = SortitionDB::get_block_snapshot_for_winning_stacks_block(
        &sort_db.index_conn(),
        &sortition_tip.sortition_id,
        parent_block,
    )
    .unwrap()
    .unwrap();

    eprintln!(
        "Find parents stacks header: {} in sortition {}",
        &parent_block, &parents_sortition.sortition_id
    );
    let parent_stacks_header = StacksChainState::get_anchored_block_header_info(
        state.db(),
        &parents_sortition.consensus_hash,
        parent_block,
    )
    .unwrap()
    .unwrap();
    let proof = VRF::prove(vrf_key, sortition_tip.sortition_hash.as_bytes());

    let total_burn = parents_sortition.total_burn;

    let iconn = sort_db.index_conn();

    let mut builder = StacksBlockBuilder::make_regtest_block_builder(
        &parent_stacks_header,
        proof.clone(),
        total_burn,
        next_hash160(),
    )
    .unwrap();
    let mut miner_epoch_info = builder.pre_epoch_begin(state, &iconn).unwrap();
    let mut epoch_tx = builder
        .epoch_begin(&iconn, &mut miner_epoch_info)
        .unwrap()
        .0;

    builder.try_mine_tx(&mut epoch_tx, &coinbase_op).unwrap();

    let block = builder.mine_anchored_block(&mut epoch_tx);
    builder.epoch_finish(epoch_tx);

    let commit_op = LeaderBlockCommitOp {
        block_header_hash: block.block_hash(),
        withdrawal_merkle_root: block.header.withdrawal_merkle_root,
        txid: next_txid(),
        burn_header_hash: BurnchainHeaderHash([0; 32]),
    };

    (BlockstackOperationType::LeaderBlockCommit(commit_op), block)
}

#[test]
fn test_simple_setup() {
    let path = "/tmp/stacks-node-tests/unit-tests/stacks-blockchain-simple-setup";
    // setup a second set of states that won't see the broadcasted blocks
    let path_blinded = "/tmp/stacks-node-tests/unit-tests/stacks-blockchain-simple-setup.blinded";
    let _r = std::fs::remove_dir_all(path);
    let _r = std::fs::remove_dir_all(path_blinded);

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path, path_blinded],
        &vrf_keys,
        &committers,
        None,
        None,
        StacksEpochId::Epoch20,
    );

    let mut coord = make_coordinator(path, None);
    let mut coord_blind = make_coordinator(path_blinded, None);

    coord.handle_new_burnchain_block().unwrap();
    coord_blind.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);

    let sort_db_blind = get_sortition_db(path_blinded, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);

    // sortition ids in stacks-subnets should never diverge in this test
    //  (because there are no more PoX reward cycles)
    let sortition_ids_diverged = false;
    let mut parent = BlockHeaderHash([0; 32]);
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks = vec![];
    for (ix, (vrf_key, miner)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let mut burnchain = get_burnchain_db(path, None);
        let mut chainstate = get_chainstate(path);
        let b = get_burnchain(path, None);
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let burnchain_blinded = get_burnchain_db(path_blinded, None);

        let (op, block) = if ix == 0 {
            make_genesis_block(
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        } else {
            make_stacks_block(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        };

        produce_burn_block(
            &mut burnchain,
            &burnchain_tip.block_hash,
            vec![op],
            [burnchain_blinded].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();
        coord_blind.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let blinded_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
        if sortition_ids_diverged {
            assert_ne!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should have diverged by block height = {}",
                blinded_tip.block_height
            );
        } else {
            assert_eq!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should not have diverged at block height = {}",
                blinded_tip.block_height
            );
        }

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        parent = block_hash;
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_conn(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(50)
    );

    // now let's start revealing stacks blocks to the blinded coordinator
    for (sortition_id, block) in stacks_blocks.iter() {
        reveal_block(
            path_blinded,
            &sort_db_blind,
            &mut coord_blind,
            sortition_id,
            block,
        );
    }
}

fn eval_at_chain_tip(chainstate_path: &str, sort_db: &SortitionDB, eval: &str) -> Value {
    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(chainstate_path);
    chainstate
        .with_read_only_clarity_tx(
            &sort_db.index_conn(),
            &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
            |conn| {
                conn.with_readonly_clarity_env(
                    false,
                    PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                    LimitedCostTracker::new_free(),
                    |env| env.eval_raw(eval),
                )
                .unwrap()
            },
        )
        .unwrap()
}

fn reveal_block<T: BlockEventDispatcher, N: CoordinatorNotices, U: RewardSetProvider>(
    chainstate_path: &str,
    sort_db: &SortitionDB,
    coord: &mut ChainsCoordinator<T, N, U, (), ()>,
    my_sortition: &SortitionId,
    block: &StacksBlock,
) {
    let mut chainstate = get_chainstate(chainstate_path);
    let sortition = SortitionDB::get_block_snapshot(sort_db.conn(), &my_sortition)
        .unwrap()
        .unwrap();
    preprocess_block(&mut chainstate, sort_db, &sortition, block.clone());
    coord.handle_new_stacks_block().unwrap();
}

fn preprocess_block(
    chain_state: &mut StacksChainState,
    sort_db: &SortitionDB,
    my_sortition: &BlockSnapshot,
    block: StacksBlock,
) {
    let ic = sort_db.index_conn();
    let parent_consensus_hash = SortitionDB::get_block_snapshot_for_winning_stacks_block(
        &ic,
        &my_sortition.sortition_id,
        &block.header.parent_block,
    )
    .unwrap()
    .unwrap()
    .consensus_hash;
    // Preprocess the anchored block
    chain_state
        .preprocess_anchored_block(
            &ic,
            &my_sortition.consensus_hash,
            &block,
            &parent_consensus_hash,
            5,
        )
        .unwrap();
}

#[test]
fn test_check_chainstate_db_versions() {
    let path = "/tmp/stacks-blockchain-check_chainstate_db_versions";
    let _ = std::fs::remove_dir_all(path);

    let sortdb_path = format!("{}/sortdb", &path);
    let chainstate_path = format!("{}/chainstate", &path);

    let epoch_2 = StacksEpoch {
        epoch_id: StacksEpochId::Epoch20,
        start_height: 0,
        end_height: 10000,
        block_limit: BLOCK_LIMIT_MAINNET_20.clone(),
        network_epoch: PEER_VERSION_EPOCH_2_0,
    };
    let epoch_2_05 = StacksEpoch {
        epoch_id: StacksEpochId::Epoch2_05,
        start_height: 0,
        end_height: 10000,
        block_limit: BLOCK_LIMIT_MAINNET_205.clone(),
        network_epoch: PEER_VERSION_EPOCH_2_05,
    };

    // should work just fine in epoch 2 if the DBs don't exist
    assert!(
        check_chainstate_db_versions(&[epoch_2.clone()], &sortdb_path, &chainstate_path).unwrap()
    );

    // should work just fine in epoch 2.05 if the DBs don't exist
    assert!(
        check_chainstate_db_versions(&[epoch_2_05.clone()], &sortdb_path, &chainstate_path)
            .unwrap()
    );

    StacksChainState::make_chainstate_dirs(&chainstate_path).unwrap();

    let sortdb_v1 =
        SortitionDB::connect_v1(&sortdb_path, 100, &BurnchainHeaderHash([0x00; 32]), 0, true)
            .unwrap();
    let chainstate_v1 = StacksChainState::open_db_without_migrations(
        false,
        CHAIN_ID_TESTNET,
        &StacksChainState::header_index_root_path(PathBuf::from(&chainstate_path))
            .to_str()
            .unwrap(),
    )
    .unwrap();

    assert!(fs::metadata(&chainstate_path).is_ok());
    assert!(fs::metadata(&sortdb_path).is_ok());
    assert_eq!(
        StacksChainState::get_db_config_from_path(&chainstate_path)
            .unwrap()
            .version,
        "1"
    );
    assert_eq!(
        SortitionDB::get_db_version_from_path(&sortdb_path)
            .unwrap()
            .unwrap(),
        "1"
    );

    // should work just fine in epoch 2
    assert!(
        check_chainstate_db_versions(&[epoch_2.clone()], &sortdb_path, &chainstate_path).unwrap()
    );

    // should fail in epoch 2.05
    assert!(
        !check_chainstate_db_versions(&[epoch_2_05.clone()], &sortdb_path, &chainstate_path)
            .unwrap()
    );
}
