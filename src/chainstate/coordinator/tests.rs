use util::hash::Hash160;
use std::collections::VecDeque;
use chainstate::coordinator::*;
use chainstate::stacks::*;
use chainstate::burn::operations::*;

use std::sync::{ Arc, RwLock, atomic::{Ordering, AtomicU64, AtomicBool}};

use crossbeam_channel::{select, bounded, Sender, Receiver, Select, TrySendError};
use util::vrf::*;
use core;
use burnchains::{*, db::*};
use chainstate::burn::*;
use chainstate::burn::db::sortdb::{SortitionDB, PoxId, SortitionId};
use chainstate::stacks::index::TrieHash;
use chainstate::stacks::db::{
    StacksHeaderInfo, StacksChainState, ClarityTx
};
use monitoring::{
    increment_stx_blocks_processed_counter,
};
use vm::{
    Value, types::QualifiedContractIdentifier,
    costs::{ExecutionCost, LimitedCostTracker},
    types::PrincipalData, clarity::ClarityConnection
};

use address;
use chainstate;

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

pub fn produce_burn_block(burnchain_db: &mut BurnchainDB, par: &BurnchainHeaderHash, mut ops: Vec<BlockstackOperationType>) -> BurnchainHeaderHash {
    let BurnchainBlockData { header: par_header, .. } = burnchain_db.get_burnchain_block(par).unwrap();
    assert_eq!(&par_header.block_hash, par);
    let block_height = par_header.block_height + 1;
    let timestamp = par_header.timestamp + 1;
    let num_txs = ops.len() as u64;
    let block_hash = next_burn_header_hash();
    let header = BurnchainBlockHeader {
        block_height, timestamp, num_txs,
        block_hash: block_hash.clone(),
        parent_block_hash: par.clone()
    };

    for op in ops.iter_mut() {
        op.set_block_height(block_height);
        op.set_burn_header_hash(block_hash.clone());
    }

    burnchain_db.raw_store_burnchain_block(header, ops).unwrap();
    block_hash
}

fn p2pkh_from(sk: &StacksPrivateKey) -> StacksAddress {
    let pk = StacksPublicKey::from_private(sk);
    StacksAddress::from_public_keys(
        chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &address::AddressHashMode::SerializeP2PKH,
        1, &vec![pk]).unwrap()
}

pub fn setup_states(path: &str, vrf_keys: &[VRFPrivateKey], committers: &[StacksPrivateKey]) {
    let burnchain = get_burnchain(path);

    let sortition_db = SortitionDB::connect(
        &burnchain.get_db_path(), burnchain.first_block_height, &burnchain.first_block_hash,
        0, true).unwrap();

    let mut burnchain_blocks_db = BurnchainDB::connect(
        &burnchain.get_burnchaindb_path(), burnchain.first_block_height, &burnchain.first_block_hash,
        0, true).unwrap();

    let first_sortition = SortitionDB::get_canonical_burn_chain_tip(sortition_db.conn()).unwrap();
    let first_consensus_hash = &first_sortition.consensus_hash;

    // build a bunch of VRF key registers

    let mut registers = vec![];
    for (ix, (sk, miner_sk)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let public_key = VRFPublicKey::from_private(sk);
        let consensus_hash = first_consensus_hash.clone();
        let memo = vec![0];
        let address = p2pkh_from(miner_sk);
        let vtxindex = 1+ix as u32;
        let block_height = 0;
        let burn_header_hash = BurnchainHeaderHash([0; 32]);
        let txid = next_txid();

        registers.push(BlockstackOperationType::LeaderKeyRegister(
            LeaderKeyRegisterOp {
                public_key, consensus_hash, memo, address, vtxindex, block_height,
                burn_header_hash, txid
            }));
    }

    produce_burn_block(&mut burnchain_blocks_db, &first_sortition.burn_header_hash, registers);

    let initial_balances = Some(vec![]);
    let block_limit = ExecutionCost::max_value();

    let chain_state_db = StacksChainState::open_and_exec(
        false, 0xdeadbeef, &format!("{}/chainstate/", path),
        initial_balances, |_| {}, block_limit)
        .unwrap();
}

pub struct NullEventDispatcher;

impl BlockEventDispatcher for NullEventDispatcher {
    fn announce_block(&self, _block: StacksBlock, _metadata: StacksHeaderInfo,
                      _receipts: Vec<StacksTransactionReceipt>, _parent: &StacksBlockId) {
        assert!(false, "We should never try to announce to the null dispatcher");
    }
}

pub fn make_coordinator<'a>(path: &str) -> ChainsCoordinator<'a, NullEventDispatcher, ()> {
    ChainsCoordinator::test_new(&get_burnchain(path), path)
}

fn get_burnchain(path: &str) -> Burnchain {
    let mut b = Burnchain::new(&format!("{}/burnchain/db/", path), "bitcoin", "regtest").unwrap();
    b.reward_cycle_period = 5;
    b
}

fn get_sortition_db(path: &str) -> SortitionDB {
    let burnchain = get_burnchain(path);
    SortitionDB::open(&burnchain.get_db_path(), false).unwrap()
}

fn get_burnchain_db(path: &str) -> BurnchainDB {
    let burnchain = get_burnchain(path);
    BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap()
}

fn get_chainstate(path: &str) -> StacksChainState {
    StacksChainState::open(false, 0xdeadbeef, &format!("{}/chainstate/", path)).unwrap()
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork.
fn make_genesis_block(sort_db: &SortitionDB, state: &mut StacksChainState,
                     parent_block: &BlockHeaderHash,
                     miner: &StacksPrivateKey, my_burn: u64,
                     vrf_key: &VRFPrivateKey, key_index: u32) -> (BlockstackOperationType, StacksBlock) {
    let tx_auth = TransactionAuth::from_p2pkh(miner).unwrap();

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet, 
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
    tx.chain_id = 0xdeadbeef;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(miner).unwrap();

    let coinbase_op = tx_signer.get_tx().unwrap();

    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

    let parent_stacks_header = StacksHeaderInfo::genesis_block_header_info(TrieHash([0u8; 32]));

    let proof = VRF::prove(vrf_key, sortition_tip.sortition_hash.as_bytes());

    let mut builder = StacksBlockBuilder::make_block_builder(
        &parent_stacks_header, proof.clone(), 0, next_hash160()).unwrap();

    let mut epoch_tx = builder.epoch_begin(state).unwrap();
    builder.try_mine_tx(&mut epoch_tx, &coinbase_op).unwrap();

    let block = builder.mine_anchored_block(&mut epoch_tx);
    builder.epoch_finish(epoch_tx);

    let commit_op = LeaderBlockCommitOp {
        block_header_hash: block.block_hash(),
        burn_fee: my_burn,
        input: BurnchainSigner {
            num_sigs: 1,
            hash_mode: address::AddressHashMode::SerializeP2PKH,
            public_keys: vec![ StacksPublicKey::from_private(miner) ]
        },
        key_block_ptr: 1, // all registers happen in block height 1
        key_vtxindex: (1+key_index) as u16,
        memo: vec![],
        new_seed: VRFSeed::from_proof(&proof),

        parent_block_ptr: 0,
        parent_vtxindex: 0,

        txid: next_txid(),
        vtxindex: 1,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0; 32]),
    };

    (BlockstackOperationType::LeaderBlockCommit(commit_op), block)
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
fn make_stacks_block(sort_db: &SortitionDB, state: &mut StacksChainState,
                     parent_block: &BlockHeaderHash,
                     miner: &StacksPrivateKey, my_burn: u64,
                     vrf_key: &VRFPrivateKey, key_index: u32) -> (BlockstackOperationType, StacksBlock) {
    let tx_auth = TransactionAuth::from_p2pkh(miner).unwrap();

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet, 
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));
    tx.chain_id = 0xdeadbeef;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(miner).unwrap();

    let coinbase_op = tx_signer.get_tx().unwrap();

    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    let parents_sortition = SortitionDB::get_block_snapshot_for_winning_stacks_block(
        &sort_db.index_conn(), &sortition_tip.sortition_id, parent_block).unwrap().unwrap();

    let parent_vtxindex = SortitionDB::get_block_winning_vtxindex(sort_db.conn(), &parents_sortition.sortition_id)
        .unwrap().unwrap();

    eprintln!("Find parents stacks header...");
    let parent_stacks_header = StacksChainState::get_anchored_block_header_info(&state.headers_db,
                                                                                &parents_sortition.consensus_hash,
                                                                                parent_block).unwrap().unwrap();
    let proof = VRF::prove(vrf_key, sortition_tip.sortition_hash.as_bytes());

    let total_burn = parents_sortition.total_burn;

    let mut builder = StacksBlockBuilder::make_block_builder(
        &parent_stacks_header, proof.clone(), total_burn, next_hash160()).unwrap();
    let mut epoch_tx = builder.epoch_begin(state).unwrap();
    builder.try_mine_tx(&mut epoch_tx, &coinbase_op).unwrap();

    let block = builder.mine_anchored_block(&mut epoch_tx);
    builder.epoch_finish(epoch_tx);

    let commit_op = LeaderBlockCommitOp {
        block_header_hash: block.block_hash(),
        burn_fee: my_burn,
        input: BurnchainSigner {
            num_sigs: 1,
            hash_mode: address::AddressHashMode::SerializeP2PKH,
            public_keys: vec![ StacksPublicKey::from_private(miner) ]
        },
        key_block_ptr: 1, // all registers happen in block height 1
        key_vtxindex: (1+key_index) as u16,
        memo: vec![],
        new_seed: VRFSeed::from_proof(&proof),

        parent_block_ptr: parents_sortition.block_height as u32,
        parent_vtxindex,

        txid: next_txid(),
        vtxindex: 1,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0; 32]),
    };

    (BlockstackOperationType::LeaderBlockCommit(commit_op), block)
}

#[test]
fn test_simple_setup() {
    let path = "/tmp/stacks-blockchain-simple-setup";
    let _r = std::fs::remove_dir_all(path);

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    setup_states(path, &vrf_keys, &committers);

    let mut coord = make_coordinator(path);

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db.get_sortition_result(&tip.sortition_id).unwrap().unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut parent = BlockHeaderHash([0; 32]);
    // process sequential blocks, and their sortitions...
    for (ix, (vrf_key, miner)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let mut burnchain = get_burnchain_db(path);
        let mut chainstate = get_chainstate(path);
        let (op, block) =
            if ix == 0 {
                make_genesis_block(&sort_db, &mut chainstate, &parent, miner, 10000, vrf_key, ix as u32)
            } else {
                make_stacks_block(&sort_db, &mut chainstate, &parent, miner, 10000, vrf_key, ix as u32)
            };
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(&mut burnchain, &burnchain_tip.block_hash, vec![op]);
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.process_ready_blocks().unwrap();

        parent = block_hash;
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn())
        .unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate.with_read_only_clarity_tx(
            &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
            |conn| conn.with_readonly_clarity_env(
                PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                LimitedCostTracker::new_max_limit(),
                |env| env.eval_raw("block-height")).unwrap()),
        Value::UInt(50));
}

fn preprocess_block(chain_state: &mut StacksChainState, sort_db: &SortitionDB,
                    my_sortition: &BlockSnapshot, block: StacksBlock) {
    let ic = sort_db.index_conn();

    let parent_consensus_hash = SortitionDB::get_block_snapshot_for_winning_stacks_block(
        &ic, &my_sortition.sortition_id, &block.header.parent_block).unwrap().unwrap()
        .consensus_hash;
    // Preprocess the anchored block
    chain_state.preprocess_anchored_block(
        &ic, &my_sortition.consensus_hash, &block,
        &parent_consensus_hash).unwrap();
}
