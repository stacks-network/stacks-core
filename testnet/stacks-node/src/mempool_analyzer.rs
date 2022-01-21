#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate postgres;
use postgres::{Client, Error, NoTls};

#[macro_use]
extern crate stacks;

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

use std::io;
use std::io::prelude::*;
use std::process;
use std::{collections::HashMap, env};
use std::{convert::TryFrom, fs};

use cost_estimates::metrics::UnitMetric;
use stacks::burnchains::BLOCKSTACK_MAGIC_MAINNET;
use stacks::cost_estimates::UnitEstimator;

use lazy_static::lazy_static; // 1.4.0
use stacks::burnchains::bitcoin::indexer::{BitcoinIndexerConfig, BitcoinIndexerRuntime};
use stacks::burnchains::bitcoin::spv;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::db::ChainStateBootData;
use stacks::chainstate::stacks::index::marf::MarfConnection;
use stacks::chainstate::stacks::index::marf::MARF;
use stacks::chainstate::stacks::miner::*;
use stacks::chainstate::stacks::*;
use stacks::codec::StacksMessageCodec;
use stacks::core::mempool::*;
use stacks::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, PoxId};
use stacks::types::chainstate::{StacksBlockHeader, StacksBlockId};
use stacks::types::proof::ClarityMarfTrieId;
use stacks::util::get_epoch_time_ms;
use stacks::util::hash::{hex_bytes, to_hex};
use stacks::util::log;
use stacks::util::retry::LogReader;
use stacks::*;
use stacks::{
    burnchains::{db::BurnchainBlockData, PoxConstants},
    chainstate::{
        burn::db::sortdb::SortitionDB,
        stacks::db::{StacksChainState, StacksHeaderInfo},
    },
    core::MemPoolDB,
    util::db::sqlite_open,
    util::{hash::Hash160, vrf::VRFProof},
    vm::costs::ExecutionCost,
};
use stacks::{
    net::{db::LocalPeer, p2p::PeerNetwork, PeerAddress},
    vm::representations::UrlString,
};
use std::sync::Mutex;

lazy_static! {
    static ref client: Mutex<Client> = Mutex::new(
        Client::connect(
            "postgresql://postgres:postgres@localhost/temp_database",
            NoTls,
        )
        .expect("couldnt start climate")
    );
}

struct MemPoolEventDispatcherImpl {}

impl MemPoolEventDispatcherImpl {
    fn new() -> MemPoolEventDispatcherImpl {
        return MemPoolEventDispatcherImpl {};
    }
}

#[derive(Debug)]
struct MempoolTxRow {
    pub tx_id: Txid,
    pub status_code: i32,
    pub reason: String,
}

fn mempool_tx_row_from_event(event: &TransactionEvent) -> MempoolTxRow {
    match event {
        TransactionEvent::Success(TransactionSuccessEvent {
            txid,
            fee: _,
            execution_cost: _,
            result: _,
        }) => MempoolTxRow {
            tx_id: txid.clone(),
            status_code: 0,
            reason: "".to_string(),
        },
        TransactionEvent::ProcessingError(TransactionErrorEvent { txid, error }) => MempoolTxRow {
            tx_id: txid.clone(),
            status_code: 1,
            reason: error.to_string(),
        },
        TransactionEvent::Skipped(TransactionSkippedEvent { txid, error }) => MempoolTxRow {
            tx_id: txid.clone(),
            status_code: 2,
            reason: error.to_string(),
        },
    }
}

impl MemPoolEventDispatcher for MemPoolEventDispatcherImpl {
    fn mempool_txs_dropped(&self, _txids: Vec<Txid>, _reason: MemPoolDropReason) {
        panic!("`mempool_txs_dropped` was not expected in this workflow.");
    }
    fn mined_block_event(
        &self,
        _target_burn_height: u64,
        _block: &StacksBlock,
        _block_size_bytes: u64,
        _consumed: &ExecutionCost,
        _confirmed_microblock_cost: &ExecutionCost,
        tx_results: Vec<TransactionEvent>,
    ) {
        for tx_event in tx_results {
            let tuple = mempool_tx_row_from_event(&tx_event);

            client
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO mempool_tx_attempt (tx_id, status, comment) VALUES ($1, $2, $3)",
                    &[&"id3", &"status3", &"comment3"],
                )
                .expect("tried to insert");
        }
    }
    fn mined_microblock_event(
        &self,
        _microblock: &StacksMicroblock,
        _tx_results: Vec<TransactionEvent>,
        _anchor_block_consensus_hash: ConsensusHash,
        _anchor_block: BlockHeaderHash,
    ) {
        panic!("`mined_microblock_event` was not expected in this workflow.");
    }
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "Usage: {} <working-dir> [min-fee [max-time]]

Given a <working-dir>, try to ''mine'' an anchored block. This invokes the miner block
assembly, but does not attempt to broadcast a block commit. This is useful for determining
what transactions a given chain state would include in an anchor block, or otherwise
simulating a miner.
",
            argv[0]
        );
        process::exit(1);
    }

    let dispatcher = MemPoolEventDispatcherImpl::new();

    let start = get_epoch_time_ms();
    let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[1]);
    let chain_state_path = format!("{}/mainnet/chainstate/", &argv[1]);

    let mut min_fee = u64::max_value();
    let mut max_time = u64::max_value();

    if argv.len() >= 3 {
        min_fee = argv[2].parse().expect("Could not parse min_fee");
    }
    if argv.len() >= 4 {
        max_time = argv[3].parse().expect("Could not parse max_time");
    }

    let sort_db = SortitionDB::open(&sort_db_path, false)
        .expect(&format!("Failed to open {}", &sort_db_path));
    let chain_id = core::CHAIN_ID_MAINNET;
    let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path)
        .expect("Failed to open stacks chain state");
    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
        .expect("Failed to get sortition chain tip");

    let estimator = Box::new(UnitEstimator);
    let metric = Box::new(UnitMetric);

    let mut mempool_db = MemPoolDB::open(true, chain_id, &chain_state_path, estimator, metric)
        .expect("Failed to open mempool db");

    let stacks_block = chain_state.get_stacks_chain_tip(&sort_db).unwrap().unwrap();
    let parent_header = StacksChainState::get_anchored_block_header_info(
        chain_state.db(),
        &stacks_block.consensus_hash,
        &stacks_block.anchored_block_hash,
    )
    .expect("Failed to load chain tip header info")
    .expect("Failed to load chain tip header info");

    let sk = StacksPrivateKey::new();
    let mut tx_auth = TransactionAuth::from_p2pkh(&sk).unwrap();
    tx_auth.set_origin_nonce(0);

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
    );

    coinbase_tx.chain_id = chain_id;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&coinbase_tx);
    tx_signer.sign_origin(&sk).unwrap();
    let coinbase_tx = tx_signer.get_tx().unwrap();

    let mut settings = BlockBuilderSettings::limited();
    settings.max_miner_time_ms = max_time;
    settings.mempool_settings.min_tx_fee = min_fee;

    let result = StacksBlockBuilder::build_anchored_block(
        &chain_state,
        &sort_db.index_conn(),
        &mut mempool_db,
        &parent_header,
        chain_tip.total_burn,
        VRFProof::empty(),
        Hash160([0; 20]),
        &coinbase_tx,
        settings,
        None,
        u64::MAX,
    );

    let stop = get_epoch_time_ms();

    println!(
        "{} mined block @ height = {} off of {} ({}/{}) in {}ms. Min-fee: {}, Max-time: {}",
        if result.is_ok() {
            "Successfully"
        } else {
            "Failed to"
        },
        parent_header.block_height + 1,
        StacksBlockHeader::make_index_block_hash(
            &parent_header.consensus_hash,
            &parent_header.anchored_header.block_hash()
        ),
        &parent_header.consensus_hash,
        &parent_header.anchored_header.block_hash(),
        stop.saturating_sub(start),
        min_fee,
        max_time
    );

    if let Ok((block, execution_cost, size)) = result {
        let mut total_fees = 0;
        for tx in block.txs.iter() {
            total_fees += tx.get_tx_fee();
        }
        println!(
            "Block {}: {} uSTX, {} bytes, cost {:?}",
            block.block_hash(),
            total_fees,
            size,
            &execution_cost
        );
    }

    process::exit(0);
}
