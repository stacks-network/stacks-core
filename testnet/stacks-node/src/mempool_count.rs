/// Usage: {} <working-dir> [max-time]
///
/// This program can be used to "analyze the mempool".
///
/// In particular, it can be used to mine an "unlimited block". That is, it will attempt
/// to build a block from the transactions in the mempool, but will never run out of
/// space in the block. Thus, each transaction in the mempool will be tried once.
///
/// Note that nonces which are too high initially can become appropriate as blocks are processed.
///
/// <working-dir> specifies the `working_dir` from the miner's config file.
/// [max-time] optionally gives an amount of time to stop mining after, useful for debugging.
extern crate stacks;

#[macro_use(slog_info)]
extern crate slog;
use std::env;
use std::process;

use cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;

use crate::util::hash::Hash160;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::StacksBlockBuilder;
use stacks::clarity_vm::clarity::UnlimitedBlockLimitFns;
use stacks::core::MemPoolDB;
use stacks::util::vrf::VRFProof;
use stacks::*;

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!(
            "Usage: {} <working-dir> [max-time]
 ",
            argv[0]
        );
        process::exit(1);
    }

    let base_path = argv[1].clone();
    info!("base_path {}", &base_path);
    let sort_db_path = format!("{}/mainnet/burnchain/sortition", &base_path);
    let chain_state_path = format!("{}/mainnet/chainstate/", &base_path);

    let sort_db = SortitionDB::open(&sort_db_path, false)
        .expect(&format!("Failed to open {}", &sort_db_path));

    let chain_id = core::CHAIN_ID_MAINNET;

    let estimator = Box::new(UnitEstimator);
    let metric = Box::new(UnitMetric);

    let mempool_db = MemPoolDB::open(true, chain_id, &chain_state_path, estimator, metric)
        .expect("Failed to open mempool db");
    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
        .expect("Failed to get sortition chain tip");

    let (mut chain_state, _) = StacksChainState::open_and_exec_with_limits(
        true,
        chain_id,
        &chain_state_path,
        None,
        UnlimitedBlockLimitFns(),
    )
    .expect("Failed to open stacks chain state");
    let stacks_block = chain_state.get_stacks_chain_tip(&sort_db).unwrap().unwrap();
    let parent_header = StacksChainState::get_anchored_block_header_info(
        chain_state.db(),
        &stacks_block.consensus_hash,
        &stacks_block.anchored_block_hash,
    )
    .expect("Failed to load chain tip header info")
    .expect("Failed to load chain tip header info");

    let mut builder = StacksBlockBuilder::make_block_builder(
        chain_state.mainnet,
        &parent_header,
        VRFProof::empty(),
        chain_tip.total_burn,
        Hash160([0; 20]),
    )
    .expect("make builder");

    let burn_dbconn = &sort_db.index_conn();
    let mut miner_epoch_info = builder
        .pre_epoch_begin(&mut chain_state, burn_dbconn)
        .expect("wft");
    let (mut clarity_tx, _) = builder
        .epoch_begin(burn_dbconn, &mut miner_epoch_info)
        .expect("should have worked");

    let all_txs = MemPoolDB::get_all_txs(mempool_db.conn()).expect("couldn't get tx's");
    for tx in all_txs {
        info!("tx {:?}", &tx);
        let sender_address = tx.metadata.origin_address;
        let sender_nonce =
            StacksChainState::get_account(&mut clarity_tx, &sender_address.clone().into()).nonce;
        info!("sender_nonce {:?}", &sender_nonce);
    }
}
