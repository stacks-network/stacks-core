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

    let (mut chain_state, _) = StacksChainState::open_and_exec(
        true,
        chain_id,
        &chain_state_path,
        None,
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
    let mut num_equal = 0;
    let mut num_too_low = 0;
    let mut num_too_high = 0;

    for tx in all_txs {
        let supplied_origin_nonce = tx.metadata.origin_nonce;
        let origin_address = tx.metadata.origin_address;
        let needed_nonce =
            StacksChainState::get_account(&mut clarity_tx, &origin_address.clone().into()).nonce;
        let same = supplied_origin_nonce == needed_nonce;
        if supplied_origin_nonce == needed_nonce {
            num_equal += 1;
        } else if supplied_origin_nonce < needed_nonce {
            num_too_low += 1;
        } else if supplied_origin_nonce > needed_nonce {
            num_too_high += 1;
        }
        info!("origin {:?} supplied={} needed={} same={}", &origin_address, supplied_origin_nonce, needed_nonce, same);
    }

    info!("num_equal {} num_too_low {} num_too_high {}", num_equal, num_too_low, num_too_high);
}
