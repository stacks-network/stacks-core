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

use stacks::*;
use stacks::core::MemPoolDB;

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

    let chain_state_path = format!("{}/mainnet/chainstate/", &argv[1]);

    let chain_id = core::CHAIN_ID_MAINNET;

    let estimator = Box::new(UnitEstimator);
    let metric = Box::new(UnitMetric);

    let mempool_db = MemPoolDB::open(true, chain_id, &chain_state_path, estimator, metric)
        .expect("Failed to open mempool db");

    let all_txs = MemPoolDB::get_all_txs(mempool_db.conn());
    for tx in all_txs {
        info!("tx {:?}", &tx);
    }
    
}
