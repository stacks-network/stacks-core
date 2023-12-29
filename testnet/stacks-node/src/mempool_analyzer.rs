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

#[macro_use(slog_warn)]
extern crate slog;
use std::env;
use std::fs::File;
use std::io::Write;
use std::process;

use cost_estimates::metrics::UnitMetric;
use stacks::burnchains::PoxConstants;
use stacks::clarity_vm::clarity::ProductionBlockLimitFns;
use stacks::core::BLOCK_LIMIT_MAINNET_21;
use stacks::cost_estimates::UnitEstimator;

use clarity_vm::clarity::UnlimitedBlockLimitFns;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::miner::*;
use stacks::chainstate::stacks::*;
use stacks::core::mempool::*;
use stacks::types::chainstate::BlockHeaderHash;
use stacks::*;
use stacks::{
    chainstate::{burn::db::sortdb::SortitionDB, stacks::db::StacksChainState},
    core::MemPoolDB,
    util::{hash::Hash160, vrf::VRFProof},
    vm::costs::ExecutionCost,
};

#[derive(Debug)]
/// Prints transaction events to the standard output.
struct PrintDebugEventDispatcher {}

impl PrintDebugEventDispatcher {
    fn new() -> PrintDebugEventDispatcher {
        return PrintDebugEventDispatcher {};
    }
}

impl MemPoolEventDispatcher for PrintDebugEventDispatcher {
    fn mempool_txs_dropped(&self, _txids: Vec<Txid>, _reason: MemPoolDropReason) {
        println!("`mempool_txs_dropped` was called.");
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
            println!("{:?}", &tx_event);
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
            "Usage: {} <working-dir> [max-time]

 This program can be used to \"analyze the mempool\".

 In particular, it can be used to mine an \"unlimited block\". That is, it will attempt
 to build a block from the transactions in the mempool, but will never run out of
 space in the block. Thus, each transaction in the mempool will be tried once.

 Note that nonces which are too high initially can become appropriate as blocks are processed.

 <working-dir> specifies the `working_dir` from the miner's config file.
 [max-time] optionally gives an amount of time to stop mining after, useful for debugging.
 ",
            argv[0]
        );
        process::exit(1);
    }

    let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[1]);
    let chain_state_path = format!("{}/mainnet/chainstate/", &argv[1]);

    let min_fee = u64::max_value();
    let max_time = if argv.len() >= 3 {
        argv[2].parse().expect("Could not parse max_time")
    } else {
        u64::max_value()
    };
    eprintln!("mempool_analyzer: max_time {}", max_time);

    let sort_db = SortitionDB::open(&sort_db_path, false, PoxConstants::mainnet_default())
        .expect(&format!("Failed to open {}", &sort_db_path));
    let chain_id = core::CHAIN_ID_MAINNET;
    let (chain_state, _) = StacksChainState::open_and_exec_with_limits(
        true,
        chain_id,
        &chain_state_path,
        None,
        None,
        UnlimitedBlockLimitFns(),
    )
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
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None),
    );

    coinbase_tx.chain_id = chain_id;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&coinbase_tx);
    tx_signer.sign_origin(&sk).unwrap();
    let coinbase_tx = tx_signer.get_tx().unwrap();

    let mut settings = BlockBuilderSettings::limited();
    settings.max_miner_time_ms = max_time;
    settings.mempool_settings.min_tx_fee = min_fee;

    let dispatcher = PrintDebugEventDispatcher::new();
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
        Some(&dispatcher),
    );

    if let Ok((block, execution_cost, size)) = result {
        let mut total_fees = 0;
        for tx in block.txs.iter() {
            total_fees += tx.get_tx_fee();
        }
        let standard_limits = ProductionBlockLimitFns();
        let cost_limits = BLOCK_LIMIT_MAINNET_21;
        println!(
            r#"
Unlimited Block:
  {transaction_count} transactions
  {total_fees} uSTX fees
  {size} bytes ({size_percent}%)
  Costs:
    write_length: {write_length} ({write_length_percent:.2}%)
    write_count:  {write_count} ({write_count_percent:.2}%)
    read_length:  {read_length} ({read_length_percent:.2}%)
    read_count:   {read_count} ({read_count_percent:.2}%)
    runtime:      {runtime} ({runtime_percent:.2}%)
        "#,
            transaction_count = block.txs.len(),
            total_fees = total_fees,
            size = size,
            size_percent = (size as f64 / standard_limits.output_length_limit as f64 * 100.0),
            write_length = execution_cost.write_length,
            write_length_percent =
                (execution_cost.write_length as f64 / cost_limits.write_length as f64 * 100.0),
            write_count = execution_cost.write_count,
            write_count_percent =
                (execution_cost.write_count as f64 / cost_limits.write_count as f64 * 100.0),
            read_length = execution_cost.read_length,
            read_length_percent =
                (execution_cost.read_length as f64 / cost_limits.read_length as f64 * 100.0),
            read_count = execution_cost.read_count,
            read_count_percent =
                (execution_cost.read_count as f64 / cost_limits.read_count as f64 * 100.0),
            runtime = execution_cost.runtime,
            runtime_percent = (execution_cost.runtime as f64 / cost_limits.runtime as f64 * 100.0),
        );

        let html_content = format!(
            r#"
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Mempool Analysis</title>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .block-info {{ margin-bottom: 20px; }}
                    .block-info h2 {{ color: #333366; }}
                    .block-info p {{ color: #666; }}
                </style>
            </head>
            <body>
                <div class="block-info">
                    <h2>Unlimited Block</h2>
                    <ul>
                        <li>{transaction_count} transactions</li>
                        <li>{total_fees} uSTX fees</li>
                        <li>{size} bytes ({size_percent:.2}%)</li>
                        <li>Costs:</li>
                        <ul>
                            <li>write_length: {write_length} ({write_length_percent:.2}%)</li>
                            <li>write_count:  {write_count} ({write_count_percent:.2}%)</li>
                            <li>read_length:  {read_length} ({read_length_percent:.2}%)</li>
                            <li>read_count:   {read_count} ({read_count_percent:.2}%)</li>
                            <li>runtime:      {runtime} ({runtime_percent:.2}%)</li>
                        </ul>
                    </ul>
                </div>
            </body>
            </html>
            "#,
            transaction_count = block.txs.len(),
            total_fees = total_fees,
            size = size,
            size_percent = (size as f64 / standard_limits.output_length_limit as f64 * 100.0),
            write_length = execution_cost.write_length,
            write_length_percent =
                (execution_cost.write_length as f64 / cost_limits.write_length as f64 * 100.0),
            write_count = execution_cost.write_count,
            write_count_percent =
                (execution_cost.write_count as f64 / cost_limits.write_count as f64 * 100.0),
            read_length = execution_cost.read_length,
            read_length_percent =
                (execution_cost.read_length as f64 / cost_limits.read_length as f64 * 100.0),
            read_count = execution_cost.read_count,
            read_count_percent =
                (execution_cost.read_count as f64 / cost_limits.read_count as f64 * 100.0),
            runtime = execution_cost.runtime,
            runtime_percent = (execution_cost.runtime as f64 / cost_limits.runtime as f64 * 100.0),
        );

        let mut file = File::create("block_details.html").expect("Could not create file");
        file.write_all(html_content.as_bytes())
            .expect("Could not write to file");
    }
}
