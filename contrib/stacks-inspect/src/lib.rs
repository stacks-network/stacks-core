// Copyright (C) 2025 Stacks Open Internet Foundation
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

pub mod cli;

use std::time::Instant;
use std::{fs, process};

use clarity::types::chainstate::SortitionId;
use clarity::util::hash::{Sha512Trunc256Sum, to_hex};
use clarity_cli::read_file_or_stdin;
pub use cli::{
    ContractHashArgs, ReplayMockMiningArgs, TryMineArgs, ValidateBlockArgs, ValidateBlockMode,
};
use regex::Regex;
use rusqlite::{Connection, OpenFlags};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::hash::Hash160;
use stacks_common::util::vrf::VRFProof;
use stacks_common::{debug, info, warn};
use stackslib::burnchains::Burnchain;
use stackslib::chainstate::burn::ConsensusHash;
use stackslib::chainstate::burn::db::sortdb::{
    SortitionDB, SortitionHandleContext, get_ancestor_sort_id,
};
use stackslib::chainstate::coordinator::OnChainRewardSetProvider;
use stackslib::chainstate::nakamoto::miner::{
    BlockMetadata, NakamotoBlockBuilder, NakamotoTenureInfo,
};
use stackslib::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stackslib::chainstate::stacks::db::blocks::DummyEventDispatcher;
use stackslib::chainstate::stacks::db::{
    ChainstateTx, StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo,
};
use stackslib::chainstate::stacks::miner::*;
use stackslib::chainstate::stacks::{Error as ChainstateError, *};
use stackslib::clarity_vm::clarity::ClarityInstance;
use stackslib::clarity_vm::database::GetTenureStartId;
use stackslib::config::{Config, DEFAULT_MAINNET_CONFIG};
use stackslib::core::*;
use stackslib::cost_estimates::UnitEstimator;
use stackslib::cost_estimates::metrics::UnitMetric;
use stackslib::util_lib::db::IndexDBTx;

#[derive(Debug, Default)]
pub struct CommonOpts {
    pub config: Option<Config>,
}

/// Replay blocks from chainstate database
/// Terminates on error using `process::exit()`
///
/// Arguments:
///  - `args`: Parsed CLI arguments
///  - `conf`: Optional config for running on non-mainnet chainstate
pub fn command_validate_block(args: &ValidateBlockArgs, conf: Option<&Config>) {
    let start = Instant::now();
    let db_path = &args.database_path;
    let staging_blocks_db_path = format!("{db_path}/chainstate/vm/index.sqlite");
    let conn =
        Connection::open_with_flags(&staging_blocks_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();

    let query = match &args.mode {
        Some(ValidateBlockMode::Prefix { prefix }) => format!(
            "SELECT index_block_hash FROM staging_blocks WHERE orphaned = 0 AND index_block_hash LIKE \"{prefix}%\""
        ),
        Some(ValidateBlockMode::First { count }) => format!(
            "SELECT index_block_hash FROM staging_blocks WHERE orphaned = 0 ORDER BY height ASC LIMIT {count}"
        ),
        Some(ValidateBlockMode::Last { count }) => format!(
            "SELECT index_block_hash FROM staging_blocks WHERE orphaned = 0 ORDER BY height DESC LIMIT {count}"
        ),
        Some(ValidateBlockMode::Range { start, end }) => {
            let offset = start.saturating_sub(1);
            let limit = end.saturating_sub(*start);
            format!(
                "SELECT index_block_hash FROM staging_blocks WHERE orphaned = 0 ORDER BY height ASC LIMIT {offset}, {limit}"
            )
        }
        Some(ValidateBlockMode::IndexRange { start, end }) => {
            let limit = end.saturating_sub(*start);
            format!(
                "SELECT index_block_hash FROM staging_blocks WHERE orphaned = 0 ORDER BY index_block_hash ASC LIMIT {start}, {limit}"
            )
        }
        // Default: validate ALL blocks
        None => "SELECT index_block_hash FROM staging_blocks WHERE orphaned = 0".into(),
    };

    let mut stmt = conn.prepare(&query).unwrap();
    let mut hashes_set = stmt.query(NO_PARAMS).unwrap();

    let mut index_block_hashes: Vec<String> = vec![];
    while let Ok(Some(row)) = hashes_set.next() {
        index_block_hashes.push(row.get(0).unwrap());
    }

    let total = index_block_hashes.len();
    println!("Will check {total} blocks");
    for (i, index_block_hash) in index_block_hashes.iter().enumerate() {
        if i % 100 == 0 {
            println!("Checked {i}...");
        }
        replay_staging_block(db_path, index_block_hash, conf);
    }
    println!("Finished. run_time_seconds = {}", start.elapsed().as_secs());
}

/// Replay blocks from chainstate database
/// Terminates on error using `process::exit()`
///
/// Arguments:
///  - `args`: Parsed CLI arguments
///  - `conf`: Optional config for running on non-mainnet chainstate
pub fn command_validate_block_nakamoto(args: &ValidateBlockArgs, conf: Option<&Config>) {
    let start = Instant::now();
    let db_path = &args.database_path;

    let chain_state_path = format!("{db_path}/chainstate/");

    let conf = conf.unwrap_or(&DEFAULT_MAINNET_CONFIG);

    let (chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )
    .unwrap();

    let conn = chainstate.nakamoto_blocks_db();

    let query = match &args.mode {
        Some(ValidateBlockMode::Prefix { prefix }) => format!(
            "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0 AND index_block_hash LIKE \"{prefix}%\""
        ),
        Some(ValidateBlockMode::First { count }) => format!(
            "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0 ORDER BY height ASC LIMIT {count}"
        ),
        Some(ValidateBlockMode::Last { count }) => format!(
            "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0 ORDER BY height DESC LIMIT {count}"
        ),
        Some(ValidateBlockMode::Range { start, end }) => {
            let offset = start.saturating_sub(1);
            let limit = end.saturating_sub(*start);
            format!(
                "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0 ORDER BY height ASC LIMIT {offset}, {limit}"
            )
        }
        Some(ValidateBlockMode::IndexRange { start, end }) => {
            let limit = end.saturating_sub(*start);
            format!(
                "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0 ORDER BY index_block_hash ASC LIMIT {start}, {limit}"
            )
        }
        // Default: validate ALL blocks
        None => "SELECT index_block_hash FROM nakamoto_staging_blocks WHERE orphaned = 0".into(),
    };

    let mut stmt = conn.prepare(&query).unwrap();
    let mut hashes_set = stmt.query(NO_PARAMS).unwrap();

    let mut index_block_hashes: Vec<String> = vec![];
    while let Ok(Some(row)) = hashes_set.next() {
        index_block_hashes.push(row.get(0).unwrap());
    }

    let total = index_block_hashes.len();
    println!("Will check {total} blocks");
    for (i, index_block_hash) in index_block_hashes.iter().enumerate() {
        if i % 100 == 0 {
            println!("Checked {i}...");
        }
        replay_naka_staging_block(db_path, index_block_hash, conf);
    }
    println!("Finished. run_time_seconds = {}", start.elapsed().as_secs());
}

/// Replay mock mined blocks from JSON files
/// Terminates on error using `process::exit()`
///
/// Arguments:
///  - `args`: Parsed CLI arguments
///  - `conf`: Optional config for running on non-mainnet chainstate
pub fn command_replay_mock_mining(args: &ReplayMockMiningArgs, conf: Option<&Config>) {
    // Process CLI args
    let db_path = &args.chainstate_path;

    let blocks_path = fs::canonicalize(&args.mock_mining_output_path)
        .unwrap_or_else(|e| panic!("Not a valid path: {e}"));

    // Validate directory path
    if !blocks_path.is_dir() {
        panic!("{blocks_path:?} is not a valid directory");
    }

    // Read entries in directory
    let dir_entries = blocks_path
        .read_dir()
        .unwrap_or_else(|e| panic!("Failed to read {blocks_path:?}: {e}"))
        .filter_map(|e| e.ok());

    // Get filenames, filtering out anything that isn't a regular file
    let filenames = dir_entries.filter_map(|e| match e.file_type() {
        Ok(t) if t.is_file() => e.file_name().into_string().ok(),
        _ => None,
    });

    // Get vec of (block_height, filename), to prepare for sorting
    //
    // NOTE: Trusting the filename is not ideal. We could sort on data read from the file,
    // but that requires reading all files
    let re = Regex::new(r"^([0-9]+)\.json$").unwrap();
    let mut indexed_files = filenames
        .filter_map(|filename| {
            // Use regex to extract block number from filename
            let Some(cap) = re.captures(&filename) else {
                debug!("Regex capture failed on {filename}");
                return None;
            };
            // cap.get(0) return entire filename
            // cap.get(1) return block number
            let i = 1;
            let Some(m) = cap.get(i) else {
                debug!("cap.get({i}) failed on {filename} match");
                return None;
            };
            let Ok(bh) = m.as_str().parse::<u64>() else {
                debug!("parse::<u64>() failed on '{}'", m.as_str());
                return None;
            };
            Some((bh, filename))
        })
        .collect::<Vec<_>>();

    // Sort by block height
    indexed_files.sort_by_key(|(bh, _)| *bh);

    if indexed_files.is_empty() {
        panic!("No block files found in {blocks_path:?}");
    }

    info!(
        "Replaying {} blocks starting at {}",
        indexed_files.len(),
        indexed_files[0].0
    );

    for (bh, filename) in indexed_files {
        let filepath = blocks_path.join(filename);
        let block = AssembledAnchorBlock::deserialize_from_file(&filepath)
            .unwrap_or_else(|e| panic!("Error reading block {bh} from file: {e}"));
        info!("Replaying block from {filepath:?}";
            "block_height" => bh,
            "block" => ?block
        );
        replay_mock_mined_block(db_path, block, conf);
    }
}

/// Replay mock mined blocks from JSON files
/// Terminates on error using `process::exit()`
///
/// Arguments:
///  - `args`: Parsed CLI arguments
///  - `conf`: Optional config for running on non-mainnet chainstate
pub fn command_try_mine(args: &TryMineArgs, conf: Option<&Config>) {
    // Parse subcommand-specific args
    let db_path = &args.chainstate_path;
    let min_fee = args.min_fee.unwrap_or(u64::MAX);
    let max_time = args.max_time.unwrap_or(u64::MAX);

    let start = Instant::now();

    let conf = conf.unwrap_or(&DEFAULT_MAINNET_CONFIG);

    let burnchain_path = format!("{db_path}/burnchain");
    let sort_db_path = format!("{db_path}/burnchain/sortition");
    let chain_state_path = format!("{db_path}/chainstate/");

    let burnchain = conf.get_burnchain();
    let sort_db = SortitionDB::open(&sort_db_path, false, burnchain.pox_constants.clone())
        .unwrap_or_else(|e| panic!("Failed to open {sort_db_path}: {e}"));
    let (chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )
    .unwrap_or_else(|e| panic!("Failed to open stacks chain state: {e}"));
    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
        .unwrap_or_else(|e| panic!("Failed to get sortition chain tip: {e}"));

    let estimator = Box::new(UnitEstimator);
    let metric = Box::new(UnitMetric);

    let mut mempool_db = MemPoolDB::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        estimator,
        metric,
    )
    .unwrap_or_else(|e| panic!("Failed to open mempool db: {e}"));

    // Parent Stacks header for block we are going to mine
    let parent_stacks_header =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sort_db)
            .unwrap_or_else(|e| panic!("Error looking up chain tip: {e}"))
            .expect("No chain tip found");

    let burn_dbconn = sort_db.index_handle(&chain_tip.sortition_id);

    let mut settings = BlockBuilderSettings::limited();
    settings.max_miner_time_ms = max_time;

    let result = match &parent_stacks_header.anchored_header {
        StacksBlockHeaderTypes::Epoch2(..) => {
            let sk = StacksPrivateKey::random();
            let mut tx_auth = TransactionAuth::from_p2pkh(&sk).unwrap();
            tx_auth.set_origin_nonce(0);

            let mut coinbase_tx = StacksTransaction::new(
                TransactionVersion::Mainnet,
                tx_auth,
                TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
            );

            coinbase_tx.chain_id = conf.burnchain.chain_id;
            coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
            let mut tx_signer = StacksTransactionSigner::new(&coinbase_tx);
            tx_signer.sign_origin(&sk).unwrap();
            let coinbase_tx = tx_signer.get_tx().unwrap();

            StacksBlockBuilder::build_anchored_block(
                &chainstate,
                &burn_dbconn,
                &mut mempool_db,
                &parent_stacks_header,
                chain_tip.total_burn,
                &VRFProof::empty(),
                &Hash160([0; 20]),
                &coinbase_tx,
                settings,
                None,
                &Burnchain::new(
                    &burnchain_path,
                    &burnchain.chain_name,
                    &burnchain.network_name,
                )
                .unwrap_or_else(|e| panic!("Failed to instantiate burnchain: {e}")),
            )
            .map(|(block, cost, size)| (block.block_hash(), block.txs, cost, size))
        }
        StacksBlockHeaderTypes::Nakamoto(..) => {
            NakamotoBlockBuilder::build_nakamoto_block(
                &chainstate,
                &burn_dbconn,
                &mut mempool_db,
                &parent_stacks_header,
                // tenure ID consensus hash of this block
                &parent_stacks_header.consensus_hash,
                // the burn so far on the burnchain (i.e. from the last burnchain block)
                chain_tip.total_burn,
                NakamotoTenureInfo::default(),
                settings,
                None,
                0,
                &[],
            )
            .map(
                |BlockMetadata {
                     block,
                     tenure_consumed,
                     tenure_size,
                     ..
                 }| {
                    (
                        block.header.block_hash(),
                        block.txs,
                        tenure_consumed,
                        tenure_size,
                    )
                },
            )
        }
    };

    let elapsed = start.elapsed();
    let summary = format!(
        "block @ height = {h} off of {pid} ({pch}/{pbh}) in {t}ms. Min-fee: {min_fee}, Max-time: {max_time}",
        h = parent_stacks_header.stacks_block_height + 1,
        pid = &parent_stacks_header.index_block_hash(),
        pch = &parent_stacks_header.consensus_hash,
        pbh = &parent_stacks_header.anchored_header.block_hash(),
        t = elapsed.as_millis(),
    );

    let code = match result {
        Ok((block_hash, txs, cost, size)) => {
            let total_fees: u64 = txs.iter().map(|tx| tx.get_tx_fee()).sum();

            println!("Successfully mined {summary}");
            println!("Block {block_hash}: {total_fees} uSTX, {size} bytes, cost {cost:?}");
            0
        }
        Err(e) => {
            println!("Failed to mine {summary}");
            println!("Error: {e}");
            1
        }
    };

    process::exit(code);
}

/// Compute the contract hash for a given contract
///
/// Arguments:
///  - `args`: Parsed CLI arguments
///  - `conf`: Optional config (unused)
pub fn command_contract_hash(args: &ContractHashArgs, _conf: Option<&Config>) {
    // Process CLI args
    let contract_path = &args.contract_source;
    let contract_source = read_file_or_stdin(contract_path);

    let hash = Sha512Trunc256Sum::from_data(contract_source.as_bytes());
    let hex_string = to_hex(hash.as_bytes());
    let source_name = if contract_path == "-" {
        "stdin"
    } else {
        contract_path
    };
    println!("Contract hash for {source_name}:\n{hex_string}");
}

/// Fetch and process a `StagingBlock` from database and call `replay_block()` to validate
fn replay_staging_block(db_path: &str, index_block_hash_hex: &str, conf: Option<&Config>) {
    let block_id = StacksBlockId::from_hex(index_block_hash_hex).unwrap();
    let chain_state_path = format!("{db_path}/chainstate/");
    let sort_db_path = format!("{db_path}/burnchain/sortition");

    let conf = conf.unwrap_or(&DEFAULT_MAINNET_CONFIG);

    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )
    .unwrap();

    let burnchain = conf.get_burnchain();
    let epochs = conf.burnchain.get_epoch_list();
    let mut sortdb = SortitionDB::connect(
        &sort_db_path,
        burnchain.first_block_height,
        &burnchain.first_block_hash,
        u64::from(burnchain.first_block_timestamp),
        &epochs,
        burnchain.pox_constants.clone(),
        None,
        true,
    )
    .unwrap();
    let sort_tx = sortdb.tx_begin_at_tip();

    let blocks_path = chainstate.blocks_path.clone();
    let (mut chainstate_tx, clarity_instance) = chainstate
        .chainstate_tx_begin()
        .expect("Failed to start chainstate tx");
    let mut next_staging_block =
        StacksChainState::load_staging_block_info(&chainstate_tx.tx, &block_id)
            .expect("Failed to load staging block data")
            .expect("No such index block hash in block database");

    next_staging_block.block_data = StacksChainState::load_block_bytes(
        &blocks_path,
        &next_staging_block.consensus_hash,
        &next_staging_block.anchored_block_hash,
    )
    .unwrap()
    .unwrap_or_default();

    let Some(parent_header_info) =
        StacksChainState::get_parent_header_info(&mut chainstate_tx, &next_staging_block).unwrap()
    else {
        println!("Failed to load parent head info for block: {index_block_hash_hex}");
        return;
    };

    let block =
        StacksChainState::extract_stacks_block(&next_staging_block).expect("Failed to get block");
    let block_size = next_staging_block.block_data.len() as u64;

    replay_block(
        sort_tx,
        chainstate_tx,
        clarity_instance,
        &parent_header_info,
        &next_staging_block.parent_microblock_hash,
        next_staging_block.parent_microblock_seq,
        &block_id,
        &block,
        block_size,
        &next_staging_block.consensus_hash,
        &next_staging_block.anchored_block_hash,
        next_staging_block.commit_burn,
        next_staging_block.sortition_burn,
    );
}

/// Process a mock mined block and call `replay_block()` to validate
fn replay_mock_mined_block(db_path: &str, block: AssembledAnchorBlock, conf: Option<&Config>) {
    let chain_state_path = format!("{db_path}/chainstate/");
    let sort_db_path = format!("{db_path}/burnchain/sortition");

    let conf = conf.unwrap_or(&DEFAULT_MAINNET_CONFIG);

    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )
    .unwrap();

    let burnchain = conf.get_burnchain();
    let epochs = conf.burnchain.get_epoch_list();
    let mut sortdb = SortitionDB::connect(
        &sort_db_path,
        burnchain.first_block_height,
        &burnchain.first_block_hash,
        u64::from(burnchain.first_block_timestamp),
        &epochs,
        burnchain.pox_constants.clone(),
        None,
        true,
    )
    .unwrap();
    let sort_tx = sortdb.tx_begin_at_tip();

    let (chainstate_tx, clarity_instance) = chainstate
        .chainstate_tx_begin()
        .expect("Failed to start chainstate tx");

    let block_consensus_hash = &block.consensus_hash;
    let block_hash = block.anchored_block.block_hash();
    let block_id = StacksBlockId::new(block_consensus_hash, &block_hash);
    let block_size = block
        .anchored_block
        .block_size()
        .map(u64::try_from)
        .unwrap_or_else(|e| panic!("Error serializing block {block_hash}: {e}"))
        .expect("u64 overflow");

    let Some(parent_header_info) = StacksChainState::get_anchored_block_header_info(
        &chainstate_tx,
        &block.parent_consensus_hash,
        &block.anchored_block.header.parent_block,
    )
    .unwrap() else {
        println!("Failed to load parent head info for block: {block_hash}");
        return;
    };

    replay_block(
        sort_tx,
        chainstate_tx,
        clarity_instance,
        &parent_header_info,
        &block.anchored_block.header.parent_microblock,
        block.anchored_block.header.parent_microblock_sequence,
        &block_id,
        &block.anchored_block,
        block_size,
        block_consensus_hash,
        &block_hash,
        // I think the burn is used for miner rewards but not necessary for validation
        0,
        0,
    );
}

/// Validate a block against chainstate
#[allow(clippy::too_many_arguments)]
fn replay_block(
    mut sort_tx: IndexDBTx<SortitionHandleContext, SortitionId>,
    mut chainstate_tx: ChainstateTx,
    clarity_instance: &mut ClarityInstance,
    parent_header_info: &StacksHeaderInfo,
    parent_microblock_hash: &BlockHeaderHash,
    parent_microblock_seq: u16,
    block_id: &StacksBlockId,
    block: &StacksBlock,
    block_size: u64,
    block_consensus_hash: &ConsensusHash,
    block_hash: &BlockHeaderHash,
    block_commit_burn: u64,
    block_sortition_burn: u64,
) {
    let parent_block_header = match &parent_header_info.anchored_header {
        StacksBlockHeaderTypes::Epoch2(bh) => bh,
        StacksBlockHeaderTypes::Nakamoto(_) => panic!("Nakamoto blocks not supported yet"),
    };
    let parent_block_hash = parent_block_header.block_hash();

    let Some(cost) =
        StacksChainState::get_stacks_block_anchored_cost(chainstate_tx.conn(), block_id).unwrap()
    else {
        println!("No header info found for {block_id}");
        return;
    };

    let Some(next_microblocks) = StacksChainState::inner_find_parent_microblock_stream(
        &chainstate_tx.tx,
        block_hash,
        &parent_block_hash,
        &parent_header_info.consensus_hash,
        parent_microblock_hash,
        parent_microblock_seq,
    )
    .unwrap() else {
        println!("No microblock stream found for {block_id}");
        return;
    };

    let (burn_header_hash, burn_header_height, burn_header_timestamp, _winning_block_txid) =
        match SortitionDB::get_block_snapshot_consensus(&sort_tx, block_consensus_hash).unwrap() {
            Some(sn) => (
                sn.burn_header_hash,
                sn.block_height as u32,
                sn.burn_header_timestamp,
                sn.winning_block_txid,
            ),
            None => {
                // shouldn't happen
                panic!(
                    "CORRUPTION: staging block {block_consensus_hash}/{block_hash} does not correspond to a burn block"
                );
            }
        };

    info!(
        "Process block {}/{} = {} in burn block {}, parent microblock {}",
        block_consensus_hash, block_hash, &block_id, &burn_header_hash, parent_microblock_hash,
    );

    if !StacksChainState::check_block_attachment(parent_block_header, &block.header) {
        let msg = format!(
            "Invalid stacks block {}/{} -- does not attach to parent {}/{}",
            block_consensus_hash,
            block.block_hash(),
            parent_block_header.block_hash(),
            &parent_header_info.consensus_hash
        );
        println!("{msg}");
        return;
    }

    // validation check -- validate parent microblocks and find the ones that connect the
    // block's parent to this block.
    let next_microblocks = StacksChainState::extract_connecting_microblocks(
        parent_header_info,
        block_consensus_hash,
        block_hash,
        block,
        next_microblocks,
    )
    .unwrap();
    let (last_microblock_hash, last_microblock_seq) = match next_microblocks.len() {
        0 => (EMPTY_MICROBLOCK_PARENT_HASH.clone(), 0),
        _ => {
            let l = next_microblocks.len();
            (
                next_microblocks[l - 1].block_hash(),
                next_microblocks[l - 1].header.sequence,
            )
        }
    };
    assert_eq!(*parent_microblock_hash, last_microblock_hash);
    assert_eq!(parent_microblock_seq, last_microblock_seq);

    let pox_constants = sort_tx.context.pox_constants.clone();

    match StacksChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut sort_tx,
        &pox_constants,
        parent_header_info,
        block_consensus_hash,
        &burn_header_hash,
        burn_header_height,
        burn_header_timestamp,
        block,
        block_size,
        &next_microblocks,
        block_commit_burn,
        block_sortition_burn,
        true,
    ) {
        Ok((receipt, _, _)) => {
            if receipt.anchored_block_cost != cost {
                println!(
                    "Failed processing block! block = {block_id}. Unexpected cost. expected = {cost}, evaluated = {}",
                    receipt.anchored_block_cost
                );
                process::exit(1);
            }

            info!("Block processed successfully! block = {block_id}");
        }
        Err(e) => {
            println!("Failed processing block! block = {block_id}, error = {e:?}");
            process::exit(1);
        }
    };
}

/// Fetch and process a NakamotoBlock from database and call `replay_block_nakamoto()` to validate
fn replay_naka_staging_block(db_path: &str, index_block_hash_hex: &str, conf: &Config) {
    let block_id = StacksBlockId::from_hex(index_block_hash_hex).unwrap();
    let chain_state_path = format!("{db_path}/chainstate/");
    let sort_db_path = format!("{db_path}/burnchain/sortition");

    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &chain_state_path,
        None,
    )
    .unwrap();

    let burnchain = conf.get_burnchain();
    let epochs = conf.burnchain.get_epoch_list();
    let mut sortdb = SortitionDB::connect(
        &sort_db_path,
        burnchain.first_block_height,
        &burnchain.first_block_hash,
        u64::from(burnchain.first_block_timestamp),
        &epochs,
        burnchain.pox_constants.clone(),
        None,
        true,
    )
    .unwrap();

    let (block, block_size) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(&block_id)
        .unwrap()
        .unwrap();
    replay_block_nakamoto(&mut sortdb, &mut chainstate, &block, block_size).unwrap();
}

#[allow(clippy::result_large_err)]
fn replay_block_nakamoto(
    sort_db: &mut SortitionDB,
    stacks_chain_state: &mut StacksChainState,
    block: &NakamotoBlock,
    block_size: u64,
) -> Result<(), ChainstateError> {
    // find corresponding snapshot
    let next_ready_block_snapshot =
        SortitionDB::get_block_snapshot_consensus(sort_db.conn(), &block.header.consensus_hash)?
            .unwrap_or_else(|| {
                panic!(
                    "CORRUPTION: staging Nakamoto block {}/{} does not correspond to a burn block",
                    &block.header.consensus_hash,
                    &block.header.block_hash()
                )
            });

    info!("Process staging Nakamoto block";
           "consensus_hash" => %block.header.consensus_hash,
           "stacks_block_hash" => %block.header.block_hash(),
           "stacks_block_id" => %block.header.block_id(),
           "burn_block_hash" => %next_ready_block_snapshot.burn_header_hash
    );

    let Some(mut expected_total_tenure_cost) = NakamotoChainState::get_total_tenure_cost_at(
        stacks_chain_state.db(),
        &block.header.block_id(),
    )
    .unwrap() else {
        println!("Failed to find cost for block {}", block.header.block_id());
        return Ok(());
    };

    let expected_cost = if block.get_tenure_tx_payload().is_some() {
        expected_total_tenure_cost
    } else {
        let Some(expected_parent_total_tenure_cost) = NakamotoChainState::get_total_tenure_cost_at(
            stacks_chain_state.db(),
            &block.header.parent_block_id,
        )
        .unwrap() else {
            println!(
                "Failed to find cost for parent of block {}",
                block.header.block_id()
            );
            return Ok(());
        };
        expected_total_tenure_cost.sub(&expected_parent_total_tenure_cost).expect("FATAL: failed to subtract parent total cost from self total cost in non-tenure-changing block");
        expected_total_tenure_cost
    };

    let elected_height = sort_db
        .get_consensus_hash_height(&block.header.consensus_hash)?
        .ok_or_else(|| ChainstateError::NoSuchBlockError)?;
    let elected_in_cycle = sort_db
        .pox_constants
        .block_height_to_reward_cycle(sort_db.first_block_height, elected_height)
        .ok_or_else(|| {
            ChainstateError::InvalidStacksBlock(
                "Elected in block height before first_block_height".into(),
            )
        })?;
    let active_reward_set = OnChainRewardSetProvider::<DummyEventDispatcher>(None)
        .read_reward_set_nakamoto_of_cycle(
            elected_in_cycle,
            stacks_chain_state,
            sort_db,
            &block.header.parent_block_id,
            true,
        )
        .map_err(|e| {
            warn!(
                "Cannot process Nakamoto block: could not load reward set that elected the block";
                "err" => ?e,
                "consensus_hash" => %block.header.consensus_hash,
                "stacks_block_hash" => %block.header.block_hash(),
                "stacks_block_id" => %block.header.block_id(),
                "parent_block_id" => %block.header.parent_block_id,
            );
            ChainstateError::NoSuchBlockError
        })?;
    let (mut chainstate_tx, clarity_instance) = stacks_chain_state.chainstate_tx_begin()?;

    // find parent header
    let Some(parent_header_info) =
        NakamotoChainState::get_block_header(&chainstate_tx.tx, &block.header.parent_block_id)?
    else {
        // no parent; cannot process yet
        info!("Cannot process Nakamoto block: missing parent header";
               "consensus_hash" => %block.header.consensus_hash,
               "stacks_block_hash" => %block.header.block_hash(),
               "stacks_block_id" => %block.header.block_id(),
               "parent_block_id" => %block.header.parent_block_id
        );
        return Ok(());
    };

    // sanity check -- must attach to parent
    let parent_block_id = StacksBlockId::new(
        &parent_header_info.consensus_hash,
        &parent_header_info.anchored_header.block_hash(),
    );
    if parent_block_id != block.header.parent_block_id {
        drop(chainstate_tx);

        let msg = "Discontinuous Nakamoto Stacks block";
        warn!("{}", &msg;
              "child parent_block_id" => %block.header.parent_block_id,
              "expected parent_block_id" => %parent_block_id,
              "consensus_hash" => %block.header.consensus_hash,
              "stacks_block_hash" => %block.header.block_hash(),
              "stacks_block_id" => %block.header.block_id()
        );
        return Err(ChainstateError::InvalidStacksBlock(msg.into()));
    }

    // set the sortition handle's pointer to the block's burnchain view.
    //   this is either:
    //    (1)  set by the tenure change tx if one exists
    //    (2)  the same as parent block id

    let burnchain_view = if let Some(tenure_change) = block.get_tenure_tx_payload() {
        if let Some(ref parent_burn_view) = parent_header_info.burn_view {
            // check that the tenure_change's burn view descends from the parent
            let parent_burn_view_sn = SortitionDB::get_block_snapshot_consensus(
                sort_db.conn(),
                parent_burn_view,
            )?
            .ok_or_else(|| {
                warn!(
                    "Cannot process Nakamoto block: could not find parent block's burnchain view";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                ChainstateError::InvalidStacksBlock(
                    "Failed to load burn view of parent block ID".into(),
                )
            })?;
            let handle = sort_db.index_handle_at_ch(&tenure_change.burn_view_consensus_hash)?;
            let connected_sort_id = get_ancestor_sort_id(
                &handle,
                parent_burn_view_sn.block_height,
                &handle.context.chain_tip,
            )?
            .ok_or_else(|| {
                warn!(
                    "Cannot process Nakamoto block: could not find parent block's burnchain view";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                ChainstateError::InvalidStacksBlock(
                    "Failed to load burn view of parent block ID".into(),
                )
            })?;
            if connected_sort_id != parent_burn_view_sn.sortition_id {
                warn!(
                    "Cannot process Nakamoto block: parent block's burnchain view does not connect to own burn view";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                return Err(ChainstateError::InvalidStacksBlock(
                    "Does not connect to burn view of parent block ID".into(),
                ));
            }
        }
        &tenure_change.burn_view_consensus_hash
    } else {
        parent_header_info.burn_view.as_ref().ok_or_else(|| {
                warn!(
                    "Cannot process Nakamoto block: parent block does not have a burnchain view and current block has no tenure tx";
                    "consensus_hash" => %block.header.consensus_hash,
                    "stacks_block_hash" => %block.header.block_hash(),
                    "stacks_block_id" => %block.header.block_id(),
                    "parent_block_id" => %block.header.parent_block_id
                );
                ChainstateError::InvalidStacksBlock("Failed to load burn view of parent block ID".into())
            })?
    };
    let Some(burnchain_view_sn) =
        SortitionDB::get_block_snapshot_consensus(sort_db.conn(), burnchain_view)?
    else {
        // This should be checked already during block acceptance and parent block processing
        //   - The check for expected burns returns `NoSuchBlockError` if the burnchain view
        //      could not be found for a block with a tenure tx.
        // We error here anyways, but the check during block acceptance makes sure that the staging
        //  db doesn't get into a situation where it continuously tries to retry such a block (because
        //  such a block shouldn't land in the staging db).
        warn!(
            "Cannot process Nakamoto block: failed to find Sortition ID associated with burnchain view";
            "consensus_hash" => %block.header.consensus_hash,
            "stacks_block_hash" => %block.header.block_hash(),
            "stacks_block_id" => %block.header.block_id(),
            "burn_view_consensus_hash" => %burnchain_view,
        );
        return Ok(());
    };

    // find commit and sortition burns if this is a tenure-start block
    let new_tenure = block.is_wellformed_tenure_start_block()?;
    let (commit_burn, sortition_burn) = if new_tenure {
        // find block-commit to get commit-burn
        let block_commit = SortitionDB::get_block_commit(
            sort_db.conn(),
            &next_ready_block_snapshot.winning_block_txid,
            &next_ready_block_snapshot.sortition_id,
        )?
        .expect("FATAL: no block-commit for tenure-start block");

        let sort_burn =
            SortitionDB::get_block_burn_amount(sort_db.conn(), &next_ready_block_snapshot)?;
        (block_commit.burn_fee, sort_burn)
    } else {
        (0, 0)
    };

    // attach the block to the chain state and calculate the next chain tip.
    let pox_constants = sort_db.pox_constants.clone();

    // NOTE: because block status is updated in a separate transaction, we need `chainstate_tx`
    // and `clarity_instance` to go out of scope before we can issue the it (since we need a
    // mutable reference to `stacks_chain_state` to start it).  This means ensuring that, in the
    // `Ok(..)` case, the `clarity_commit` gets dropped beforehand.  In order to do this, we first
    // run `::append_block()` here, and capture both the Ok(..) and Err(..) results as
    // Option<..>'s.  Then, if we errored, we can explicitly drop the `Ok(..)` option (even
    // though it will always be None), which gets the borrow-checker to believe that it's safe
    // to access `stacks_chain_state` again.  In the `Ok(..)` case, it's instead sufficient so
    // simply commit the block before beginning the second transaction to mark it processed.
    let block_id = block.block_id();
    let mut burn_view_handle = sort_db.index_handle(&burnchain_view_sn.sortition_id);
    let (ok_opt, err_opt) = match NakamotoChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut burn_view_handle,
        burnchain_view,
        &pox_constants,
        &parent_header_info,
        &next_ready_block_snapshot.burn_header_hash,
        next_ready_block_snapshot
            .block_height
            .try_into()
            .expect("Failed to downcast u64 to u32"),
        next_ready_block_snapshot.burn_header_timestamp,
        block,
        block_size,
        commit_burn,
        sortition_burn,
        &active_reward_set,
        true,
    ) {
        Ok((receipt, _, _, _)) => (Some(receipt), None),
        Err(e) => (None, Some(e)),
    };

    if let Some(receipt) = ok_opt {
        // check the cost
        let evaluated_cost = receipt.anchored_block_cost.clone();
        if evaluated_cost != expected_cost {
            println!(
                "Failed processing block! block = {block_id}. Unexpected cost. expected = {expected_cost}, evaluated = {evaluated_cost}"
            );
            process::exit(1);
        }
    }

    if let Some(e) = err_opt {
        // force rollback
        drop(chainstate_tx);

        warn!(
            "Failed to append {}/{}: {:?}",
            &block.header.consensus_hash,
            &block.header.block_hash(),
            &e;
            "stacks_block_id" => %block.header.block_id()
        );

        // as a separate transaction, mark this block as processed and orphaned.
        // This is done separately so that the staging blocks DB, which receives writes
        // from the network to store blocks, will be available for writes while a block is
        // being processed. Therefore, it's *very important* that block-processing happens
        // within the same, single thread.  Also, it's *very important* that this update
        // succeeds, since *we have already processed* the block.
        return Err(e);
    };

    Ok(())
}
