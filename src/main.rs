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

#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate blockstack_lib;
extern crate rusqlite;
#[macro_use]
extern crate stacks_common;

#[macro_use]
extern crate serde_json;

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

use std::io;
use std::io::prelude::*;
use std::process;
use std::thread;
use std::{collections::HashMap, env};
use std::{convert::TryFrom, fs};

use blockstack_lib::burnchains::BLOCKSTACK_MAGIC_MAINNET;
use blockstack_lib::clarity_cli;
use blockstack_lib::cost_estimates::UnitEstimator;
use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::OpenFlags;

use blockstack_lib::burnchains::bitcoin::indexer::BitcoinIndexer;
use blockstack_lib::burnchains::bitcoin::indexer::{BitcoinIndexerConfig, BitcoinIndexerRuntime};
use blockstack_lib::burnchains::bitcoin::spv;
use blockstack_lib::burnchains::bitcoin::BitcoinNetworkType;
use blockstack_lib::burnchains::db::BurnchainDB;
use blockstack_lib::burnchains::Address;
use blockstack_lib::burnchains::Burnchain;
use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::burn::ConsensusHash;
use blockstack_lib::chainstate::stacks::db::blocks::DummyEventDispatcher;
use blockstack_lib::chainstate::stacks::db::blocks::StagingBlock;
use blockstack_lib::chainstate::stacks::db::ChainStateBootData;
use blockstack_lib::chainstate::stacks::index::marf::MARFOpenOpts;
use blockstack_lib::chainstate::stacks::index::marf::MarfConnection;
use blockstack_lib::chainstate::stacks::index::marf::MARF;
use blockstack_lib::chainstate::stacks::index::ClarityMarfTrieId;
use blockstack_lib::chainstate::stacks::miner::*;
use blockstack_lib::chainstate::stacks::StacksBlockHeader;
use blockstack_lib::chainstate::stacks::*;
use blockstack_lib::clarity::vm::costs::ExecutionCost;
use blockstack_lib::clarity::vm::types::StacksAddressExtensions;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::core::*;
use blockstack_lib::cost_estimates::metrics::UnitMetric;
use blockstack_lib::net::relay::Relayer;
use blockstack_lib::net::{db::LocalPeer, p2p::PeerNetwork, PeerAddress};
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, PoxId, StacksBlockId,
};
use blockstack_lib::util::get_epoch_time_ms;
use blockstack_lib::util::hash::{hex_bytes, to_hex};
use blockstack_lib::util::log;
use blockstack_lib::util::retry::LogReader;
use blockstack_lib::util::sleep_ms;
use blockstack_lib::util_lib::strings::UrlString;
use blockstack_lib::{
    burnchains::{db::BurnchainBlockData, PoxConstants},
    chainstate::{
        burn::db::sortdb::SortitionDB,
        stacks::db::{StacksChainState, StacksHeaderInfo},
    },
    core::MemPoolDB,
    util::{hash::Hash160, vrf::VRFProof},
    util_lib::db::sqlite_open,
};
use std::collections::HashSet;
use std::time::Instant;

fn main() {
    let mut argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: {} command [args...]", argv[0]);
        process::exit(1);
    }

    if argv[1] == "--version" {
        println!(
            "{}",
            &blockstack_lib::version_string(
                option_env!("CARGO_PKG_NAME").unwrap_or(&argv[0]),
                option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0.0")
            )
        );
        process::exit(0);
    }

    if argv[1] == "decode-bitcoin-header" {
        if argv.len() < 4 {
            eprintln!(
                "Usage: {} decode-bitcoin-header [-t|-r] BLOCK_HEIGHT PATH",
                argv[0]
            );
            process::exit(1);
        }

        let mut testnet = false;
        let mut regtest = false;
        let mut idx = 0;
        for i in 0..argv.len() {
            if argv[i] == "-t" {
                testnet = true;
                idx = i;
            } else if argv[i] == "-r" {
                regtest = true;
                idx = i;
            }
        }
        if regtest && testnet {
            // don't allow both
            eprintln!(
                "Usage: {} decode-bitcoin-header [-t|-r] BLOCK_HEIGHT PATH",
                argv[0]
            );
            process::exit(1);
        }
        if idx > 0 {
            argv.remove(idx);
        }

        let mode = if testnet {
            BitcoinNetworkType::Testnet
        } else if regtest {
            BitcoinNetworkType::Regtest
        } else {
            BitcoinNetworkType::Mainnet
        };

        let height = argv[2].parse::<u64>().expect("Invalid block height");
        let headers_path = &argv[3];

        let spv_client = spv::SpvClient::new(headers_path, 0, Some(height), mode, false, false)
            .expect("FATAL: could not instantiate SPV client");
        match spv_client
            .read_block_header(height)
            .expect("FATAL: could not read block header database")
        {
            Some(header) => {
                println!("{:#?}", header);
                process::exit(0);
            }
            None => {
                eprintln!("Failed to read header");
                process::exit(1);
            }
        }
    }

    if argv[1] == "decode-tx" {
        if argv.len() < 3 {
            eprintln!("Usage: {} decode-tx TRANSACTION", argv[0]);
            process::exit(1);
        }

        let tx_str = &argv[2];
        let tx_bytes = hex_bytes(tx_str)
            .map_err(|_e| {
                eprintln!("Failed to decode transaction: must be a hex string");
                process::exit(1);
            })
            .unwrap();

        let mut cursor = io::Cursor::new(&tx_bytes);
        let mut debug_cursor = LogReader::from_reader(&mut cursor);

        let tx = StacksTransaction::consensus_deserialize(&mut debug_cursor)
            .map_err(|e| {
                eprintln!("Failed to decode transaction: {:?}", &e);
                eprintln!("Bytes consumed:");
                for buf in debug_cursor.log().iter() {
                    eprintln!("  {}", to_hex(buf));
                }
                process::exit(1);
            })
            .unwrap();

        println!("Verified: {:#?}", tx.verify());
        println!("Address: {}", tx.auth.origin().address_mainnet());

        println!("{:#?}", &tx);
        process::exit(0);
    }

    if argv[1] == "decode-block" {
        if argv.len() < 3 {
            eprintln!("Usage: {} decode-block BLOCK_PATH", argv[0]);
            process::exit(1);
        }

        let block_path = &argv[2];
        let block_data = fs::read(block_path).expect(&format!("Failed to open {}", block_path));

        let block = StacksBlock::consensus_deserialize(&mut io::Cursor::new(&block_data))
            .map_err(|_e| {
                eprintln!("Failed to decode block");
                process::exit(1);
            })
            .unwrap();

        println!("{:#?}", &block);
        process::exit(0);
    }

    if argv[1] == "get-tenure" {
        if argv.len() < 4 {
            eprintln!("Usage: {} get-tenure CHAIN_STATE_DIR BLOCK_HASH", argv[0]);
            process::exit(1);
        }

        let index_block_hash = &argv[3];
        let index_block_hash = StacksBlockId::from_hex(&index_block_hash).unwrap();
        let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

        let (chainstate, _) =
            StacksChainState::open(true, CHAIN_ID_MAINNET, &chain_state_path, None).unwrap();

        let (consensus_hash, block_hash) = chainstate
            .get_block_header_hashes(&index_block_hash)
            .unwrap()
            .expect("FATAL: no such block");
        let mut block_info =
            StacksChainState::load_staging_block_info(chainstate.db(), &index_block_hash)
                .unwrap()
                .expect("No such block");
        block_info.block_data = StacksChainState::load_block_bytes(
            &chainstate.blocks_path,
            &consensus_hash,
            &block_hash,
        )
        .unwrap()
        .expect("No such block");

        let block =
            StacksBlock::consensus_deserialize(&mut io::Cursor::new(&block_info.block_data))
                .map_err(|_e| {
                    eprintln!("Failed to decode block");
                    process::exit(1);
                })
                .unwrap();

        let microblocks =
            StacksChainState::find_parent_microblock_stream(chainstate.db(), &block_info)
                .unwrap()
                .unwrap_or(vec![]);

        let mut mblock_report = vec![];
        for mblock in microblocks.iter() {
            let mut tx_report = vec![];
            for tx in mblock.txs.iter() {
                tx_report.push(json!({
                    "txid": format!("{}", tx.txid()),
                    "fee": format!("{}", tx.get_tx_fee()),
                    "tx": format!("{}", to_hex(&tx.serialize_to_vec())),
                }));
            }
            mblock_report.push(json!({
                "microblock": format!("{}", mblock.block_hash()),
                "txs": tx_report
            }));
        }

        let mut block_tx_report = vec![];
        for tx in block.txs.iter() {
            block_tx_report.push(json!({
                "txid": format!("{}", tx.txid()),
                "fee": format!("{}", tx.get_tx_fee()),
                "tx": format!("{}", to_hex(&tx.serialize_to_vec()))
            }));
        }

        let report = json!({
            "block": {
                "block_id": format!("{}", index_block_hash),
                "block_hash": format!("{}", block.block_hash()),
                "height": format!("{}", block.header.total_work.work),
                "txs": block_tx_report
            },
            "microblocks": mblock_report
        });

        println!("{}", &report.to_string());

        process::exit(0);
    }

    if argv[1] == "analyze-fees" {
        if argv.len() < 4 {
            eprintln!("Usage: {} analyze-fees CHAIN_STATE_DIR NUM_BLOCKS", argv[0]);
            process::exit(1);
        }

        let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);
        let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
        let (chainstate, _) =
            StacksChainState::open(true, CHAIN_ID_MAINNET, &chain_state_path, None).unwrap();
        let sort_db = SortitionDB::open(&sort_db_path, false)
            .expect(&format!("Failed to open {}", &sort_db_path));

        let num_blocks = argv[3].parse::<u64>().unwrap();

        let mut block_info = chainstate
            .get_stacks_chain_tip(&sort_db)
            .unwrap()
            .expect("FATAL: no chain tip");
        block_info.block_data = StacksChainState::load_block_bytes(
            &chainstate.blocks_path,
            &block_info.consensus_hash,
            &block_info.anchored_block_hash,
        )
        .unwrap()
        .expect("No such block");

        let mut tx_fees = HashMap::new();
        let mut tx_mined_heights = HashMap::new();
        let mut tx_mined_deltas: HashMap<u64, Vec<Txid>> = HashMap::new();

        for _i in 0..num_blocks {
            let block_hash = StacksBlockHeader::make_index_block_hash(
                &block_info.consensus_hash,
                &block_info.anchored_block_hash,
            );
            debug!("Consider block {} ({} of {})", &block_hash, _i, num_blocks);

            let block =
                StacksBlock::consensus_deserialize(&mut io::Cursor::new(&block_info.block_data))
                    .map_err(|_e| {
                        eprintln!("Failed to decode block {}", &block_hash);
                        process::exit(1);
                    })
                    .unwrap();

            let microblocks =
                StacksChainState::find_parent_microblock_stream(chainstate.db(), &block_info)
                    .unwrap()
                    .unwrap_or(vec![]);

            let mut txids_at_height = vec![];

            for mblock in microblocks.iter() {
                for tx in mblock.txs.iter() {
                    tx_fees.insert(tx.txid(), tx.get_tx_fee());
                    txids_at_height.push(tx.txid());
                }
            }

            for tx in block.txs.iter() {
                if tx.get_tx_fee() > 0 {
                    // not a coinbase
                    tx_fees.insert(tx.txid(), tx.get_tx_fee());
                    txids_at_height.push(tx.txid());
                }
            }

            tx_mined_heights.insert(block_info.height, txids_at_height);

            // next block
            block_info = match StacksChainState::load_staging_block_info(
                chainstate.db(),
                &StacksBlockHeader::make_index_block_hash(
                    &block_info.parent_consensus_hash,
                    &block_info.parent_anchored_block_hash,
                ),
            )
            .unwrap()
            {
                Some(blk) => blk,
                None => {
                    break;
                }
            };
            block_info.block_data = StacksChainState::load_block_bytes(
                &chainstate.blocks_path,
                &block_info.consensus_hash,
                &block_info.anchored_block_hash,
            )
            .unwrap()
            .expect("No such block");
        }

        let estimator = Box::new(UnitEstimator);
        let metric = Box::new(UnitMetric);
        let mempool_db =
            MemPoolDB::open(true, CHAIN_ID_MAINNET, &chain_state_path, estimator, metric)
                .expect("Failed to open mempool db");

        let mut total_txs = 0;
        for (_, txids) in tx_mined_heights.iter() {
            total_txs += txids.len();
        }

        let mut tx_cnt = 0;
        for (mined_height, txids) in tx_mined_heights.iter() {
            for txid in txids.iter() {
                tx_cnt += 1;
                if tx_cnt % 100 == 0 {
                    debug!("Check tx {} of {}", tx_cnt, total_txs);
                }

                if let Some(txinfo) = MemPoolDB::get_tx(&mempool_db.db, txid).unwrap() {
                    let delta = mined_height.saturating_sub(txinfo.metadata.block_height);
                    if let Some(txids_at_delta) = tx_mined_deltas.get_mut(&delta) {
                        txids_at_delta.push(txid.clone());
                    } else {
                        tx_mined_deltas.insert(delta, vec![txid.clone()]);
                    }
                }
            }
        }

        let mut deltas: Vec<_> = tx_mined_deltas.keys().collect();
        deltas.sort();

        let mut reports = vec![];
        for delta in deltas {
            let mut delta_tx_fees = vec![];
            let empty_txids = vec![];
            let txids = tx_mined_deltas.get(&delta).unwrap_or(&empty_txids);
            if txids.len() == 0 {
                continue;
            }
            for txid in txids.iter() {
                delta_tx_fees.push(*tx_fees.get(txid).unwrap_or(&0));
            }
            delta_tx_fees.sort();
            let total_tx_fees = delta_tx_fees.iter().fold(0, |acc, x| acc + x);

            let avg_tx_fee = if delta_tx_fees.len() > 0 {
                total_tx_fees / (delta_tx_fees.len() as u64)
            } else {
                0
            };
            let min_tx_fee = *delta_tx_fees.iter().min().unwrap_or(&0);
            let median_tx_fee = delta_tx_fees[delta_tx_fees.len() / 2];
            let percent_90_tx_fee = delta_tx_fees[(delta_tx_fees.len() * 90) / 100];
            let percent_95_tx_fee = delta_tx_fees[(delta_tx_fees.len() * 95) / 100];
            let percent_99_tx_fee = delta_tx_fees[(delta_tx_fees.len() * 99) / 100];
            let max_tx_fee = *delta_tx_fees.iter().max().unwrap_or(&0);

            reports.push(json!({
                "delta": format!("{}", delta),
                "tx_total": format!("{}", delta_tx_fees.len()),
                "tx_fees": json!({
                    "avg": format!("{}", avg_tx_fee),
                    "min": format!("{}", min_tx_fee),
                    "max": format!("{}", max_tx_fee),
                    "p50": format!("{}", median_tx_fee),
                    "p90": format!("{}", percent_90_tx_fee),
                    "p95": format!("{}", percent_95_tx_fee),
                    "p99": format!("{}", percent_99_tx_fee),
                }),
            }));
        }

        println!("{}", serde_json::Value::Array(reports).to_string());
        process::exit(0);
    }

    if argv[1] == "get-block-inventory" {
        if argv.len() < 3 {
            eprintln!(
                "Usage: {} get-block-inventory <working-dir>

Given a <working-dir>, obtain a 2100 header hash block inventory (with an empty header cache).
",
                argv[0]
            );
            process::exit(1);
        }

        let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
        let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

        let sort_db = SortitionDB::open(&sort_db_path, false)
            .expect(&format!("Failed to open {}", &sort_db_path));
        let chain_id = CHAIN_ID_MAINNET;
        let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path, None)
            .expect("Failed to open stacks chain state");
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
            .expect("Failed to get sortition chain tip");

        let start = time::Instant::now();

        let header_hashes = {
            let ic = sort_db.index_conn();

            ic.get_stacks_header_hashes(2100, &chain_tip.consensus_hash, &HashMap::new())
                .unwrap()
        };

        println!(
            "Fetched header hashes in {}",
            start.elapsed().as_seconds_f32()
        );
        let start = time::Instant::now();

        let block_inv = chain_state.get_blocks_inventory(&header_hashes).unwrap();
        println!("Fetched block inv in {}", start.elapsed().as_seconds_f32());
        println!("{:?}", &block_inv);

        println!("Done!");
        process::exit(0);
    }

    if argv[1] == "can-download-microblock" {
        if argv.len() < 3 {
            eprintln!(
                "Usage: {} can-download-microblock <working-dir>

Given a <working-dir>, obtain a 2100 header hash inventory (with an empty header cache), and then
check if the associated microblocks can be downloaded 
",
                argv[0]
            );
            process::exit(1);
        }

        let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
        let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

        let sort_db = SortitionDB::open(&sort_db_path, false)
            .expect(&format!("Failed to open {}", &sort_db_path));
        let chain_id = CHAIN_ID_MAINNET;
        let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path, None)
            .expect("Failed to open stacks chain state");
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
            .expect("Failed to get sortition chain tip");

        let start = time::Instant::now();
        let local_peer = LocalPeer::new(
            0,
            0,
            PeerAddress::from_ipv4(127, 0, 0, 1),
            0,
            None,
            0,
            UrlString::try_from("abc").unwrap(),
        );

        let header_hashes = {
            let ic = sort_db.index_conn();

            ic.get_stacks_header_hashes(2100, &chain_tip.consensus_hash, &HashMap::new())
                .unwrap()
        };

        println!(
            "Fetched header hashes in {}",
            start.elapsed().as_seconds_f32()
        );

        let start = time::Instant::now();
        let mut total_load_headers = 0;

        for (consensus_hash, block_hash_opt) in header_hashes.iter() {
            let block_hash = match block_hash_opt {
                Some(b) => b,
                None => continue,
            };

            let index_block_hash =
                StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_hash);
            let start_load_header = get_epoch_time_ms();
            let parent_header_opt = {
                let child_block_info = match StacksChainState::load_staging_block_info(
                    &chain_state.db(),
                    &index_block_hash,
                ) {
                    Ok(Some(hdr)) => hdr,
                    _ => {
                        debug!("No such block: {:?}", &index_block_hash);
                        continue;
                    }
                };

                match StacksChainState::load_block_header(
                    &chain_state.blocks_path,
                    &child_block_info.parent_consensus_hash,
                    &child_block_info.parent_anchored_block_hash,
                ) {
                    Ok(header_opt) => {
                        header_opt.map(|hdr| (hdr, child_block_info.parent_consensus_hash))
                    }
                    Err(_) => {
                        // we don't know about this parent block yet
                        debug!("{:?}: Do not have parent of anchored block {}/{} yet, so cannot ask for the microblocks it produced", &local_peer, &consensus_hash, &block_hash);
                        continue;
                    }
                }
            };

            let end_load_header = get_epoch_time_ms();
            total_load_headers += end_load_header.saturating_sub(start_load_header);

            if let Some((parent_header, parent_consensus_hash)) = parent_header_opt {
                PeerNetwork::can_download_microblock_stream(
                    &local_peer,
                    &chain_state,
                    &parent_consensus_hash,
                    &parent_header.block_hash(),
                    &consensus_hash,
                    &block_hash,
                )
                .unwrap();
            } else {
                continue;
            }
        }

        println!(
            "Checked can_download in {} (headers load took {}ms)",
            start.elapsed().as_seconds_f32(),
            total_load_headers
        );

        println!("Done!");
        process::exit(0);
    }

    if argv[1] == "evaluate-pox-anchor" {
        if argv.len() < 4 {
            eprintln!("Usage: {} evaluate-pox-anchor <path to mainnet/burnchain/sortition> <height> (last-height)", argv[0]);
            process::exit(1);
        }
        let start_height: u64 = argv[3].parse().expect("Failed to parse <height> argument");
        let end_height: u64 = argv
            .get(4)
            .map(|x| x.parse().expect("Failed to parse <end-height> argument"))
            .unwrap_or(start_height);

        let sort_db =
            SortitionDB::open(&argv[2], false).expect(&format!("Failed to open {}", argv[2]));
        let chain_tip = SortitionDB::get_canonical_sortition_tip(sort_db.conn())
            .expect("Failed to get sortition chain tip");
        let sort_conn = sort_db.index_handle(&chain_tip);

        let mut results = vec![];

        for eval_height in start_height..(1 + end_height) {
            if (sort_conn.context.first_block_height + 100) >= eval_height {
                eprintln!("Block height too low to evaluate");
                process::exit(1);
            }

            let eval_tip = SortitionDB::get_ancestor_snapshot(&sort_conn, eval_height, &chain_tip)
                .expect("Failed to get chain tip to evaluate at")
                .expect("Failed to get chain tip to evaluate at");

            let pox_consts = PoxConstants::mainnet_default();

            let result = sort_conn
                .get_chosen_pox_anchor_check_position(
                    &eval_tip.burn_header_hash,
                    &pox_consts,
                    false,
                )
                .expect("Failed to compute PoX cycle");

            match result {
                Ok((_, _, confirmed_by)) => results.push((eval_height, true, confirmed_by)),
                Err(confirmed_by) => results.push((eval_height, false, confirmed_by)),
            };
        }

        println!("Block height, Would select anchor, Anchor agreement");
        for r in results.iter() {
            println!("{}, {}, {}", &r.0, &r.1, &r.2);
        }

        process::exit(0);
    }

    /// Note: This is running specific candidates.
    if argv[1] == "try-mine" {
        if argv.len() < 4 {
            eprintln!(
                "Usage: {} try-mine <working-dir> <id-list>

<working-dir> is the directory with the chain state.
<id-list> is mandatory in this branch and is a list of id's to try.
",
                argv[0]
            );
            process::exit(1);
        }

        let base_path = argv[2].clone();
        let id_list_path = argv[3].clone();

        let id_contents =
            fs::read_to_string(id_list_path).expect("Something went wrong reading the file");
        let id_list:Vec<&str> = id_contents.split("\n").collect();
        info!("id_list {:?}", &id_list);
        info!("id_contents {:?}", &id_contents);
        let start = get_epoch_time_ms();
        let sort_db_path = format!("{}/mainnet/burnchain/sortition", &base_path);
        let chain_state_path = format!("{}/mainnet/chainstate/", &base_path);

        let mut min_fee = u64::max_value();
        let mut max_time = u64::max_value();

        let sort_db = SortitionDB::open(&sort_db_path, false)
            .expect(&format!("Failed to open {}", &sort_db_path));
        let chain_id = CHAIN_ID_MAINNET;
        let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path, None)
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

        {
            let build_start = Instant::now();
            let result = StacksBlockBuilder::build_anchored_block(
                &chain_state,
                &sort_db.index_conn(),
                &mut mempool_db,
                &parent_header,
                chain_tip.total_burn,
                VRFProof::empty(),
                Hash160([0; 20]),
                &coinbase_tx,
                settings.clone(),
                None,
                &id_list,
            );

            let build_end = Instant::now();
            let delta = build_end - build_start;
            info!("build_anchored_block delta: {:?}", &delta);
            let stop = get_epoch_time_ms();

            println!(
                "{} mined block @ height = {} off of {} ({}/{}) in {}ms. Min-fee: {}, Max-time: {}",
                if result.is_ok() {
                    "Successfully"
                } else {
                    "Failed to"
                },
                parent_header.stacks_block_height + 1,
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
        }

        process::exit(0);
    }
}
