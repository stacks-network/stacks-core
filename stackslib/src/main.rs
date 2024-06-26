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

#[macro_use]
extern crate stacks_common;

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::BufReader;
use std::{env, fs, io, process, thread};

use blockstack_lib::burnchains::bitcoin::indexer::{
    BitcoinIndexer, BitcoinIndexerConfig, BitcoinIndexerRuntime,
};
use blockstack_lib::burnchains::bitcoin::{spv, BitcoinNetworkType};
use blockstack_lib::burnchains::db::{BurnchainBlockData, BurnchainDB};
use blockstack_lib::burnchains::{
    Address, Burnchain, PoxConstants, Txid, BLOCKSTACK_MAGIC_MAINNET,
};
use blockstack_lib::chainstate::burn::db::sortdb::{
    get_block_commit_by_txid, SortitionDB, SortitionHandle,
};
use blockstack_lib::chainstate::burn::operations::BlockstackOperationType;
use blockstack_lib::chainstate::burn::{BlockSnapshot, ConsensusHash};
use blockstack_lib::chainstate::coordinator::{get_reward_cycle_info, OnChainRewardSetProvider};
use blockstack_lib::chainstate::nakamoto::NakamotoChainState;
use blockstack_lib::chainstate::stacks::db::blocks::{DummyEventDispatcher, StagingBlock};
use blockstack_lib::chainstate::stacks::db::{
    ChainStateBootData, StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo,
};
use blockstack_lib::chainstate::stacks::index::marf::{MARFOpenOpts, MarfConnection, MARF};
use blockstack_lib::chainstate::stacks::index::ClarityMarfTrieId;
use blockstack_lib::chainstate::stacks::miner::*;
use blockstack_lib::chainstate::stacks::{StacksBlockHeader, *};
use blockstack_lib::clarity::vm::costs::ExecutionCost;
use blockstack_lib::clarity::vm::types::StacksAddressExtensions;
use blockstack_lib::clarity::vm::ClarityVersion;
use blockstack_lib::clarity_cli;
use blockstack_lib::clarity_cli::vm_execute;
use blockstack_lib::core::{MemPoolDB, *};
use blockstack_lib::cost_estimates::metrics::UnitMetric;
use blockstack_lib::cost_estimates::UnitEstimator;
use blockstack_lib::net::db::LocalPeer;
use blockstack_lib::net::p2p::PeerNetwork;
use blockstack_lib::net::relay::Relayer;
use blockstack_lib::net::StacksMessage;
use blockstack_lib::util_lib::db::sqlite_open;
use blockstack_lib::util_lib::strings::UrlString;
use libstackerdb::StackerDBChunkData;
use rusqlite::types::ToSql;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, PoxId, StacksAddress, StacksBlockId,
};
use stacks_common::types::net::PeerAddress;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160};
use stacks_common::util::retry::LogReader;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::vrf::VRFProof;
use stacks_common::util::{get_epoch_time_ms, log, sleep_ms};

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

    if argv[1] == "peer-pub-key" {
        if argv.len() < 3 {
            eprintln!("Usage: {} peer-pub-key <local-peer-seed>", argv[0]);
            process::exit(1);
        }

        let local_seed = hex_bytes(&argv[2]).expect("Failed to parse hex input local-peer-seed");
        let node_privkey = Secp256k1PrivateKey::from_seed(&local_seed);
        let pubkey = Secp256k1PublicKey::from_private(&node_privkey).to_hex();
        println!("{}", pubkey);
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
        let block_data =
            fs::read(block_path).unwrap_or_else(|_| panic!("Failed to open {block_path}"));

        let block = StacksBlock::consensus_deserialize(&mut io::Cursor::new(&block_data))
            .map_err(|_e| {
                eprintln!("Failed to decode block");
                process::exit(1);
            })
            .unwrap();

        println!("{:#?}", &block);
        process::exit(0);
    }

    if argv[1] == "decode-net-message" {
        let data: String = argv[2].clone();
        let buf = if data == "-" {
            let mut buffer = vec![];
            io::stdin().read_to_end(&mut buffer).unwrap();
            buffer
        } else {
            let data: serde_json::Value = serde_json::from_str(data.as_str()).unwrap();
            let data_array = data.as_array().unwrap();
            let mut buf = vec![];
            for elem in data_array {
                buf.push(elem.as_u64().unwrap() as u8);
            }
            buf
        };
        match read_next::<StacksMessage, _>(&mut &buf[..]) {
            Ok(msg) => {
                println!("{:#?}", &msg);
                process::exit(0);
            }
            Err(_) => {
                let ptr = &mut &buf[..];
                let mut debug_cursor = LogReader::from_reader(ptr);
                let _ = read_next::<StacksMessage, _>(&mut debug_cursor);
                process::exit(1);
            }
        }
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

        let sort_db = SortitionDB::open(&sort_db_path, false, PoxConstants::mainnet_default())
            .unwrap_or_else(|_| panic!("Failed to open {sort_db_path}"));
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

        let sort_db = SortitionDB::open(&sort_db_path, false, PoxConstants::mainnet_default())
            .unwrap_or_else(|_| panic!("Failed to open {sort_db_path}"));
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
            vec![],
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

        let sort_db = SortitionDB::open(&argv[2], false, PoxConstants::mainnet_default())
            .unwrap_or_else(|_| panic!("Failed to open {}", argv[2]));
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
                .get_chosen_pox_anchor_check_position_v205(
                    &eval_tip.burn_header_hash,
                    &pox_consts,
                    false,
                )
                .expect("Failed to compute PoX cycle");

            match result {
                Ok((_, _, _, confirmed_by)) => results.push((eval_height, true, confirmed_by)),
                Err(confirmed_by) => results.push((eval_height, false, confirmed_by)),
            };
        }

        println!("Block height, Would select anchor, Anchor agreement");
        for r in results.iter() {
            println!("{}, {}, {}", &r.0, &r.1, &r.2);
        }

        process::exit(0);
    }

    if argv[1] == "try-mine" {
        if argv.len() < 3 {
            eprintln!(
                "Usage: {} try-mine <working-dir> [min-fee [max-time]]

Given a <working-dir>, try to ''mine'' an anchored block. This invokes the miner block
assembly, but does not attempt to broadcast a block commit. This is useful for determining
what transactions a given chain state would include in an anchor block, or otherwise
simulating a miner.
",
                argv[0]
            );
            process::exit(1);
        }

        let start = get_epoch_time_ms();
        let burnchain_path = format!("{}/mainnet/burnchain", &argv[2]);
        let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
        let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

        let mut min_fee = u64::MAX;
        let mut max_time = u64::MAX;

        if argv.len() >= 4 {
            min_fee = argv[3].parse().expect("Could not parse min_fee");
        }
        if argv.len() >= 5 {
            max_time = argv[4].parse().expect("Could not parse max_time");
        }

        let sort_db = SortitionDB::open(&sort_db_path, false, PoxConstants::mainnet_default())
            .unwrap_or_else(|_| panic!("Failed to open {sort_db_path}"));
        let chain_id = CHAIN_ID_MAINNET;
        let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path, None)
            .expect("Failed to open stacks chain state");
        let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
            .expect("Failed to get sortition chain tip");

        let estimator = Box::new(UnitEstimator);
        let metric = Box::new(UnitMetric);

        let mut mempool_db = MemPoolDB::open(true, chain_id, &chain_state_path, estimator, metric)
            .expect("Failed to open mempool db");

        let header_tip = NakamotoChainState::get_canonical_block_header(chain_state.db(), &sort_db)
            .unwrap()
            .unwrap();
        let parent_header = StacksChainState::get_anchored_block_header_info(
            chain_state.db(),
            &header_tip.consensus_hash,
            &header_tip.anchored_header.block_hash(),
        )
        .expect("Failed to load chain tip header info")
        .expect("Failed to load chain tip header info");

        let sk = StacksPrivateKey::new();
        let mut tx_auth = TransactionAuth::from_p2pkh(&sk).unwrap();
        tx_auth.set_origin_nonce(0);

        let mut coinbase_tx = StacksTransaction::new(
            TransactionVersion::Mainnet,
            tx_auth,
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
        );

        coinbase_tx.chain_id = chain_id;
        coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&coinbase_tx);
        tx_signer.sign_origin(&sk).unwrap();
        let coinbase_tx = tx_signer.get_tx().unwrap();

        let mut settings = BlockBuilderSettings::limited();
        settings.max_miner_time_ms = max_time;

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
            &Burnchain::new(&burnchain_path, "bitcoin", "main").unwrap(),
        );

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

        process::exit(0);
    }

    if argv[1] == "tip-mine" {
        tip_mine();
    }

    if argv[1] == "decode-microblocks" {
        if argv.len() < 3 {
            eprintln!(
                "Usage: {} decode-microblocks MICROBLOCK_STREAM_PATH",
                argv[0]
            );
            process::exit(1);
        }

        let mblock_path = &argv[2];
        let mblock_data =
            fs::read(mblock_path).unwrap_or_else(|_| panic!("Failed to open {mblock_path}"));

        let mut cursor = io::Cursor::new(&mblock_data);
        let mut debug_cursor = LogReader::from_reader(&mut cursor);
        let mblocks: Vec<StacksMicroblock> = Vec::consensus_deserialize(&mut debug_cursor)
            .map_err(|e| {
                eprintln!("Failed to decode microblocks: {:?}", &e);
                eprintln!("Bytes consumed:");
                for buf in debug_cursor.log().iter() {
                    eprintln!("  {}", to_hex(buf));
                }
                process::exit(1);
            })
            .unwrap();

        println!("{:#?}", &mblocks);
        process::exit(0);
    }

    if argv[1] == "header-indexed-get" {
        if argv.len() < 5 {
            eprintln!(
                "Usage: {} header-indexed-get STATE_DIR BLOCK_ID_HASH KEY",
                argv[0]
            );
            eprintln!("       STATE_DIR is either the chain state directory OR a marf index and data db file");
            process::exit(1);
        }
        let (marf_path, db_path, arg_next) = if argv.len() == 5 {
            let headers_dir = &argv[2];
            (
                format!("{}/vm/index.sqlite", &headers_dir),
                format!("{}/vm/headers.sqlite", &headers_dir),
                3,
            )
        } else {
            (argv[2].to_string(), argv[3].to_string(), 4)
        };
        let marf_tip = &argv[arg_next];
        let marf_key = &argv[arg_next + 1];

        if fs::metadata(&marf_path).is_err() {
            eprintln!("No such file or directory: {}", &marf_path);
            process::exit(1);
        }

        if fs::metadata(&db_path).is_err() {
            eprintln!("No such file or directory: {}", &db_path);
            process::exit(1);
        }

        let marf_bhh = StacksBlockId::from_hex(marf_tip).expect("Bad MARF block hash");
        let marf_opts = MARFOpenOpts::default();
        let mut marf = MARF::from_path(&marf_path, marf_opts).expect("Failed to open MARF");
        let value_opt = marf.get(&marf_bhh, marf_key).expect("Failed to read MARF");

        if let Some(value) = value_opt {
            let conn = sqlite_open(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)
                .expect("Failed to open DB");
            let args: &[&dyn ToSql] = &[&value.to_hex()];
            let res: Result<String, rusqlite::Error> = conn.query_row_and_then(
                "SELECT value FROM __fork_storage WHERE value_hash = ?1",
                args,
                |row| {
                    let s: String = row.get_unwrap(0);
                    Ok(s)
                },
            );

            let row =
                res.unwrap_or_else(|_| panic!("Failed to query DB for MARF value hash {value}"));
            println!("{}", row);
        } else {
            println!("(undefined)");
        }

        process::exit(0);
    }

    if argv[1] == "exec_program" {
        if argv.len() < 3 {
            eprintln!("Usage: {} exec_program [program-file.clar]", argv[0]);
            process::exit(1);
        }
        let program: String = fs::read_to_string(&argv[2])
            .unwrap_or_else(|_| panic!("Error reading file: {}", argv[2]));
        let clarity_version = ClarityVersion::default_for_epoch(clarity_cli::DEFAULT_CLI_EPOCH);
        match clarity_cli::vm_execute(&program, clarity_version) {
            Ok(Some(result)) => println!("{}", result),
            Ok(None) => println!(""),
            Err(error) => {
                panic!("Program Execution Error: \n{}", error);
            }
        }
        return;
    }

    if argv[1] == "marf-get" {
        let path = &argv[2];
        let tip = BlockHeaderHash::from_hex(&argv[3]).unwrap();
        let consensustip = ConsensusHash::from_hex(&argv[4]).unwrap();
        let itip = StacksBlockHeader::make_index_block_hash(&consensustip, &tip);
        let key = &argv[5];

        let mut marf_opts = MARFOpenOpts::default();
        marf_opts.external_blobs = true;
        let mut marf = MARF::from_path(path, marf_opts).unwrap();
        let res = marf.get(&itip, key).expect("MARF error.");
        match res {
            Some(x) => println!("{}", x),
            None => println!("None"),
        };
        return;
    }

    if argv[1] == "get-ancestors" {
        let path = &argv[2];
        let tip = BlockHeaderHash::from_hex(&argv[3]).unwrap();
        let burntip = BurnchainHeaderHash::from_hex(&argv[4]).unwrap();

        let conn = rusqlite::Connection::open(path).unwrap();
        let mut cur_burn = burntip.clone();
        let mut cur_tip = tip.clone();
        loop {
            println!("{}, {}", cur_burn, cur_tip);
            let (next_burn, next_tip) = match
                conn.query_row("SELECT parent_burn_header_hash, parent_anchored_block_hash FROM staging_blocks WHERE anchored_block_hash = ? and burn_header_hash = ?",
                               &[&cur_tip as &dyn rusqlite::types::ToSql, &cur_burn], |row| Ok((row.get_unwrap(0), row.get_unwrap(1)))) {
                    Ok(x) => x,
                    Err(e) => {
                        match e {
                            rusqlite::Error::QueryReturnedNoRows => {},
                            e => {
                                eprintln!("SQL Error: {}", e);
                            },
                        }
                        break
                    }
                };
            cur_burn = next_burn;
            cur_tip = next_tip;
        }
        return;
    }

    if argv[1] == "docgen" {
        println!(
            "{}",
            blockstack_lib::clarity::vm::docs::make_json_api_reference()
        );
        return;
    }

    if argv[1] == "docgen_boot" {
        println!(
            "{}",
            blockstack_lib::chainstate::stacks::boot::docs::make_json_boot_contracts_reference()
        );
        return;
    }

    if argv[1] == "local" {
        clarity_cli::invoke_command(&format!("{} {}", argv[0], argv[1]), &argv[2..]);
        return;
    }

    if argv[1] == "replay-block" {
        let print_help_and_exit = || -> ! {
            let n = &argv[0];
            eprintln!("Usage:");
            eprintln!("  {n} <chainstate_path>");
            eprintln!("  {n} <chainstate_path> prefix <index-block-hash-prefix>");
            eprintln!("  {n} <chainstate_path> range <start_block> <end_block>");
            eprintln!("  {n} <chainstate_path> <first|last> <block_count>");
            process::exit(1);
        };
        if argv.len() < 2 {
            print_help_and_exit();
        }
        let stacks_path = &argv[2];
        let mode = argv.get(3).map(String::as_str);
        let staging_blocks_db_path = format!("{stacks_path}/mainnet/chainstate/vm/index.sqlite");
        let conn =
            Connection::open_with_flags(&staging_blocks_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();

        let query = match mode {
            Some("prefix") => format!(
                "SELECT index_block_hash FROM staging_blocks WHERE index_block_hash LIKE \"{}%\"",
                argv[4]
            ),
            Some("first") => format!(
                "SELECT index_block_hash FROM staging_blocks ORDER BY height ASC LIMIT {}",
                argv[4]
            ),
            Some("range") => {
                let arg4 = argv[4]
                    .parse::<u64>()
                    .expect("<start_block> not a valid u64");
                let arg5 = argv[5].parse::<u64>().expect("<end_block> not a valid u64");
                let start = arg4.saturating_sub(1);
                let blocks = arg5.saturating_sub(arg4);
                format!("SELECT index_block_hash FROM staging_blocks ORDER BY height ASC LIMIT {start}, {blocks}")
            }
            Some("last") => format!(
                "SELECT index_block_hash FROM staging_blocks ORDER BY height DESC LIMIT {}",
                argv[4]
            ),
            Some(_) => print_help_and_exit(),
            // Default to ALL blocks
            None => "SELECT index_block_hash FROM staging_blocks".into(),
        };

        let mut stmt = conn.prepare(&query).unwrap();
        let mut hashes_set = stmt.query(rusqlite::NO_PARAMS).unwrap();

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
            replay_block(stacks_path, index_block_hash);
        }
        println!("Finished!");
        process::exit(0);
    }

    if argv[1] == "deserialize-db" {
        if argv.len() < 4 {
            eprintln!("Usage: {} clarity_sqlite_db [byte-prefix]", &argv[0]);
            process::exit(1);
        }
        let db_path = &argv[2];
        let byte_prefix = &argv[3];
        let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let query = format!(
            "SELECT value FROM data_table WHERE key LIKE \"{}%\"",
            byte_prefix
        );
        let mut stmt = conn.prepare(&query).unwrap();
        let mut rows = stmt.query(rusqlite::NO_PARAMS).unwrap();
        while let Ok(Some(row)) = rows.next() {
            let val_string: String = row.get(0).unwrap();
            let clarity_value = match clarity::vm::Value::try_deserialize_hex_untyped(&val_string) {
                Ok(x) => x,
                Err(_e) => continue,
            };
            println!("{} => {}", val_string, clarity_value);
        }

        process::exit(0);
    }

    if argv[1] == "check-deser-data" {
        if argv.len() < 3 {
            eprintln!("Usage: {} check-file.txt", &argv[0]);
            process::exit(1);
        }
        let txt_path = &argv[2];
        let check_file = File::open(txt_path).unwrap();
        let mut i = 1;
        for line in io::BufReader::new(check_file).lines() {
            if i % 100000 == 0 {
                println!("{}...", i);
            }
            i += 1;
            let line = line.unwrap().trim().to_string();
            if line.len() == 0 {
                continue;
            }
            let vals: Vec<_> = line.split(" => ").map(|x| x.trim()).collect();
            let hex_string = &vals[0];
            let expected_value_display = &vals[1];
            let value = clarity::vm::Value::try_deserialize_hex_untyped(&hex_string).unwrap();
            assert_eq!(&value.to_string(), expected_value_display);
        }

        process::exit(0);
    }

    if argv[1] == "post-stackerdb" {
        if argv.len() < 4 {
            eprintln!(
                "Usage: {} post-stackerdb slot_id slot_version privkey data",
                &argv[0]
            );
            process::exit(1);
        }
        let slot_id: u32 = argv[2].parse().unwrap();
        let slot_version: u32 = argv[3].parse().unwrap();
        let privkey: String = argv[4].clone();
        let data: String = argv[5].clone();

        let buf = if data == "-" {
            let mut buffer = vec![];
            io::stdin().read_to_end(&mut buffer).unwrap();
            buffer
        } else {
            data.as_bytes().to_vec()
        };

        let mut chunk = StackerDBChunkData::new(slot_id, slot_version, buf);
        let privk = StacksPrivateKey::from_hex(&privkey).unwrap();
        chunk.sign(&privk).unwrap();

        println!("{}", &serde_json::to_string(&chunk).unwrap());
        process::exit(0);
    }

    if argv[1] == "analyze-sortition-mev" {
        analyze_sortition_mev(argv);
        // should be unreachable
        process::exit(1);
    }

    if argv[1] == "replay-chainstate" {
        if argv.len() < 7 {
            eprintln!("Usage: {} OLD_CHAINSTATE_PATH OLD_SORTITION_DB_PATH OLD_BURNCHAIN_DB_PATH NEW_CHAINSTATE_PATH NEW_BURNCHAIN_DB_PATH", &argv[0]);
            process::exit(1);
        }

        let old_chainstate_path = &argv[2];
        let old_sort_path = &argv[3];
        let old_burnchaindb_path = &argv[4];

        let new_chainstate_path = &argv[5];
        let burnchain_db_path = &argv[6];

        let (old_chainstate, _) =
            StacksChainState::open(false, 0x80000000, old_chainstate_path, None).unwrap();
        let old_sortition_db =
            SortitionDB::open(old_sort_path, true, PoxConstants::mainnet_default()).unwrap();

        // initial argon balances -- see testnet/stacks-node/conf/testnet-follower-conf.toml
        let initial_balances = vec![
            (
                StacksAddress::from_string("ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2")
                    .unwrap()
                    .to_account_principal(),
                10000000000000000,
            ),
            (
                StacksAddress::from_string("ST319CF5WV77KYR1H3GT0GZ7B8Q4AQPY42ETP1VPF")
                    .unwrap()
                    .to_account_principal(),
                10000000000000000,
            ),
            (
                StacksAddress::from_string("ST221Z6TDTC5E0BYR2V624Q2ST6R0Q71T78WTAX6H")
                    .unwrap()
                    .to_account_principal(),
                10000000000000000,
            ),
            (
                StacksAddress::from_string("ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B")
                    .unwrap()
                    .to_account_principal(),
                10000000000000000,
            ),
        ];

        let burnchain = Burnchain::regtest(&burnchain_db_path);
        let first_burnchain_block_height = burnchain.first_block_height;
        let first_burnchain_block_hash = burnchain.first_block_hash;
        let epochs = StacksEpoch::all(first_burnchain_block_height, u64::MAX, u64::MAX);
        let (mut new_sortition_db, _) = burnchain
            .connect_db(
                true,
                first_burnchain_block_hash,
                BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP.into(),
                epochs,
            )
            .unwrap();

        let old_burnchaindb =
            BurnchainDB::connect(&old_burnchaindb_path, &burnchain, true).unwrap();

        let mut boot_data = ChainStateBootData {
            initial_balances,
            post_flight_callback: None,
            first_burnchain_block_hash,
            first_burnchain_block_height: first_burnchain_block_height as u32,
            first_burnchain_block_timestamp: 0,
            pox_constants: PoxConstants::regtest_default(),
            get_bulk_initial_lockups: None,
            get_bulk_initial_balances: None,
            get_bulk_initial_namespaces: None,
            get_bulk_initial_names: None,
        };

        let (mut new_chainstate, _) = StacksChainState::open_and_exec(
            false,
            0x80000000,
            new_chainstate_path,
            Some(&mut boot_data),
            None,
        )
        .unwrap();

        let all_snapshots = old_sortition_db.get_all_snapshots().unwrap();
        let all_stacks_blocks =
            StacksChainState::get_all_staging_block_headers(&old_chainstate.db()).unwrap();

        // order block hashes by arrival index
        let mut stacks_blocks_arrival_indexes = vec![];
        for snapshot in all_snapshots.iter() {
            if !snapshot.sortition {
                continue;
            }
            if snapshot.arrival_index == 0 {
                continue;
            }
            let index_hash = StacksBlockHeader::make_index_block_hash(
                &snapshot.consensus_hash,
                &snapshot.winning_stacks_block_hash,
            );
            stacks_blocks_arrival_indexes.push((index_hash, snapshot.arrival_index));
        }
        stacks_blocks_arrival_indexes.sort_by(|ref a, ref b| a.1.partial_cmp(&b.1).unwrap());
        let stacks_blocks_arrival_order: Vec<StacksBlockId> = stacks_blocks_arrival_indexes
            .into_iter()
            .map(|(h, _)| h)
            .collect();

        let mut stacks_blocks_available: HashMap<StacksBlockId, StagingBlock> = HashMap::new();
        let num_staging_blocks = all_stacks_blocks.len();
        for staging_block in all_stacks_blocks.into_iter() {
            if !staging_block.orphaned {
                let index_hash = StacksBlockHeader::make_index_block_hash(
                    &staging_block.consensus_hash,
                    &staging_block.anchored_block_hash,
                );
                eprintln!(
                    "Will consider {}/{}",
                    &staging_block.consensus_hash, &staging_block.anchored_block_hash
                );
                stacks_blocks_available.insert(index_hash, staging_block);
            }
        }

        eprintln!(
            "\nWill replay {} stacks epochs out of {}\n",
            &stacks_blocks_available.len(),
            num_staging_blocks
        );

        let mut known_stacks_blocks = HashSet::new();
        let mut next_arrival = 0;

        let epochs = StacksEpoch::all(first_burnchain_block_height, u64::MAX, u64::MAX);

        let (p2p_new_sortition_db, _) = burnchain
            .connect_db(
                true,
                first_burnchain_block_hash,
                BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP.into(),
                epochs,
            )
            .unwrap();
        let (mut p2p_chainstate, _) =
            StacksChainState::open(false, 0x80000000, new_chainstate_path, None).unwrap();

        let _ = thread::spawn(move || {
            loop {
                // simulate the p2p refreshing itself
                // update p2p's read-only view of the unconfirmed state
                p2p_chainstate
                    .refresh_unconfirmed_state(&p2p_new_sortition_db.index_conn())
                    .expect("Failed to open unconfirmed Clarity state");

                sleep_ms(100);
            }
        });

        for old_snapshot in all_snapshots.into_iter() {
            // replay this burnchain block
            let BurnchainBlockData {
                header: burn_block_header,
                ops: blockstack_txs,
            } = BurnchainDB::get_burnchain_block(
                &old_burnchaindb.conn(),
                &old_snapshot.burn_header_hash,
            )
            .unwrap();
            if old_snapshot.parent_burn_header_hash == BurnchainHeaderHash::sentinel() {
                // skip initial snapshot -- it's a placeholder
                continue;
            }

            let (new_snapshot, ..) = {
                let sortition_tip =
                    SortitionDB::get_canonical_burn_chain_tip(new_sortition_db.conn()).unwrap();
                new_sortition_db
                    .evaluate_sortition(
                        &burn_block_header,
                        blockstack_txs,
                        &burnchain,
                        &sortition_tip.sortition_id,
                        None,
                        |_| {},
                    )
                    .unwrap()
            };

            // importantly, the burnchain linkage must all match
            assert_eq!(old_snapshot.burn_header_hash, new_snapshot.burn_header_hash);
            assert_eq!(
                old_snapshot.parent_burn_header_hash,
                new_snapshot.parent_burn_header_hash
            );
            assert_eq!(old_snapshot.sortition, new_snapshot.sortition);
            assert_eq!(
                old_snapshot.winning_stacks_block_hash,
                new_snapshot.winning_stacks_block_hash
            );
            assert_eq!(old_snapshot.consensus_hash, new_snapshot.consensus_hash);
            assert_eq!(old_snapshot.sortition_hash, new_snapshot.sortition_hash);
            assert_eq!(old_snapshot.block_height, new_snapshot.block_height);
            assert_eq!(old_snapshot.total_burn, new_snapshot.total_burn);
            assert_eq!(old_snapshot.ops_hash, new_snapshot.ops_hash);

            // "discover" the stacks blocks
            if new_snapshot.sortition {
                let mut stacks_block_id = StacksBlockHeader::make_index_block_hash(
                    &new_snapshot.consensus_hash,
                    &new_snapshot.winning_stacks_block_hash,
                );
                known_stacks_blocks.insert(stacks_block_id.clone());

                if next_arrival >= stacks_blocks_arrival_order.len() {
                    // all blocks should have been queued up
                    continue;
                }

                if stacks_block_id == stacks_blocks_arrival_order[next_arrival] {
                    while next_arrival < stacks_blocks_arrival_order.len()
                        && known_stacks_blocks.contains(&stacks_block_id)
                    {
                        if let Some(_) = stacks_blocks_available.get(&stacks_block_id) {
                            // load up the block
                            let stacks_block_opt = StacksChainState::load_block(
                                &old_chainstate.blocks_path,
                                &new_snapshot.consensus_hash,
                                &new_snapshot.winning_stacks_block_hash,
                            )
                            .unwrap();
                            if let Some(stacks_block) = stacks_block_opt {
                                // insert it into the new chainstate
                                let ic = new_sortition_db.index_conn();
                                Relayer::process_new_anchored_block(
                                    &ic,
                                    &mut new_chainstate,
                                    &new_snapshot.consensus_hash,
                                    &stacks_block,
                                    0,
                                )
                                .unwrap();
                            } else {
                                warn!(
                                    "No such stacks block {}/{}",
                                    &new_snapshot.consensus_hash,
                                    &new_snapshot.winning_stacks_block_hash
                                );
                            }
                        } else {
                            warn!(
                                "Missing stacks block {}/{}",
                                &new_snapshot.consensus_hash,
                                &new_snapshot.winning_stacks_block_hash
                            );
                        }

                        next_arrival += 1;
                        if next_arrival >= stacks_blocks_arrival_order.len() {
                            break;
                        }
                        stacks_block_id = stacks_blocks_arrival_order[next_arrival].clone();
                    }
                }

                // TODO: also process microblocks
                // TODO: process blocks in arrival order
            }

            // process all new blocks
            loop {
                let sortition_tip =
                    SortitionDB::get_canonical_burn_chain_tip(new_sortition_db.conn())
                        .unwrap()
                        .sortition_id;
                let sortition_tx = new_sortition_db.tx_handle_begin(&sortition_tip).unwrap();
                let null_event_dispatcher: Option<&DummyEventDispatcher> = None;
                let receipts = new_chainstate
                    .process_blocks(
                        old_burnchaindb.conn(),
                        sortition_tx,
                        1,
                        null_event_dispatcher,
                    )
                    .unwrap();
                if receipts.len() == 0 {
                    break;
                }
            }
        }

        eprintln!(
            "Final arrival index is {} out of {}",
            next_arrival,
            stacks_blocks_arrival_order.len()
        );
        return;
    }

    if argv.len() < 4 {
        eprintln!("Usage: {} blockchain network working_dir", argv[0]);
        process::exit(1);
    }
}

fn tip_mine() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 6 {
        eprintln!(
            "Usage: {} tip-mine <working-dir> <event-log> <mine-tip-height> <max-txns>

Given a <working-dir>, try to ''mine'' an anchored block. This invokes the miner block
assembly, but does not attempt to broadcast a block commit. This is useful for determining
what transactions a given chain state would include in an anchor block, or otherwise
simulating a miner.
",
            argv[0]
        );
        process::exit(1);
    }

    let burnchain_path = format!("{}/mainnet/burnchain", &argv[2]);
    let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
    let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

    let events_file = &argv[3];
    let mine_tip_height: u64 = argv[4].parse().expect("Could not parse mine_tip_height");
    let mine_max_txns: u64 = argv[5].parse().expect("Could not parse mine-num-txns");

    let sort_db = SortitionDB::open(&sort_db_path, false, PoxConstants::mainnet_default())
        .unwrap_or_else(|_| panic!("Failed to open {sort_db_path}"));
    let chain_id = CHAIN_ID_MAINNET;
    let mut chain_state = StacksChainState::open(true, chain_id, &chain_state_path, None)
        .expect("Failed to open stacks chain state")
        .0;
    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
        .expect("Failed to get sortition chain tip");

    let estimator = Box::new(UnitEstimator);
    let metric = Box::new(UnitMetric);

    let mut mempool_db = MemPoolDB::open(true, chain_id, &chain_state_path, estimator, metric)
        .expect("Failed to open mempool db");

    {
        info!("Clearing mempool");
        let mut tx = mempool_db.tx_begin().unwrap();
        let min_height = u32::MAX as u64;
        MemPoolDB::garbage_collect(&mut tx, min_height, None).unwrap();
        tx.commit().unwrap();
    }

    let header_tip = NakamotoChainState::get_canonical_block_header(chain_state.db(), &sort_db)
        .unwrap()
        .unwrap();

    // Find ancestor block
    let mut stacks_header = header_tip.to_owned();
    loop {
        let parent_block_id = match stacks_header.anchored_header {
            StacksBlockHeaderTypes::Nakamoto(ref nakamoto_header) => {
                nakamoto_header.parent_block_id.clone()
            }
            StacksBlockHeaderTypes::Epoch2(ref epoch2_header) => {
                let block_info = StacksChainState::load_staging_block(
                    chain_state.db(),
                    &chain_state.blocks_path,
                    &stacks_header.consensus_hash,
                    &epoch2_header.block_hash(),
                )
                .unwrap()
                .unwrap();
                StacksBlockId::new(
                    &block_info.parent_consensus_hash,
                    &epoch2_header.parent_block,
                )
            }
        };

        let stacks_parent_header =
            NakamotoChainState::get_block_header(chain_state.db(), &parent_block_id)
                .unwrap()
                .unwrap();
        if stacks_parent_header.anchored_header.height() < mine_tip_height {
            break;
        }
        stacks_header = stacks_parent_header;
    }
    info!(
        "Found stacks_chain_tip with height {}",
        header_tip.anchored_header.height()
    );
    info!(
        "Mining off parent block with height {}",
        header_tip.anchored_header.height()
    );

    info!(
        "Submitting up to {} transactions to the mempool",
        mine_max_txns
    );
    let mut found_block_height = false;
    let mut parsed_tx_count = 0;
    let mut submit_tx_count = 0;
    let events_file = File::open(events_file).expect("Unable to open file");
    let events_reader = BufReader::new(events_file);
    'outer: for line in events_reader.lines() {
        let line_json: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let path = line_json["path"].as_str().unwrap();
        let payload = &line_json["payload"];
        match path {
            "new_block" => {
                let payload = payload.as_object().unwrap();
                let block_height = payload["block_height"].as_u64().unwrap();
                if !found_block_height && block_height >= mine_tip_height {
                    found_block_height = true;
                    info!("Found target block height {}", block_height);
                }
                info!(
                    "Found new_block height {} parsed_tx_count {} submit_tx_count {}",
                    block_height, parsed_tx_count, submit_tx_count
                );
            }
            "new_mempool_tx" => {
                let payload = payload.as_array().unwrap();
                for item in payload {
                    let raw_tx_hex = item.as_str().unwrap();
                    let raw_tx_bytes = hex_bytes(&raw_tx_hex[2..]).unwrap();
                    let mut cursor = io::Cursor::new(&raw_tx_bytes);
                    let raw_tx = StacksTransaction::consensus_deserialize(&mut cursor).unwrap();
                    if found_block_height {
                        if submit_tx_count >= mine_max_txns {
                            info!("Reached mine_max_txns {}", submit_tx_count);
                            break 'outer;
                        }
                        let result = mempool_db.submit(
                            &mut chain_state,
                            &sort_db,
                            &stacks_header.consensus_hash,
                            &stacks_header.anchored_header.block_hash(),
                            &raw_tx,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        );
                        parsed_tx_count += 1;
                        if result.is_ok() {
                            submit_tx_count += 1;
                        }
                    }
                }
            }
            _ => {}
        };
    }
    info!("Parsed {} transactions", parsed_tx_count);
    info!(
        "Submitted {} transactions into the mempool",
        submit_tx_count
    );

    info!("Mining a block");

    let start = get_epoch_time_ms();

    let parent_header = NakamotoChainState::get_block_header(
        chain_state.db(),
        &StacksBlockId::new(
            &stacks_header.consensus_hash,
            &stacks_header.anchored_header.block_hash(),
        ),
    )
    .expect("Failed to load chain tip header info")
    .expect("Failed to load chain tip header info");

    let sk = StacksPrivateKey::new();
    let mut tx_auth = TransactionAuth::from_p2pkh(&sk).unwrap();
    tx_auth.set_origin_nonce(0);

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
    );

    coinbase_tx.chain_id = chain_id;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&coinbase_tx);
    tx_signer.sign_origin(&sk).unwrap();
    let coinbase_tx = tx_signer.get_tx().unwrap();

    let settings = BlockBuilderSettings::max_value();

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
        &Burnchain::new(&burnchain_path, "bitcoin", "main").unwrap(),
    );

    let stop = get_epoch_time_ms();

    println!(
        "{} mined block @ height = {} off of {} ({}/{}) in {}ms.",
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

fn replay_block(stacks_path: &str, index_block_hash_hex: &str) {
    let index_block_hash = StacksBlockId::from_hex(index_block_hash_hex).unwrap();
    let chain_state_path = format!("{stacks_path}/mainnet/chainstate/");
    let sort_db_path = format!("{stacks_path}/mainnet/burnchain/sortition");
    let burn_db_path = format!("{stacks_path}/mainnet/burnchain/burnchain.sqlite");
    let burnchain_blocks_db = BurnchainDB::open(&burn_db_path, false).unwrap();

    let (mut chainstate, _) =
        StacksChainState::open(true, CHAIN_ID_MAINNET, &chain_state_path, None).unwrap();

    let mut sortdb = SortitionDB::connect(
        &sort_db_path,
        BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
        &BurnchainHeaderHash::from_hex(BITCOIN_MAINNET_FIRST_BLOCK_HASH).unwrap(),
        BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP.into(),
        STACKS_EPOCHS_MAINNET.as_ref(),
        PoxConstants::mainnet_default(),
        None,
        true,
    )
    .unwrap();
    let mut sort_tx = sortdb.tx_begin_at_tip();

    let blocks_path = chainstate.blocks_path.clone();
    let (mut chainstate_tx, clarity_instance) = chainstate
        .chainstate_tx_begin()
        .expect("Failed to start chainstate tx");
    let mut next_staging_block =
        StacksChainState::load_staging_block_info(&chainstate_tx.tx, &index_block_hash)
            .expect("Failed to load staging block data")
            .expect("No such index block hash in block database");

    next_staging_block.block_data = StacksChainState::load_block_bytes(
        &blocks_path,
        &next_staging_block.consensus_hash,
        &next_staging_block.anchored_block_hash,
    )
    .unwrap()
    .unwrap_or_default();

    let Some(next_microblocks) =
        StacksChainState::find_parent_microblock_stream(&chainstate_tx.tx, &next_staging_block)
            .unwrap()
    else {
        println!("No microblock stream found for {index_block_hash_hex}");
        return;
    };

    let (burn_header_hash, burn_header_height, burn_header_timestamp, _winning_block_txid) =
        match SortitionDB::get_block_snapshot_consensus(
            &sort_tx,
            &next_staging_block.consensus_hash,
        )
        .unwrap()
        {
            Some(sn) => (
                sn.burn_header_hash,
                sn.block_height as u32,
                sn.burn_header_timestamp,
                sn.winning_block_txid,
            ),
            None => {
                // shouldn't happen
                panic!(
                    "CORRUPTION: staging block {}/{} does not correspond to a burn block",
                    &next_staging_block.consensus_hash, &next_staging_block.anchored_block_hash
                );
            }
        };

    info!(
        "Process block {}/{} = {} in burn block {}, parent microblock {}",
        next_staging_block.consensus_hash,
        next_staging_block.anchored_block_hash,
        &index_block_hash,
        &burn_header_hash,
        &next_staging_block.parent_microblock_hash,
    );

    let Some(parent_header_info) =
        StacksChainState::get_parent_header_info(&mut chainstate_tx, &next_staging_block).unwrap()
    else {
        println!("Failed to load parent head info for block: {index_block_hash_hex}");
        return;
    };

    let block =
        StacksChainState::extract_stacks_block(&next_staging_block).expect("Failed to get block");
    let block_size = next_staging_block.block_data.len() as u64;

    let parent_block_header = match &parent_header_info.anchored_header {
        StacksBlockHeaderTypes::Epoch2(bh) => bh,
        StacksBlockHeaderTypes::Nakamoto(_) => panic!("Nakamoto blocks not supported yet"),
    };

    if !StacksChainState::check_block_attachment(&parent_block_header, &block.header) {
        let msg = format!(
            "Invalid stacks block {}/{} -- does not attach to parent {}/{}",
            &next_staging_block.consensus_hash,
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
        &parent_header_info,
        &next_staging_block,
        &block,
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
    assert_eq!(
        next_staging_block.parent_microblock_hash,
        last_microblock_hash
    );
    assert_eq!(
        next_staging_block.parent_microblock_seq,
        last_microblock_seq
    );

    let block_am = StacksChainState::find_stacks_tip_affirmation_map(
        &burnchain_blocks_db,
        sort_tx.tx(),
        &next_staging_block.consensus_hash,
        &next_staging_block.anchored_block_hash,
    )
    .unwrap();

    let pox_constants = sort_tx.context.pox_constants.clone();

    match StacksChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut sort_tx,
        &pox_constants,
        &parent_header_info,
        &next_staging_block.consensus_hash,
        &burn_header_hash,
        burn_header_height,
        burn_header_timestamp,
        &block,
        block_size,
        &next_microblocks,
        next_staging_block.commit_burn,
        next_staging_block.sortition_burn,
        block_am.weight(),
        true,
    ) {
        Ok((_receipt, _, _)) => {
            info!("Block processed successfully! block = {index_block_hash}");
        }
        Err(e) => {
            println!("Failed processing block! block = {index_block_hash}, error = {e:?}");
            process::exit(1);
        }
    };
}

/// Perform an analysis of the anti-MEV algorithm in epoch 3.0, vis-a-vis the status quo.
/// Results are printed to stdout.
/// Exits with 0 on success, and 1 on failure.
fn analyze_sortition_mev(argv: Vec<String>) {
    if argv.len() < 7 || (argv.len() >= 7 && argv.len() % 2 != 1) {
        eprintln!(
            "Usage: {} /path/to/burnchain/db /path/to/sortition/db /path/to/chainstate/db start_height end_height [advantage_miner advantage_burn ..]",
            &argv[0]
        );
        process::exit(1);
    }

    let burnchaindb_path = argv[2].clone();
    let sortdb_path = argv[3].clone();
    let chainstate_path = argv[4].clone();
    let start_height: u64 = argv[5].parse().unwrap();
    let end_height: u64 = argv[6].parse().unwrap();

    let mut advantages = HashMap::new();
    if argv.len() >= 7 {
        let mut i = 7;
        while i + 2 < argv.len() {
            let advantaged_miner = argv[i].clone();
            let advantage: u64 = argv[i + 1].parse().unwrap();
            advantages.insert(advantaged_miner, advantage);
            i += 2;
        }
    }

    let mut sortdb =
        SortitionDB::open(&sortdb_path, true, PoxConstants::mainnet_default()).unwrap();
    sortdb.dryrun = true;
    let burnchain = Burnchain::new(&burnchaindb_path, "bitcoin", "mainnet").unwrap();
    let burnchaindb = BurnchainDB::connect(&burnchaindb_path, &burnchain, true).unwrap();
    let (mut chainstate, _) =
        StacksChainState::open(true, 0x00000001, &chainstate_path, None).unwrap();

    let mut wins_epoch2 = BTreeMap::new();
    let mut wins_epoch3 = BTreeMap::new();

    for height in start_height..end_height {
        debug!("Get ancestor snapshots for {}", height);
        let (tip_sort_id, parent_ancestor_sn, ancestor_sn) = {
            let mut sort_tx = sortdb.tx_begin_at_tip();
            let tip_sort_id = sort_tx.tip();
            let ancestor_sn = sort_tx
                .get_block_snapshot_by_height(height)
                .unwrap()
                .unwrap();
            let parent_ancestor_sn = sort_tx
                .get_block_snapshot_by_height(height - 1)
                .unwrap()
                .unwrap();
            (tip_sort_id, parent_ancestor_sn, ancestor_sn)
        };

        let mut burn_block =
            BurnchainDB::get_burnchain_block(burnchaindb.conn(), &ancestor_sn.burn_header_hash)
                .unwrap();

        debug!(
            "Get reward cycle info at {}",
            burn_block.header.block_height
        );
        let rc_info_opt = get_reward_cycle_info(
            burn_block.header.block_height,
            &burn_block.header.parent_block_hash,
            &tip_sort_id,
            &burnchain,
            &burnchaindb,
            &mut chainstate,
            &mut sortdb,
            &OnChainRewardSetProvider::new(),
            false,
        )
        .unwrap();

        let mut ops = burn_block.ops.clone();
        for op in ops.iter_mut() {
            if let BlockstackOperationType::LeaderBlockCommit(op) = op {
                if let Some(extra_burn) = advantages.get(&op.apparent_sender.to_string()) {
                    debug!(
                        "Miner {} gets {} extra burn fee",
                        &op.apparent_sender.to_string(),
                        extra_burn
                    );
                    op.burn_fee += *extra_burn;
                }
            }
        }
        burn_block.ops = ops;

        debug!("Re-evaluate sortition at height {}", height);
        let (next_sn, state_transition) = sortdb
            .evaluate_sortition(
                &burn_block.header,
                burn_block.ops.clone(),
                &burnchain,
                &tip_sort_id,
                rc_info_opt,
                |_| (),
            )
            .unwrap();

        assert_eq!(next_sn.block_height, ancestor_sn.block_height);
        assert_eq!(next_sn.burn_header_hash, ancestor_sn.burn_header_hash);

        let mut sort_tx = sortdb.tx_begin_at_tip();
        let tip_pox_id = sort_tx.get_pox_id().unwrap();
        let next_sn_nakamoto = BlockSnapshot::make_snapshot_in_epoch(
            &mut sort_tx,
            &burnchain,
            &ancestor_sn.sortition_id,
            &tip_pox_id,
            &parent_ancestor_sn,
            &burn_block.header,
            &state_transition,
            0,
            StacksEpochId::Epoch30,
        )
        .unwrap();

        assert_eq!(next_sn.block_height, next_sn_nakamoto.block_height);
        assert_eq!(next_sn.burn_header_hash, next_sn_nakamoto.burn_header_hash);

        let winner_epoch2 = get_block_commit_by_txid(
            &sort_tx,
            &ancestor_sn.sortition_id,
            &next_sn.winning_block_txid,
        )
        .unwrap()
        .map(|cmt| format!("{:?}", &cmt.apparent_sender.to_string()))
        .unwrap_or("(null)".to_string());

        let winner_epoch3 = get_block_commit_by_txid(
            &sort_tx,
            &ancestor_sn.sortition_id,
            &next_sn_nakamoto.winning_block_txid,
        )
        .unwrap()
        .map(|cmt| format!("{:?}", &cmt.apparent_sender.to_string()))
        .unwrap_or("(null)".to_string());

        wins_epoch2.insert(
            (next_sn.block_height, next_sn.burn_header_hash),
            winner_epoch2,
        );
        wins_epoch3.insert(
            (
                next_sn_nakamoto.block_height,
                next_sn_nakamoto.burn_header_hash,
            ),
            winner_epoch3,
        );
    }

    let mut all_wins_epoch2 = BTreeMap::new();
    let mut all_wins_epoch3 = BTreeMap::new();

    println!("Wins epoch 2");
    println!("------------");
    println!("height,burn_header_hash,winner");
    for ((height, bhh), winner) in wins_epoch2.iter() {
        println!("{},{},{}", height, bhh, winner);
        if let Some(cnt) = all_wins_epoch2.get_mut(winner) {
            *cnt += 1;
        } else {
            all_wins_epoch2.insert(winner, 1);
        }
    }

    println!("------------");
    println!("Wins epoch 3");
    println!("------------");
    println!("height,burn_header_hash,winner");
    for ((height, bhh), winner) in wins_epoch3.iter() {
        println!("{},{},{}", height, bhh, winner);
        if let Some(cnt) = all_wins_epoch3.get_mut(winner) {
            *cnt += 1;
        } else {
            all_wins_epoch3.insert(winner, 1);
        }
    }

    println!("---------------");
    println!("Differences");
    println!("---------------");
    println!("height,burn_header_hash,winner_epoch2,winner_epoch3");
    for ((height, bhh), winner) in wins_epoch2.iter() {
        let Some(epoch3_winner) = wins_epoch3.get(&(*height, *bhh)) else {
            continue;
        };
        if epoch3_winner != winner {
            println!("{},{},{},{}", height, bhh, winner, epoch3_winner);
        }
    }

    println!("---------------");
    println!("All epoch2 wins");
    println!("---------------");
    println!("miner,count");
    for (winner, count) in all_wins_epoch2.iter() {
        println!("{},{}", winner, count);
    }

    println!("---------------");
    println!("All epoch3 wins");
    println!("---------------");
    println!("miner,count,degradation");
    for (winner, count) in all_wins_epoch3.into_iter() {
        let degradation = (count as f64)
            / (all_wins_epoch2
                .get(&winner)
                .map(|cnt| *cnt as f64)
                .unwrap_or(0.00000000000001f64));
        println!("{},{},{}", &winner, count, degradation);
    }

    process::exit(0);
}
