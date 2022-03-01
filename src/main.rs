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

use blockstack_lib::burnchains::db::BurnchainDB;
use blockstack_lib::burnchains::Address;
use blockstack_lib::burnchains::Burnchain;
use blockstack_lib::chainstate::burn::ConsensusHash;
use blockstack_lib::chainstate::stacks::db::blocks::StagingBlock;
use blockstack_lib::chainstate::stacks::db::ChainStateBootData;
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
    BlockHeaderHash, BurnchainHeaderHash, StacksBlockId,
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

fn main() {
    let argv: Vec<String> = env::args().collect();
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
        let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path)
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
        let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path)
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
        let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
        let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

        let mut min_fee = u64::max_value();
        let mut max_time = u64::max_value();

        if argv.len() >= 4 {
            min_fee = argv[3].parse().expect("Could not parse min_fee");
        }
        if argv.len() >= 5 {
            max_time = argv[4].parse().expect("Could not parse max_time");
        }

        let sort_db = SortitionDB::open(&sort_db_path, false)
            .expect(&format!("Failed to open {}", &sort_db_path));
        let chain_id = CHAIN_ID_MAINNET;
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

    if argv[1] == "decode-microblocks" {
        if argv.len() < 3 {
            eprintln!(
                "Usage: {} decode-microblocks MICROBLOCK_STREAM_PATH",
                argv[0]
            );
            process::exit(1);
        }

        let mblock_path = &argv[2];
        let mblock_data = fs::read(mblock_path).expect(&format!("Failed to open {}", mblock_path));

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
        let mut marf = MARF::from_path(&marf_path).expect("Failed to open MARF");
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

            let row = res.expect(&format!(
                "Failed to query DB for MARF value hash {}",
                &value
            ));
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
        let program: String =
            fs::read_to_string(&argv[2]).expect(&format!("Error reading file: {}", argv[2]));
        match clarity_cli::vm_execute(&program) {
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
        let mut marf = MARF::from_path(path).unwrap();
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

    if argv[1] == "process-block" {
        let path = &argv[2];
        let sort_path = &argv[3];
        let (mut chainstate, _) = StacksChainState::open(false, 0x80000000, path).unwrap();
        let mut sortition_db = SortitionDB::open(sort_path, true).unwrap();
        let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sortition_db.conn())
            .unwrap()
            .sortition_id;
        let mut tx = sortition_db.tx_handle_begin(&sortition_tip).unwrap();
        chainstate.process_next_staging_block(&mut tx).unwrap();
        return;
    }

    if argv.len() < 4 {
        eprintln!("Usage: {} blockchain network working_dir", argv[0]);
        process::exit(1);
    }
}
