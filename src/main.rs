/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate blockstack_lib;
extern crate rusqlite;

use blockstack_lib::*;

use std::fs;
use std::env;
use std::process;
use std::io::prelude::*;
use std::io;

use blockstack_lib::util::log;

use blockstack_lib::net::StacksMessageCodec;
use blockstack_lib::chainstate::stacks::*;
use blockstack_lib::util::hash::{hex_bytes, to_hex};
use blockstack_lib::util::retry::LogReader;
use blockstack_lib::chainstate::stacks::index::marf::MARF;
use blockstack_lib::chainstate::stacks::StacksBlockHeader;
use blockstack_lib::chainstate::burn::BlockHeaderHash;
use blockstack_lib::burnchains::BurnchainHeaderHash;

use blockstack_lib::burnchains::bitcoin::spv;
use blockstack_lib::burnchains::bitcoin::BitcoinNetworkType;

use rusqlite::Connection;
use rusqlite::types::ToSql;
use rusqlite::OpenFlags;

fn main() {

    log::set_loglevel(log::LOG_INFO).unwrap();

    let mut argv : Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: {} command [args...]", argv[0]);
        process::exit(1);
    }

    if argv[1] == "decode-bitcoin-header" {
        if argv.len() < 4 {
            eprintln!("Usage: {} decode-bitcoin-header [-t|-r] BLOCK_HEIGHT PATH", argv[0]);
            process::exit(1);
        }

        let mut testnet = false;
        let mut regtest = false;
        let mut idx = 0;
        for i in 0..argv.len() {
            if argv[i] == "-t" {
                testnet = true;
                idx = i;
            }
            else if argv[i] == "-r" {
                regtest = true;
                idx = i;
            }
        }
        if regtest && testnet {
            // don't allow both
            eprintln!("Usage: {} decode-bitcoin-header [-t|-r] BLOCK_HEIGHT PATH", argv[0]);
            process::exit(1);
        }
        if idx > 0 {
            argv.remove(idx);
        }

        let mode = if testnet { BitcoinNetworkType::Testnet } else if regtest { BitcoinNetworkType::Regtest } else { BitcoinNetworkType::Mainnet };

        let height = argv[2].parse::<u64>().expect("Invalid block height");
        let headers_path = &argv[3];

        let spv_client = spv::SpvClient::new(headers_path, 0, Some(height), mode, false, false).expect("FATAL: could not instantiate SPV client");
        match spv_client.read_block_header(height).expect("FATAL: could not read block header database") {
            Some(header) => {
                println!("{:#?}", header);
                process::exit(0);
            },
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
        let tx_bytes = hex_bytes(tx_str).map_err(|_e| {
            eprintln!("Failed to decode transaction: must be a hex string");
            process::exit(1);
        }).unwrap();

        let mut cursor = io::Cursor::new(&tx_bytes);
        let mut debug_cursor = LogReader::from_reader(&mut cursor);

        let tx = StacksTransaction::consensus_deserialize(&mut debug_cursor).map_err(|e| {
            eprintln!("Failed to decode transaction: {:?}", &e);
            eprintln!("Bytes consumed:");
            for buf in debug_cursor.log().iter() {
                eprintln!("  {}", to_hex(buf));
            }
            process::exit(1);
        }).unwrap();

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

        let block = StacksBlock::consensus_deserialize(&mut io::Cursor::new(&block_data)).map_err(|_e| {
            eprintln!("Failed to decode block");
            process::exit(1);
        }).unwrap();

        println!("{:#?}", &block);
        process::exit(0);
    }

    if argv[1] == "decode-microblocks" {
        if argv.len() < 3 {
            eprintln!("Usage: {} decode-microblocks MICROBLOCK_STREAM_PATH", argv[0]);
            process::exit(1);
        }

        let mblock_path = &argv[2];
        let mblock_data = fs::read(mblock_path).expect(&format!("Failed to open {}", mblock_path));

        let mut cursor = io::Cursor::new(&mblock_data);
        let mut debug_cursor = LogReader::from_reader(&mut cursor);
        let mblocks : Vec<StacksMicroblock> = Vec::consensus_deserialize(&mut debug_cursor).map_err(|e| {
            eprintln!("Failed to decode microblocks: {:?}", &e);
            eprintln!("Bytes consumed:");
            for buf in debug_cursor.log().iter() {
                eprintln!("  {}", to_hex(buf));
            }
            process::exit(1);
        }).unwrap();

        println!("{:#?}", &mblocks);
        process::exit(0);
    }

    if argv[1] == "header-indexed-get" {
        if argv.len() < 5 {
            eprintln!("Usage: {} header-indexed-get CHAINSTATE_DIR BLOCK_ID_HASH KEY", argv[0]);
            process::exit(1);
        }
        let headers_dir = &argv[2];
        let marf_path = format!("{}/vm/index", &headers_dir);
        let db_path = format!("{}/vm/headers.db", &headers_dir);
        let marf_tip = &argv[3];
        let marf_key = &argv[4];

        if fs::metadata(&marf_path).is_err() {
            eprintln!("No such file or directory: {}", &marf_path);
            process::exit(1);
        }

        if fs::metadata(&db_path).is_err() {
            eprintln!("No such file or directory: {}", &db_path);
            process::exit(1);
        }
        
        let marf_bhh = BlockHeaderHash::from_hex(marf_tip).expect("Bad MARF block hash");
        let mut marf = MARF::from_path(&marf_path, None).expect("Failed to open MARF");
        let value_opt = marf.get(&marf_bhh, marf_key).expect("Failed to read MARF");

        if let Some(value) = value_opt {
            let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).expect("Failed to open DB");
            let args : &[&dyn ToSql] = &[&value.to_hex()];
            let res : Result<String, rusqlite::Error> = conn.query_row_and_then("SELECT value FROM __fork_storage WHERE value_hash = ?1", args,
                                                                                |row| { let s : String = row.get(0); Ok(s) });

            let row = res.expect(&format!("Failed to query DB for MARF value hash {}", &value));
            println!("{}", row);
        }
        else {
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
            .expect(&format!("Error reading file: {}", argv[2]));
        match vm::execute(&program) {
            Ok(Some(result)) => println!("{}", result),
            Ok(None) => println!(""),
            Err(error) => { 
                panic!("Program Execution Error: \n{}", error);
            }
        }
        return
    }

    if argv[1] == "marf-get" {
        let path = &argv[2];
        let tip = BlockHeaderHash::from_hex(&argv[3]).unwrap();
        let burntip = BurnchainHeaderHash::from_hex(&argv[4]).unwrap();
        let itip = StacksBlockHeader::make_index_block_hash(&burntip, &tip);
        let key = &argv[5];
        let mut marf = MARF::from_path(path, Some(&itip)).unwrap();
        let res = marf.get(&itip, key).expect("MARF error.");
        match res {
            Some(x) => println!("{}", x),
            None => println!("None"),
        };
        return
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
                               &[&cur_tip as &dyn rusqlite::types::ToSql, &cur_burn], |row| (row.get(0), row.get(1))) {
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
        return
    }

    if argv[1] == "docgen" {
        println!("{}", vm::docs::make_json_api_reference());
        return
    }

    if argv[1] == "local" {
        clarity::invoke_command(&format!("{} {}", argv[0], argv[1]), &argv[2..]);
        return
    }

    if argv.len() < 4 {
        eprintln!("Usage: {} blockchain network working_dir", argv[0]);
        process::exit(1);
    }

    let blockchain = &argv[1];
    let network = &argv[2];
    let working_dir = &argv[3];

    match (blockchain.as_str(), network.as_str()) {
        ("bitcoin", "mainnet") | ("bitcoin", "testnet") | ("bitcoin", "regtest") => {
            let block_height_res = core::sync_burnchain_bitcoin(&working_dir, &network);
            match block_height_res {
                Err(e) => {
                    eprintln!("Failed to sync {} {}: {:?}", blockchain, network, e);
                    process::exit(1);
                },
                Ok(height) => {
                    println!("Synchronized state to block {}", height);
                }
            }
        },
        (_, _) => {
            eprintln!("Unrecognized blockchain and/or network");
            process::exit(1);
        }
    };
}
