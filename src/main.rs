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
#![allow(unused_assignments)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate rand;
extern crate ini;
extern crate secp256k1;
extern crate serde;
extern crate rusqlite;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate sha2;
extern crate sha3;
extern crate ripemd160;
extern crate dirs;
extern crate regex;
extern crate byteorder;
extern crate mio;
extern crate hashbrown;
extern crate libc;

#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;

#[cfg(test)]
#[macro_use]
extern crate assert_json_diff;

#[macro_use]
extern crate blockstack_lib;
use blockstack_lib::*;

use std::fs;
use std::env;
use std::process;

use util::log;

use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

fn main() {

    log::set_loglevel(log::LOG_DEBUG).unwrap();

    let argv : Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: {} command [args...]", argv[0]);
        process::exit(1);
    }

    if argv[1] == "decode-bitcoin-header" {
        if argv.len() < 4 {
            eprintln!("Usage: {} decode-bitcoin-header BLOCK_HEIGHT PATH", argv[0]);
            process::exit(1);
        }

        use burnchains::bitcoin::spv;

        let height = argv[2].parse::<u64>().expect("Invalid block height");
        let headers_path = &argv[3];

        let header_opt = spv::SpvClient::read_block_header(headers_path, height).unwrap();
        match header_opt {
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

        let mut index = 0;
        let tx = StacksTransaction::deserialize(&tx_bytes, &mut index, tx_bytes.len() as u32).map_err(|_e| {
            eprintln!("Failed to decode transaction");
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

        let mut index = 0;
        let block = StacksBlock::deserialize(&block_data, &mut index, block_data.len() as u32).map_err(|_e| {
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

        let mut index = 0;
        let mblocks : Vec<StacksMicroblock> = Vec::deserialize(&mblock_data, &mut index, mblock_data.len() as u32).map_err(|_e| {
            eprintln!("Failed to decode microblocks");
            process::exit(1);
        }).unwrap();

        println!("{:#?}", &mblocks);
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

    if argv[1] == "testnet" {
        use testnet;
        use rand::RngCore;
        use util::hash::{to_hex};
        
        // Testnet's name
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let testnet_id = format!("stacks-testnet-{}", to_hex(&buf));
        
        let conf = testnet::Config {
            testnet_name: "testnet".to_string(),
            chain: "bitcoin".to_string(),
            burnchain_path: format!("/tmp/{}/burnchain", testnet_id),
            burnchain_block_time:2000,
            leader_config: vec![testnet::LeaderConfig {
                name: "L1".to_string(),
                path: format!("/tmp/{}/L1", testnet_id),
                mem_pool_path: format!("/tmp/{}/L1/mempool", testnet_id)
            }]
        };
        
        let mut run_loop = testnet::RunLoop::new(conf);
        run_loop.start();
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



