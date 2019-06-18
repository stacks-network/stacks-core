/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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
extern crate serde_json;
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

#[macro_use] extern crate serde_derive;

#[macro_use]
mod util;

#[macro_use]
mod chainstate;

mod address;
mod burnchains;
mod core;
mod deps;
mod net;
mod vm;

mod clarity;

use std::fs;
use std::env;
use std::process;

use util::log;

fn main() {

    log::set_loglevel(log::LOG_DEBUG).unwrap();

    let argv : Vec<String> = env::args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: {} command [args...]", argv[0]);
        process::exit(1);
    }

    if argv[1] == "read_bitcoin_header" {
        if argv.len() < 4 {
            eprintln!("Usage: {} read_bitcoin_header BLOCK_HEIGHT PATH", argv[0]);
            process::exit(1);
        }

        use burnchains::BurnchainHeaderHash;
        use burnchains::bitcoin::spv;
        use util::hash::to_hex;
        use deps::bitcoin::network::serialize::BitcoinHash;

        let height = argv[2].parse::<u64>().unwrap();
        let headers_path = &argv[3];

        let header_opt = spv::SpvClient::read_block_header(headers_path, height).unwrap();
        match header_opt {
            Some(header) => {
                println!("{:?}", header);
                println!("{}", to_hex(BurnchainHeaderHash::from_bytes_be(header.header.bitcoin_hash().as_bytes()).unwrap().as_bytes()));
                process::exit(0);
            },
            None => {
                eprintln!("Failed to read header");
                process::exit(1);
            }
        }
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
