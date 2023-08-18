// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

#[macro_use]
extern crate stacks_common;

extern crate clarity;
extern crate serde;
extern crate serde_json;
extern crate toml;

mod config;
mod rpc;

use crate::rpc::SignerSession;
use crate::rpc::StackerDBSession;
use std::env;
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process;

use clarity::vm::types::QualifiedContractIdentifier;

use stacks_common::types::chainstate::StacksPrivateKey;

use libstackerdb::StackerDBChunkData;

/// Consume one argument from `args`, which may go by multiple names in `argnames`.
/// If it has an argument (`has_optarg`), then return it.
///
/// Returns Ok(Some(arg)) if this argument was passed and it has argument `arg`
/// Returns Ok(Some("")) if this argument was passed but `has_optarg` is false
/// Returns Ok(None) if this argument is not present
/// Returns Err(..) if an argument was expected but not found.
fn consume_arg(
    args: &mut Vec<String>,
    argnames: &[&str],
    has_optarg: bool,
) -> Result<Option<String>, String> {
    if let Some(ref switch) = args
        .iter()
        .find(|ref arg| argnames.iter().find(|ref argname| argname == arg).is_some())
    {
        let idx = args
            .iter()
            .position(|ref arg| arg == switch)
            .expect("BUG: did not find the thing that was just found");
        let argval = if has_optarg {
            // following argument is the argument value
            if idx + 1 < args.len() {
                Some(args[idx + 1].clone())
            } else {
                // invalid usage -- expected argument
                return Err(format!("Expected argument for {}", argnames.join(",")));
            }
        } else {
            // only care about presence of this option
            Some("".to_string())
        };

        args.remove(idx);
        if has_optarg {
            // also clear the argument
            args.remove(idx);
        }
        Ok(argval)
    } else {
        // not found
        Ok(None)
    }
}

/// Print an error message, usage, and exit
fn usage(err_msg: Option<&str>) {
    if let Some(err_msg) = err_msg {
        eprintln!("{}", err_msg);
    }
    eprintln!(
        "Usage: {} subcommand [args]",
        &env::args().collect::<Vec<_>>()[0]
    );
    process::exit(1);
}

/// Get -h,--host and -c,--contract
fn parse_host_and_contract(argv: &mut Vec<String>) -> (SocketAddr, QualifiedContractIdentifier) {
    let host_opt = match consume_arg(argv, &["-h", "--host"], true) {
        Ok(x) => x,
        Err(msg) => {
            usage(Some(&msg));
            unreachable!()
        }
    };
    let contract_opt = match consume_arg(argv, &["-c", "--contract"], true) {
        Ok(x) => x,
        Err(msg) => {
            usage(Some(&msg));
            unreachable!()
        }
    };

    let host = match host_opt {
        Some(host) => match host.to_socket_addrs() {
            Ok(mut iter) => match iter.next() {
                Some(host) => host,
                None => {
                    usage(Some("No hosts resolved"));
                    unreachable!()
                }
            },
            Err(..) => {
                usage(Some("Failed to resolve host"));
                unreachable!()
            }
        },
        None => {
            usage(Some("Need -h,--host"));
            unreachable!()
        }
    };
    let contract = match contract_opt {
        Some(host) => match QualifiedContractIdentifier::parse(&host) {
            Ok(qcid) => qcid,
            Err(..) => {
                usage(Some("Invalid contract ID"));
                unreachable!()
            }
        },
        None => {
            usage(Some("Need -c,--contract"));
            unreachable!()
        }
    };

    (host, contract)
}

/// Handle the get-chunk subcommand
fn handle_get_chunk(mut argv: Vec<String>) {
    let (host, contract) = parse_host_and_contract(&mut argv);
    if argv.len() < 4 {
        usage(Some("Expected slot_id and slot_version"));
    }

    let slot_id: u32 = match argv[2].parse() {
        Ok(x) => x,
        Err(..) => {
            usage(Some("Expected u32 for slot ID"));
            unreachable!()
        }
    };

    let slot_version: u32 = match argv[3].parse() {
        Ok(x) => x,
        Err(..) => {
            usage(Some("Expected u32 for slot version"));
            unreachable!()
        }
    };

    let mut session = StackerDBSession::new(host.clone(), contract.clone());
    session.connect(host, contract).unwrap();
    let chunk_opt = session.get_chunk(slot_id, slot_version).unwrap();
    if let Some(chunk) = chunk_opt {
        io::stdout().write(&chunk).unwrap();
    }
    process::exit(0);
}

/// Handle the get-latest-chunk subcommand
fn handle_get_latest_chunk(mut argv: Vec<String>) {
    let (host, contract) = parse_host_and_contract(&mut argv);
    if argv.len() < 3 {
        usage(Some("Expected slot_id"));
    }

    let slot_id: u32 = match argv[2].parse() {
        Ok(x) => x,
        Err(..) => {
            usage(Some("Expected u32 for slot ID"));
            unreachable!()
        }
    };

    let mut session = StackerDBSession::new(host.clone(), contract.clone());
    session.connect(host, contract).unwrap();
    let chunk_opt = session.get_latest_chunk(slot_id).unwrap();
    if let Some(chunk) = chunk_opt {
        io::stdout().write(&chunk).unwrap();
    }
    process::exit(0);
}

/// Handle listing chunks
fn handle_list_chunks(mut argv: Vec<String>) {
    let (host, contract) = parse_host_and_contract(&mut argv);

    let mut session = StackerDBSession::new(host.clone(), contract.clone());
    session.connect(host, contract).unwrap();
    let chunk_list = session.list_chunks().unwrap();
    println!("{}", serde_json::to_string(&chunk_list).unwrap());
    process::exit(0);
}

/// Handle uploading a chunk
fn handle_put_chunk(mut argv: Vec<String>) {
    let (host, contract) = parse_host_and_contract(&mut argv);
    if argv.len() < 6 {
        usage(Some("Expected slot_id, slot_version, private_key, data"));
    }

    let slot_id: u32 = match argv[2].parse() {
        Ok(x) => x,
        Err(..) => {
            usage(Some("Expected u32 for slot ID"));
            unreachable!()
        }
    };

    let slot_version: u32 = match argv[3].parse() {
        Ok(x) => x,
        Err(..) => {
            usage(Some("Expected u32 for slot version"));
            unreachable!()
        }
    };

    let privk = match StacksPrivateKey::from_hex(&argv[4]) {
        Ok(x) => x,
        Err(..) => {
            usage(Some("Failed to parse private key"));
            unreachable!()
        }
    };

    let data = if argv[5] == "-" {
        let mut buf = vec![];
        io::stdin().read_to_end(&mut buf).unwrap();
        buf
    } else {
        argv[5].as_bytes().to_vec()
    };

    let mut chunk = StackerDBChunkData::new(slot_id, slot_version, data);
    chunk.sign(&privk).unwrap();

    let mut session = StackerDBSession::new(host.clone(), contract.clone());
    session.connect(host, contract).unwrap();
    let chunk_ack = session.put_chunk(chunk).unwrap();
    println!("{}", serde_json::to_string(&chunk_ack).unwrap());
    process::exit(0);
}

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        usage(Some("No subcommand given"));
    }

    let subcommand = argv[1].clone();
    match subcommand.as_str() {
        "get-chunk" => {
            handle_get_chunk(argv);
        }
        "get-latest-chunk" => {
            handle_get_latest_chunk(argv);
        }
        "list-chunks" => {
            handle_list_chunks(argv);
        }
        "put-chunk" => {
            handle_put_chunk(argv);
        }
        _ => {
            usage(Some(&format!("Unrecognized subcommand '{}'", &subcommand)));
        }
    }
}
