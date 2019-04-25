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

extern crate rand;
extern crate bitcoin;
extern crate ini;
extern crate jsonrpc;
extern crate secp256k1;
extern crate serde;
extern crate serde_json;
extern crate crypto;
extern crate rusqlite;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate sha2;
extern crate dirs;
extern crate regex;

#[macro_use] extern crate serde_derive;

#[macro_use] mod util;
mod burnchains;
mod chainstate;
mod core;
mod vm;
mod address;

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
        use bitcoin::network::serialize::BitcoinHash;

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
            eprintln!("Usage: {} exec_program [program-file.scm]", argv[0]);
            process::exit(1);
        }
        let program: String = fs::read_to_string(&argv[2])
            .expect(&format!("Error reading file: {}", argv[2]));
        match vm::execute(&program) {
            Ok(result) => println!("{}", result),
            Err(error) => { 
                panic!("Program Execution Error: \n {}", error);
            }
        }
        return
    }

    if argv[1] == "docgen" {
        println!("{}", vm::docs::make_json_api_reference());
        return
    }

    if argv[1] == "local" {
        // "local" VM CLI invocations.
        if argv.len() < 3 {
            eprintln!("Usage: {} local [command]
where command is one of:

  initialize         to initialize a local VM state database.
  check              to typecheck a potential contract definition.
  launch             to launch a initialize a new contract in the local state database.
  eval               to evaluate (in read-only mode) a program in a given contract context.
  execute            to execute a public function of a defined contract.

", argv[0]);
            process::exit(1);
        }

        use vm::parser::parse;
        use vm::contexts::OwnedEnvironment;
        use vm::database::{ContractDatabaseConnection};
        use vm::{SymbolicExpression, SymbolicExpressionType};
        use vm::checker::{type_check, AnalysisDatabase};
        use vm::types::Value;

        match argv[2].as_ref() {
            "initialize" => {
                if argv.len() < 4 {
                    eprintln!("Usage: {} local initialize [vm-state.db]", argv[0]);
                    process::exit(1);
                }
                AnalysisDatabase::initialize(&argv[3]);
                match ContractDatabaseConnection::initialize(&argv[3]) {
                    Ok(_) => println!("Database created."),
                    Err(error) => eprintln!("Initialization error: \n {}", error)
                }
                return
            },
            "check" => {
                if argv.len() < 4 {
                    eprintln!("Usage: {} local check [program-file.scm] (vm-state.db)", argv[0]);
                    process::exit(1);
                }

                let content: String = fs::read_to_string(&argv[3])
                    .expect(&format!("Error reading file: {}", argv[3]));
                
                let mut db = {
                    if argv.len() >= 5 {
                        AnalysisDatabase::open(&argv[4])
                    } else {
                        AnalysisDatabase::memory()
                    }
                };

                let mut ast = parse(&content).expect("Failed to parse program");
                type_check(&"transient", &mut ast, &mut db, false)
                    .unwrap_or_else(|e| {
                        eprintln!("Type check error.\n{}", e);
                        process::exit(1);
                    });

                return
            },
            "eval" => {
                if argv.len() < 6 {
                    eprintln!("Usage: {} local eval [context-contract-name] [program.scm] [vm-state.db]", argv[0]);
                    process::exit(1);
                }
                let vm_filename = &argv[5];

                let mut db = match ContractDatabaseConnection::open(vm_filename) {
                    Ok(db) => db,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n {}", error);
                        process::exit(1);
                    }
                };
                let content: String = fs::read_to_string(&argv[4])
                    .expect(&format!("Error reading file: {}", argv[4]));
                
                let mut vm_env = OwnedEnvironment::new(&mut db);
                let contract_name = &argv[3];
                
                let result = vm_env.get_exec_environment(None)
                    .eval_read_only(contract_name, &content);

                match result {
                    Ok(x) => {
                        println!("Program executed successfully! Output: \n {}", x);
                    },
                    Err(error) => println!("Program execution error: \n {}", error)
                }
                return
            }
            "launch" => {
                if argv.len() < 6 {
                    eprintln!("Usage: {} local launch [contract-name] [contract-definition.scm] [vm-state.db]", argv[0]);
                    process::exit(1);
                }
                let vm_filename = &argv[5];

                let contract_name = &argv[3];
                let contract_content: String = fs::read_to_string(&argv[4])
                    .expect(&format!("Error reading file: {}", argv[4]));

                // typecheck and insert into typecheck tables
                // Aaron todo: AnalysisDatabase and ContractDatabase should share a db connection...
                //     that way, we can do the initialization _and_ the type check insert in a single
                //     transaction that commits together.

                let mut db = AnalysisDatabase::open(vm_filename);
                let mut ast = parse(&contract_content).expect("Failed to parse program.");

                type_check(contract_name, &mut ast, &mut db, true)
                    .unwrap_or_else(|e| {
                        eprintln!("Type check error.\n{}", e);
                        process::exit(1);
                    });

                let mut db = match ContractDatabaseConnection::open(vm_filename) {
                    Ok(db) => db,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n {}", error);
                        process::exit(1);
                    }
                };

                let mut vm_env = OwnedEnvironment::new(&mut db);

                let result = {
                    let mut env = vm_env.get_exec_environment(None);
                    env.initialize_contract(&contract_name, &contract_content)
                };
                match result {
                    Ok(_x) => {
                        vm_env.commit();
                        println!("Contract initialized!");
                    },
                    Err(error) => println!("Contract initialization error: \n {}", error)
                }
                return
            },
            "execute" => {
                if argv.len() < 7 {
                    eprintln!("Usage: {} local execute [vm-state.db] [contract-name] [public-function-name] [sender-address] [args...]", argv[0]);
                    process::exit(1);
                }
                let vm_filename = &argv[3];

                let mut db = match ContractDatabaseConnection::open(vm_filename) {
                    Ok(db) => db,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n {}", error);
                        process::exit(1);
                    }
                };

                let mut vm_env = OwnedEnvironment::new(&mut db);
                let contract_name = &argv[4];
                let tx_name = &argv[5];
                
                let sender_in = &argv[6];

                let mut sender = vm::parser::parse(&format!("'{}", sender_in))
                    .expect(&format!("Error parsing sender {}", sender_in))
                    .pop()
                    .expect(&format!("Failed to read a sender from {}", sender_in));
                let sender = {
                    if let Some(Value::Principal(principal_data)) = sender.match_atom_value() {
                        Value::Principal(principal_data.clone())
                    } else {
                        eprintln!("Unexpected result parsing sender: {}", argv[5]);
                        process::exit(1);
                    }
                };
                let arguments: Vec<_> = argv[7..]
                    .iter()
                    .map(|argument| {
                        let mut argument_parsed = vm::parser::parse(argument)
                            .expect(&format!("Error parsing argument \"{}\"", argument));
                        if let Some(SymbolicExpression{ expr: SymbolicExpressionType::AtomValue(x),
                                                        id: _ }) = argument_parsed.pop() {
                            SymbolicExpression::atom_value(x.clone())
                        } else {
                            eprintln!("Unexpected result parsing argument: {}", argument);
                            process::exit(1);
                        }
                    })
                    .collect();

                let result = {
                    let mut env = vm_env.get_exec_environment(Some(sender));
                    env.execute_contract(&contract_name, &tx_name, &arguments)
                };
                match result {
                    Ok(x) => {
                        vm_env.commit();
                        println!("Transaction executed successfully! Output: {}", x);
                    },
                    Err(error) => println!("Transaction execution error: \n {}", error)
                }
                return
            },
            _ => {}
        }
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
