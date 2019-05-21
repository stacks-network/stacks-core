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
extern crate linefeed;
extern crate getopts;

#[macro_use] extern crate serde_derive;

#[macro_use] mod util;
mod burnchains;
mod chainstate;
mod core;
mod vm;
use vm::database::{ContractDatabase, ContractDatabaseConnection};
mod address;

use std::fs;
use std::env;
use std::process;
use std::string::String;

use util::log;

use getopts::Options;

// TODO: Move arg parsing structs and impls into another file.
struct LocalArgParseResult {
    pub matches: getopts::Matches,
}

impl LocalArgParseResult {
    pub fn get_required<T>(&self, name: &str) -> T
    where T: std::str::FromStr, <T as std::str::FromStr>::Err: std::fmt::Display
    {
        match self.get_optional(name) {
            Some(result) => result,
            None => panic!("Required argument not provided '{}'", name)
        }
    }

    pub fn get_optional<T>(&self, name: &str) -> Option<T>
    where T: std::str::FromStr, <T as std::str::FromStr>::Err: std::fmt::Display
    {
        match self.matches.opt_get(name) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("Failed to parse arg '{}'\n{}", name, error);
                process::exit(1);
            },
        }
    }

    pub fn flag_exists(&self, name: &str) -> bool {
        return self.matches.opt_present(name);
    }
}

struct LocalArgParser<'a> {
    pub opts: Options,
    usage_brief: String,
    program_args: &'a [String],
}

impl<'a> LocalArgParser<'a> {
    fn new(usage_brief: String, program_args: &[String]) -> LocalArgParser {
        LocalArgParser {
            opts: Options::new(),
            usage_brief: usage_brief,
            program_args: program_args,
        }
    }

    fn add_data_opt(&mut self, required: bool) {
        if required {
            self.opts.reqopt("d", "data", "database file path", "DATA_FILE");
        } else {
            self.opts.optopt("d", "data", "database file path", "DATA_FILE");
        }
    }

    fn parse(&mut self) -> LocalArgParseResult {
        let matches = match self.opts.parse(self.program_args) {
            Ok(val) => val,
            Err(error) => {
                eprintln!("{}\n{}", self.opts.usage(&self.usage_brief.to_string()), error);
                process::exit(1);
            }
        };
        return LocalArgParseResult {
            matches: matches
        };
    }
}

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
        let local_usage_brief = "Usage: local [command]
where command is one of:

  initialize         to initialize a local VM state database.
  mine_block         to simulated mining a new block.
  get_block_height   to print the simulated block height.
  check              to typecheck a potential contract definition.
  launch             to launch a initialize a new contract in the local state database.
  eval               to evaluate (in read-only mode) a program in a given contract context.
  execute            to execute a public function of a defined contract.
";

        use std::io;
        use std::io::Read;
        use vm::parser::parse;
        use vm::contexts::OwnedEnvironment;
        use vm::database::{ContractDatabase, ContractDatabaseConnection, ContractDatabaseTransacter};
        use vm::{SymbolicExpression, SymbolicExpressionType};
        use vm::checker::{type_check, AnalysisDatabase, AnalysisDatabaseConnection};
        use vm::types::Value;

        let cmd_arg = &argv[2];
        let usage_brief = format!("Usage: local {}", cmd_arg);
        let mut arg_parser = LocalArgParser::new(usage_brief, &argv[2..]);

        match cmd_arg.as_ref() {
            "initialize" => {
                arg_parser.add_data_opt(true);
                let args = arg_parser.parse();
                let db = args.get_required::<String>("data");
                ContractDatabaseConnection::initialize(&db).unwrap_or_else(|error| {
                    eprintln!("Initialization error: \n{}", error);
                    process::exit(1);
                });
                AnalysisDatabaseConnection::initialize(&db);
                println!("Database created.");
                return
            },
            "mine_blocks" => {
                arg_parser.add_data_opt(true);
                arg_parser.opts.reqopt("c", "count", "block count", "COUNT");
                let args = arg_parser.parse();
                let count = args.get_required::<u32>("count");
                let db_arg = args.get_required::<String>("data");
                let mut db_conn = match ContractDatabaseConnection::open(&db_arg) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n{}", error);
                        process::exit(1);
                    }
                };
                let mut sp = db_conn.begin_save_point();
                sp.sim_mine_blocks(count);
                sp.commit();
                println!("Simulated block mine!");
                return
            },
            "mine_block" => {
                arg_parser.add_data_opt(true);
                arg_parser.opts.optopt("t", "time", "block timestamp", "TIME");
                let args = arg_parser.parse();
                let time_opt = args.get_optional::<u64>("time");
                let db_arg = args.get_required::<String>("data");
                let mut db_conn = match ContractDatabaseConnection::open(&db_arg) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n{}", error);
                        process::exit(1);
                    }
                };

                let mut sp = db_conn.begin_save_point();
                match time_opt {
                    Some(time) => {
                        sp.sim_mine_block_with_time(time);
                    },
                    None => {
                        sp.sim_mine_block();
                    }
                }

                sp.commit();
                println!("Simulated block mine!");
                return
            }
            "get_block_height" => {
                arg_parser.add_data_opt(true);
                let args = arg_parser.parse();
                let db_arg = args.get_required::<String>("data");
                let mut db_conn = match ContractDatabaseConnection::open(&db_arg) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n{}", error);
                        process::exit(1);
                    }
                };
                let mut sp = db_conn.begin_save_point();
                let mut block_height = sp.get_simmed_block_height();
                match block_height {
                    Ok(x) => {
                        println!("Simulated block height: \n{}", x);
                    },
                    Err(error) => {
                        eprintln!("Program execution error: \n{}", error);
                        process::exit(1);
                    }
                }
                return
            }
            "check" => {
                arg_parser.add_data_opt(false);
                arg_parser.opts.reqopt("f", "file", "contract definition file", "CONTRACT FILE");
                arg_parser.opts.optflag("a", "analysis", "output analysis");
                let args = arg_parser.parse();
                let (mut db_conn, mut analysis_db_conn) = match args.get_optional::<String>("data") {
                    Some(db_arg) => {
                        let db = ContractDatabaseConnection::open(&db_arg).unwrap_or_else(|error| {
                            eprintln!("Could not open vm-state: \n{}", error);
                            process::exit(1);
                        });
                        // TODO: This creates 2 sqlite connections to the same file.. fix after a AnalysisDatabaseConnection refactor.
                        let analysis_db = AnalysisDatabaseConnection::open(&db_arg);
                        (db, analysis_db)
                    },
                    None => {
                        let db = ContractDatabaseConnection::memory().unwrap();
                        let analysis_db = AnalysisDatabaseConnection::memory();
                        (db, analysis_db)
                    }
                };
                let contract_file = args.get_required::<String>("file");

                let content: String = fs::read_to_string(&contract_file)
                    .expect(&format!("Error reading file: {}", contract_file.to_string()));
                
                let mut analysis_db_sp = analysis_db_conn.begin_save_point();
                let mut ast = parse(&content).expect("Failed to parse program");
                let mut contract_analysis = type_check(&"transient", &mut ast, &mut analysis_db_sp, false).unwrap_or_else(|e| {
                    eprintln!("Type check error.\n{}", e);
                    process::exit(1);
                });

                if args.flag_exists("analysis") {
                    println!("{}", contract_analysis.serialize());
                }
                
                return
            },
            "repl" => {
                arg_parser.add_data_opt(false);
                let args = arg_parser.parse();

                let (mut db_conn, mut analysis_db_conn) = match args.get_optional::<String>("data") {
                    Some(db_arg) => {
                        let db = ContractDatabaseConnection::open(&db_arg).unwrap_or_else(|error| {
                            eprintln!("Could not open vm-state: \n{}", error);
                            process::exit(1);
                        });
                        // TODO: This creates 2 sqlite connections to the same file.. fix after a AnalysisDatabaseConnection refactor.
                        let analysis_db = AnalysisDatabaseConnection::open(&db_arg);
                        (db, analysis_db)
                    },
                    None => {
                        let db = ContractDatabaseConnection::memory().unwrap();
                        let analysis_db = AnalysisDatabaseConnection::memory();
                        (db, analysis_db)
                    }
                };

                let mut outer_sp = db_conn.begin_save_point_raw();                    
                let mut db = ContractDatabase::from_savepoint(outer_sp);

                let mut vm_env = OwnedEnvironment::new(&mut db);
                let mut exec_env = vm_env.get_exec_environment(None);

                let mut reader = match linefeed::Interface::new("local-repl") {
                    Ok(r) => r,
                    Err(error) => panic!("Could not create linefeed: \n{}", error)
                };

                reader.set_report_signal(linefeed::Signal::Break, true);
                reader.set_report_signal(linefeed::Signal::Continue, true);
                reader.set_report_signal(linefeed::Signal::Interrupt, true);
                reader.set_report_signal(linefeed::Signal::Suspend, true);
                reader.set_report_signal(linefeed::Signal::Quit, true);
                
                match reader.set_prompt("> ") {
                    Ok(r) => r,
                    Err(error) => panic!("Could not create linefeed: \n{}", error)
                };

                loop {
                    let content = match reader.read_line() {
                        Ok(result) => match result {
                            linefeed::ReadResult::Input(input) => input,
                            linefeed::ReadResult::Signal(_) => process::exit(0),
                            linefeed::ReadResult::Eof => process::exit(0),
                        },
                        Err(error) => panic!("Could not read line: \n{}", error)
                    };
                    
                    if !content.trim().is_empty() {
                        reader.add_history_unique(content.clone());
                    }
                    
                    let mut ast = match parse(&content) {
                        Ok(val) => val,
                        Err(error) => {
                            println!("Parse error:\n{}", error);
                            continue;
                        }
                    };

                    let mut analysis_db = analysis_db_conn.begin_save_point();
                    match type_check("transient", &mut ast, &mut analysis_db, true) {
                        Ok(_) => (),
                        Err(error) => {
                            println!("Type check error:\n{}", error);
                            continue;
                        } 
                    }

                    let eval_result = match exec_env.eval_raw(&content) {
                        Ok(val) => val,
                        Err(error) => {
                            println!("Execution error:\n{}", error);
                            continue;
                        }
                    };
                    
                    println!("{}", eval_result);
                }
            },
            "eval" => {
                arg_parser.add_data_opt(false);
                arg_parser.opts.optopt("c", "contract", "contract name", "CONTRACT NAME");
                arg_parser.opts.optopt("f", "file", "program file", "PROGRAM FILE");
                let args = arg_parser.parse();
                let (mut db_conn, mut analysis_db_conn) = match args.get_optional::<String>("data") {
                    Some(db_arg) => {
                        let db = ContractDatabaseConnection::open(&db_arg).unwrap_or_else(|error| {
                            eprintln!("Could not open vm-state: \n{}", error);
                            process::exit(1);
                        });
                        // TODO: This creates 2 sqlite connections to the same file.. fix after a AnalysisDatabaseConnection refactor.
                        let analysis_db = AnalysisDatabaseConnection::open(&db_arg);
                        (db, analysis_db)
                    },
                    None => {
                        let db = ContractDatabaseConnection::memory().unwrap();
                        let analysis_db = AnalysisDatabaseConnection::memory();
                        (db, analysis_db)
                    }
                };

                let content: String = {
                    match args.get_optional::<String>("file") {
                        Some(content_arg) => {
                            fs::read_to_string(&content_arg)
                                .expect(&format!("Error reading file: {}", content_arg))
                        },
                        None => {
                            let mut buffer = String::new();
                            io::stdin().read_to_string(&mut buffer)
                                .expect("Error reading from stdin.");
                            buffer
                        }
                    }
                };
                
                let mut ast = match parse(&content) {
                    Ok(val) => val,
                    Err(error) => {
                        eprintln!("Parse error:\n{}", error);
                        process::exit(1);
                    }
                };

                // TODO: perform type checking
                /*
                match type_check("transient", &mut ast, &mut analysis_db, false) {
                    Ok(_) => (),
                    Err(error) => {
                        eprintln!("Type check error:\n{}", error);
                        process::exit(1);
                    } 
                };
                */

                let mut vm_env = OwnedEnvironment::new(&mut db_conn);
                let contract_opt = args.get_optional::<String>("contract");
                let result = match contract_opt {
                    Some(contract_name) => {
                        vm_env.get_exec_environment(None).eval_read_only(&contract_name, &content)
                    },
                    None => {
                        vm_env.get_exec_environment(None).eval_raw(&content)
                    }
                };

                match result {
                    Ok(x) => {
                        println!("Program executed successfully! Output: \n{}", x);
                    },
                    Err(error) => { 
                        eprintln!("Program execution error: \n{}", error);
                        process::exit(1);
                    }
                }
                return
            }
            "launch" => {
                arg_parser.add_data_opt(true);
                arg_parser.opts.reqopt("c", "contract", "contract name", "CONTRACT NAME");
                arg_parser.opts.reqopt("f", "file", "contract definition file", "CONTRACT FILE");
                let args = arg_parser.parse();
                let db_arg = args.get_required::<String>("data");
                let mut db_conn = match ContractDatabaseConnection::open(&db_arg) {
                    Ok(db_conn) => db_conn,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n{}", error);
                        process::exit(1);
                    }
                };

                let contract_name = args.get_required::<String>("contract");
                let file_arg = args.get_required::<String>("file");
                let contract_content: String = fs::read_to_string(&file_arg)
                    .expect(&format!("Error reading file: {}", file_arg));

                // Aaron todo: AnalysisDatabase and ContractDatabase now use savepoints
                //     on the same connection, so they can abort together, _however_,
                //     this results in some pretty weird function interfaces. I'll need
                //     to think about whether or not there's a more ergonomic way to do this.


                let mut outer_sp = db_conn.begin_save_point_raw();

                { 
                    let mut analysis_db = AnalysisDatabase::from_savepoint(
                        outer_sp.savepoint().expect("Failed to initialize savepoint for analysis"));
                    
                    let mut ast = match parse(&contract_content) {
                        Ok(val) => val,
                        Err(error) => {
                            eprintln!("Parse error:\n{}", error);
                            process::exit(1);
                        }
                    };

                    type_check(&contract_name, &mut ast, &mut analysis_db, true)
                        .unwrap_or_else(|e| {
                            eprintln!("Type check error.\n{}", e);
                            process::exit(1);
                        });

                    analysis_db.commit()
                }
                
                let mut db = ContractDatabase::from_savepoint(outer_sp);

                let result = {
                    let mut vm_env = OwnedEnvironment::new(&mut db);
                    let result = {
                        let mut env = vm_env.get_exec_environment(None);                        
                        env.initialize_contract(&contract_name, &contract_content)
                    };
                    if result.is_ok() {
                        vm_env.commit();
                    }
                    result
                };

                match result {
                    Ok(_x) => {
                        db.commit();
                        println!("Contract initialized!");
                    },
                    Err(error) => println!("Contract initialization error: \n{}", error)
                }
                return
            },
            "execute" => {

                arg_parser.add_data_opt(true);
                arg_parser.opts.reqopt("c", "contract", "contract name", "CONTRACT NAME");
                arg_parser.opts.reqopt("f", "function", "public function name", "FUNCTION NAME");
                arg_parser.opts.reqopt("s", "sender", "sender address", "SENDER ADDRESS");
                arg_parser.opts.optmulti("a", "args", "function args", "FUNCTION ARGS");
                let args = arg_parser.parse();
                let db_arg = args.get_required::<String>("data");
                let mut db_conn = match ContractDatabaseConnection::open(&db_arg) {
                    Ok(db_conn) => db_conn,
                    Err(error) => {
                        eprintln!("Could not open vm-state: \n{}", error);
                        process::exit(1);
                    }
                };

                let mut vm_env = OwnedEnvironment::new(&mut db_conn);
                let contract_name = args.get_required::<String>("contract");
                let tx_name = args.get_required::<String>("function");
                
                let sender_in = args.get_required::<String>("sender");

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
                let arguments: Vec<_> = args.matches.opt_strs("args")
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

                // TODO: should this perform type checking?

                let result = {
                    let mut env = vm_env.get_exec_environment(Some(sender));
                    env.execute_contract(&contract_name, &tx_name, &arguments)
                };
                match result {
                    Ok(x) => {
                        if let Value::Bool(x) = x {
                            vm_env.commit();
                            if x {
                                println!("Transaction executed and committed.");
                            } else {
                                println!("Aborted: Transaction returned false.");
                            }
                        } else {
                            panic!(format!("Expected a bool result from transaction. Found: {}", x));
                        }
                    },
                    Err(error) => println!("Transaction execution error: \n{}", error),
                }
                return
            },
            _ => {
                eprintln!("{}", local_usage_brief);
                process::exit(1);
            },
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
