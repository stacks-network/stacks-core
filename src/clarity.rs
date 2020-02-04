use rand::Rng;
use std::io;
use std::io::{Read, Write};
use std::fs;
use std::env;
use std::process;
use std::convert::TryInto;
use std::path::PathBuf;

use util::log;

use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::index::storage::{TrieFileStorage};

use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;

use util::db::FromColumn;

use vm::ast::parse;
use vm::contexts::OwnedEnvironment;
use vm::database::{ClarityDatabase, SqliteConnection,
                   MarfedKV, MemoryBackingStore, NULL_HEADER_DB};
use vm::errors::{InterpreterResult};
use vm::{SymbolicExpression, SymbolicExpressionType, Value};
use vm::analysis::{AnalysisDatabase, run_analysis};
use vm::analysis::contract_interface_builder::build_contract_interface;
use vm::analysis::types::ContractAnalysis;
use vm::types::{QualifiedContractIdentifier, PrincipalData};

use address::c32::c32_address;

use serde::Serialize;

#[cfg(test)]
macro_rules! panic_test {
    () => { panic!() }
}
#[cfg(not(test))]
macro_rules! panic_test {
    () => { process::exit(1) }
}

#[cfg_attr(tarpaulin, skip)]
fn print_usage(invoked_by: &str) {
    eprintln!("Usage: {} [command]
where command is one of:

  initialize         to initialize a local VM state database.
  check              to typecheck a potential contract definition.
  launch             to launch a initialize a new contract in the local state database.
  eval               to evaluate (in read-only mode) a program in a given contract context.
  eval_raw           to typecheck and evaluate an expression without a contract or database context.
  repl               to typecheck and evaluate expressions in a stdin/stdout loop.
  execute            to execute a public function of a defined contract.
  generate_address   to generate a random Stacks public address for testing purposes.
", invoked_by);
    panic_test!()
}

#[cfg_attr(tarpaulin, skip)]
fn friendly_expect<A,B: std::fmt::Display>(input: Result<A,B>, msg: &str) -> A {
    input.unwrap_or_else(|e| {
        eprintln!("{}\nCaused by: {}", msg, e);
        panic_test!();
    })
}

#[cfg_attr(tarpaulin, skip)]
fn friendly_expect_opt<A>(input: Option<A>, msg: &str) -> A {
    input.unwrap_or_else(|| {
        eprintln!("{}", msg);
        panic_test!();
    })
}

fn create_or_open_db(path: &String) -> Connection {
    let open_flags = match fs::metadata(path) {
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                // need to create 
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            }
            else {
                panic!("FATAL: could not stat {}", path);
            }
        },
        Ok(_md) => {
            // can just open 
            OpenFlags::SQLITE_OPEN_READ_WRITE
        }
    };

    let conn = friendly_expect(Connection::open_with_flags(path, open_flags), &format!("FATAL: failed to open '{}'", path));
    conn
}

fn get_cli_chain_tip(conn: &Connection) -> BlockHeaderHash {
    let mut stmt = friendly_expect(conn.prepare("SELECT block_hash FROM cli_chain_tips ORDER BY id DESC LIMIT 1"), "FATAL: could not prepare query");
    let mut rows = friendly_expect(stmt.query(NO_PARAMS), "FATAL: could not fetch rows");
    let mut hash_opt = None;
    while let Some(row_res) = rows.next() {
        match row_res {
            Ok(row) => {
                let bhh = friendly_expect(BlockHeaderHash::from_column(&row, "block_hash"), "FATAL: could not parse block hash");
                hash_opt = Some(bhh);
                break;
            },
            Err(e) => {
                panic!("FATAL: could not read block hash: {:?}", e);
            }
        }
    }
    match hash_opt {
        Some(bhh) => bhh,
        None => TrieFileStorage::block_sentinel()
    }
}

fn advance_cli_chain_tip(path: &String) -> (BlockHeaderHash, BlockHeaderHash) {
    let mut conn = create_or_open_db(path);
    let tx = friendly_expect(conn.transaction(), &format!("FATAL: failed to begin transaction on '{}'", path));

    friendly_expect(tx.execute("CREATE TABLE IF NOT EXISTS cli_chain_tips(id INTEGER PRIMARY KEY AUTOINCREMENT, block_hash TEXT UNIQUE NOT NULL);", NO_PARAMS),
                    &format!("FATAL: failed to create 'cli_chain_tips' table"));
   
    let parent_block_hash = get_cli_chain_tip(&tx);
    
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let next_block_hash  = friendly_expect_opt(BlockHeaderHash::from_bytes(&random_bytes),
                                              "Failed to generate random block header.");

    friendly_expect(tx.execute("INSERT INTO cli_chain_tips (block_hash) VALUES (?1)", &[&next_block_hash]), 
                    &format!("FATAL: failed to store next block hash in '{}'", path));

    friendly_expect(tx.commit(), &format!("FATAL: failed to commit new chain tip to '{}'", path));

    (parent_block_hash, next_block_hash)
}

// This function is pretty weird! But it helps cut down on
//   repeating a lot of block initialization for the simulation commands.
fn in_block<F,R>(db_path: &String, mut marf_kv: MarfedKV, f: F) -> R
where F: FnOnce(MarfedKV) -> (MarfedKV, R) {

    // store CLI data alongside the MARF database state
    let mut cli_db_path_buf = PathBuf::from(db_path);
    cli_db_path_buf.push("cli.sqlite");
    let cli_db_path = cli_db_path_buf
        .to_str()
        .expect(&format!("FATAL: failed to convert '{}' to a string", db_path))
        .to_string();

    // need to load the last block 
    let (from, to) = advance_cli_chain_tip(&cli_db_path);
    marf_kv.begin(&from, &to);
    let (mut marf_return, result) = f(marf_kv);
    marf_return.commit_to(&to);
    result
}

// like in_block, but does _not_ advance the chain tip.  Used for read-only queries against the
// chain tip itself.
fn at_chaintip<F,R>(db_path: &String, mut marf_kv: MarfedKV, f: F) -> R
where F: FnOnce(MarfedKV) -> (MarfedKV, R) {

    // store CLI data alongside the MARF database state
    let mut cli_db_path_buf = PathBuf::from(db_path);
    cli_db_path_buf.push("cli.sqlite");
    let cli_db_path = cli_db_path_buf
        .to_str()
        .expect(&format!("FATAL: failed to convert '{}' to a string", db_path))
        .to_string();

    let cli_db_conn = create_or_open_db(&cli_db_path);
    let from = get_cli_chain_tip(&cli_db_conn);
    let to = BlockHeaderHash([2u8; 32]);        // 0x0202020202 ... (pattern not used anywhere else) 

    marf_kv.begin(&from, &to);
    let (mut marf_return, result) = f(marf_kv);
    marf_return.rollback();
    result
}

pub fn invoke_command(invoked_by: &str, args: &[String]) {
    if args.len() < 1 {
        print_usage(invoked_by)
    }

    match args[0].as_ref() {
        "initialize" => {
            if args.len() < 2 {
                eprintln!("Usage: {} {} [vm-state.db]", invoked_by, args[0]);
                panic_test!();
            }

            let marf_kv = friendly_expect(MarfedKV::open(&args[1], None), "Failed to open VM database.");
            in_block(&args[1], marf_kv, |mut kv| {
                { let mut db = kv.as_clarity_db(&NULL_HEADER_DB);
                  db.initialize() };
                (kv, ())
            });
            println!("Database created.");
        },
        "generate_address" => {
            // random 20 bytes
            let random_bytes = rand::thread_rng().gen::<[u8; 20]>();
            // version = 22
            let addr = friendly_expect(c32_address(22, &random_bytes), "Failed to generate address");
            println!("{}", addr);
        },
        "check" => {
            if args.len() < 2 {
                eprintln!("Usage: {} {} [program-file.clar] (vm-state.db)", invoked_by, args[0]);
                panic_test!();
            }

            let contract_id = QualifiedContractIdentifier::transient();

            let content: String = friendly_expect(fs::read_to_string(&args[1]),
                                                  &format!("Error reading file: {}", args[1]));

            let mut ast = friendly_expect(parse(&contract_id, &content), "Failed to parse program");

            let contract_analysis = {
                if args.len() >= 3 {
                    // use a persisted marf
                    let marf_kv = friendly_expect(MarfedKV::open(&args[2], None), "Failed to open VM database.");
                    let result = at_chaintip(
                        &args[2],
                        marf_kv,
                        |mut marf| {
                            let result = { let mut db = AnalysisDatabase::new(&mut marf);
                                           run_analysis(&contract_id, &mut ast, &mut db, false) };
                            (marf, result)
                        });
                    result
                } else {
                    let mut analysis_marf = MemoryBackingStore::new();
                    let mut db = analysis_marf.as_analysis_db();
                    run_analysis(&contract_id, &mut ast, &mut db, false)
                }
            }.unwrap_or_else(|e| {
                println!("{}", &e.diagnostic);
                panic_test!();
            });

            match args.last() {
                Some(s) if s == "--output_analysis" => {
                    println!("{}", build_contract_interface(&contract_analysis).serialize());
                },
                _ => {
                    println!("Checks passed.");
                }
            }
        },
        "repl" => {
            let mut marf = MemoryBackingStore::new();
            let mut vm_env = OwnedEnvironment::new(marf.as_clarity_db());
            let mut exec_env = vm_env.get_exec_environment(None);

            let mut analysis_marf = MemoryBackingStore::new();
            let mut analysis_db = analysis_marf.as_analysis_db();

            let contract_id = QualifiedContractIdentifier::transient();

            let mut stdout = io::stdout();

            loop {
                let content: String = {
                    let mut buffer = String::new();
                    stdout.write(b"> ").unwrap_or_else(|e| {
                        panic!("Failed to write stdout prompt string:\n{}", e);
                    });
                    stdout.flush().unwrap_or_else(|e| {
                        panic!("Failed to flush stdout prompt string:\n{}", e);
                    });
                    match io::stdin().read_line(&mut buffer) {
                        Ok(_) => buffer,
                        Err(error) => {
                            eprintln!("Error reading from stdin:\n{}", error);
                            panic_test!();
                        }
                    }
                };

                let mut ast = match parse(&contract_id, &content) {
                    Ok(val) => val,
                    Err(error) => {
                        println!("Parse error:\n{}", error);
                        continue;
                    }
                };

                match run_analysis(&contract_id, &mut ast, &mut analysis_db, true) {
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
        "eval_raw" => {
            let content: String = {
                let mut buffer = String::new();
                friendly_expect(io::stdin().read_to_string(&mut buffer), "Error reading from stdin.");
                buffer
            };

            let mut analysis_marf = MemoryBackingStore::new();
            let mut analysis_db = analysis_marf.as_analysis_db();

            let mut marf = MemoryBackingStore::new();
            let mut vm_env = OwnedEnvironment::new(marf.as_clarity_db());
 
            
            let contract_id = QualifiedContractIdentifier::transient(); 
            
            let mut ast = friendly_expect(parse(&contract_id, &content), "Failed to parse program.");
            match run_analysis(&contract_id, &mut ast, &mut analysis_db, true) {
                Ok(_) => {
                    let result = vm_env.get_exec_environment(None).eval_raw(&content);
                    match result {
                        Ok(x) => {
                            println!("Program executed successfully! Output: \n{}", x);
                        },
                        Err(error) => {
                            eprintln!("Program execution error: \n{}", error);
                            panic_test!();
                        }
                    }
                },
                Err(error) => {
                    eprintln!("Type check error.\n{}", error);
                    panic_test!();
                }
            }
        },
        "eval" => {
            if args.len() < 3 {
                eprintln!("Usage: {} {} [contract-identifier] (program.clar) [vm-state.db]", invoked_by, args[0]);
                panic_test!();
            }

            let vm_filename = 
                if args.len() == 3 {
                    &args[2]
                } else {
                    &args[3]
                };



            let content: String = {
                if args.len() == 3 {
                    let mut buffer = String::new();
                    friendly_expect(io::stdin().read_to_string(&mut buffer),
                                    "Error reading from stdin.");
                    buffer
                } else {
                    friendly_expect(fs::read_to_string(&args[2]),
                                    &format!("Error reading file: {}", args[2]))
                }
            };

            let contract_identifier = friendly_expect(QualifiedContractIdentifier::parse(&args[1]), "Failed to parse contract identifier.");

            let marf_kv = friendly_expect(MarfedKV::open(vm_filename, None), "Failed to open VM database.");
            let result = in_block(vm_filename, marf_kv, |mut marf| {
                let result = {
                    let db = marf.as_clarity_db(&NULL_HEADER_DB);
                    let mut vm_env = OwnedEnvironment::new(db);
                    vm_env.get_exec_environment(None)
                        .eval_read_only(&contract_identifier, &content)
                };
                (marf, result)
            });

            match result {
                Ok(x) => {
                    println!("Program executed successfully! Output: \n{}", x);
                },
                Err(error) => { 
                    eprintln!("Program execution error: \n{}", error);
                    panic_test!();
                }
            }
        },
        "launch" => {
            if args.len() < 4 {
                eprintln!("Usage: {} {} [contract-identifier] [contract-definition.clar] [vm-state.db]", invoked_by, args[0]);
                panic_test!();
            }
            let vm_filename = &args[3];

            let contract_identifier = friendly_expect(QualifiedContractIdentifier::parse(&args[1]), "Failed to parse contract identifier.");

            let contract_content: String = friendly_expect(fs::read_to_string(&args[2]),
                                                           &format!("Error reading file: {}", args[2]));

            let mut ast = friendly_expect(parse(&contract_identifier, &contract_content), "Failed to parse program.");
            let marf_kv = friendly_expect(MarfedKV::open(vm_filename, None), "Failed to open VM database.");
            let result = in_block(
                vm_filename,
                marf_kv,
                |mut marf| {
                    let analysis_result = { 
                        let mut db = AnalysisDatabase::new(&mut marf);
                        
                        run_analysis(&contract_identifier, &mut ast, &mut db, true)
                    };

                    match analysis_result {
                        Err(e) => (marf, Err(e)),
                        Ok(analysis) => {
                            let result = {
                                let db = marf.as_clarity_db(&NULL_HEADER_DB);
                                let mut vm_env = OwnedEnvironment::new(db);
                                vm_env.initialize_contract(contract_identifier, &contract_content)
                            };
                            (marf, Ok((analysis, result)))
                        }
                    }
                });

            match result {
                Ok((contract_analysis, Ok(_x))) => {
                    match args.last() {
                        Some(s) if s == "--output_analysis" => {
                            println!("{}", build_contract_interface(&contract_analysis).serialize());
                        },
                        _ => {
                            println!("Contract initialized!");
                        }
                    }
                },
                Err(error) => {
                    eprintln!("Contract initialization error: \n{}", error);
                    panic_test!();
                },
                Ok((_, Err(error))) => {
                    eprintln!("Contract initialization error: \n{}", error);
                    panic_test!();
                }
            }
        },
        "execute" => {
            if args.len() < 5 {
                eprintln!("Usage: {} {} [vm-state.db] [contract-identifier] [public-function-name] [sender-address] [args...]", invoked_by, args[0]);
                panic_test!();
            }
            let vm_filename = &args[1];
            let marf_kv = friendly_expect(MarfedKV::open(vm_filename, None), "Failed to open VM database.");

            let contract_identifier = friendly_expect(QualifiedContractIdentifier::parse(&args[2]), "Failed to parse contract identifier.");

            let tx_name = &args[3];            
            let sender_in = &args[4];

            let sender = {
                if let Ok(sender) = PrincipalData::parse_standard_principal(sender_in) {
                    PrincipalData::Standard(sender.clone())
                } else {
                    eprintln!("Unexpected result parsing sender: {}", sender_in);
                    panic_test!();
                }
            };

            let arguments: Vec<_> = args[5..]
                .iter()
                .map(|argument| {
                    let mut argument_parsed = friendly_expect(
                        parse(&contract_identifier, argument),
                        &format!("Error parsing argument \"{}\"", argument));
                    let argument_value = friendly_expect_opt(
                        argument_parsed.pop(),
                        &format!("Failed to parse a value from the argument: {}", argument));
                    let argument_value = friendly_expect_opt(
                        argument_value.match_literal_value(),
                        &format!("Expected a literal value from the argument: {}", argument));
                    SymbolicExpression::atom_value(argument_value.clone())
                })
                .collect();

            let result = in_block(vm_filename, marf_kv, |mut marf| {
                let result = {
                    let db = marf.as_clarity_db(&NULL_HEADER_DB);
                    let mut vm_env = OwnedEnvironment::new(db);
                    vm_env.execute_transaction(Value::Principal(sender), contract_identifier, &tx_name, &arguments) };
                (marf, result)
            });

            match result {
                Ok((x, _)) => {
                    if let Value::Response(data) = x {
                        if data.committed {
                            println!("Transaction executed and committed. Returned: {}", data.data);
                        } else {
                            println!("Aborted: {}", data.data);
                        }
                    } else {
                        panic!(format!("Expected a ResponseType result from transaction. Found: {}", x));
                    }
                },
                Err(error) => {
                    eprintln!("Transaction execution error: \n{}", error);
                    panic_test!();
                }
            }
        },
        _ => {
            print_usage(invoked_by)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_samples() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().gen::<i32>());
        
        eprintln!("initialize");
        invoke_command("test", &["initialize".to_string(), db_name.clone()]);

        eprintln!("check tokens");
        invoke_command("test", &["check".to_string(), "sample-programs/tokens.clar".to_string()]);
        
        eprintln!("check tokens");
        invoke_command("test", &["check".to_string(), "sample-programs/tokens.clar".to_string(), db_name.clone()]);
        
        eprintln!("launch tokens");
        invoke_command("test", &["launch".to_string(), "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                                 "sample-programs/tokens.clar".to_string(), db_name.clone()]);

        eprintln!("check names");
        invoke_command("test", &["check".to_string(), "sample-programs/names.clar".to_string(), db_name.clone()]);

        eprintln!("launch names");
        invoke_command("test", &["launch".to_string(), "S1G2081040G2081040G2081040G208105NK8PE5.names".to_string(),
                                 "sample-programs/names.clar".to_string(), db_name.clone()]);

        eprintln!("execute tokens");
        invoke_command("test", &["execute".to_string(), db_name.clone(), "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                                 "mint!".to_string(), "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR".to_string(),
                                 "u1000".to_string()]);
    }
}
