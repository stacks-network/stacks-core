use std::io;
use std::io::{Read, Write};
use std::fs;
use std::env;
use std::process;
use util::log;

use vm::parser::parse;
use vm::contexts::OwnedEnvironment;
use vm::database::{ContractDatabase, ContractDatabaseConnection, ContractDatabaseTransacter};
use vm::{SymbolicExpression, SymbolicExpressionType};
use vm::checker::{type_check, AnalysisDatabase, AnalysisDatabaseConnection};
use vm::types::Value;

use serde::Serialize;

fn print_usage(invoked_by: &str) {
    eprintln!("Usage: {} [command]
where command is one of:

  initialize         to initialize a local VM state database.
  mine_block         to simulated mining a new block.
  get_block_height   to print the simulated block height.
  check              to typecheck a potential contract definition.
  launch             to launch a initialize a new contract in the local state database.
  eval               to evaluate (in read-only mode) a program in a given contract context.
  eval_raw           to typecheck and evaluate an expression without a contract or database context.
  repl               to typecheck and evaluate expressions in a stdin/stdout loop.
  execute            to execute a public function of a defined contract.

", invoked_by);
    process::exit(1);
}

pub fn invoke_command(invoked_by: &str, args: &[String]) {
    if args.len() < 1 {
        print_usage(invoked_by)
    }

    match args[0].as_ref() {
        "initialize" => {
            if args.len() < 2 {
                eprintln!("Usage: {} {} [vm-state.db]", invoked_by, args[0]);
                process::exit(1);
            }
            AnalysisDatabaseConnection::initialize(&args[1]);
            match ContractDatabaseConnection::initialize(&args[1]) {
                Ok(_) => println!("Database created."),
                Err(error) => {
                    eprintln!("Initialization error: \n{}", error);
                    process::exit(1);
                }
            }
        },
        "mine_block" => {
            // TODO: add optional args for specifying timestamps and number of blocks to mine.
            if args.len() < 3 {
                eprintln!("Usage: {} {} [block time] [vm-state.db]", invoked_by, args[0]);
                process::exit(1);
            }

            let block_time: u64 = args[1].parse().expect("Failed to parse block time");

            let mut db = match ContractDatabaseConnection::open(&args[2]) {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let mut sp = db.begin_save_point();
            sp.sim_mine_block_with_time(block_time);
            sp.commit();
            println!("Simulated block mine!");
        },
        "get_block_height" => {
            if args.len() < 2 {
                eprintln!("Usage: {} {} [vm-state.db]", invoked_by, args[0]);
                process::exit(1);
            }

            let mut db = match ContractDatabaseConnection::open(&args[1]) {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let mut sp = db.begin_save_point();
            let mut blockheight = sp.get_simmed_block_height();
            match blockheight {
                Ok(x) => {
                    println!("Simulated block height: \n{}", x);
                },
                Err(error) => {
                    eprintln!("Program execution error: \n{}", error);
                    process::exit(1);
                }
            }
        },
        "check" => {
            if args.len() < 2 {
                eprintln!("Usage: {} {} [program-file.scm] (vm-state.db)", invoked_by, args[0]);
                process::exit(1);
            }
            
            let content: String = fs::read_to_string(&args[1])
                .expect(&format!("Error reading file: {}", args[1]));
            
            let mut db_conn = {
                if args.len() >= 3 {
                    AnalysisDatabaseConnection::open(&args[2])
                } else {
                    AnalysisDatabaseConnection::memory()
                }
            };
            
            let mut db = db_conn.begin_save_point();
            let mut ast = parse(&content).expect("Failed to parse program");
            let mut contract_analysis = type_check(&":transient:", &mut ast, &mut db, false).unwrap_or_else(|e| {
                eprintln!("Type check error.\n{}", e);
                process::exit(1);
            });

            match args.last() {
                Some(s) if s == "--output_analysis" => {
                    println!("{}", contract_analysis.serialize());
                },
                _ => {}
            }
        },
        "repl" => {
            let mut db_conn = match ContractDatabaseConnection::memory() {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let mut outer_sp = db_conn.begin_save_point_raw();                    
            let mut db = ContractDatabase::from_savepoint(outer_sp);

            let mut vm_env = OwnedEnvironment::new(&mut db);
            let mut exec_env = vm_env.get_exec_environment(None);

            let mut analysis_db_conn = AnalysisDatabaseConnection::memory();

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
                            process::exit(1);
                        }
                    }
                };

                let mut ast = match parse(&content) {
                    Ok(val) => val,
                    Err(error) => {
                        println!("Parse error:\n{}", error);
                        continue;
                    }
                };

                let mut analysis_db = analysis_db_conn.begin_save_point();
                match type_check(":transient:", &mut ast, &mut analysis_db, true) {
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
                io::stdin().read_to_string(&mut buffer)
                    .expect("Error reading from stdin.");
                buffer
            };

            let mut db_conn = match ContractDatabaseConnection::memory() {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let mut outer_sp = db_conn.begin_save_point_raw();                    
            let mut db = ContractDatabase::from_savepoint(outer_sp);
            let mut analysis_db_conn = AnalysisDatabaseConnection::memory();

            let mut vm_env = OwnedEnvironment::new(&mut db);

            let mut ast = parse(&content).expect("Failed to parse program.");
            let mut analysis_db = analysis_db_conn.begin_save_point();
            match type_check(":transient:", &mut ast, &mut analysis_db, true) {
                Ok(_) => {
                    let result = vm_env.get_exec_environment(None).eval_raw(&content);
                    match result {
                        Ok(x) => {
                            println!("Program executed successfully! Output: \n{}", x);
                        },
                        Err(error) => {
                            eprintln!("Program execution error: \n{}", error);
                            process::exit(1);
                        }
                    }
                },
                Err(error) => {
                    eprintln!("Type check error.\n{}", error);
                    process::exit(1);
                }
            }
        },
        "eval" => {
            if args.len() < 3 {
                eprintln!("Usage: {} {} [context-contract-name] (program.scm) [vm-state.db]", invoked_by, args[0]);
                process::exit(1);
            }

            let vm_filename = {
                if args.len() == 3 {
                    &args[2]
                } else {
                    &args[3]
                }
            };
            
            let mut db = match ContractDatabaseConnection::open(vm_filename) {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let content: String = {
                if args.len() == 3 {
                    let mut buffer = String::new();
                    io::stdin().read_to_string(&mut buffer)
                        .expect("Error reading from stdin.");
                    buffer
                } else {
                    fs::read_to_string(&args[2])
                        .expect(&format!("Error reading file: {}", args[2]))
                }
            };

            let mut vm_env = OwnedEnvironment::new(&mut db);
            let contract_name = &args[1];
            
            let result = vm_env.get_exec_environment(None)
                .eval_read_only(contract_name, &content);

            match result {
                Ok(x) => {
                    println!("Program executed successfully! Output: \n{}", x);
                },
                Err(error) => { 
                    eprintln!("Program execution error: \n{}", error);
                    process::exit(1);
                }
            }
        },
        "launch" => {
            if args.len() < 4 {
                eprintln!("Usage: {} {} [contract-name] [contract-definition.scm] [vm-state.db]", invoked_by, args[0]);
                process::exit(1);
            }
            let vm_filename = &args[3];

            let contract_name = &args[1];
            let contract_content: String = fs::read_to_string(&args[2])
                .expect(&format!("Error reading file: {}", args[2]));

            // typecheck and insert into typecheck tables
            // Aaron todo: AnalysisDatabase and ContractDatabase now use savepoints
            //     on the same connection, so they can abort together, _however_,
            //     this results in some pretty weird function interfaces. I'll need
            //     to think about whether or not there's a more ergonomic way to do this.


            let mut db_conn = match ContractDatabaseConnection::open(vm_filename) {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let mut outer_sp = db_conn.begin_save_point_raw();

            { 
                let mut analysis_db = AnalysisDatabase::from_savepoint(
                    outer_sp.savepoint().expect("Failed to initialize savepoint for analysis"));
                let mut ast = parse(&contract_content).expect("Failed to parse program.");

                type_check(contract_name, &mut ast, &mut analysis_db, true)
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
                Err(error) => {
                    eprintln!("Contract initialization error: \n{}", error);
                    process::exit(1);
                }
            }
        },
        "execute" => {
            if args.len() < 5 {
                eprintln!("Usage: {} {} [vm-state.db] [contract-name] [public-function-name] [sender-address] [args...]", invoked_by, args[0]);
                process::exit(1);
            }
            let vm_filename = &args[1];

            let mut db = match ContractDatabaseConnection::open(vm_filename) {
                Ok(db) => db,
                Err(error) => {
                    eprintln!("Could not open vm-state: \n{}", error);
                    process::exit(1);
                }
            };

            let mut vm_env = OwnedEnvironment::new(&mut db);
            let contract_name = &args[2];
            let tx_name = &args[3];
            
            let sender_in = &args[4];

            let mut sender = parse(&format!("'{}", sender_in))
                .expect(&format!("Error parsing sender {}", sender_in))
                .pop()
                .expect(&format!("Failed to read a sender from {}", sender_in));
            let sender = {
                if let Some(Value::Principal(principal_data)) = sender.match_atom_value() {
                    Value::Principal(principal_data.clone())
                } else {
                    eprintln!("Unexpected result parsing sender: {}", sender_in);
                    process::exit(1);
                }
            };
            let arguments: Vec<_> = args[5..]
                .iter()
                .map(|argument| {
                    let mut argument_parsed = parse(argument)
                        .expect(&format!("Error parsing argument \"{}\"", argument));
                    let argument_value = argument_parsed.pop()
                        .expect(&format!("Failed to parse a value from the argument: {}", argument));
                    let argument_value = argument_value
                        .match_atom_value()
                        .expect(&format!("Expected a literal value from the argument: {}", argument));
                    SymbolicExpression::atom_value(argument_value.clone())
                })
                .collect();

            let result = {
                let mut env = vm_env.get_exec_environment(Some(sender));
                env.execute_contract(&contract_name, &tx_name, &arguments)
            };
            match result {
                Ok(x) => {
                    if let Value::Response(data) = x {
                        vm_env.commit();
                        if data.committed {
                            println!("Transaction executed and committed. Returned: {}", data.data);
                        } else {
                            println!("Aborted: {}", data.data);
                        }
                    } else {
                        panic!(format!("Expected a bool result from transaction. Found: {}", x));
                    }
                },
                Err(error) => {
                    eprintln!("Transaction execution error: \n{}", error);
                    process::exit(1);
                }
            }
        },
        _ => {
            print_usage(invoked_by)
        }
    }
}
