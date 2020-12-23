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

use rand::Rng;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process;

use util::log;

use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::index::{storage::TrieFileStorage, MarfTrieId};
use chainstate::stacks::StacksBlockId;

use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};

use util::db::FromColumn;

use util::hash::Sha512Trunc256Sum;

use vm::analysis;
use vm::analysis::contract_interface_builder::build_contract_interface;
use vm::analysis::{errors::CheckResult, AnalysisDatabase, ContractAnalysis};
use vm::ast::build_ast;
use vm::contexts::OwnedEnvironment;
use vm::costs::LimitedCostTracker;
use vm::database::{
    ClarityDatabase, HeadersDB, MarfedKV, MemoryBackingStore, STXBalance, SqliteConnection,
    NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use vm::errors::{Error, InterpreterResult, RuntimeErrorType};
use vm::types::{PrincipalData, QualifiedContractIdentifier};
use vm::{execute as vm_execute, SymbolicExpression, SymbolicExpressionType, Value};

use address::c32::c32_address;

use burnchains::BurnchainHeaderHash;
use chainstate::burn::VRFSeed;
use chainstate::stacks::StacksAddress;

use serde::Serialize;

use crate::vm::database::marf::WritableMarfStore;

#[cfg(test)]
macro_rules! panic_test {
    () => {
        panic!()
    };
}
#[cfg(not(test))]
macro_rules! panic_test {
    () => {
        process::exit(1)
    };
}

#[cfg_attr(tarpaulin, skip)]
fn print_usage(invoked_by: &str) {
    eprintln!(
        "Usage: {} [command]
where command is one of:

  initialize         to initialize a local VM state database.
  check              to typecheck a potential contract definition.
  launch             to launch a initialize a new contract in the local state database.
  eval               to evaluate (in read-only mode) a program in a given contract context.
  eval_at_chaintip   like `eval`, but does not advance to a new block.
  eval_at_block      like `eval_at_chaintip`, but accepts a index-block-hash to evaluate at,
                     must be passed eval string via stdin.
  eval_raw           to typecheck and evaluate an expression without a contract or database context.
  repl               to typecheck and evaluate expressions in a stdin/stdout loop.
  execute            to execute a public function of a defined contract.
  generate_address   to generate a random Stacks public address for testing purposes.
",
        invoked_by
    );
    panic_test!()
}

#[cfg_attr(tarpaulin, skip)]
fn friendly_expect<A, B: std::fmt::Display>(input: Result<A, B>, msg: &str) -> A {
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

struct EvalInput {
    marf_kv: MarfedKV,
    contract_identifier: QualifiedContractIdentifier,
    content: String,
}

fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
) -> Result<Vec<SymbolicExpression>, Error> {
    let ast = build_ast(contract_identifier, source_code, &mut ())
        .map_err(|e| RuntimeErrorType::ASTError(e))?;
    Ok(ast.expressions)
}

fn run_analysis(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    save_contract: bool,
) -> CheckResult<ContractAnalysis> {
    analysis::run_analysis(
        contract_identifier,
        expressions,
        analysis_db,
        save_contract,
        LimitedCostTracker::new_free(),
    )
    .map_err(|(e, _)| e)
}

fn create_or_open_db(path: &String) -> Connection {
    let open_flags = match fs::metadata(path) {
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                // need to create
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                panic!("FATAL: could not stat {}", path);
            }
        }
        Ok(_md) => {
            // can just open
            OpenFlags::SQLITE_OPEN_READ_WRITE
        }
    };

    let conn = friendly_expect(
        Connection::open_with_flags(path, open_flags),
        &format!("FATAL: failed to open '{}'", path),
    );
    conn
}

fn get_cli_chain_tip(conn: &Connection) -> StacksBlockId {
    let mut stmt = friendly_expect(
        conn.prepare("SELECT block_hash FROM cli_chain_tips ORDER BY id DESC LIMIT 1"),
        "FATAL: could not prepare query",
    );
    let mut rows = friendly_expect(stmt.query(NO_PARAMS), "FATAL: could not fetch rows");
    let mut hash_opt = None;
    while let Some(row_res) = rows.next() {
        match row_res {
            Ok(row) => {
                let bhh = friendly_expect(
                    StacksBlockId::from_column(&row, "block_hash"),
                    "FATAL: could not parse block hash",
                );
                hash_opt = Some(bhh);
                break;
            }
            Err(e) => {
                panic!("FATAL: could not read block hash: {:?}", e);
            }
        }
    }
    match hash_opt {
        Some(bhh) => bhh,
        None => StacksBlockId::sentinel(),
    }
}

fn get_cli_block_height(conn: &Connection, block_id: &StacksBlockId) -> Option<u64> {
    let mut stmt = friendly_expect(
        conn.prepare("SELECT id FROM cli_chain_tips WHERE block_hash = ?1"),
        "FATAL: could not prepare query",
    );
    let mut rows = friendly_expect(stmt.query(&[block_id]), "FATAL: could not fetch rows");
    let mut row_opt = None;
    while let Some(row_res) = rows.next() {
        match row_res {
            Ok(row) => {
                let rowid = friendly_expect(
                    u64::from_column(&row, "id"),
                    "FATAL: could not parse row ID",
                );
                row_opt = Some(rowid);
                break;
            }
            Err(e) => {
                panic!("FATAL: could not read block hash: {:?}", e);
            }
        }
    }
    row_opt
}

fn advance_cli_chain_tip(path: &String) -> (StacksBlockId, StacksBlockId) {
    let mut conn = create_or_open_db(path);
    let tx = friendly_expect(
        conn.transaction(),
        &format!("FATAL: failed to begin transaction on '{}'", path),
    );

    friendly_expect(tx.execute("CREATE TABLE IF NOT EXISTS cli_chain_tips(id INTEGER PRIMARY KEY AUTOINCREMENT, block_hash TEXT UNIQUE NOT NULL);", NO_PARAMS),
                    &format!("FATAL: failed to create 'cli_chain_tips' table"));

    let parent_block_hash = get_cli_chain_tip(&tx);

    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let next_block_hash = friendly_expect_opt(
        StacksBlockId::from_bytes(&random_bytes),
        "Failed to generate random block header.",
    );

    friendly_expect(
        tx.execute(
            "INSERT INTO cli_chain_tips (block_hash) VALUES (?1)",
            &[&next_block_hash],
        ),
        &format!("FATAL: failed to store next block hash in '{}'", path),
    );

    friendly_expect(
        tx.commit(),
        &format!("FATAL: failed to commit new chain tip to '{}'", path),
    );

    (parent_block_hash, next_block_hash)
}

// This function is pretty weird! But it helps cut down on
//   repeating a lot of block initialization for the simulation commands.
fn in_block<F, R>(db_path: &str, mut marf_kv: MarfedKV, f: F) -> R
where
    F: FnOnce(WritableMarfStore) -> (WritableMarfStore, R),
{
    // store CLI data alongside the MARF database state
    let mut cli_db_path_buf = PathBuf::from(db_path);
    cli_db_path_buf.push("cli.sqlite");
    let cli_db_path = cli_db_path_buf
        .to_str()
        .expect(&format!(
            "FATAL: failed to convert '{}' to a string",
            db_path
        ))
        .to_string();

    // need to load the last block
    let (from, to) = advance_cli_chain_tip(&cli_db_path);
    let marf_tx = marf_kv.begin(&from, &to);
    let (marf_return, result) = f(marf_tx);
    marf_return.commit_to(&to);
    result
}

// like in_block, but does _not_ advance the chain tip.  Used for read-only queries against the
// chain tip itself.
fn at_chaintip<F, R>(db_path: &String, mut marf_kv: MarfedKV, f: F) -> R
where
    F: FnOnce(WritableMarfStore) -> (WritableMarfStore, R),
{
    // store CLI data alongside the MARF database state
    let mut cli_db_path_buf = PathBuf::from(db_path);
    cli_db_path_buf.push("cli.sqlite");
    let cli_db_path = cli_db_path_buf
        .to_str()
        .expect(&format!(
            "FATAL: failed to convert '{}' to a string",
            db_path
        ))
        .to_string();

    let cli_db_conn = create_or_open_db(&cli_db_path);
    let from = get_cli_chain_tip(&cli_db_conn);
    let to = StacksBlockId([2u8; 32]); // 0x0202020202 ... (pattern not used anywhere else)

    let marf_tx = marf_kv.begin(&from, &to);
    let (marf_return, result) = f(marf_tx);
    marf_return.rollback_block();
    result
}

fn at_block<F, R>(blockhash: &str, mut marf_kv: MarfedKV, f: F) -> R
where
    F: FnOnce(WritableMarfStore) -> (WritableMarfStore, R),
{
    // store CLI data alongside the MARF database state
    let from = StacksBlockId::from_hex(blockhash)
        .expect(&format!("FATAL: failed to parse inputted blockhash"));
    let to = StacksBlockId([2u8; 32]); // 0x0202020202 ... (pattern not used anywhere else)

    let marf_tx = marf_kv.begin(&from, &to);
    let (marf_return, result) = f(marf_tx);
    marf_return.rollback_block();
    result
}

struct CLIHeadersDB {
    db_path: String,
}

impl CLIHeadersDB {
    pub fn new(db_path: &str) -> CLIHeadersDB {
        CLIHeadersDB {
            db_path: db_path.to_string(),
        }
    }

    pub fn open(&self) -> Connection {
        let mut cli_db_path_buf = PathBuf::from(&self.db_path);
        cli_db_path_buf.push("cli.sqlite");
        let cli_db_path = cli_db_path_buf
            .to_str()
            .expect(&format!(
                "FATAL: failed to convert '{}' to a string",
                &self.db_path
            ))
            .to_string();

        let cli_db_conn = create_or_open_db(&cli_db_path);
        cli_db_conn
    }
}

impl HeadersDB for CLIHeadersDB {
    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        // mock it
        let conn = self.open();
        if let Some(_) = get_cli_block_height(&conn, id_bhh) {
            let hash_bytes = Sha512Trunc256Sum::from_data(&id_bhh.0);
            Some(BurnchainHeaderHash(hash_bytes.0))
        } else {
            None
        }
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        let conn = self.open();
        if let Some(_) = get_cli_block_height(&conn, id_bhh) {
            // mock it, but make it unique
            let hash_bytes = Sha512Trunc256Sum::from_data(&id_bhh.0);
            let hash_bytes_2 = Sha512Trunc256Sum::from_data(&hash_bytes.0);
            Some(VRFSeed(hash_bytes_2.0))
        } else {
            None
        }
    }

    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        let conn = self.open();
        if let Some(_) = get_cli_block_height(&conn, id_bhh) {
            // mock it, but make it unique
            let hash_bytes = Sha512Trunc256Sum::from_data(&id_bhh.0);
            let hash_bytes_2 = Sha512Trunc256Sum::from_data(&hash_bytes.0);
            let hash_bytes_3 = Sha512Trunc256Sum::from_data(&hash_bytes_2.0);
            Some(BlockHeaderHash(hash_bytes_3.0))
        } else {
            None
        }
    }
    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        let conn = self.open();
        if let Some(height) = get_cli_block_height(&conn, id_bhh) {
            Some((height * 600 + 1231006505) as u64)
        } else {
            None
        }
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        let conn = self.open();
        if let Some(height) = get_cli_block_height(&conn, id_bhh) {
            Some(height as u32)
        } else {
            None
        }
    }
    fn get_miner_address(&self, _id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        None
    }
    fn get_total_liquid_ustx(&self, _id_bhh: &StacksBlockId) -> u128 {
        0
    }
}

fn get_eval_input(invoked_by: &str, args: &[String]) -> EvalInput {
    if args.len() < 3 || args.len() > 4 {
        eprintln!(
            "Usage: {} {} [contract-identifier] (program.clar) [vm-state.db]",
            invoked_by, args[0]
        );
        panic_test!();
    }

    let vm_filename = if args.len() == 3 { &args[2] } else { &args[3] };

    let content: String = {
        if args.len() == 3 {
            let mut buffer = String::new();
            friendly_expect(
                io::stdin().read_to_string(&mut buffer),
                "Error reading from stdin.",
            );
            buffer
        } else {
            friendly_expect(
                fs::read_to_string(&args[2]),
                &format!("Error reading file: {}", args[2]),
            )
        }
    };

    let contract_identifier = friendly_expect(
        QualifiedContractIdentifier::parse(&args[1]),
        "Failed to parse contract identifier.",
    );

    let marf_kv = friendly_expect(
        MarfedKV::open(vm_filename, None),
        "Failed to open VM database.",
    );
    // return (marf_kv, contract_identifier, vm_filename, content);
    return EvalInput {
        marf_kv,
        contract_identifier,
        content,
    };
}

#[derive(Serialize, Deserialize)]
struct InitialAllocation {
    principal: String,
    amount: u64,
}

pub fn invoke_command(invoked_by: &str, args: &[String]) {
    if args.len() < 1 {
        print_usage(invoked_by)
    }

    match args[0].as_ref() {
        "initialize" => {
            let (db_name, allocations) = if args.len() == 3 {
                let filename = &args[1];
                let json_in = if filename == "-" {
                    let mut buffer = String::new();
                    friendly_expect(
                        io::stdin().read_to_string(&mut buffer),
                        "Error reading from stdin.",
                    );
                    buffer
                } else {
                    friendly_expect(
                        fs::read_to_string(filename),
                        &format!("Error reading file: {}", filename),
                    )
                };
                let allocations: Vec<InitialAllocation> =
                    friendly_expect(serde_json::from_str(&json_in), "Failure parsing JSON");

                let allocations: Vec<_> = allocations
                    .into_iter()
                    .map(|a| {
                        (
                            friendly_expect(
                                PrincipalData::parse(&a.principal),
                                "Failed to parse principal in JSON",
                            ),
                            a.amount,
                        )
                    })
                    .collect();

                (&args[2], allocations)
            } else if args.len() == 2 {
                (&args[1], Vec::new())
            } else {
                eprintln!(
                    "Usage: {} {} (initial-allocations.json) [vm-state.db]",
                    invoked_by, args[0]
                );
                eprintln!("   initial-allocations.json is a JSON array of {{ principal: \"ST...\", amount: 100 }} like objects.");
                eprintln!("   if the provided filename is `-`, the JSON is read from stdin.");
                panic_test!();
            };

            let marf_kv =
                friendly_expect(MarfedKV::open(db_name, None), "Failed to open VM database.");
            let header_db = CLIHeadersDB::new(&db_name);
            in_block(db_name, marf_kv, |mut kv| {
                {
                    let mut db = kv.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
                    db.initialize();
                    db.begin();
                    for (principal, amount) in allocations.iter() {
                        let balance = STXBalance::initial(*amount as u128);
                        let total_balance = balance.get_total_balance();

                        let mut snapshot = db.get_stx_balance_snapshot_genesis(principal);
                        snapshot.set_balance(balance);
                        snapshot.save();

                        println!("{} credited: {} uSTX", principal, total_balance);
                    }
                    db.commit();
                };
                (kv, ())
            });
            println!("Database created.");
        }
        "generate_address" => {
            // random 20 bytes
            let random_bytes = rand::thread_rng().gen::<[u8; 20]>();
            // version = 22
            let addr =
                friendly_expect(c32_address(22, &random_bytes), "Failed to generate address");
            println!("{}", addr);
        }
        "check" => {
            if args.len() < 2 {
                eprintln!(
                    "Usage: {} {} [program-file.clar] (vm-state.db)",
                    invoked_by, args[0]
                );
                panic_test!();
            }

            let contract_id = QualifiedContractIdentifier::transient();

            let content: String = if &args[1] == "-" {
                let mut buffer = String::new();
                friendly_expect(
                    io::stdin().read_to_string(&mut buffer),
                    "Error reading from stdin.",
                );
                buffer
            } else {
                friendly_expect(
                    fs::read_to_string(&args[1]),
                    &format!("Error reading file: {}", args[1]),
                )
            };

            let mut ast = friendly_expect(parse(&contract_id, &content), "Failed to parse program");

            let contract_analysis = {
                if args.len() >= 3 {
                    // use a persisted marf
                    let marf_kv = friendly_expect(
                        MarfedKV::open(&args[2], None),
                        "Failed to open VM database.",
                    );
                    let result = at_chaintip(&args[2], marf_kv, |mut marf| {
                        let result = {
                            let mut db = marf.as_analysis_db();
                            run_analysis(&contract_id, &mut ast, &mut db, false)
                        };
                        (marf, result)
                    });
                    result
                } else {
                    let mut analysis_marf = MemoryBackingStore::new();
                    let mut db = analysis_marf.as_analysis_db();
                    run_analysis(&contract_id, &mut ast, &mut db, false)
                }
            }
            .unwrap_or_else(|e| {
                println!("{}", &e.diagnostic);
                panic_test!();
            });

            match args.last() {
                Some(s) if s == "--output_analysis" => {
                    println!(
                        "{}",
                        build_contract_interface(&contract_analysis).serialize()
                    );
                }
                _ => {
                    println!("Checks passed.");
                }
            }
        }
        "repl" => {
            let mut marf = MemoryBackingStore::new();
            let mut vm_env = OwnedEnvironment::new_cost_limited(
                marf.as_clarity_db(),
                LimitedCostTracker::new_free(),
            );
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
        }
        "eval_raw" => {
            let content: String = {
                let mut buffer = String::new();
                friendly_expect(
                    io::stdin().read_to_string(&mut buffer),
                    "Error reading from stdin.",
                );
                buffer
            };

            let mut analysis_marf = MemoryBackingStore::new();
            let mut analysis_db = analysis_marf.as_analysis_db();

            let mut marf = MemoryBackingStore::new();
            let mut vm_env = OwnedEnvironment::new_cost_limited(
                marf.as_clarity_db(),
                LimitedCostTracker::new_free(),
            );

            let contract_id = QualifiedContractIdentifier::transient();

            let mut ast =
                friendly_expect(parse(&contract_id, &content), "Failed to parse program.");
            match run_analysis(&contract_id, &mut ast, &mut analysis_db, true) {
                Ok(_) => {
                    let result = vm_env.get_exec_environment(None).eval_raw(&content);
                    match result {
                        Ok(x) => {
                            println!("Program executed successfully! Output: \n{}", x);
                        }
                        Err(error) => {
                            eprintln!("Program execution error: \n{}", error);
                            panic_test!();
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Type check error.\n{}", error);
                    panic_test!();
                }
            }
        }
        "eval" => {
            let evalInput = get_eval_input(invoked_by, args);
            let vm_filename = if args.len() == 3 { &args[2] } else { &args[3] };
            let marf_kv = friendly_expect(
                MarfedKV::open(vm_filename, None),
                "Failed to open VM database.",
            );
            let header_db = CLIHeadersDB::new(&vm_filename);
            let result = in_block(vm_filename, marf_kv, |mut marf| {
                let result = {
                    let db = marf.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
                    let mut vm_env =
                        OwnedEnvironment::new_cost_limited(db, LimitedCostTracker::new_free());
                    vm_env
                        .get_exec_environment(None)
                        .eval_read_only(&evalInput.contract_identifier, &evalInput.content)
                };
                (marf, result)
            });

            match result {
                Ok(x) => {
                    println!("Program executed successfully! Output: \n{}", x);
                }
                Err(error) => {
                    eprintln!("Program execution error: \n{}", error);
                    panic_test!();
                }
            }
        }
        "eval_at_chaintip" => {
            let evalInput = get_eval_input(invoked_by, args);
            let vm_filename = if args.len() == 3 { &args[2] } else { &args[3] };
            let marf_kv = friendly_expect(
                MarfedKV::open(vm_filename, None),
                "Failed to open VM database.",
            );
            let header_db = CLIHeadersDB::new(&vm_filename);
            let result = at_chaintip(vm_filename, marf_kv, |mut marf| {
                let result = {
                    let db = marf.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
                    let mut vm_env =
                        OwnedEnvironment::new_cost_limited(db, LimitedCostTracker::new_free());
                    vm_env
                        .get_exec_environment(None)
                        .eval_read_only(&evalInput.contract_identifier, &evalInput.content)
                };
                (marf, result)
            });

            match result {
                Ok(x) => {
                    println!("Program executed successfully! Output: \n{}", x);
                }
                Err(error) => {
                    eprintln!("Program execution error: \n{}", error);
                    panic_test!();
                }
            }
        }
        "eval_at_block" => {
            if args.len() != 4 {
                eprintln!(
                    "Usage: {} {} [index-block-hash] [contract-identifier] [vm/clarity dir]",
                    invoked_by, &args[0]
                );
                panic_test!();
            }
            let chain_tip = &args[1];
            let contract_identifier = friendly_expect(
                QualifiedContractIdentifier::parse(&args[2]),
                "Failed to parse contract identifier.",
            );
            let content: String = {
                let mut buffer = String::new();
                friendly_expect(
                    io::stdin().read_to_string(&mut buffer),
                    "Error reading from stdin.",
                );
                buffer
            };

            let vm_filename = &args[3];
            let marf_kv = friendly_expect(
                MarfedKV::open(vm_filename, None),
                "Failed to open VM database.",
            );
            let header_db = CLIHeadersDB::new(&vm_filename);
            let result = at_block(chain_tip, marf_kv, |mut marf| {
                let result = {
                    let db = marf.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
                    let mut vm_env =
                        OwnedEnvironment::new_cost_limited(db, LimitedCostTracker::new_free());
                    vm_env
                        .get_exec_environment(None)
                        .eval_read_only(&contract_identifier, &content)
                };
                (marf, result)
            });

            match result {
                Ok(x) => {
                    println!("Program executed successfully! Output: \n{}", x);
                }
                Err(error) => {
                    eprintln!("Program execution error: \n{}", error);
                    panic_test!();
                }
            }
        }
        "launch" => {
            if args.len() < 4 {
                eprintln!(
                    "Usage: {} {} [contract-identifier] [contract-definition.clar] [vm-state.db]",
                    invoked_by, args[0]
                );
                panic_test!();
            }
            let vm_filename = &args[3];

            let contract_identifier = friendly_expect(
                QualifiedContractIdentifier::parse(&args[1]),
                "Failed to parse contract identifier.",
            );

            let contract_content: String = friendly_expect(
                fs::read_to_string(&args[2]),
                &format!("Error reading file: {}", args[2]),
            );

            let mut ast = friendly_expect(
                parse(&contract_identifier, &contract_content),
                "Failed to parse program.",
            );
            let marf_kv = friendly_expect(
                MarfedKV::open(vm_filename, None),
                "Failed to open VM database.",
            );
            let header_db = CLIHeadersDB::new(&vm_filename);
            let result = in_block(vm_filename, marf_kv, |mut marf| {
                let analysis_result = {
                    let mut db = AnalysisDatabase::new(&mut marf);

                    run_analysis(&contract_identifier, &mut ast, &mut db, true)
                };

                match analysis_result {
                    Err(e) => (marf, Err(e)),
                    Ok(analysis) => {
                        let result = {
                            let db = marf.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
                            let mut vm_env = OwnedEnvironment::new_cost_limited(
                                db,
                                LimitedCostTracker::new_free(),
                            );
                            vm_env.initialize_contract(contract_identifier, &contract_content)
                        };
                        (marf, Ok((analysis, result)))
                    }
                }
            });

            match result {
                Ok((contract_analysis, Ok(_x))) => match args.last() {
                    Some(s) if s == "--output_analysis" => {
                        println!(
                            "{}",
                            build_contract_interface(&contract_analysis).serialize()
                        );
                    }
                    _ => {
                        println!("Contract initialized!");
                    }
                },
                Err(error) => {
                    eprintln!("Contract initialization error: \n{}", error);
                    panic_test!();
                }
                Ok((_, Err(error))) => {
                    eprintln!("Contract initialization error: \n{}", error);
                    panic_test!();
                }
            }
        }
        "execute" => {
            if args.len() < 5 {
                eprintln!("Usage: {} {} [vm-state.db] [contract-identifier] [public-function-name] [sender-address] [args...]", invoked_by, args[0]);
                panic_test!();
            }
            let vm_filename = &args[1];
            let marf_kv = friendly_expect(
                MarfedKV::open(vm_filename, None),
                "Failed to open VM database.",
            );
            let header_db = CLIHeadersDB::new(&vm_filename);

            let contract_identifier = friendly_expect(
                QualifiedContractIdentifier::parse(&args[2]),
                "Failed to parse contract identifier.",
            );

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
                    let argument_parsed = friendly_expect(
                        vm_execute(argument),
                        &format!("Error parsing argument \"{}\"", argument),
                    );
                    let argument_value = friendly_expect_opt(
                        argument_parsed,
                        &format!("Failed to parse a value from the argument: {}", argument),
                    );
                    SymbolicExpression::atom_value(argument_value.clone())
                })
                .collect();

            let result = in_block(vm_filename, marf_kv, |mut marf| {
                let result = {
                    let db = marf.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
                    let mut vm_env =
                        OwnedEnvironment::new_cost_limited(db, LimitedCostTracker::new_free());
                    vm_env.execute_transaction(
                        Value::Principal(sender),
                        contract_identifier,
                        &tx_name,
                        &arguments,
                    )
                };
                (marf, result)
            });

            match result {
                Ok((x, _, events)) => {
                    if let Value::Response(data) = x {
                        if data.committed {
                            println!(
                                "Transaction executed and committed. Returned: {}\n{:?}",
                                data.data, events
                            );
                        } else {
                            println!("Aborted: {}", data.data);
                        }
                    } else {
                        panic!(format!(
                            "Expected a ResponseType result from transaction. Found: {}",
                            x
                        ));
                    }
                }
                Err(error) => {
                    eprintln!("Transaction execution error: \n{}", error);
                    panic_test!();
                }
            }
        }
        _ => print_usage(invoked_by),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_initial_alloc() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().gen::<i32>());
        let json_name = format!("/tmp/test-alloc_{}.json", rand::thread_rng().gen::<i32>());
        let clar_name = format!("/tmp/test-alloc_{}.clar", rand::thread_rng().gen::<i32>());

        fs::write(
            &json_name,
            r#"
[ { "principal": "S1G2081040G2081040G2081040G208105NK8PE5",
    "amount": 1000 },
  { "principal": "S1G2081040G2081040G2081040G208105NK8PE5.names",
    "amount": 2000 } ]
"#,
        )
        .unwrap();

        fs::write(&clar_name, r#"
(unwrap-panic (if (is-eq (stx-get-balance 'S1G2081040G2081040G2081040G208105NK8PE5) u1000) (ok 1) (err 2)))
(unwrap-panic (if (is-eq (stx-get-balance 'S1G2081040G2081040G2081040G208105NK8PE5.names) u2000) (ok 1) (err 2)))
"#).unwrap();

        invoke_command(
            "test",
            &["initialize".to_string(), json_name.clone(), db_name.clone()],
        );

        invoke_command(
            "test",
            &[
                "launch".to_string(),
                "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                clar_name,
                db_name,
            ],
        );
    }

    #[test]
    fn test_samples() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().gen::<i32>());

        eprintln!("initialize");
        invoke_command("test", &["initialize".to_string(), db_name.clone()]);

        eprintln!("check tokens");
        invoke_command(
            "test",
            &[
                "check".to_string(),
                "sample-contracts/tokens.clar".to_string(),
            ],
        );

        eprintln!("check tokens");
        invoke_command(
            "test",
            &[
                "check".to_string(),
                "sample-contracts/tokens.clar".to_string(),
                db_name.clone(),
            ],
        );

        eprintln!("launch tokens");
        invoke_command(
            "test",
            &[
                "launch".to_string(),
                "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                "sample-contracts/tokens.clar".to_string(),
                db_name.clone(),
            ],
        );

        eprintln!("check names");
        invoke_command(
            "test",
            &[
                "check".to_string(),
                "sample-contracts/names.clar".to_string(),
                db_name.clone(),
            ],
        );

        eprintln!("launch names");
        invoke_command(
            "test",
            &[
                "launch".to_string(),
                "S1G2081040G2081040G2081040G208105NK8PE5.names".to_string(),
                "sample-contracts/names.clar".to_string(),
                db_name.clone(),
            ],
        );

        eprintln!("execute tokens");
        invoke_command(
            "test",
            &[
                "execute".to_string(),
                db_name.clone(),
                "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                "mint!".to_string(),
                "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR".to_string(),
                "(+ u900 u100)".to_string(),
            ],
        );

        eprintln!("eval tokens");
        invoke_command(
            "test",
            &[
                "eval".to_string(),
                "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                "sample-contracts/tokens-mint.clar".to_string(),
                db_name.clone(),
            ],
        );

        eprintln!("eval_at_chaintip tokens");
        invoke_command(
            "test",
            &[
                "eval_at_chaintip".to_string(),
                "S1G2081040G2081040G2081040G208105NK8PE5.tokens".to_string(),
                "sample-contracts/tokens-mint.clar".to_string(),
                db_name.clone(),
            ],
        );
    }
}
