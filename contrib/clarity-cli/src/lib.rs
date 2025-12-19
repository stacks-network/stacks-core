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

use std::io::Write;
use std::path::PathBuf;
use std::{fs, io};

use clarity::vm::analysis::contract_interface_builder::build_contract_interface;
use clarity::vm::analysis::{AnalysisDatabase, ContractAnalysis};
use clarity::vm::ast::build_ast;
use clarity::vm::contexts::{AssetMap, GlobalContext, OwnedEnvironment};
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{
    BurnStateDB, ClarityDatabase, HeadersDB, NULL_BURN_STATE_DB, STXBalance,
};
use clarity::vm::errors::{RuntimeError, StaticCheckError, VmExecutionError};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{
    ClarityVersion, ContractContext, ContractName, SymbolicExpression, Value, analysis, ast,
    eval_all,
};
use lazy_static::lazy_static;
use rand::Rng;
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;
use serde_json::json;
use stacks_common::address::c32::c32_address;
use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use stacks_common::debug;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum, bytes_to_hex};
use stackslib::burnchains::{PoxConstants, Txid};
use stackslib::chainstate::stacks::boot::{
    BOOT_CODE_BNS, BOOT_CODE_COST_VOTING_MAINNET, BOOT_CODE_COST_VOTING_TESTNET, BOOT_CODE_COSTS,
    BOOT_CODE_COSTS_2, BOOT_CODE_COSTS_2_TESTNET, BOOT_CODE_COSTS_3, BOOT_CODE_COSTS_4,
    BOOT_CODE_GENESIS, BOOT_CODE_LOCKUP, BOOT_CODE_POX_MAINNET, BOOT_CODE_POX_TESTNET,
    POX_2_MAINNET_CODE, POX_2_TESTNET_CODE,
};
use stackslib::chainstate::stacks::index::ClarityMarfTrieId;
use stackslib::clarity_vm::clarity::{ClarityMarfStore, ClarityMarfStoreTransaction};
use stackslib::clarity_vm::database::MemoryBackingStore;
use stackslib::clarity_vm::database::marf::{MarfedKV, PersistentWritableMarfStore};
use stackslib::core::{BLOCK_LIMIT_MAINNET_205, HELIUM_BLOCK_LIMIT_20, StacksEpochId};
use stackslib::util_lib::boot::{boot_code_addr, boot_code_id};
use stackslib::util_lib::db::{FromColumn, sqlite_open};

lazy_static! {
    pub static ref STACKS_BOOT_CODE_MAINNET_2_1: [(&'static str, &'static str); 10] = [
        ("pox", &BOOT_CODE_POX_MAINNET),
        ("lockup", BOOT_CODE_LOCKUP),
        ("costs", BOOT_CODE_COSTS),
        ("cost-voting", BOOT_CODE_COST_VOTING_MAINNET),
        ("bns", BOOT_CODE_BNS),
        ("genesis", BOOT_CODE_GENESIS),
        ("costs-2", BOOT_CODE_COSTS_2),
        ("pox-2", &POX_2_MAINNET_CODE),
        ("costs-3", BOOT_CODE_COSTS_3),
        ("costs-4", BOOT_CODE_COSTS_4),
    ];
    pub static ref STACKS_BOOT_CODE_TESTNET_2_1: [(&'static str, &'static str); 10] = [
        ("pox", &BOOT_CODE_POX_TESTNET),
        ("lockup", BOOT_CODE_LOCKUP),
        ("costs", BOOT_CODE_COSTS),
        ("cost-voting", &BOOT_CODE_COST_VOTING_TESTNET),
        ("bns", BOOT_CODE_BNS),
        ("genesis", BOOT_CODE_GENESIS),
        ("costs-2", BOOT_CODE_COSTS_2_TESTNET),
        ("pox-2", &POX_2_TESTNET_CODE),
        ("costs-3", BOOT_CODE_COSTS_3),
        ("costs-4", BOOT_CODE_COSTS_4),
    ];
}

#[cfg(test)]
macro_rules! panic_test {
    () => {
        panic!()
    };
}
#[cfg(not(test))]
macro_rules! panic_test {
    () => {
        std::process::exit(1)
    };
}

fn friendly_expect<A, B: std::fmt::Display>(input: Result<A, B>, msg: &str) -> A {
    input.unwrap_or_else(|e| {
        eprintln!("{msg}\nCaused by: {e}");
        panic_test!();
    })
}

fn friendly_expect_opt<A>(input: Option<A>, msg: &str) -> A {
    input.unwrap_or_else(|| {
        eprintln!("{msg}");
        panic_test!();
    })
}

/// Represents an initial allocation entry from JSON
#[derive(Deserialize)]
pub struct InitialAllocation {
    pub principal: String,
    pub amount: u64,
}

/// Parse allocation JSON string into (PrincipalData, u64) pairs
pub fn parse_allocations_json(json_content: &str) -> Result<Vec<(PrincipalData, u64)>, String> {
    let initial_allocations: Vec<InitialAllocation> = serde_json::from_str(json_content)
        .map_err(|e| format!("Failed to parse allocations JSON: {e}"))?;

    initial_allocations
        .into_iter()
        .map(|a| {
            let principal = PrincipalData::parse(&a.principal)
                .map_err(|e| format!("Failed to parse principal {}: {e}", a.principal))?;
            Ok((principal, a.amount))
        })
        .collect()
}

pub const DEFAULT_CLI_EPOCH: StacksEpochId = StacksEpochId::Epoch33;

fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<Vec<SymbolicExpression>, VmExecutionError> {
    let ast = build_ast(
        contract_identifier,
        source_code,
        &mut (),
        clarity_version,
        epoch,
    )
    .map_err(|e| RuntimeError::ASTError(Box::new(e)))?;
    Ok(ast.expressions)
}

trait ClarityStorage {
    fn get_clarity_db<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a>;
    fn get_analysis_db(&mut self) -> AnalysisDatabase<'_>;
}

impl ClarityStorage for PersistentWritableMarfStore<'_> {
    fn get_clarity_db<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        self.as_clarity_db(headers_db, burn_db)
    }

    fn get_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        self.as_analysis_db()
    }
}

impl ClarityStorage for MemoryBackingStore {
    fn get_clarity_db<'a>(
        &'a mut self,
        _headers_db: &'a dyn HeadersDB,
        _burn_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        self.as_clarity_db()
    }

    fn get_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        self.as_analysis_db()
    }
}

fn run_analysis_free<C: ClarityStorage>(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    marf_kv: &mut C,
    save_contract: bool,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<ContractAnalysis, Box<(StaticCheckError, LimitedCostTracker)>> {
    analysis::run_analysis(
        contract_identifier,
        expressions,
        &mut marf_kv.get_analysis_db(),
        save_contract,
        LimitedCostTracker::new_free(),
        epoch,
        clarity_version,
        // no type map data is used in the clarity_cli
        false,
    )
}

fn run_analysis<C: ClarityStorage>(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    header_db: &CLIHeadersDB,
    marf_kv: &mut C,
    save_contract: bool,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<ContractAnalysis, Box<(StaticCheckError, LimitedCostTracker)>> {
    let mainnet = header_db.is_mainnet();
    let cost_track = LimitedCostTracker::new(
        mainnet,
        default_chain_id(mainnet),
        if mainnet {
            BLOCK_LIMIT_MAINNET_205
        } else {
            HELIUM_BLOCK_LIMIT_20
        },
        &mut marf_kv.get_clarity_db(header_db, &NULL_BURN_STATE_DB),
        epoch,
    )
    .unwrap();
    analysis::run_analysis(
        contract_identifier,
        expressions,
        &mut marf_kv.get_analysis_db(),
        save_contract,
        cost_track,
        epoch,
        clarity_version,
        // no type map data is used in the clarity_cli
        false,
    )
}

fn create_or_open_db(path: &String) -> Connection {
    let open_flags = if path == ":memory:" {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        match fs::metadata(path) {
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    // need to create
                    if let Some(dirp) = PathBuf::from(path).parent() {
                        fs::create_dir_all(dirp).unwrap_or_else(|e| {
                            eprintln!("Failed to create {dirp:?}: {e:?}");
                            panic_test!();
                        });
                    }
                    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                } else {
                    panic!("FATAL: could not stat {path}");
                }
            }
            Ok(_md) => {
                // can just open
                OpenFlags::SQLITE_OPEN_READ_WRITE
            }
        }
    };

    friendly_expect(
        sqlite_open(path, open_flags, false),
        &format!("FATAL: failed to open '{path}'"),
    )
}

fn get_cli_chain_tip(conn: &Connection) -> StacksBlockId {
    let mut stmt = friendly_expect(
        conn.prepare("SELECT block_hash FROM cli_chain_tips ORDER BY id DESC LIMIT 1"),
        "FATAL: could not prepare query",
    );
    let mut rows = friendly_expect(stmt.query(NO_PARAMS), "FATAL: could not fetch rows");
    let mut hash_opt = None;
    while let Some(row) = rows.next().expect("FATAL: could not read block hash") {
        let bhh = friendly_expect(
            StacksBlockId::from_column(row, "block_hash"),
            "FATAL: could not parse block hash",
        );
        hash_opt = Some(bhh);
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
    let mut rows = friendly_expect(stmt.query([block_id]), "FATAL: could not fetch rows");

    rows.next()
        .expect("FATAL: could not read block hash")
        .map(|row| friendly_expect(u64::from_column(row, "id"), "FATAL: could not parse row ID"))
}

fn get_cli_db_path(db_path: &str) -> String {
    if db_path == ":memory:" {
        return db_path.to_string();
    }

    let mut cli_db_path_buf = PathBuf::from(db_path);
    cli_db_path_buf.push("cli.sqlite");

    cli_db_path_buf
        .to_str()
        .unwrap_or_else(|| panic!("FATAL: failed to convert '{db_path}' to a string"))
        .to_string()
}

// This function is pretty weird! But it helps cut down on
//   repeating a lot of block initialization for the simulation commands.
fn in_block<F, R>(
    mut headers_db: CLIHeadersDB,
    mut marf_kv: MarfedKV,
    f: F,
) -> (CLIHeadersDB, MarfedKV, R)
where
    F: FnOnce(
        CLIHeadersDB,
        PersistentWritableMarfStore,
    ) -> (CLIHeadersDB, PersistentWritableMarfStore, R),
{
    // need to load the last block
    let (from, to) = headers_db.advance_cli_chain_tip();
    let (headers_return, result) = {
        let marf_tx = marf_kv.begin(&from, &to);
        let (headers_return, marf_return, result) = f(headers_db, marf_tx);
        marf_return
            .commit_to_processed_block(&to)
            .expect("FATAL: failed to commit block");
        (headers_return, result)
    };
    (headers_return, marf_kv, result)
}

// like in_block, but does _not_ advance the chain tip.  Used for read-only queries against the
// chain tip itself.
fn at_chaintip<F, R>(db_path: &str, mut marf_kv: MarfedKV, f: F) -> R
where
    F: FnOnce(PersistentWritableMarfStore) -> (PersistentWritableMarfStore, R),
{
    // store CLI data alongside the MARF database state
    let cli_db_path = get_cli_db_path(db_path);
    let cli_db_conn = create_or_open_db(&cli_db_path);
    let from = get_cli_chain_tip(&cli_db_conn);
    let to = StacksBlockId([2u8; 32]); // 0x0202020202 ... (pattern not used anywhere else)

    let marf_tx = marf_kv.begin(&from, &to);
    let (marf_return, result) = f(marf_tx);
    marf_return.drop_current_trie();
    result
}

fn at_block<F, R>(blockhash: &str, mut marf_kv: MarfedKV, f: F) -> R
where
    F: FnOnce(PersistentWritableMarfStore) -> (PersistentWritableMarfStore, R),
{
    // store CLI data alongside the MARF database state
    let from = StacksBlockId::from_hex(blockhash)
        .unwrap_or_else(|_| panic!("FATAL: failed to parse inputted blockhash: {blockhash}"));
    let to = StacksBlockId([2u8; 32]); // 0x0202020202 ... (pattern not used anywhere else)

    let marf_tx = marf_kv.begin(&from, &to);
    let (marf_return, result) = f(marf_tx);
    marf_return.drop_current_trie();
    result
}

fn default_chain_id(mainnet: bool) -> u32 {
    if mainnet {
        CHAIN_ID_MAINNET
    } else {
        CHAIN_ID_TESTNET
    }
}

fn with_env_costs<F, R>(
    mainnet: bool,
    epoch: StacksEpochId,
    header_db: &CLIHeadersDB,
    marf: &mut PersistentWritableMarfStore,
    f: F,
) -> (R, ExecutionCost)
where
    F: FnOnce(&mut OwnedEnvironment) -> R,
{
    let mut db = marf.as_clarity_db(header_db, &NULL_BURN_STATE_DB);
    let cost_track = LimitedCostTracker::new(
        mainnet,
        default_chain_id(mainnet),
        if mainnet {
            BLOCK_LIMIT_MAINNET_205
        } else {
            HELIUM_BLOCK_LIMIT_20
        },
        &mut db,
        epoch,
    )
    .unwrap();
    let mut vm_env = OwnedEnvironment::new_cost_limited(
        mainnet,
        default_chain_id(mainnet),
        db,
        cost_track,
        epoch,
    );
    let result = f(&mut vm_env);
    let cost = vm_env.get_cost_total();
    (result, cost)
}

/// Execute program in a transient environment. To be used only by CLI tools
///  for program evaluation, not by consensus critical code.
pub fn vm_execute_in_epoch(
    program: &str,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<Option<Value>, VmExecutionError> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone(), clarity_version);
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        default_chain_id(false),
        conn,
        LimitedCostTracker::new_free(),
        epoch,
    );
    global_context.execute(|g| {
        let parsed =
            ast::build_ast(&contract_id, program, &mut (), clarity_version, epoch)?.expressions;
        eval_all(&parsed, &mut contract_context, g, None)
    })
}

/// Execute program in a transient environment in the latest epoch.
/// To be used only by CLI tools for program evaluation, not by consensus
/// critical code.
pub fn vm_execute(
    program: &str,
    clarity_version: ClarityVersion,
) -> Result<Option<Value>, VmExecutionError> {
    vm_execute_in_epoch(program, clarity_version, StacksEpochId::latest())
}

struct CLIHeadersDB {
    db_path: String,
    conn: Connection,
}

impl CLIHeadersDB {
    fn instantiate(&mut self, mainnet: bool) {
        let cli_db_path = self.get_cli_db_path();
        let tx = friendly_expect(
            self.conn.transaction(),
            &format!("FATAL: failed to begin transaction on '{cli_db_path}'"),
        );

        friendly_expect(
            tx.execute(
                "CREATE TABLE IF NOT EXISTS cli_chain_tips(id INTEGER PRIMARY KEY AUTOINCREMENT, block_hash TEXT UNIQUE NOT NULL);",
                NO_PARAMS
            ),
            "FATAL: failed to create 'cli_chain_tips' table",
        );

        friendly_expect(
            tx.execute(
                "CREATE TABLE IF NOT EXISTS cli_config(testnet BOOLEAN NOT NULL);",
                NO_PARAMS,
            ),
            "FATAL: failed to create 'cli_config' table",
        );

        if !mainnet {
            friendly_expect(
                tx.execute("INSERT INTO cli_config (testnet) VALUES (?1)", [&true]),
                "FATAL: failed to set testnet flag",
            );
        }

        friendly_expect(
            tx.commit(),
            &format!("FATAL: failed to instantiate CLI DB at {cli_db_path:?}"),
        );
    }

    /// Create or open a new CLI DB at db_path.  If it already exists, then this method is a no-op.
    pub fn new(db_path: &str, mainnet: bool) -> CLIHeadersDB {
        let instantiate = db_path == ":memory:" || fs::metadata(db_path).is_err();

        let cli_db_path = get_cli_db_path(db_path);
        let conn = create_or_open_db(&cli_db_path);
        let mut db = CLIHeadersDB {
            db_path: db_path.to_string(),
            conn,
        };

        if instantiate {
            db.instantiate(mainnet);
        }
        db
    }

    /// Open an CLI DB at db_path. Returns Err() if it doesn't exist.
    /// Normally this would be Option<..>, but since this gets used with friendly_expect,
    /// using a Result<..> is necessary.
    pub fn resume(db_path: &str) -> Result<CLIHeadersDB, String> {
        let cli_db_path = get_cli_db_path(db_path);
        if let Err(e) = fs::metadata(&cli_db_path) {
            return Err(format!("Failed to access {cli_db_path:?}: {e:?}"));
        }
        let conn = create_or_open_db(&cli_db_path);
        let db = CLIHeadersDB {
            db_path: db_path.to_string(),
            conn,
        };

        Ok(db)
    }

    /// Make a new CLI DB in memory.
    pub fn new_memory(mainnet: bool) -> CLIHeadersDB {
        CLIHeadersDB::new(":memory:", mainnet)
    }

    fn get_cli_db_path(&self) -> String {
        get_cli_db_path(&self.db_path)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn is_mainnet(&self) -> bool {
        let mut stmt = friendly_expect(
            self.conn.prepare("SELECT testnet FROM cli_config LIMIT 1"),
            "FATAL: could not prepare query",
        );
        let mut rows = friendly_expect(stmt.query(NO_PARAMS), "FATAL: could not fetch rows");
        let mut mainnet = true;
        while let Some(row) = rows.next().expect("FATAL: could not read config row") {
            let testnet: bool = row.get_unwrap("testnet");
            mainnet = !testnet;
        }
        mainnet
    }

    pub fn advance_cli_chain_tip(&mut self) -> (StacksBlockId, StacksBlockId) {
        let db_path = &self.db_path;
        let tx = friendly_expect(
            self.conn.transaction(),
            &format!("FATAL: failed to begin transaction on '{db_path}'"),
        );

        let parent_block_hash = get_cli_chain_tip(&tx);

        let random_bytes = rand::thread_rng().r#gen::<[u8; 32]>();
        let next_block_hash = friendly_expect_opt(
            StacksBlockId::from_bytes(&random_bytes),
            "Failed to generate random block header.",
        );

        friendly_expect(
            tx.execute(
                "INSERT INTO cli_chain_tips (block_hash) VALUES (?1)",
                [&next_block_hash],
            ),
            &format!("FATAL: failed to store next block hash in '{db_path}'"),
        );

        friendly_expect(
            tx.commit(),
            &format!("FATAL: failed to commit new chain tip to '{db_path}'"),
        );

        (parent_block_hash, next_block_hash)
    }
}

impl HeadersDB for CLIHeadersDB {
    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        // mock it
        let conn = self.conn();
        if get_cli_block_height(conn, id_bhh).is_some() {
            let hash_bytes = Sha512Trunc256Sum::from_data(&id_bhh.0);
            Some(BurnchainHeaderHash(hash_bytes.0))
        } else {
            None
        }
    }

    fn get_consensus_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<ConsensusHash> {
        // mock it
        let conn = self.conn();
        if get_cli_block_height(conn, id_bhh).is_some() {
            let hash_bytes = Hash160::from_data(&id_bhh.0);
            Some(ConsensusHash(hash_bytes.0))
        } else {
            None
        }
    }

    fn get_vrf_seed_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<VRFSeed> {
        let conn = self.conn();
        if get_cli_block_height(conn, id_bhh).is_some() {
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
        _epoch: &StacksEpochId,
    ) -> Option<BlockHeaderHash> {
        let conn = self.conn();
        if get_cli_block_height(conn, id_bhh).is_some() {
            // mock it, but make it unique
            let hash_bytes = Sha512Trunc256Sum::from_data(&id_bhh.0);
            let hash_bytes_2 = Sha512Trunc256Sum::from_data(&hash_bytes.0);
            let hash_bytes_3 = Sha512Trunc256Sum::from_data(&hash_bytes_2.0);
            Some(BlockHeaderHash(hash_bytes_3.0))
        } else {
            None
        }
    }

    fn get_burn_block_time_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: Option<&StacksEpochId>,
    ) -> Option<u64> {
        let conn = self.conn();
        get_cli_block_height(conn, id_bhh).map(|height| height * 600 + 1231006505)
    }

    fn get_stacks_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        let conn = self.conn();
        get_cli_block_height(conn, id_bhh).map(|height| height * 10 + 1713799973)
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        let conn = self.conn();
        get_cli_block_height(conn, id_bhh).map(|height| height as u32)
    }

    fn get_miner_address(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<StacksAddress> {
        None
    }

    fn get_burnchain_tokens_spent_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        // if the block is defined at all, then return a constant
        get_cli_block_height(self.conn(), id_bhh).map(|_| 2000)
    }

    fn get_burnchain_tokens_spent_for_winning_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        // if the block is defined at all, then return a constant
        get_cli_block_height(self.conn(), id_bhh).map(|_| 1000)
    }

    fn get_tokens_earned_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        // if the block is defined at all, then return a constant
        get_cli_block_height(self.conn(), id_bhh).map(|_| 3000)
    }

    fn get_stacks_height_for_tenure_height(
        &self,
        _tip: &StacksBlockId,
        tenure_height: u32,
    ) -> Option<u32> {
        Some(tenure_height)
    }
}

/// This function uses Clarity1 to parse the boot code.
fn install_boot_code<C: ClarityStorage>(
    header_db: &CLIHeadersDB,
    marf: &mut C,
    epoch: StacksEpochId,
) {
    let mainnet = header_db.is_mainnet();
    let boot_code = if mainnet {
        *STACKS_BOOT_CODE_MAINNET_2_1
    } else {
        *STACKS_BOOT_CODE_TESTNET_2_1
    };

    {
        let db = marf.get_clarity_db(header_db, &NULL_BURN_STATE_DB);
        let mut vm_env = OwnedEnvironment::new_free(mainnet, default_chain_id(mainnet), db, epoch);
        vm_env
            .execute_in_env(
                QualifiedContractIdentifier::transient().issuer.into(),
                None,
                None,
                |env| {
                    let res: Result<_, VmExecutionError> =
                        Ok(env.global_context.database.set_clarity_epoch_version(epoch));
                    res
                },
            )
            .unwrap()
            .0
            .unwrap();
    }

    for (boot_code_name, boot_code_contract) in boot_code.iter() {
        let contract_identifier = QualifiedContractIdentifier::new(
            boot_code_addr(mainnet).into(),
            ContractName::try_from(boot_code_name.to_string()).unwrap(),
        );
        let contract_content = *boot_code_contract;

        debug!(
            "Instantiate boot code contract '{contract_identifier}' ({} bytes)...",
            boot_code_contract.len()
        );

        let mut ast = friendly_expect(
            parse(
                &contract_identifier,
                contract_content,
                ClarityVersion::Clarity1,
                epoch,
            ),
            "Failed to parse program.",
        );

        let analysis_result = run_analysis_free(
            &contract_identifier,
            &mut ast,
            marf,
            true,
            ClarityVersion::Clarity2,
            epoch,
        );
        match analysis_result {
            Ok(_) => {
                let db = marf.get_clarity_db(header_db, &NULL_BURN_STATE_DB);
                let mut vm_env =
                    OwnedEnvironment::new_free(mainnet, default_chain_id(mainnet), db, epoch);
                vm_env
                    .initialize_versioned_contract(
                        contract_identifier,
                        ClarityVersion::Clarity1,
                        contract_content,
                        None,
                    )
                    .unwrap();
            }
            Err(e) => {
                panic!("failed to instantiate boot contract: {e:?}");
            }
        };
    }

    // set up PoX
    let pox_contract = boot_code_id("pox", mainnet);
    let sender = PrincipalData::from(pox_contract.clone());
    let pox_params = if mainnet {
        PoxConstants::mainnet_default()
    } else {
        PoxConstants::testnet_default()
    };

    let params = vec![
        SymbolicExpression::atom_value(Value::UInt(0)), // first burnchain block height
        SymbolicExpression::atom_value(Value::UInt(pox_params.prepare_length as u128)),
        SymbolicExpression::atom_value(Value::UInt(pox_params.reward_cycle_length as u128)),
        SymbolicExpression::atom_value(Value::UInt(pox_params.pox_rejection_fraction as u128)),
    ];

    let db = marf.get_clarity_db(header_db, &NULL_BURN_STATE_DB);
    let mut vm_env = OwnedEnvironment::new_free(mainnet, default_chain_id(mainnet), db, epoch);
    vm_env
        .execute_transaction(
            sender,
            None,
            pox_contract,
            "set-burnchain-parameters",
            params.as_slice(),
        )
        .unwrap();
}

pub fn add_costs(result: &mut serde_json::Value, costs: bool, runtime: ExecutionCost) {
    if costs {
        result["costs"] = serde_json::to_value(runtime).unwrap();
    }
}

pub fn add_assets(result: &mut serde_json::Value, assets: bool, asset_map: AssetMap) {
    if assets {
        result["assets"] = asset_map.to_json();
    }
}

pub fn add_serialized_output(result: &mut serde_json::Value, value: Value) {
    let result_raw = {
        let bytes = value.serialize_to_vec().unwrap();
        bytes_to_hex(&bytes)
    };
    result["output_serialized"] = serde_json::to_value(result_raw.as_str()).unwrap();
}

/// Initialize a local VM state database
pub fn execute_initialize(
    db_name: &str,
    mainnet: bool,
    epoch: StacksEpochId,
    allocations: Vec<(PrincipalData, u64)>,
) -> (i32, Option<serde_json::Value>) {
    debug!("Initialize {db_name}");

    // Create database and MARF
    let mut header_db = CLIHeadersDB::new(db_name, mainnet);
    let mut marf_kv = friendly_expect(
        MarfedKV::open(db_name, None, None),
        "Failed to open VM database.",
    );

    // Install bootcode
    let state = in_block(header_db, marf_kv, |header_db, mut marf| {
        install_boot_code(&header_db, &mut marf, epoch);
        (header_db, marf, ())
    });

    header_db = state.0;
    marf_kv = state.1;

    // Set initial balances
    in_block(header_db, marf_kv, |header_db, mut kv| {
        {
            let mut db = kv.as_clarity_db(&header_db, &NULL_BURN_STATE_DB);
            db.begin();
            for (principal, amount) in allocations.iter() {
                let balance = STXBalance::initial(*amount as u128);
                let total_balance = balance.get_total_balance().unwrap();

                let mut snapshot = db.get_stx_balance_snapshot_genesis(principal).unwrap();
                snapshot.set_balance(balance);
                snapshot.save().unwrap();

                println!("{principal} credited: {total_balance} uSTX");
            }
            db.commit().unwrap();
        };
        (header_db, kv, ())
    });

    (
        0,
        Some(json!({
            "message": "Database created.",
            "network": if mainnet { "mainnet" } else { "testnet" }
        })),
    )
}

/// Generate a random Stacks address for testing purposes
pub fn execute_generate_address() -> (i32, Option<serde_json::Value>) {
    // Generate random 20 bytes
    let random_bytes = rand::thread_rng().r#gen::<[u8; 20]>();

    // Version = 22
    let addr = friendly_expect(c32_address(22, &random_bytes), "Failed to generate address");

    (0, Some(json!({ "address": format!("{addr}") })))
}

/// Typecheck a potential contract definition
#[allow(clippy::too_many_arguments)]
pub fn execute_check(
    content: &str,
    contract_id: &QualifiedContractIdentifier,
    output_analysis: bool,
    costs: bool,
    mainnet: bool,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    db_path: Option<&str>,
    testnet_given: bool,
) -> (i32, Option<serde_json::Value>) {
    // Parse the contract
    let mut ast = friendly_expect(
        parse(contract_id, content, clarity_version, epoch),
        "Failed to parse program",
    );

    // Run analysis (either with persisted DB or in-memory)
    let contract_analysis_res = {
        if let Some(vm_filename) = db_path {
            // Warn if --testnet was given but we're using DB state
            if testnet_given {
                eprintln!(
                    "WARN: ignoring --testnet in favor of DB state in {vm_filename:?}. Re-instantiate the DB to change."
                );
            }

            // Use a persisted MARF
            let header_db =
                friendly_expect(CLIHeadersDB::resume(vm_filename), "Failed to open CLI DB");
            let marf_kv = friendly_expect(
                MarfedKV::open(vm_filename, None, None),
                "Failed to open VM database.",
            );

            at_chaintip(vm_filename, marf_kv, |mut marf| {
                let result = run_analysis(
                    contract_id,
                    &mut ast,
                    &header_db,
                    &mut marf,
                    false,
                    clarity_version,
                    epoch,
                );
                (marf, result)
            })
        } else {
            // Use in-memory analysis
            let header_db = CLIHeadersDB::new_memory(mainnet);
            let mut analysis_marf = MemoryBackingStore::new();

            install_boot_code(&header_db, &mut analysis_marf, epoch);
            run_analysis(
                contract_id,
                &mut ast,
                &header_db,
                &mut analysis_marf,
                false,
                clarity_version,
                epoch,
            )
        }
    };

    // Handle analysis result
    let mut contract_analysis = match contract_analysis_res {
        Ok(contract_analysis) => contract_analysis,
        Err(boxed) => {
            let (e, cost_tracker) = *boxed;
            let mut result = json!({
                "message": "Checks failed.",
                "error": {
                    "analysis": serde_json::to_value(&e.diagnostic).unwrap(),
                },
            });
            add_costs(&mut result, costs, cost_tracker.get_total());
            return (1, Some(result));
        }
    };

    // Build success result
    let mut result = json!({
        "message": "Checks passed."
    });

    add_costs(
        &mut result,
        costs,
        contract_analysis.take_contract_cost_tracker().get_total(),
    );

    if output_analysis {
        result["analysis"] =
            serde_json::to_value(build_contract_interface(&contract_analysis).unwrap()).unwrap();
    }

    (0, Some(result))
}

/// Typecheck and evaluate expressions in a stdin/stdout REPL loop
pub fn execute_repl(
    mainnet: bool,
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
) -> (i32, Option<serde_json::Value>) {
    let mut marf = MemoryBackingStore::new();
    let mut vm_env = OwnedEnvironment::new_free(
        mainnet,
        default_chain_id(mainnet),
        marf.as_clarity_db(),
        epoch,
    );
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);
    let mut exec_env = vm_env.get_exec_environment(None, None, &placeholder_context);
    let mut analysis_marf = MemoryBackingStore::new();

    let contract_id = QualifiedContractIdentifier::transient();

    let mut stdout = io::stdout();

    loop {
        // Read input line
        let content: String = {
            let mut buffer = String::new();
            stdout.write_all(b"> ").unwrap_or_else(|e| {
                panic!("Failed to write stdout prompt string:\n{e}");
            });
            stdout.flush().unwrap_or_else(|e| {
                panic!("Failed to flush stdout prompt string:\n{e}");
            });
            match io::stdin().read_line(&mut buffer) {
                Ok(_) => buffer,
                Err(error) => {
                    eprintln!("Error reading from stdin:\n{error}");
                    panic_test!();
                }
            }
        };

        // Parse the expression
        let mut ast = match parse(&contract_id, &content, clarity_version, epoch) {
            Ok(val) => val,
            Err(error) => {
                println!("Parse error:\n{error}");
                continue;
            }
        };

        // Type-check the expression
        match run_analysis_free(
            &contract_id,
            &mut ast,
            &mut analysis_marf,
            true,
            clarity_version,
            epoch,
        ) {
            Ok(_) => (),
            Err(boxed) => {
                let (error, _) = *boxed;
                println!("Type check error:\n{error}");
                continue;
            }
        }

        // Evaluate the expression
        let eval_result = match exec_env.eval_raw(&content) {
            Ok(val) => val,
            Err(error) => {
                println!("Execution error:\n{error}");
                continue;
            }
        };

        println!("{eval_result}");
    }
}

/// Typecheck and evaluate an expression without a contract or database context.
pub fn execute_eval_raw(
    content: &str,
    mainnet: bool,
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
) -> (i32, Option<serde_json::Value>) {
    let mut analysis_marf = MemoryBackingStore::new();
    let mut marf = MemoryBackingStore::new();
    let mut vm_env = OwnedEnvironment::new_free(
        mainnet,
        default_chain_id(mainnet),
        marf.as_clarity_db(),
        epoch,
    );

    let contract_id = QualifiedContractIdentifier::transient();
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);

    // Parse the expression
    let mut ast = friendly_expect(
        parse(&contract_id, content, clarity_version, epoch),
        "Failed to parse program.",
    );

    // Type-check and evaluate
    match run_analysis_free(
        &contract_id,
        &mut ast,
        &mut analysis_marf,
        true,
        clarity_version,
        epoch,
    ) {
        Ok(_) => {
            // Analysis passed, now evaluate
            let result = vm_env
                .get_exec_environment(None, None, &placeholder_context)
                .eval_raw(content);
            match result {
                Ok(x) => (
                    0,
                    Some(json!({
                        "output": serde_json::to_value(&x).unwrap()
                    })),
                ),
                Err(error) => (
                    1,
                    Some(json!({
                        "error": {
                            "runtime": serde_json::to_value(format!("{error}")).unwrap()
                        }
                    })),
                ),
            }
        }
        Err(boxed) => {
            let (error, _) = *boxed;
            (
                1,
                Some(json!({
                    "error": {
                        "analysis": serde_json::to_value(format!("{error}")).unwrap()
                    }
                })),
            )
        }
    }
}

/// Evaluate (in read-only mode) a program in a given contract context
/// This advances to a new block before evaluation.
pub fn execute_eval(
    contract_identifier: &QualifiedContractIdentifier,
    content: &str,
    costs: bool,
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
    vm_filename: &str,
) -> (i32, Option<serde_json::Value>) {
    // Open database
    let header_db = friendly_expect(CLIHeadersDB::resume(vm_filename), "Failed to open CLI DB");
    let marf_kv = friendly_expect(
        MarfedKV::open(vm_filename, None, None),
        "Failed to open VM database.",
    );
    let mainnet = header_db.is_mainnet();
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);

    // Evaluate in a new block
    let (_, _, result_and_cost) = in_block(header_db, marf_kv, |header_db, mut marf| {
        let result_and_cost = with_env_costs(mainnet, epoch, &header_db, &mut marf, |vm_env| {
            vm_env
                .get_exec_environment(None, None, &placeholder_context)
                .eval_read_only(contract_identifier, content)
        });
        (header_db, marf, result_and_cost)
    });

    // Return success or error with costs
    match result_and_cost {
        (Ok(result), cost) => {
            let mut result_json = json!({
                "output": serde_json::to_value(&result).unwrap(),
                "success": true,
            });

            add_serialized_output(&mut result_json, result);
            add_costs(&mut result_json, costs, cost);

            (0, Some(result_json))
        }
        (Err(error), cost) => {
            let mut result_json = json!({
                "error": {
                    "runtime": serde_json::to_value(format!("{error}")).unwrap()
                },
                "success": false,
            });

            add_costs(&mut result_json, costs, cost);

            (1, Some(result_json))
        }
    }
}

/// Like eval, but does not advance to a new block
/// Evaluates at the current chaintip without advancing the block height.
pub fn execute_eval_at_chaintip(
    contract_identifier: &QualifiedContractIdentifier,
    content: &str,
    costs: bool,
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
    vm_filename: &str,
) -> (i32, Option<serde_json::Value>) {
    // Open database
    let header_db = friendly_expect(CLIHeadersDB::resume(vm_filename), "Failed to open CLI DB");
    let marf_kv = friendly_expect(
        MarfedKV::open(vm_filename, None, None),
        "Failed to open VM database.",
    );

    let mainnet = header_db.is_mainnet();
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);

    // Evaluate at chaintip (no block advance)
    let result_and_cost = at_chaintip(vm_filename, marf_kv, |mut marf| {
        let result_and_cost = with_env_costs(mainnet, epoch, &header_db, &mut marf, |vm_env| {
            vm_env
                .get_exec_environment(None, None, &placeholder_context)
                .eval_read_only(contract_identifier, content)
        });
        let (result, cost) = result_and_cost;

        (marf, (result, cost))
    });

    // Return success or error with costs
    match result_and_cost {
        (Ok(result), cost) => {
            let mut result_json = json!({
                "output": serde_json::to_value(&result).unwrap(),
                "success": true,
            });

            add_serialized_output(&mut result_json, result);
            add_costs(&mut result_json, costs, cost);

            (0, Some(result_json))
        }
        (Err(error), cost) => {
            let mut result_json = json!({
                "error": {
                    "runtime": serde_json::to_value(format!("{error}")).unwrap()
                },
                "success": false,
            });

            add_costs(&mut result_json, costs, cost);

            (1, Some(result_json))
        }
    }
}

/// Like eval-at-chaintip, but accepts an index-block-hash to evaluate at
/// Evaluates at a specific block height identified by the index block hash.
/// Reads code from stdin.
pub fn execute_eval_at_block(
    chain_tip: &str,
    contract_identifier: &QualifiedContractIdentifier,
    content: &str,
    costs: bool,
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
    vm_filename: &str,
) -> (i32, Option<serde_json::Value>) {
    let header_db = friendly_expect(CLIHeadersDB::resume(vm_filename), "Failed to open CLI DB");
    let marf_kv = friendly_expect(
        MarfedKV::open(vm_filename, None, None),
        "Failed to open VM database.",
    );
    let mainnet = header_db.is_mainnet();
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);

    // Evaluate at specific block
    let result_and_cost = at_block(chain_tip, marf_kv, |mut marf| {
        let result_and_cost = with_env_costs(mainnet, epoch, &header_db, &mut marf, |vm_env| {
            vm_env
                .get_exec_environment(None, None, &placeholder_context)
                .eval_read_only(contract_identifier, content)
        });
        (marf, result_and_cost)
    });

    // Return success or error with costs
    match result_and_cost {
        (Ok(result), cost) => {
            let mut result_json = json!({
                "output": serde_json::to_value(&result).unwrap(),
                "success": true,
            });

            add_serialized_output(&mut result_json, result);
            add_costs(&mut result_json, costs, cost);

            (0, Some(result_json))
        }
        (Err(error), cost) => {
            let mut result_json = json!({
                "error": {
                    "runtime": serde_json::to_value(format!("{error}")).unwrap()
                },
                "success": false,
            });

            add_costs(&mut result_json, costs, cost);

            (1, Some(result_json))
        }
    }
}

/// Initialize a new contract in the local state database
/// Parses, analyzes, and initializes a contract in the database.
#[allow(clippy::too_many_arguments)]
pub fn execute_launch(
    contract_identifier: &QualifiedContractIdentifier,
    _contract_src_file: &str,
    contract_content: &str,
    costs: bool,
    assets: bool,
    output_analysis: bool,
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
    vm_filename: &str,
) -> (i32, Option<serde_json::Value>) {
    // Parse the contract
    let mut ast = friendly_expect(
        parse(
            contract_identifier,
            contract_content,
            clarity_version,
            epoch,
        ),
        "Failed to parse program.",
    );

    // Open database
    let header_db = friendly_expect(CLIHeadersDB::resume(vm_filename), "Failed to open CLI DB");
    let marf_kv = friendly_expect(
        MarfedKV::open(vm_filename, None, None),
        "Failed to open VM database.",
    );
    let mainnet = header_db.is_mainnet();

    // Run analysis and initialize contract in a new block
    let (_, _, analysis_result_and_cost) = in_block(header_db, marf_kv, |header_db, mut marf| {
        let analysis_result = run_analysis(
            contract_identifier,
            &mut ast,
            &header_db,
            &mut marf,
            true,
            clarity_version,
            epoch,
        );
        match analysis_result {
            Err(e) => (header_db, marf, Err(e)),
            Ok(analysis) => {
                let result_and_cost =
                    with_env_costs(mainnet, epoch, &header_db, &mut marf, |vm_env| {
                        vm_env.initialize_versioned_contract(
                            contract_identifier.clone(),
                            clarity_version,
                            contract_content,
                            None,
                        )
                    });
                let (result, cost) = result_and_cost;
                (header_db, marf, Ok((analysis, (result, cost))))
            }
        }
    });

    // Return success or error with costs, assets, analysis, and events
    match analysis_result_and_cost {
        Ok((contract_analysis, (Ok((_x, asset_map, events)), cost))) => {
            let mut result = json!({
                "message": "Contract initialized!"
            });

            add_costs(&mut result, costs, cost);
            add_assets(&mut result, assets, asset_map);

            if output_analysis {
                result["analysis"] =
                    serde_json::to_value(build_contract_interface(&contract_analysis).unwrap())
                        .unwrap();
            }
            let events_json: Vec<_> = events
                .into_iter()
                .map(|event| event.json_serialize(0, &Txid([0u8; 32]), true).unwrap())
                .collect();

            result["events"] = serde_json::Value::Array(events_json);
            (0, Some(result))
        }
        Err(boxed) => {
            let (error, cost_tracker) = *boxed;
            let mut result = json!({
                "error": {
                    "initialization": serde_json::to_value(format!("{error}")).unwrap()
                }
            });

            add_costs(&mut result, costs, cost_tracker.get_total());

            (1, Some(result))
        }
        Ok((_, (Err(error), ..))) => (
            1,
            Some(json!({
                "error": {
                    "initialization": serde_json::to_value(format!("{error}")).unwrap()
                }
            })),
        ),
    }
}

/// Execute a public function of a defined contract
/// Executes a public function on an initialized contract.
#[allow(clippy::too_many_arguments)]
pub fn execute_execute(
    vm_filename: &str,
    contract_identifier: &QualifiedContractIdentifier,
    tx_name: &str,
    sender: PrincipalData,
    arguments: &[SymbolicExpression],
    costs: bool,
    assets: bool,
    epoch: StacksEpochId,
) -> (i32, Option<serde_json::Value>) {
    // Open database
    let header_db = friendly_expect(CLIHeadersDB::resume(vm_filename), "Failed to open CLI DB");
    let marf_kv = friendly_expect(
        MarfedKV::open(vm_filename, None, None),
        "Failed to open VM database.",
    );
    let mainnet = header_db.is_mainnet();

    // Execute transaction in a new block
    let (_, _, result_and_cost) = in_block(header_db, marf_kv, |header_db, mut marf| {
        let result_and_cost = with_env_costs(mainnet, epoch, &header_db, &mut marf, |vm_env| {
            vm_env.execute_transaction(
                sender,
                None,
                contract_identifier.clone(),
                tx_name,
                arguments,
            )
        });
        let (result, cost) = result_and_cost;
        (header_db, marf, (result, cost))
    });

    // Return success or error with costs, assets, and events
    match result_and_cost {
        (Ok((x, asset_map, events)), cost) => {
            if let Value::Response(data) = x {
                if data.committed {
                    let mut result = json!({
                        "message": "Transaction executed and committed.",
                        "output": serde_json::to_value(&data.data).unwrap(),
                        "success": true,
                    });

                    add_serialized_output(&mut result, *data.data);
                    add_costs(&mut result, costs, cost);
                    add_assets(&mut result, assets, asset_map);

                    let events_json: Vec<_> = events
                        .into_iter()
                        .map(|event| event.json_serialize(0, &Txid([0u8; 32]), true).unwrap())
                        .collect();

                    result["events"] = serde_json::Value::Array(events_json);
                    (0, Some(result))
                } else {
                    let mut result = json!({
                        "message": "Aborted.",
                        "output": serde_json::to_value(&data.data).unwrap(),
                        "success": false,
                    });

                    add_costs(&mut result, costs, cost);
                    add_serialized_output(&mut result, *data.data);
                    add_assets(&mut result, assets, asset_map);

                    (0, Some(result))
                }
            } else {
                let result = json!({
                    "error": {
                        "runtime": "Expected a ResponseType result from transaction.",
                        "output": serde_json::to_value(&x).unwrap()
                    },
                    "success": false,
                });
                (1, Some(result))
            }
        }
        (Err(error), ..) => {
            let result = json!({
                "error": {
                    "runtime": "Transaction execution error.",
                    "error": serde_json::to_value(format!("{error}")).unwrap()
                },
                "success": false,
            });
            (1, Some(result))
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use stacks_common::util::cargo_workspace;

    use super::*;

    #[test]
    fn test_initial_alloc() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());
        let json_name = format!("/tmp/test-alloc_{}.json", rand::thread_rng().r#gen::<i32>());
        let clar_name = format!("/tmp/test-alloc_{}.clar", rand::thread_rng().r#gen::<i32>());

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

        let contract_code = r#"
(unwrap-panic (if (is-eq (stx-get-balance 'S1G2081040G2081040G2081040G208105NK8PE5) u1000) (ok 1) (err 2)))
(unwrap-panic (if (is-eq (stx-get-balance 'S1G2081040G2081040G2081040G208105NK8PE5.names) u2000) (ok 1) (err 2)))
"#;
        fs::write(&clar_name, contract_code).unwrap();

        let json_content = fs::read_to_string(&json_name).unwrap();
        let allocations = parse_allocations_json(&json_content).unwrap();

        let (exit, result) = execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, allocations);

        assert_eq!(exit, 0);
        assert_eq!(result.unwrap()["network"], "mainnet");

        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .unwrap();

        let (exit, _result) = execute_launch(
            &contract_id,
            &clar_name,
            contract_code,
            false,
            false,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        assert_eq!(exit, 0);
    }

    #[test]
    fn test_init_mainnet() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());

        let (exit, result) = execute_initialize(
            &db_name,
            true,
            DEFAULT_CLI_EPOCH,
            vec![], // no allocations
        );

        assert_eq!(exit, 0);
        assert_eq!(result.unwrap()["network"], "mainnet");

        let header_db = CLIHeadersDB::new(&db_name, true);
        assert!(header_db.is_mainnet());
    }

    #[test]
    fn test_init_testnet() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());

        let (exit, result) = execute_initialize(
            &db_name,
            false, // testnet
            DEFAULT_CLI_EPOCH,
            vec![], // no allocations
        );

        assert_eq!(exit, 0);
        assert_eq!(result.unwrap()["network"], "testnet");

        let header_db = CLIHeadersDB::new(&db_name, true);
        assert!(!header_db.is_mainnet());
    }

    fn cargo_workspace_as_string<P>(relative_path: P) -> String
    where
        P: AsRef<Path>,
    {
        cargo_workspace(relative_path).display().to_string()
    }

    #[test]
    fn test_samples() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());

        eprintln!("initialize");
        execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, vec![]);

        eprintln!("check tokens");
        let content = fs::read_to_string(cargo_workspace_as_string("sample/contracts/tokens.clar"))
            .expect("Failed to read tokens.clar");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            None, // no db_path
            false,
        );

        assert_eq!(exit, 0);
        assert!(!result.unwrap()["message"].as_str().unwrap().is_empty());

        eprintln!("check tokens (idempotency)");
        let content = fs::read_to_string(cargo_workspace_as_string("sample/contracts/tokens.clar"))
            .expect("Failed to read tokens.clar");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            Some(&db_name),
            false,
        );

        assert_eq!(exit, 0);
        assert!(!result.unwrap()["message"].as_str().unwrap().is_empty());

        eprintln!("launch tokens");
        let file_path = cargo_workspace_as_string("sample/contracts/tokens.clar");
        let content = fs::read_to_string(&file_path).expect("Failed to read tokens.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_launch(
            &contract_id,
            &file_path,
            &content,
            false,
            false,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        assert_eq!(exit, 0);
        assert!(!result.unwrap()["message"].as_str().unwrap().is_empty());

        eprintln!("check names");
        let content = fs::read_to_string(cargo_workspace_as_string("sample/contracts/names.clar"))
            .expect("Failed to read names.clar");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            Some(&db_name),
            false,
        );

        assert_eq!(exit, 0);
        assert!(!result.unwrap()["message"].as_str().unwrap().is_empty());

        eprintln!("check names with different contract ID");
        let content = fs::read_to_string(cargo_workspace_as_string("sample/contracts/names.clar"))
            .expect("Failed to read names.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            Some(&db_name),
            false,
        );

        assert_eq!(exit, 0);
        assert!(!result.unwrap()["message"].as_str().unwrap().is_empty());

        eprintln!("check names with analysis");
        let content = fs::read_to_string(cargo_workspace_as_string("sample/contracts/names.clar"))
            .expect("Failed to read names.clar");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            true,
            false,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            Some(&db_name),
            false,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert!(!result["message"].as_str().unwrap().is_empty());
        assert!(result["analysis"] != json!(null));

        eprintln!("check names with cost");
        let content = fs::read_to_string(cargo_workspace_as_string("sample/contracts/names.clar"))
            .expect("Failed to read names.clar");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            false,
            true,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            Some(&db_name),
            false,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert!(!result["message"].as_str().unwrap().is_empty());
        assert!(result["costs"] != json!(null));
        assert!(result["assets"] == json!(null));

        eprintln!("launch names with costs and assets");
        let file_path = cargo_workspace_as_string("sample/contracts/names.clar");
        let content = fs::read_to_string(&file_path).expect("Failed to read names.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.names")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_launch(
            &contract_id,
            &file_path,
            &content,
            true,
            true,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert!(!result["message"].as_str().unwrap().is_empty());
        assert!(result["costs"] != json!(null));
        assert!(result["assets"] != json!(null));

        eprintln!("execute tokens");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let sender =
            PrincipalData::parse_standard_principal("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
                .map(PrincipalData::Standard)
                .expect("Failed to parse sender");
        let arg_parsed = vm_execute_in_epoch(
            "(+ u900 u100)",
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
        )
        .expect("Failed to parse argument")
        .expect("Failed to get value from argument");
        let arguments = vec![SymbolicExpression::atom_value(arg_parsed)];
        let (exit, result) = execute_execute(
            &db_name,
            &contract_id,
            "mint!",
            sender,
            &arguments,
            false,
            false,
            DEFAULT_CLI_EPOCH,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert!(!result["message"].as_str().unwrap().is_empty());
        assert!(result["events"].as_array().unwrap().is_empty());
        assert_eq!(result["output"], json!({"UInt": 1000}));

        eprintln!("eval tokens");
        let snippet = fs::read_to_string(cargo_workspace_as_string(
            "sample/contracts/tokens-mint.clar",
        ))
        .expect("Failed to read tokens-mint.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_eval(
            &contract_id,
            &snippet,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert_eq!(
            result["output"],
            json!({
                "Response": {
                    "committed": true,
                    "data": {
                        "UInt": 100
                    }
                }
            })
        );

        eprintln!("eval tokens with cost");
        let snippet = fs::read_to_string(cargo_workspace_as_string(
            "sample/contracts/tokens-mint.clar",
        ))
        .expect("Failed to read tokens-mint.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_eval(
            &contract_id,
            &snippet,
            true,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert_eq!(
            result["output"],
            json!({
                "Response": {
                    "committed": true,
                    "data": {
                        "UInt": 100
                    }
                }
            })
        );
        assert!(result["costs"] != json!(null));

        eprintln!("eval_at_chaintip tokens");
        let snippet = fs::read_to_string(cargo_workspace_as_string(
            "sample/contracts/tokens-mint.clar",
        ))
        .expect("Failed to read tokens-mint.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_eval_at_chaintip(
            &contract_id,
            &snippet,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert_eq!(
            result["output"],
            json!({
                "Response": {
                    "committed": true,
                    "data": {
                        "UInt": 100
                    }
                }
            })
        );

        eprintln!("eval_at_chaintip tokens with cost");
        let snippet = fs::read_to_string(cargo_workspace_as_string(
            "sample/contracts/tokens-mint.clar",
        ))
        .expect("Failed to read tokens-mint.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_eval_at_chaintip(
            &contract_id,
            &snippet,
            true,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        let result = result.unwrap();
        assert_eq!(exit, 0);
        assert_eq!(
            result["output"],
            json!({
                "Response": {
                    "committed": true,
                    "data": {
                        "UInt": 100
                    }
                }
            })
        );
        assert!(result["costs"] != json!(null));
    }

    #[test]
    fn test_assets() {
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());

        eprintln!("initialize");
        execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, vec![]);

        eprintln!("check tokens");
        let content =
            fs::read_to_string(cargo_workspace_as_string("sample/contracts/tokens-ft.clar"))
                .expect("Failed to read tokens-ft.clar");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit, result) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            DEFAULT_CLI_EPOCH,
            None,
            false,
        );

        assert_eq!(exit, 0);
        assert!(!result.unwrap()["message"].as_str().unwrap().is_empty());

        eprintln!("launch tokens");
        let file_path = cargo_workspace_as_string("sample/contracts/tokens-ft.clar");
        let content = fs::read_to_string(&file_path).expect("Failed to read tokens-ft.clar");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens-ft")
                .expect("Failed to parse contract ID");
        let (exit, result) = execute_launch(
            &contract_id,
            &file_path,
            &content,
            false,
            true,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        let result = result.unwrap();
        eprintln!("{}", serde_json::to_string(&result).unwrap());

        assert_eq!(exit, 0);
        assert!(!result["message"].as_str().unwrap().is_empty());
        assert!(
            result["assets"]["tokens"]["S1G2081040G2081040G2081040G208105NK8PE5"]["S1G2081040G2081040G2081040G208105NK8PE5.tokens-ft::tokens"]
                == "10300"
        );
        assert!(result["events"].as_array().unwrap().len() == 3);
        assert!(
            result["events"].as_array().unwrap()[0]
                == json!({
                    "committed": true,
                    "event_index": 0,
                    "ft_mint_event": {
                        "amount": "10300",
                        "asset_identifier": "S1G2081040G2081040G2081040G208105NK8PE5.tokens-ft::tokens",
                        "recipient": "S1G2081040G2081040G2081040G208105NK8PE5"
                    },
                    "txid": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "type": "ft_mint_event"
                })
        );
        assert!(
            result["events"].as_array().unwrap()[1]
                == json!({
                    "committed": true,
                    "event_index": 0,
                    "ft_transfer_event": {
                        "amount": "10000",
                        "asset_identifier": "S1G2081040G2081040G2081040G208105NK8PE5.tokens-ft::tokens",
                        "recipient": "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR",
                        "sender": "S1G2081040G2081040G2081040G208105NK8PE5"
                    },
                    "txid": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "type": "ft_transfer_event"
                })
        );
        assert!(
            result["events"].as_array().unwrap()[2]
                == json!({
                    "committed": true,
                    "event_index": 0,
                    "ft_transfer_event": {
                        "amount": "300",
                        "asset_identifier": "S1G2081040G2081040G2081040G208105NK8PE5.tokens-ft::tokens",
                        "recipient": "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G",
                        "sender": "S1G2081040G2081040G2081040G208105NK8PE5"
                    },
                    "txid": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "type": "ft_transfer_event"
                })
        );
    }

    #[test]
    fn test_check_clarity3_contract_passes_with_clarity3_flag() {
        // Arrange
        let clar_path = format!(
            "/tmp/version-flag-c3-allow-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(
            &clar_path,
            // Valid only in Clarity 3.
            r#"
(define-read-only (get-tenure-info (h uint))
  (ok
    {
      tenure-time: (get-tenure-info? time h),
      tenure-miner-address: (get-tenure-info? miner-address h),
    })
)
"#,
        )
        .unwrap();

        // Act
        let content = fs::read_to_string(&clar_path).expect("Failed to read test file");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit_code, result_json) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::Clarity3,
            DEFAULT_CLI_EPOCH,
            None,
            false,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 0,
            "expected check to pass under Clarity 3, got: {}",
            result_json
        );
        assert_eq!(result_json["message"], "Checks passed.");
    }

    #[test]
    fn test_check_clarity3_contract_fails_with_clarity2_flag() {
        // Arrange
        let clar_path = format!(
            "/tmp/version-flag-c2-reject-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(
            &clar_path,
            // Valid only in Clarity 3, should fail in 2.
            r#"
(define-read-only (get-tenure-info (h uint))
  (ok
    {
      tenure-time: (get-tenure-info? time h),
      tenure-miner-address: (get-tenure-info? miner-address h),
    })
)
"#,
        )
        .unwrap();

        // Act
        let content = fs::read_to_string(&clar_path).expect("Failed to read test file");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit_code, result_json) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::Clarity2,
            DEFAULT_CLI_EPOCH,
            None,
            false,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 1,
            "expected check to fail under Clarity 2, got: {}",
            result_json
        );
        assert_eq!(result_json["message"], "Checks failed.");
        assert!(result_json["error"]["analysis"] != json!(null));
    }

    #[test]
    fn test_check_clarity3_contract_fails_with_epoch21_flag() {
        // Arrange
        let clar_path = format!(
            "/tmp/version-flag-c2-reject-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(
            &clar_path,
            // Valid only in Clarity 3, should fail in epoch 2.1 which defaults to Clarity 2.
            r#"
(define-read-only (get-tenure-info (h uint))
  (ok
    {
      tenure-time: (get-tenure-info? time h),
      tenure-miner-address: (get-tenure-info? miner-address h),
    })
)
"#,
        )
        .unwrap();

        // Act
        let content = fs::read_to_string(&clar_path).expect("Failed to read test file");
        let contract_id = QualifiedContractIdentifier::transient();
        let (exit_code, result_json) = execute_check(
            &content,
            &contract_id,
            false,
            false,
            true,
            ClarityVersion::Clarity2, // Epoch 2.1 defaults to Clarity2
            StacksEpochId::Epoch21,
            None,
            false,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 1,
            "expected check to fail under Clarity 2, got: {}",
            result_json
        );
        assert_eq!(result_json["message"], "Checks failed.");
        assert!(result_json["error"]["analysis"] != json!(null));
    }

    #[test]
    fn test_launch_clarity3_contract_passes_with_clarity3_flag() {
        // Arrange
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());
        execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, vec![]);

        let clar_path = format!(
            "/tmp/version-flag-launch-c3-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(
            &clar_path,
            // Valid only in Clarity 3.
            r#"
(define-read-only (get-tenure-info (h uint))
  (ok
    {
      tenure-time: (get-tenure-info? time h),
      tenure-miner-address: (get-tenure-info? miner-address h),
    })
)
"#,
        )
        .unwrap();

        // Act
        let content = fs::read_to_string(&clar_path).expect("Failed to read test file");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tenure")
                .expect("Failed to parse contract ID");
        let (exit_code, result_json) = execute_launch(
            &contract_id,
            &clar_path,
            &content,
            false,
            false,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::Clarity3,
            &db_name,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 0,
            "expected launch to pass under Clarity 3, got: {}",
            result_json
        );
        assert_eq!(result_json["message"], "Contract initialized!");
    }

    #[test]
    fn test_launch_clarity3_contract_fails_with_clarity2_flag() {
        // Arrange
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());
        execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, vec![]);

        let clar_path = format!(
            "/tmp/version-flag-launch-c2-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(
            &clar_path,
            // Valid only in Clarity 3, should fail in 2.
            r#"
(define-read-only (get-tenure-info (h uint))
  (ok
    {
      tenure-time: (get-tenure-info? time h),
      tenure-miner-address: (get-tenure-info? miner-address h),
    })
)
"#,
        )
        .unwrap();

        // Act
        let content = fs::read_to_string(&clar_path).expect("Failed to read test file");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tenure")
                .expect("Failed to parse contract ID");
        let (exit_code, result_json) = execute_launch(
            &contract_id,
            &clar_path,
            &content,
            false,
            false,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::Clarity2,
            &db_name,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 1,
            "expected launch to fail under Clarity 2, got: {}",
            result_json
        );
        assert!(result_json["error"]["initialization"] != json!(null));
    }

    #[test]
    fn test_eval_clarity3_contract_passes_with_clarity3_flag() {
        // Arrange
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());
        execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, vec![]);

        // Launch minimal contract at target for eval context.
        let launch_src = format!(
            "/tmp/version-flag-eval-launch-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(&launch_src, "(define-read-only (dummy) true)").unwrap();
        let launch_content = fs::read_to_string(&launch_src).expect("Failed to read launch file");
        let launch_contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tenure")
                .expect("Failed to parse contract ID");
        let _ = execute_launch(
            &launch_contract_id,
            &launch_src,
            &launch_content,
            false,
            false,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::default_for_epoch(DEFAULT_CLI_EPOCH),
            &db_name,
        );

        // Use a Clarity3-only native expression.
        let clar_path = format!(
            "/tmp/version-flag-eval-c3-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(&clar_path, "(get-tenure-info? time u1)").unwrap();

        // Act
        let snippet = fs::read_to_string(&clar_path).expect("Failed to read eval file");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tenure")
                .expect("Failed to parse contract ID");
        let (exit_code, result_json) = execute_eval(
            &contract_id,
            &snippet,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::Clarity3,
            &db_name,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 0,
            "expected eval to pass under Clarity 3, got: {}",
            result_json
        );
        assert!(result_json["success"].as_bool().unwrap());
    }

    #[test]
    fn test_eval_clarity3_contract_fails_with_clarity2_flag() {
        // Arrange
        let db_name = format!("/tmp/db_{}", rand::thread_rng().r#gen::<i32>());
        execute_initialize(&db_name, true, DEFAULT_CLI_EPOCH, vec![]);

        // Launch minimal contract at target for eval context.
        let launch_src = format!(
            "/tmp/version-flag-eval-launch-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(&launch_src, "(define-read-only (dummy) true)").unwrap();
        let launch_content = fs::read_to_string(&launch_src).expect("Failed to read launch file");
        let launch_contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tenure")
                .expect("Failed to parse contract ID");
        let _ = execute_launch(
            &launch_contract_id,
            &launch_src,
            &launch_content,
            false,
            false,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::Clarity2,
            &db_name,
        );

        // Use a Clarity3-only native expression.
        let clar_path = format!(
            "/tmp/version-flag-eval-c2-{}.clar",
            rand::thread_rng().r#gen::<i32>()
        );
        fs::write(&clar_path, "(get-tenure-info? time u1)").unwrap();

        // Act
        let snippet = fs::read_to_string(&clar_path).expect("Failed to read eval file");
        let contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tenure")
                .expect("Failed to parse contract ID");
        let (exit_code, result_json) = execute_eval(
            &contract_id,
            &snippet,
            false,
            DEFAULT_CLI_EPOCH,
            ClarityVersion::Clarity2,
            &db_name,
        );

        // Assert
        let result_json = result_json.unwrap();
        assert_eq!(
            exit_code, 1,
            "expected eval to fail under Clarity 2, got: {}",
            result_json
        );
        assert!(result_json["error"]["runtime"] != json!(null));
    }
}
