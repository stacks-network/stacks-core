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

use std::io::Read;
use std::path::PathBuf;
use std::{fs, io, process};

use clap::{Parser, Subcommand};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityVersion, SymbolicExpression};
use clarity_cli::{
    DEFAULT_CLI_EPOCH, execute_check, execute_eval, execute_eval_at_block,
    execute_eval_at_chaintip, execute_eval_raw, execute_execute, execute_generate_address,
    execute_initialize, execute_launch, execute_repl, vm_execute_in_epoch,
};
use stacks_common::types::StacksEpochId;

/// Read content from a file path or stdin if path is "-"
fn read_file_or_stdin(path: &str) -> String {
    if path == "-" {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .expect("Error reading from stdin");
        buffer
    } else {
        fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Error reading file {}: {}", path, e))
    }
}

/// Read content from an optional file path, defaulting to stdin if None or "-"
fn read_optional_file_or_stdin(path: Option<&PathBuf>) -> String {
    match path {
        Some(p) => read_file_or_stdin(p.to_str().expect("Invalid UTF-8 in path")),
        None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .expect("Error reading from stdin");
            buffer
        }
    }
}

/// Parse epoch string to StacksEpochId
fn parse_epoch(epoch_str: Option<&String>) -> StacksEpochId {
    if let Some(s) = epoch_str {
        s.parse::<StacksEpochId>()
            .unwrap_or_else(|_| panic!("Invalid epoch: {}", s))
    } else {
        DEFAULT_CLI_EPOCH
    }
}

/// Parse clarity_version string. Defaults to version for epoch if not specified.
fn parse_clarity_version(cv_str: Option<&String>, epoch: StacksEpochId) -> ClarityVersion {
    if let Some(s) = cv_str {
        s.parse::<ClarityVersion>()
            .unwrap_or_else(|_| panic!("Invalid clarity version: {}", s))
    } else {
        ClarityVersion::default_for_epoch(epoch)
    }
}

/// Parse allocations from JSON file or stdin
fn parse_allocations(allocations_file: &Option<PathBuf>) -> Vec<(PrincipalData, u64)> {
    if let Some(filename) = allocations_file {
        let json_in = read_file_or_stdin(filename.to_str().expect("Invalid UTF-8 in path"));
        clarity_cli::parse_allocations_json(&json_in).unwrap_or_else(|e| panic!("{}", e))
    } else {
        vec![]
    }
}

#[derive(Parser)]
#[command(name = "clarity-cli")]
#[command(about = "Clarity smart contract command-line interface", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a local VM state database
    #[command(name = "initialize")]
    Initialize {
        /// Use testnet bootcode and block-limits instead of mainnet
        #[arg(long)]
        testnet: bool,

        /// Stacks epoch to use
        #[arg(long)]
        epoch: Option<String>,

        /// Path to VM state database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,

        /// Initial allocations JSON file (or "-" for stdin)
        #[arg(value_name = "ALLOCATIONS_FILE")]
        allocations_file: Option<PathBuf>,
    },

    /// Generate a random Stacks public address
    #[command(name = "generate_address")]
    GenerateAddress,

    /// Typecheck a potential contract definition
    #[command(name = "check")]
    Check {
        /// Contract source file (or "-" for stdin)
        #[arg(value_name = "CONTRACT_FILE")]
        contract_file: PathBuf,

        /// Contract identifier
        #[arg(long)]
        contract_id: Option<String>,

        /// Output contract analysis
        #[arg(long)]
        output_analysis: bool,

        /// Output cost information
        #[arg(long)]
        costs: bool,

        /// Use testnet configuration
        #[arg(long)]
        testnet: bool,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Path to VM state database
        #[arg(value_name = "DB_PATH")]
        db_path: Option<PathBuf>,
    },

    /// Typecheck and evaluate expressions in a stdin/stdout loop
    #[command(name = "repl")]
    Repl {
        /// Use testnet configuration
        #[arg(long)]
        testnet: bool,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,
    },

    /// Typecheck and evaluate an expression without a contract or database context.
    ///
    /// Reads Clarity code from stdin:
    ///
    ///   echo "(+ 1 2)" | clarity-cli eval_raw
    ///
    ///   clarity-cli eval_raw < program.clar
    ///
    ///   clarity-cli eval_raw <<< "(+ 1 2)"
    #[command(name = "eval_raw")]
    EvalRaw {
        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,
    },

    /// Evaluate (in read-only mode) a program in a given contract context
    #[command(name = "eval")]
    Eval {
        /// Output cost information
        #[arg(long)]
        costs: bool,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,

        /// Contract identifier
        #[arg(value_name = "CONTRACT_ID")]
        contract_id: String,

        /// Program file (or "-" for stdin; if omitted, reads from stdin)
        #[arg(value_name = "PROGRAM_FILE")]
        program_file: Option<PathBuf>,

        /// Path to VM state database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,
    },

    /// Like eval, but does not advance to a new block
    #[command(name = "eval_at_chaintip")]
    EvalAtChaintip {
        /// Output cost information
        #[arg(long)]
        costs: bool,

        /// Coverage folder path
        #[arg(short = 'c', long)]
        coverage: Option<PathBuf>,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,

        /// Contract identifier
        #[arg(value_name = "CONTRACT_ID")]
        contract_id: String,

        /// Program file (or "-" for stdin; if omitted, reads from stdin)
        #[arg(value_name = "PROGRAM_FILE")]
        program_file: Option<PathBuf>,

        /// Path to VM state database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,
    },

    /// Like eval_at_chaintip, but accepts an index-block-hash to evaluate at.
    ///
    /// Reads Clarity code from stdin:
    ///
    ///   echo "(get-info)" | clarity-cli eval_at_block ...
    ///
    ///   clarity-cli eval_at_block ... < program.clar
    ///
    ///   clarity-cli eval_at_block ... <<< "(get-info)"
    #[command(name = "eval_at_block")]
    EvalAtBlock {
        /// Output cost information
        #[arg(long)]
        costs: bool,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Index block hash
        #[arg(value_name = "INDEX_BLOCK_HASH")]
        index_block_hash: String,

        /// Contract identifier
        #[arg(value_name = "CONTRACT_ID")]
        contract_id: String,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,

        /// Path to VM/clarity directory
        #[arg(value_name = "VM_DIR")]
        vm_dir: PathBuf,
    },

    /// Initialize a new contract in the local state database
    #[command(name = "launch")]
    Launch {
        /// Output cost information
        #[arg(long)]
        costs: bool,

        /// Output asset changes
        #[arg(long)]
        assets: bool,

        /// Output contract analysis
        #[arg(long)]
        output_analysis: bool,

        /// Coverage folder path
        #[arg(short = 'c', long)]
        coverage: Option<PathBuf>,

        /// Contract identifier
        #[arg(value_name = "CONTRACT_ID")]
        contract_id: String,

        /// Contract definition file (or "-" for stdin)
        #[arg(value_name = "CONTRACT_FILE")]
        contract_file: PathBuf,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Path to VM state database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,
    },

    /// Execute a public function of a defined contract.
    ///
    /// Arguments must be valid Clarity values (e.g., "u10" for uint, "'ST1..." for principal).
    /// Note: Principals require the Clarity quote prefix (').
    #[command(name = "execute")]
    Execute {
        /// Output cost information
        #[arg(long)]
        costs: bool,

        /// Output asset changes
        #[arg(long)]
        assets: bool,

        /// Coverage folder path
        #[arg(short = 'c', long)]
        coverage: Option<PathBuf>,

        /// Clarity version
        #[arg(long)]
        clarity_version: Option<String>,

        /// Stacks epoch
        #[arg(long)]
        epoch: Option<String>,

        /// Path to VM state database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,

        /// Contract identifier
        #[arg(value_name = "CONTRACT_ID")]
        contract_id: String,

        /// Public function name
        #[arg(value_name = "FUNCTION_NAME")]
        function_name: String,

        /// Sender address
        #[arg(value_name = "SENDER")]
        sender: String,

        /// Function arguments
        #[arg(value_name = "ARGS")]
        args: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let (exit_code, output) = match &cli.command {
        Commands::GenerateAddress => execute_generate_address(),

        Commands::Initialize {
            testnet,
            epoch,
            db_path,
            allocations_file,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let mainnet = !testnet;
            let allocations = parse_allocations(allocations_file);
            let db_name = db_path.to_str().expect("Invalid UTF-8 in db_path");

            execute_initialize(db_name, mainnet, epoch_id, allocations)
        }

        Commands::Check {
            contract_file,
            contract_id,
            output_analysis,
            costs,
            testnet,
            clarity_version,
            epoch,
            db_path,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);
            let mainnet = !testnet;

            let content = read_file_or_stdin(
                contract_file.to_str().expect("Invalid UTF-8 in contract_file"),
            );

            let cid = if let Some(cid_str) = contract_id {
                QualifiedContractIdentifier::parse(cid_str).unwrap_or_else(|e| {
                    panic!("Error parsing contract identifier '{}': {}", cid_str, e)
                })
            } else {
                QualifiedContractIdentifier::transient()
            };

            let db_path_str = db_path
                .as_ref()
                .map(|p| p.to_str().expect("Invalid UTF-8 in db_path"));

            execute_check(
                &content,
                &cid,
                *output_analysis,
                *costs,
                mainnet,
                clarity_ver,
                epoch_id,
                db_path_str,
                *testnet,
            )
        }

        Commands::Repl {
            testnet,
            epoch,
            clarity_version,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);
            let mainnet = !testnet;
            
            // Loop
            execute_repl(mainnet, epoch_id, clarity_ver)
        }

        Commands::EvalRaw {
            epoch,
            clarity_version,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);

            let content = read_file_or_stdin("-");

            execute_eval_raw(&content, epoch_id, clarity_ver)
        }

        Commands::Eval {
            costs,
            epoch,
            clarity_version,
            contract_id,
            program_file,
            db_path,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);

            let cid = QualifiedContractIdentifier::parse(contract_id)
                .unwrap_or_else(|e| panic!("Failed to parse contract identifier: {}", e));

            let content = read_optional_file_or_stdin(program_file.as_ref());

            let db_path_str = db_path.to_str().expect("Invalid UTF-8 in db_path");

            execute_eval(&cid, &content, *costs, epoch_id, clarity_ver, db_path_str)
        }

        Commands::EvalAtChaintip {
            costs,
            coverage,
            epoch,
            clarity_version,
            contract_id,
            program_file,
            db_path,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);

            let cid = QualifiedContractIdentifier::parse(contract_id)
                .unwrap_or_else(|e| panic!("Failed to parse contract identifier: {}", e));

            let content = read_optional_file_or_stdin(program_file.as_ref());

            let db_path_str = db_path.to_str().expect("Invalid UTF-8 in db_path");
            let coverage_str = coverage
                .as_ref()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string());

            execute_eval_at_chaintip(
                &cid,
                &content,
                *costs,
                epoch_id,
                clarity_ver,
                db_path_str,
                coverage_str,
            )
        }

        Commands::EvalAtBlock {
            costs,
            epoch,
            index_block_hash,
            contract_id,
            clarity_version,
            vm_dir,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);

            let cid = QualifiedContractIdentifier::parse(contract_id)
                .unwrap_or_else(|e| panic!("Failed to parse contract identifier: {}", e));

            let content = read_file_or_stdin("-");

            let vm_dir_str = vm_dir.to_str().expect("Invalid UTF-8 in vm_dir");

            execute_eval_at_block(
                index_block_hash,
                &cid,
                &content,
                *costs,
                epoch_id,
                clarity_ver,
                vm_dir_str,
            )
        }

        Commands::Launch {
            costs,
            assets,
            output_analysis,
            coverage,
            contract_id,
            contract_file,
            clarity_version,
            epoch,
            db_path,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);

            let cid = QualifiedContractIdentifier::parse(contract_id)
                .unwrap_or_else(|e| panic!("Failed to parse contract identifier: {}", e));

            let contract_src_file = contract_file
                .to_str()
                .expect("Invalid UTF-8 in contract_file");
            let contract_content = read_file_or_stdin(contract_src_file);

            let db_path_str = db_path.to_str().expect("Invalid UTF-8 in db_path");
            let coverage_str = coverage
                .as_ref()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string());

            execute_launch(
                &cid,
                contract_src_file,
                &contract_content,
                *costs,
                *assets,
                *output_analysis,
                epoch_id,
                clarity_ver,
                db_path_str,
                coverage_str,
            )
        }

        Commands::Execute {
            costs,
            assets,
            coverage,
            clarity_version,
            epoch,
            db_path,
            contract_id,
            function_name,
            sender,
            args: fn_args,
        } => {
            let epoch_id = parse_epoch(epoch.as_ref());
            let clarity_ver = parse_clarity_version(clarity_version.as_ref(), epoch_id);

            let cid = QualifiedContractIdentifier::parse(contract_id)
                .unwrap_or_else(|e| panic!("Failed to parse contract identifier: {}", e));

            let sender_principal = PrincipalData::parse_standard_principal(sender)
                .map(PrincipalData::Standard)
                .unwrap_or_else(|e| panic!("Unexpected result parsing sender {}: {}", sender, e));

            let arguments: Vec<_> = fn_args
                .iter()
                .map(|argument| {
                    let argument_parsed = vm_execute_in_epoch(argument, clarity_ver, epoch_id)
                        .unwrap_or_else(|e| panic!("Error parsing argument '{}': {}", argument, e));
                    let argument_value = argument_parsed.unwrap_or_else(|| {
                        panic!("Failed to parse a value from the argument: {}", argument)
                    });
                    SymbolicExpression::atom_value(argument_value)
                })
                .collect();

            let db_path_str = db_path.to_str().expect("Invalid UTF-8 in db_path");
            let coverage_str = coverage
                .as_ref()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string());

            execute_execute(
                db_path_str,
                &cid,
                function_name,
                sender_principal,
                &arguments,
                *costs,
                *assets,
                epoch_id,
                coverage_str,
            )
        }
    };

    // Output JSON result if present
    if let Some(json_output) = output {
        println!("{}", serde_json::to_string(&json_output).unwrap());
    }

    process::exit(exit_code);
}
