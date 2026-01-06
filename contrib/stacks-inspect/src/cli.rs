// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! CLI argument parsing for stacks-inspect using clap derive API

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Build the version string at compile time from Cargo metadata
fn build_version_string() -> &'static str {
    concat!(
        env!("CARGO_PKG_NAME"),
        " ",
        env!("CARGO_PKG_VERSION"),
        " (",
        env!("CARGO_PKG_REPOSITORY"),
        ")"
    )
}

/// Stacks blockchain inspection and debugging tool
#[derive(Parser, Debug)]
#[command(name = "stacks-inspect")]
#[command(author, version = build_version_string(), about, long_about = None)]
pub struct Cli {
    /// Path to stacks-node configuration file
    #[arg(long, global = true, value_name = "CONFIG_FILE")]
    pub config: Option<PathBuf>,

    /// Use a predefined network configuration (helium, mainnet, mocknet, xenon)
    #[arg(long, global = true, value_name = "NETWORK")]
    pub network: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    // ========== Decode Commands ==========
    /// Decode a Bitcoin block header from SPV data
    #[command(name = "decode-bitcoin-header")]
    DecodeBitcoinHeader {
        /// Block height to decode
        #[arg(value_name = "BLOCK_HEIGHT")]
        block_height: u64,

        /// Path to Bitcoin headers file
        #[arg(value_name = "HEADERS_PATH")]
        headers_path: PathBuf,

        /// Use testnet
        #[arg(short = 't', long, default_value_t = false)]
        testnet: bool,

        /// Use regtest
        #[arg(short = 'r', long, default_value_t = false)]
        regtest: bool,
    },

    /// Decode and print a Stacks transaction
    #[command(name = "decode-tx")]
    DecodeTx {
        /// Transaction hex string, path to file, or "-" for stdin
        #[arg(value_name = "TX_HEX_OR_FILE")]
        tx_input: String,
    },

    /// Decode and print a Stacks block (epoch 2.x)
    #[command(name = "decode-block")]
    DecodeBlock {
        /// Path to block file or "-" for stdin
        #[arg(value_name = "BLOCK_PATH")]
        block_path: String,
    },

    /// Decode and print a Nakamoto block
    #[command(name = "decode-nakamoto-block")]
    DecodeNakamotoBlock {
        /// Block hex string, path to file, or "-" for stdin
        #[arg(value_name = "BLOCK_HEX_OR_FILE")]
        block_input: String,
    },

    /// Decode and print a Stacks network message
    #[command(name = "decode-net-message")]
    DecodeNetMessage {
        /// Message data as JSON byte array, path to file, or "-" for stdin
        #[arg(value_name = "MESSAGE_DATA")]
        message_data: String,
    },

    /// Decode and print a microblock stream
    #[command(name = "decode-microblocks")]
    DecodeMicroblocks {
        /// Path to microblock stream file or "-" for stdin
        #[arg(value_name = "MICROBLOCKS_PATH")]
        microblocks_path: String,
    },

    // ========== MARF/Database Commands ==========
    /// Query header-indexed MARF data
    ///
    /// Can be called in two ways:
    /// - With state directory: header-indexed-get STATE_DIR BLOCK_ID_HASH KEY
    /// - With explicit paths: header-indexed-get MARF_PATH DATA_DB_PATH BLOCK_ID_HASH KEY
    #[command(name = "header-indexed-get")]
    HeaderIndexedGet {
        /// State directory, MARF index path, or MARF path when data_db_path is specified
        #[arg(value_name = "STATE_DIR_OR_MARF_PATH")]
        state_dir: String,

        /// Block ID hash to query at (or DATA_DB_PATH if 4 positional args given)
        #[arg(value_name = "BLOCK_ID_HASH_OR_DATA_DB")]
        block_id_hash_or_data_db: String,

        /// MARF key to lookup (or BLOCK_ID_HASH if 4 positional args given)
        #[arg(value_name = "KEY_OR_BLOCK_ID_HASH")]
        key_or_block_id: String,

        /// MARF key (only when data_db_path is also provided)
        #[arg(value_name = "KEY")]
        key: Option<String>,
    },

    /// Get a value from the MARF database
    #[command(name = "marf-get")]
    MarfGet {
        /// Path to MARF database
        #[arg(value_name = "MARF_PATH")]
        marf_path: PathBuf,

        /// Block header hash
        #[arg(value_name = "TIP_HASH")]
        tip_hash: String,

        /// Consensus hash
        #[arg(value_name = "CONSENSUS_HASH")]
        consensus_hash: String,

        /// Key to lookup
        #[arg(value_name = "KEY")]
        key: String,
    },

    /// Deserialize values from Clarity database
    #[command(name = "deserialize-db")]
    DeserializeDb {
        /// Path to Clarity SQLite database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,

        /// Byte prefix to filter keys
        #[arg(value_name = "BYTE_PREFIX")]
        byte_prefix: String,
    },

    /// Verify deserialized data from file
    #[command(name = "check-deser-data")]
    CheckDeserData {
        /// Path to check file
        #[arg(value_name = "CHECK_FILE")]
        check_file: PathBuf,
    },

    /// Trace block ancestry through staging database
    #[command(name = "get-ancestors")]
    GetAncestors {
        /// Path to staging database
        #[arg(value_name = "DB_PATH")]
        db_path: PathBuf,

        /// Block header hash
        #[arg(value_name = "BLOCK_HASH")]
        block_hash: String,

        /// Burn header hash
        #[arg(value_name = "BURN_HASH")]
        burn_hash: String,
    },

    // ========== Shadow Block Commands ==========
    /// Create a shadow block from transactions
    #[command(name = "make-shadow-block")]
    MakeShadowBlock {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_DIR")]
        chainstate_dir: String,

        /// Network (mainnet, krypton, naka3)
        #[arg(value_name = "NETWORK")]
        network: String,

        /// Chain tip block hash
        #[arg(value_name = "CHAIN_TIP")]
        chain_tip: String,

        /// Transaction hex strings to include
        #[arg(value_name = "TX_HEX")]
        txs: Vec<String>,
    },

    /// Repair shadow chainstate by generating and applying shadow blocks
    #[command(name = "shadow-chainstate-repair")]
    ShadowChainstateRepair {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_DIR")]
        chainstate_dir: String,

        /// Network (mainnet, krypton, naka3)
        #[arg(value_name = "NETWORK")]
        network: String,
    },

    /// Apply shadow blocks from JSON to chainstate
    #[command(name = "shadow-chainstate-patch")]
    ShadowChainstatePatch {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_DIR")]
        chainstate_dir: String,

        /// Network (mainnet, krypton, naka3)
        #[arg(value_name = "NETWORK")]
        network: String,

        /// Path to shadow blocks JSON file or "-" for stdin
        #[arg(value_name = "SHADOW_BLOCKS_JSON")]
        shadow_blocks_path: String,
    },

    /// Add a shadow block to chainstate
    #[command(name = "add-shadow-block")]
    AddShadowBlock {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_DIR")]
        chainstate_dir: String,

        /// Network (mainnet, krypton, naka3)
        #[arg(value_name = "NETWORK")]
        network: String,

        /// Shadow block hex
        #[arg(value_name = "SHADOW_BLOCK_HEX")]
        shadow_block_hex: String,
    },

    // ========== Nakamoto Commands ==========
    /// Get the Nakamoto chain tip
    #[command(name = "get-nakamoto-tip")]
    GetNakamotoTip {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_DIR")]
        chainstate_dir: String,

        /// Network (mainnet, krypton, naka3)
        #[arg(value_name = "NETWORK")]
        network: String,
    },

    /// Get account state at a chain tip
    #[command(name = "get-account")]
    GetAccount {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_DIR")]
        chainstate_dir: String,

        /// Network (mainnet, krypton, naka3)
        #[arg(value_name = "NETWORK")]
        network: String,

        /// Stacks address to query
        #[arg(value_name = "ADDRESS")]
        address: String,

        /// Optional chain tip to query at
        #[arg(value_name = "CHAIN_TIP")]
        chain_tip: Option<String>,
    },

    /// Get Nakamoto inventory from a peer
    #[command(name = "getnakamotoinv")]
    GetNakamotoInv {
        /// Peer address (HOST:PORT)
        #[arg(value_name = "PEER_ADDR")]
        peer_addr: String,

        /// Data port
        #[arg(value_name = "DATA_PORT")]
        data_port: u16,

        /// Consensus hash to query
        #[arg(value_name = "CONSENSUS_HASH")]
        consensus_hash: String,
    },

    // ========== Mining Commands ==========
    /// Simulate mining an anchored block
    #[command(name = "try-mine")]
    TryMine {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_PATH")]
        chainstate_path: String,

        /// Optional block to mine at (default: chain tip)
        #[arg(value_name = "AT_BLOCK")]
        at_block: Option<String>,

        /// Optional path to estimator to use
        #[arg(long, value_name = "ESTIMATOR")]
        estimator: Option<String>,

        /// Optional minimum fee to use
        #[arg(long, value_name = "MIN_FEE")]
        min_fee: Option<u64>,

        /// Optional maximum time in milliseconds for the mining process
        #[arg(long, value_name = "MAX_TIME")]
        max_time: Option<u64>,
    },

    /// Mine a block at tip height using event log
    #[command(name = "tip-mine")]
    TipMine {
        /// Working directory
        #[arg(value_name = "WORKING_DIR")]
        working_dir: String,

        /// Event log file path
        #[arg(value_name = "EVENT_LOG")]
        event_log: PathBuf,

        /// Target block height to mine at
        #[arg(value_name = "MINE_TIP_HEIGHT")]
        mine_tip_height: u64,

        /// Maximum transactions to include
        #[arg(value_name = "MAX_TXNS")]
        max_txns: u64,
    },

    /// Replay mock-mined blocks from JSON files
    #[command(name = "replay-mock-mining")]
    ReplayMockMining {
        /// Path to chainstate directory
        #[arg(value_name = "CHAINSTATE_PATH")]
        chainstate_path: String,

        /// Path to mock mining output directory
        #[arg(value_name = "MOCK_MINING_OUTPUT_PATH")]
        mock_mining_output_path: String,
    },

    // ========== Validation Commands ==========
    /// Validate Stacks blocks from chainstate database
    #[command(name = "validate-block")]
    ValidateBlock {
        /// Path to chainstate database
        #[arg(value_name = "DATABASE_PATH")]
        database_path: String,

        /// Query mode: prefix, index-range, range, first, or last
        #[arg(value_name = "MODE")]
        mode: Option<String>,

        /// Arguments for the query mode
        #[arg(value_name = "ARGS")]
        args: Vec<String>,
    },

    /// Validate Nakamoto blocks from chainstate database
    #[command(name = "validate-naka-block")]
    ValidateNakaBlock {
        /// Path to chainstate database
        #[arg(value_name = "DATABASE_PATH")]
        database_path: String,

        /// Query mode: prefix, index-range, range, first, or last
        #[arg(value_name = "MODE")]
        mode: Option<String>,

        /// Arguments for the query mode
        #[arg(value_name = "ARGS")]
        args: Vec<String>,
    },

    // ========== Chain State Commands ==========
    /// Get block tenure information
    #[command(name = "get-tenure")]
    GetTenure {
        /// Path to chainstate directory
        #[arg(value_name = "CHAIN_STATE_DIR")]
        chain_state_dir: String,

        /// Index block hash
        #[arg(value_name = "BLOCK_HASH")]
        block_hash: String,
    },

    /// Get block inventory (2100 headers)
    #[command(name = "get-block-inventory")]
    GetBlockInventory {
        /// Path to working directory
        #[arg(value_name = "WORKING_DIR")]
        working_dir: String,
    },

    /// Check if microblocks can be downloaded
    #[command(name = "can-download-microblock")]
    CanDownloadMicroblock {
        /// Path to working directory
        #[arg(value_name = "WORKING_DIR")]
        working_dir: String,
    },

    /// Replay chainstate from old to new database
    #[command(name = "replay-chainstate")]
    ReplayChainstate {
        /// Old chainstate path
        #[arg(value_name = "OLD_CHAINSTATE_PATH")]
        old_chainstate_path: String,

        /// Old sortition DB path
        #[arg(value_name = "OLD_SORTITION_PATH")]
        old_sortition_path: String,

        /// Old burnchain DB path
        #[arg(value_name = "OLD_BURNCHAIN_PATH")]
        old_burnchain_path: String,

        /// New chainstate path
        #[arg(value_name = "NEW_CHAINSTATE_PATH")]
        new_chainstate_path: String,

        /// New burnchain DB path
        #[arg(value_name = "NEW_BURNCHAIN_PATH")]
        new_burnchain_path: String,
    },

    // ========== PoX/Sortition Commands ==========
    /// Evaluate PoX anchor selection at a block height
    #[command(name = "evaluate-pox-anchor")]
    EvaluatePoxAnchor {
        /// Path to sortition database
        #[arg(value_name = "SORTITION_DB_PATH")]
        sortition_db_path: PathBuf,

        /// Start height to evaluate
        #[arg(value_name = "START_HEIGHT")]
        start_height: u64,

        /// End height (optional, defaults to start_height)
        #[arg(value_name = "END_HEIGHT")]
        end_height: Option<u64>,
    },

    /// Analyze sortition MEV across epochs
    #[command(name = "analyze-sortition-mev")]
    AnalyzeSortitionMev {
        /// Path to burnchain database
        #[arg(value_name = "BURNCHAIN_DB_PATH")]
        burnchain_db_path: String,

        /// Path to sortition database
        #[arg(value_name = "SORTITION_DB_PATH")]
        sortition_db_path: String,

        /// Path to chainstate database
        #[arg(value_name = "CHAINSTATE_PATH")]
        chainstate_path: String,

        /// Start block height
        #[arg(value_name = "START_HEIGHT")]
        start_height: u64,

        /// End block height
        #[arg(value_name = "END_HEIGHT")]
        end_height: u64,

        /// Advantage adjustments (pairs of miner address and burn bonus)
        #[arg(value_name = "ADVANTAGES")]
        advantages: Vec<String>,
    },

    // ========== Utility Commands ==========
    /// Generate peer public key from seed
    #[command(name = "peer-pub-key")]
    PeerPubKey {
        /// Local peer seed (hex)
        #[arg(value_name = "LOCAL_PEER_SEED")]
        local_peer_seed: String,
    },

    /// Create a signed StackerDB chunk
    #[command(name = "post-stackerdb")]
    PostStackerDb {
        /// Slot ID
        #[arg(value_name = "SLOT_ID")]
        slot_id: u32,

        /// Slot version
        #[arg(value_name = "SLOT_VERSION")]
        slot_version: u32,

        /// Private key (hex)
        #[arg(value_name = "PRIVATE_KEY")]
        private_key: String,

        /// Data (hex string, file path, or "-" for stdin)
        #[arg(value_name = "DATA")]
        data: String,
    },

    /// Compute contract hash from source
    #[command(name = "contract-hash")]
    ContractHash {
        /// Contract source file or "-" for stdin
        #[arg(value_name = "CONTRACT_SOURCE")]
        contract_source: String,
    },

    /// Output blockchain constants as JSON
    #[command(name = "dump-consts")]
    DumpConsts,

    /// Generate Clarity API reference as JSON
    #[command(name = "docgen")]
    Docgen,

    /// Generate boot contracts reference as JSON
    #[command(name = "docgen_boot")]
    DocgenBoot,

    /// Execute a Clarity program file
    #[command(name = "exec_program")]
    ExecProgram {
        /// Path to Clarity program file
        #[arg(value_name = "PROGRAM_FILE")]
        program_file: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli_structure() {
        // Validates that all clap attributes are correct
        Cli::command().debug_assert();
    }

    #[test]
    fn test_decode_tx_parsing() {
        let cli = Cli::try_parse_from([
            "stacks-inspect",
            "decode-tx",
            "0x00000001",
        ]).unwrap();

        match cli.command {
            Command::DecodeTx { tx_input } => {
                assert_eq!(tx_input, "0x00000001");
            }
            _ => panic!("Expected DecodeTx command"),
        }
    }

    #[test]
    fn test_global_options() {
        let cli = Cli::try_parse_from([
            "stacks-inspect",
            "--network", "mainnet",
            "docgen",
        ]).unwrap();

        assert_eq!(cli.network, Some("mainnet".to_string()));
        assert!(matches!(cli.command, Command::Docgen));
    }

    #[test]
    fn test_config_option() {
        let cli = Cli::try_parse_from([
            "stacks-inspect",
            "--config", "/path/to/config.toml",
            "dump-consts",
        ]).unwrap();

        assert_eq!(cli.config, Some(PathBuf::from("/path/to/config.toml")));
        assert!(matches!(cli.command, Command::DumpConsts));
    }
}
