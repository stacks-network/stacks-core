use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Offline squashing CLI for Index, Clarity, and Sortition MARF snapshots.
#[derive(Parser, Debug)]
#[command(
    name = "marf-squash",
    about = "Offline squashing tool for Index, Clarity, and Sortition MARFs"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create squashed MARFs and copy canonical chain data.
    Squash(SquashArgs),
}

/// Arguments for generating squashed MARFs.
#[derive(Parser, Debug)]
pub struct SquashArgs {
    /// Path to the chainstate folder (the parent of chainstate/ and burnchain/).
    #[arg(long, value_name = "DIR")]
    pub chainstate: PathBuf,
    /// Output directory for the squashed MARF files.
    #[arg(long = "out-dir", value_name = "DIR")]
    pub out_dir: PathBuf,
    /// Bitcoin block height where a Nakamoto tenure started (sortition=true).
    /// The snapshot includes the complete tenure: all Stacks blocks produced
    /// by the miner who won this sortition. Epoch 3.x (Nakamoto) only.
    #[arg(long, value_name = "HEIGHT")]
    pub tenure_start_bitcoin_height: u64,
    /// Squash the Clarity MARF (chainstate/vm/clarity/marf.sqlite).
    #[arg(long)]
    pub clarity: bool,
    /// Squash the Index MARF (chainstate/vm/index.sqlite).
    #[arg(long)]
    pub index: bool,
    /// Squash the Sortition MARF (burnchain/sortition/marf.sqlite).
    #[arg(long)]
    pub sortition: bool,
    /// Squash all three MARFs and copy all auxiliary data (blocks + bitcoin).
    #[arg(long)]
    pub all: bool,
    /// Copy canonical block data (epoch 2.x files, confirmed microblocks, nakamoto.sqlite).
    /// Requires --index (or --all).
    #[arg(long)]
    pub blocks: bool,
    /// Copy Bitcoin auxiliary files (burnchain.sqlite + headers.sqlite).
    /// Requires --sortition (or --all).
    #[arg(long)]
    pub bitcoin: bool,
    /// Path to the node config TOML file. Used to extract PoX constants
    /// Required for testnet.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TargetPaths {
    pub db: PathBuf,
    pub blobs: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ChainstatePaths {
    pub clarity: TargetPaths,
    pub index: TargetPaths,
    pub sortition: TargetPaths,
}

#[derive(Serialize, Deserialize)]
pub struct SquashManifest {
    pub snapshot: SnapshotSection,
    pub roots: RootsSection,
    pub squash_roots: SquashRootsSection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<BlocksSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksums: Option<ChecksumsSection>,
}

#[derive(Serialize, Deserialize)]
pub struct SnapshotSection {
    pub version: u32,
    pub stacks_height: u32,
    pub bitcoin_height: u64,
    pub block_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub chain_id: u32,
    pub mainnet: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RootsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clarity_archival_marf_root_hash: Option<String>,
    pub index_archival_marf_root_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sortition_archival_marf_root_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SquashRootsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clarity_squash_root_node_hash: Option<String>,
    pub index_squash_root_node_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sortition_squash_root_node_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BlocksSection {
    pub epoch2x_files: u64,
    pub epoch2x_bytes: u64,
    pub epoch2x_microblock_rows: u64,
    pub epoch2x_microblock_bytes: u64,
    pub nakamoto_rows: u64,
    pub nakamoto_bytes: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ChecksumsSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch2_block_archive_hash: Option<String>,
    pub files: BTreeMap<String, String>,
}

/// Manifest file names.
pub const GSS_MANIFEST: &str = "GSS_manifest.toml";

/// File extensions that indicate SQLite sidecars (WAL, SHM, journal).
pub const SQLITE_SIDECAR_EXTENSIONS: &[&str] = &["sqlite-wal", "sqlite-shm", "sqlite-journal"];
