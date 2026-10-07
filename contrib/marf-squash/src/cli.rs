// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    /// Create squashed MARFs from a source chainstate.
    Squash(SquashArgs),
}

/// Arguments for generating squashed MARFs.
#[derive(Parser, Debug)]
pub struct SquashArgs {
    /// Path to the chainstate folder (the parent of chainstate/ and burnchain/).
    #[arg(long, value_name = "DIR")]
    pub chainstate: PathBuf,
    /// Output directory -- the node's `working_dir`. The squash writes a
    /// directly bootable `<out-dir>/<network>/` tree. `<network>` is `mainnet`
    /// for a mainnet chainstate, otherwise the source chainstate's own
    /// subdirectory name (e.g. `krypton`).
    #[arg(long = "out-dir", value_name = "DIR")]
    pub out_dir: PathBuf,
    /// Bitcoin block height where a Nakamoto tenure started (sortition=true).
    /// The snapshot includes the complete tenure: all Stacks blocks produced
    /// by the miner who won this sortition. Epoch 3.x (Nakamoto) only.
    #[arg(long, value_name = "HEIGHT")]
    pub tenure_start_bitcoin_height: u32,
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
    /// Requires --index (is implied by --all).
    #[arg(long)]
    pub blocks: bool,
    /// Copy Bitcoin auxiliary files (burnchain.sqlite + headers.sqlite).
    /// Requires --sortition (is implied by --all).
    #[arg(long)]
    pub bitcoin: bool,
    /// Path to the node config TOML file. Used to extract PoX constants
    /// Required for testnet.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}
