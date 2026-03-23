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

use clap::{Args, Subcommand};

use crate::BenchKind;
use crate::runner::{BenchEnvOverrides, BenchRunRequest};

/// Supported benchmark targets and their argument sets.
#[derive(Debug, Subcommand)]
pub enum BenchTarget {
    /// Run MARF primitive microbenchmarks.
    #[command(name = "primitives")]
    Primitives(PrimitivesArgs),
    /// Run MARF read-path benchmarks.
    Read(ReadArgs),
    /// Run MARF write-path benchmarks.
    Write(WriteArgs),
    /// Run MARF patch-node compression benchmarks.
    Patch(PatchArgs),
}

impl BenchTarget {
    /// Convert command input into one or more benchmark run requests.
    pub fn into_requests(self) -> Vec<BenchRunRequest> {
        match self {
            Self::Primitives(args) => vec![BenchRunRequest::new(
                BenchKind::Primitives,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    ..Default::default()
                },
            )],
            Self::Read(args) => vec![BenchRunRequest::new(
                BenchKind::Read,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    chain_len: args.chain_len,
                    read_proofs: Some(args.proofs),
                    keys_per_block: args.keys_per_block,
                    depths: args.depths,
                    compression: args.compression,
                    sqlite_wal_autocheckpoint: args.sqlite_wal_autocheckpoint,
                    sqlite_wal_checkpoint_mode: args.sqlite_wal_checkpoint_mode,
                    ..Default::default()
                },
            )],
            Self::Write(args) => vec![BenchRunRequest::new(
                BenchKind::Write,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    key_updates: args.key_updates,
                    write_depths: args.write_depths,
                    sqlite_wal_autocheckpoint: args.sqlite_wal_autocheckpoint,
                    sqlite_wal_checkpoint_mode: args.sqlite_wal_checkpoint_mode,
                    key_search_max_tries: args.key_search_max_tries,
                    compression: args.compression,
                    ..Default::default()
                },
            )],
            Self::Patch(args) => vec![BenchRunRequest::new(
                BenchKind::Patch,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    node_types: args.node_types,
                    ptr_states: args.ptr_states,
                    patch_diffs: args.patch_diffs,
                    ..Default::default()
                },
            )],
        }
    }
}

/// Arguments for the `primitives` benchmark target.
#[derive(Debug, Args)]
pub struct PrimitivesArgs {
    /// Set ITERS for primitives case loop count.
    #[arg(long)]
    iters: Option<usize>,

    /// Set ROUNDS for primitives repeated case runs.
    #[arg(long)]
    rounds: Option<usize>,
}

/// Arguments for the `read` benchmark target.
#[derive(Debug, Args)]
pub struct ReadArgs {
    /// Set CHAIN_LEN for read fixture length.
    #[arg(long)]
    chain_len: Option<u32>,

    /// Set ITERS for read per-case loop count.
    #[arg(long)]
    iters: Option<usize>,

    /// Set ROUNDS for read repeated case runs.
    #[arg(long)]
    rounds: Option<usize>,

    /// Enable proofed reads (MARF::get_with_proof).
    #[arg(long)]
    proofs: bool,

    /// Set KEYS_PER_BLOCK additional noise/bulk keys per block for read.
    #[arg(long)]
    keys_per_block: Option<u32>,

    /// Set DEPTHS as comma-separated values (for example: 32,128,256).
    #[arg(long)]
    depths: Option<String>,

    /// Set COMPRESSION modes as comma-separated values (for example: true,false).
    #[arg(long)]
    compression: Option<String>,

    /// Set SQLITE_WAL_AUTOCHECKPOINT page threshold for read benchmark SQLite connection.
    #[arg(long)]
    sqlite_wal_autocheckpoint: Option<usize>,

    /// Set SQLITE_WAL_CHECKPOINT_MODE for post-setup checkpoint when SQLITE_WAL_AUTOCHECKPOINT=0 (PASSIVE|FULL|RESTART|TRUNCATE).
    #[arg(long)]
    sqlite_wal_checkpoint_mode: Option<String>,
}

/// Arguments for the `write` benchmark target.
#[derive(Debug, Args)]
pub struct WriteArgs {
    /// Set ITERS for write inserted keys per workflow round.
    #[arg(long)]
    iters: Option<usize>,

    /// Set ROUNDS for write repeated workflow runs.
    #[arg(long)]
    rounds: Option<usize>,

    /// Set WRITE_DEPTHS as comma-separated values (for example: 1,64,1024).
    #[arg(long)]
    write_depths: Option<String>,

    /// Set KEY_UPDATES percent (0-100) for write update share of total writes.
    #[arg(long)]
    key_updates: Option<usize>,

    /// Set SQLITE_WAL_AUTOCHECKPOINT page threshold for write benchmark SQLite connection.
    #[arg(long)]
    sqlite_wal_autocheckpoint: Option<usize>,

    /// Set SQLITE_WAL_CHECKPOINT_MODE for post-setup checkpoint when SQLITE_WAL_AUTOCHECKPOINT=0 (PASSIVE|FULL|RESTART|TRUNCATE).
    #[arg(long)]
    sqlite_wal_checkpoint_mode: Option<String>,

    /// Set KEY_SEARCH_MAX_TRIES for write promotion-key search budget.
    #[arg(long)]
    key_search_max_tries: Option<usize>,

    /// Set COMPRESSION modes as comma-separated values (for example: true,false).
    #[arg(long)]
    compression: Option<String>,
}

/// Arguments for the `patch` benchmark target.
#[derive(Debug, Args)]
pub struct PatchArgs {
    /// Set ITERS for patch benchmark loop count.
    #[arg(long)]
    iters: Option<usize>,

    /// Set ROUNDS for patch repeated case runs.
    #[arg(long)]
    rounds: Option<usize>,

    /// Set NODE_TYPES as comma-separated values (for example: node4,node16,node48,node256 or all).
    #[arg(long)]
    node_types: Option<String>,

    /// Set PTR_STATES as comma-separated values (for example: backptr,plain or all).
    #[arg(long)]
    ptr_states: Option<String>,

    /// Set PATCH_DIFFS as comma-separated diff sizes (for example: 1,4,16,64).
    #[arg(long)]
    patch_diffs: Option<String>,
}
