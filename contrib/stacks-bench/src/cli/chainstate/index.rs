// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use stacks_bench::{Network, StacksBlockRef};

use crate::cli::common::{CliContext, ExecCommand, run_indexer_progress_ui};
use crate::commands::chainstate::index::ChainstateIndexParams;
// Re-export for use by other CLI consumers
pub use crate::commands::chainstate::index::IndexResult;
use crate::commands::common::{IndexerArgs, IndexerUiSpawner};

#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct IndexArgs {
    /// Stacks node data dir (the directory containing the `chainstate` folder).
    #[arg(long = "source", short = 's')]
    source_dir: PathBuf,

    /// The Stacks block (height, index_block_hash, or canonical block_hash) to start at, inclusive.
    #[arg(long, default_value = "1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    start_at: Option<StacksBlockRef>,

    /// The Stacks block (height, index_block_hash, or canonical block_hash) to end at, inclusive.
    /// Cannot be used with the `count` flag.
    #[arg(long, conflicts_with_all = &["block_count"])]
    #[serde(skip_serializing_if = "Option::is_none")]
    end_at: Option<StacksBlockRef>,

    /// The number of blocks to process, starting from `start-at`.
    #[arg(long = "count", short = 'c', conflicts_with_all = &["end_at"], requires = "start_at")]
    #[serde(skip_serializing_if = "Option::is_none")]
    block_count: Option<u32>,

    /// The tip block (height, index_block_hash, or canonical block_hash) to use as the anchor for
    /// resolving canonical history.
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    tip: Option<StacksBlockRef>,

    /// The network to use (`mainnet`, `testnet`, `regtest`).
    #[arg(long, short = 'n', alias = "net")]
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}

impl IndexerArgs for IndexArgs {
    fn start_at(&self) -> Option<&StacksBlockRef> {
        self.start_at.as_ref()
    }
    fn end_at(&self) -> Option<&StacksBlockRef> {
        self.end_at.as_ref()
    }
    fn block_count(&self) -> Option<u32> {
        self.block_count
    }
    fn tip(&self) -> Option<&StacksBlockRef> {
        self.tip.as_ref()
    }
    fn network(&self) -> Option<Network> {
        self.network
    }
}

impl From<&IndexArgs> for ChainstateIndexParams {
    fn from(args: &IndexArgs) -> Self {
        Self {
            source_dir: args.source_dir.clone(),
            start_at: args.start_at.clone(),
            end_at: args.end_at.clone(),
            block_count: args.block_count,
            tip: args.tip.clone(),
            network: args.network,
        }
    }
}

impl ExecCommand for IndexArgs {
    type Output = IndexResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let mut app_db = ctx.app_db();
        let params = ChainstateIndexParams::from(self);

        let indexer_ui: IndexerUiSpawner = if ctx.interactive() {
            Box::new(|rx, start, end, tip| {
                tokio::spawn(run_indexer_progress_ui(rx, start, end, tip))
            })
        } else {
            crate::commands::common::silent_indexer_ui()
        };

        // Install ctrl-c handler for graceful cancellation.
        let interrupted = Arc::new(AtomicBool::new(false));
        {
            let interrupted = interrupted.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                interrupted.store(true, Ordering::Relaxed);
            });
        }

        let result = crate::commands::chainstate::index::index_chainstate(
            &mut app_db,
            &params,
            indexer_ui,
            interrupted,
        )
        .await?;

        if ctx.interactive() {
            cliclack::note(
                "Indexing Complete",
                format!(
                    "Start: {} (height {})\n\
                     End:   {} (height {})",
                    result.start_block, result.start_height, result.end_block, result.end_height,
                ),
            )?;
        }

        Ok(result)
    }
}
