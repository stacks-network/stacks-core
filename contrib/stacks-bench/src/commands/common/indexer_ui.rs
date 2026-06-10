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

use anyhow::Result;
use stacks_bench::indexer::IndexerEvent;
use tokio::sync::mpsc;

/// Spawner for indexer event consumers. The caller provides this to control
/// how indexer progress is rendered (CLI progress bar, MCP notifications,
/// or silent drain).
///
/// Implementations must be re-invocable so multi-target benchmark runs can
/// drive one UI session per indexed window.
pub type IndexerUiSpawner = Box<
    dyn Fn(
            mpsc::UnboundedReceiver<IndexerEvent>,
            u64, // start_height
            u64, // end_height
            u64, // tip_height
        ) -> tokio::task::JoinHandle<Result<()>>
        + Send
        + Sync,
>;

/// Returns an [`IndexerUiSpawner`] that silently drains all events.
pub fn silent_indexer_ui() -> IndexerUiSpawner {
    Box::new(|rx, _, _, _| {
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
            Ok(())
        })
    })
}
