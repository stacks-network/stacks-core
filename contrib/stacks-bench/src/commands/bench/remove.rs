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
use serde::Serialize;
use stacks_bench::db::app::{AppDb, CheckpointMode};

#[derive(Serialize)]
pub struct RemoveResult {
    pub deleted_run_ids: Vec<i32>,
    pub message: String,
}

/// Delete the given benchmark runs and optionally run checkpoint + vacuum.
///
/// All run IDs must correspond to existing runs — callers are responsible for
/// validation beforehand (or catching the DB error).
pub async fn delete_benchmark_runs(
    app_db: &mut AppDb,
    run_ids: &[i32],
    cleanup: bool,
) -> Result<RemoveResult> {
    for &id in run_ids {
        app_db.delete_benchmark_run(id).await?;
    }

    if cleanup {
        let _ = app_db.checkpoint(CheckpointMode::Truncate).await;
        let _ = app_db.vacuum().await;
    }

    Ok(RemoveResult {
        deleted_run_ids: run_ids.to_vec(),
        message: format!("{} benchmark run(s) deleted", run_ids.len()),
    })
}
