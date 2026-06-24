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

use std::time::Instant;

use anyhow::Result;
use stacks_bench::bench_events::{self, BenchEvent, BenchEventSender};
use stacks_bench::db::app::{AppDb, CheckpointMode};
use stacks_bench::shadow::ShadowDir;

pub async fn run_cleanup_with_events(
    mut app_db: AppDb,
    shadow_dir: ShadowDir,
    ev: &BenchEventSender,
) -> Result<()> {
    let is_passthrough = shadow_dir.is_passthrough();
    bench_events::emit(
        ev,
        BenchEvent::CleanupStarted {
            passthrough: is_passthrough,
        },
    );

    // In passthrough mode there's no temp dir to remove — dropping the
    // ShadowDir is a no-op, and emitting `CleanupShadowDirComplete` would be
    // misleading ("Shadow directory removed" against the user's actual
    // chainstate). Just drop synchronously and skip the event.
    let shadow_start = Instant::now();
    let shadow_handle = tokio::task::spawn_blocking(move || drop(shadow_dir));

    let db_start = Instant::now();
    let ev_db = ev.clone();
    let db_handle = tokio::spawn(async move {
        let result = async {
            app_db.checkpoint(CheckpointMode::Truncate).await?;
            app_db.vacuum().await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match result {
            Ok(()) => bench_events::emit(
                &ev_db,
                BenchEvent::CleanupDbComplete {
                    duration: db_start.elapsed(),
                },
            ),
            Err(ref e) => bench_events::emit(
                &ev_db,
                BenchEvent::CleanupDbFailed {
                    error: format!("{e:#}"),
                    duration: db_start.elapsed(),
                },
            ),
        }
        result
    });

    let _ = shadow_handle.await;
    if !is_passthrough {
        bench_events::emit(
            ev,
            BenchEvent::CleanupShadowDirComplete {
                duration: shadow_start.elapsed(),
            },
        );
    }

    // Best-effort: don't fail the run if cleanup fails
    let _ = db_handle.await;

    bench_events::emit(ev, BenchEvent::CleanupComplete);
    Ok(())
}
