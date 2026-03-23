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

use std::hint::black_box;
use std::time::Instant;

use rusqlite::Connection;

use crate::allocator::{reset_stats, snapshot, Snapshot};

/// Output mode selected by `OUTPUT_FORMAT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    /// Emit only normalized summary rows.
    Summary,
    /// Emit detailed benchmark lines in addition to summaries.
    Raw,
}

impl OutputMode {
    /// Return true when detailed/raw output is enabled.
    pub fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }
}

/// A single summary row emitted by a subcommand benchmark run.
#[derive(Clone, Debug)]
pub struct SummaryLine {
    pub name: String,
    pub total_ms: f64,
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

/// Grouped summary output for one benchmark subcommand.
#[derive(Clone, Debug)]
pub struct Summary {
    pub title: &'static str,
    pub lines: Vec<SummaryLine>,
}

impl Summary {
    /// Create an empty summary with a preallocated number of rows.
    pub fn new(title: &'static str, capacity: usize) -> Self {
        Self {
            title,
            lines: Vec::with_capacity(capacity),
        }
    }

    /// Append one measured case to the summary table.
    pub fn push_line(
        &mut self,
        name: impl Into<String>,
        total_ms: f64,
        alloc_count: u64,
        alloc_bytes: u64,
    ) {
        self.lines.push(SummaryLine {
            name: name.into(),
            total_ms,
            alloc_count,
            alloc_bytes,
        });
    }
}

/// Parse output mode from `OUTPUT_FORMAT`.
pub fn parse_output_mode() -> OutputMode {
    match std::env::var("OUTPUT_FORMAT").ok().as_deref() {
        Some("raw") => OutputMode::Raw,
        _ => OutputMode::Summary,
    }
}

/// Print unified summary lines in tab-separated format.
pub fn print_summary(summary: &Summary) {
    println!("summary\tbenchmark\tname\ttotal_ms\talloc_count\talloc_bytes");
    for line in &summary.lines {
        println!(
            "summary\t{}\t{}\t{:.3}\t{}\t{}",
            summary.title, line.name, line.total_ms, line.alloc_count, line.alloc_bytes
        );
    }
}

/// SQLite WAL checkpoint mode accepted by benchmark configuration.
#[derive(Clone, Copy, Debug)]
pub enum WalCheckpointMode {
    /// Non-blocking checkpoint work.
    Passive,
    /// Full checkpoint mode.
    Full,
    /// Restart WAL after checkpointing.
    Restart,
    /// Truncate WAL after checkpointing.
    Truncate,
}

impl WalCheckpointMode {
    /// Parse mode from a case-insensitive string value.
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.eq_ignore_ascii_case("passive") {
            Some(Self::Passive)
        } else if raw.eq_ignore_ascii_case("full") {
            Some(Self::Full)
        } else if raw.eq_ignore_ascii_case("restart") {
            Some(Self::Restart)
        } else if raw.eq_ignore_ascii_case("truncate") {
            Some(Self::Truncate)
        } else {
            None
        }
    }

    /// Return SQL token used in `PRAGMA wal_checkpoint(...)`.
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Passive => "PASSIVE",
            Self::Full => "FULL",
            Self::Restart => "RESTART",
            Self::Truncate => "TRUNCATE",
        }
    }
}

/// Parse optional WAL auto-checkpoint page threshold from env.
pub fn parse_optional_wal_autocheckpoint_pages() -> Option<i64> {
    std::env::var("SQLITE_WAL_AUTOCHECKPOINT").ok().map(|raw| {
        raw.parse::<i64>()
            .unwrap_or_else(|_| panic!("SQLITE_WAL_AUTOCHECKPOINT must be an integer, got '{raw}'"))
    })
}

/// Parse optional WAL checkpoint mode from env.
pub fn parse_optional_wal_checkpoint_mode() -> Option<WalCheckpointMode> {
    std::env::var("SQLITE_WAL_CHECKPOINT_MODE")
        .ok()
        .map(|raw| {
            WalCheckpointMode::parse(&raw).unwrap_or_else(|| {
                panic!(
                    "SQLITE_WAL_CHECKPOINT_MODE must be one of PASSIVE|FULL|RESTART|TRUNCATE, got '{raw}'"
                )
            })
        })
}

/// Apply optional WAL auto-checkpoint setting to a SQLite connection.
pub fn apply_optional_wal_autocheckpoint(
    conn: &Connection,
    wal_autocheckpoint_pages: Option<i64>,
) -> rusqlite::Result<()> {
    if let Some(pages) = wal_autocheckpoint_pages {
        let sql = format!("PRAGMA wal_autocheckpoint={pages}");
        conn.execute_batch(&sql)?;
    }
    Ok(())
}

/// Run post-setup checkpoint only when WAL auto-checkpoint is disabled.
pub fn maybe_run_post_setup_wal_checkpoint(
    conn: &Connection,
    wal_autocheckpoint_pages: Option<i64>,
    wal_checkpoint_mode: Option<WalCheckpointMode>,
) -> rusqlite::Result<bool> {
    if wal_autocheckpoint_pages != Some(0) {
        return Ok(false);
    }

    let checkpoint_mode = wal_checkpoint_mode.unwrap_or(WalCheckpointMode::Passive);
    let sql = format!("PRAGMA wal_checkpoint({})", checkpoint_mode.as_sql());
    conn.execute_batch(&sql)?;
    Ok(true)
}

/// Elapsed time and allocation counters for one measured operation.
#[derive(Clone, Copy)]
pub struct BenchMeasurement {
    pub elapsed_ms: f64,
    pub snapshot: Snapshot,
}

/// Measure a successful closure while capturing allocation statistics.
pub fn measure_with_allocs<R, F>(f: F) -> BenchMeasurement
where
    F: FnOnce() -> R,
{
    reset_stats();
    let start = Instant::now();
    black_box(f());
    BenchMeasurement {
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        snapshot: snapshot(),
    }
}

/// Measure a fallible closure while capturing allocation statistics.
pub fn measure_result_with_allocs<R, E, F>(f: F) -> Result<BenchMeasurement, E>
where
    F: FnOnce() -> Result<R, E>,
{
    reset_stats();
    let start = Instant::now();
    black_box(f()?);
    Ok(BenchMeasurement {
        elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
        snapshot: snapshot(),
    })
}

/// Measure one benchmark case and optionally emit a detailed raw-output line.
pub fn run_case_with_allocs<F>(name: &str, mode: OutputMode, mut f: F) -> BenchMeasurement
where
    F: FnMut(),
{
    let measurement = measure_with_allocs(|| f());
    if mode.is_raw() {
        println!(
            "{name}\talloc_calls={}\talloc_bytes={}\trealloc_calls={}\tdealloc_calls={}\tdealloc_bytes={}\telapsed_ms={:.2}",
            measurement.snapshot.alloc_calls,
            measurement.snapshot.alloc_bytes,
            measurement.snapshot.realloc_calls,
            measurement.snapshot.dealloc_calls,
            measurement.snapshot.dealloc_bytes,
            measurement.elapsed_ms
        );
    }
    measurement
}

/// Execute a benchmark case for one or more rounds and append aggregate totals.
pub fn record_case_with_rounds<F>(
    summary: &mut Summary,
    name: &str,
    mode: OutputMode,
    rounds: usize,
    mut f: F,
) where
    F: FnMut(),
{
    let mut total_ms = 0.0;
    let mut total_alloc_calls = 0u64;
    let mut total_alloc_bytes = 0u64;

    for round in 0..rounds {
        let round_name;
        let case_name = if rounds > 1 {
            round_name = format!("{name}#round={}", round + 1);
            round_name.as_str()
        } else {
            name
        };

        let measurement = run_case_with_allocs(case_name, mode, &mut f);
        total_ms += measurement.elapsed_ms;
        total_alloc_calls = total_alloc_calls.saturating_add(measurement.snapshot.alloc_calls);
        total_alloc_bytes = total_alloc_bytes.saturating_add(measurement.snapshot.alloc_bytes);
    }

    summary.push_line(name, total_ms, total_alloc_calls, total_alloc_bytes);
}
