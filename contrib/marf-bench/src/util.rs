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

use std::collections::BTreeMap;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};

use crate::report::SummaryRow;

/// Execute a command and return an error with captured output if it fails.
pub fn run_checked(mut cmd: Command, context: &str) -> Result<()> {
    let out = cmd
        .output()
        .with_context(|| format!("{context}: command execution failed"))?;
    if out.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    bail!(
        "{context}: {}{}{}",
        stdout.trim(),
        if !stdout.is_empty() && !stderr.is_empty() {
            "\n"
        } else {
            ""
        },
        stderr.trim()
    )
}

/// Convert a revision string into a filesystem-safe token.
pub fn sanitize_revision(rev: &str) -> String {
    rev.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Print a marf-bench namespaced log line to stderr.
pub fn log(message: impl AsRef<str>) {
    eprintln!("[marf-bench] {}", message.as_ref());
}

/// Build a stable key map from summary rows.
pub fn to_row_map(rows: &[SummaryRow]) -> BTreeMap<(String, String), SummaryRow> {
    let mut map = BTreeMap::new();
    for row in rows {
        map.insert(
            (row.benchmark().to_string(), row.name().to_string()),
            row.clone(),
        );
    }
    map
}

/// Return rows sorted by benchmark then row name.
pub fn sort_rows(rows: &[SummaryRow]) -> Vec<SummaryRow> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|a, b| {
        a.benchmark()
            .cmp(b.benchmark())
            .then_with(|| a.name().cmp(b.name()))
    });
    sorted
}

/// Compute percentage delta from base to target.
pub fn pct(base: f64, target: f64) -> f64 {
    if base == 0.0 {
        return 0.0;
    }
    ((target - base) * 100.0) / base
}

/// Parse `summary` TSV lines emitted by the marf benchmark harness into typed rows.
pub fn extract_summary_lines(text: &str) -> Vec<SummaryRow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 6 || parts[0] != "summary" || parts[1] == "benchmark" {
            continue;
        }

        let total_ms = match parts[3].parse::<f64>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let alloc_count = match parts[4].parse::<u64>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let alloc_bytes = match parts[5].parse::<u64>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        rows.push(SummaryRow::new(
            parts[1],
            parts[2],
            total_ms,
            alloc_count,
            alloc_bytes,
        ));
    }
    rows
}

/// Concatenate stdout and stderr text from a process output.
pub fn combine_output_text(output: &Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// Print process output streams preserving stdout/stderr separation.
pub fn print_output(output: &Output) {
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}

/// Return median, minimum, and maximum values for a non-empty slice.
pub fn median_min_max(values: &[f64]) -> (f64, f64, f64) {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));

    let min = *sorted
        .first()
        .expect("median_min_max requires non-empty values");
    let max = *sorted
        .last()
        .expect("median_min_max requires non-empty values");
    let len = sorted.len();

    let median = if len % 2 == 1 {
        sorted[len / 2]
    } else {
        (sorted[(len / 2) - 1] + sorted[len / 2]) / 2.0
    };

    (median, min, max)
}

/// Format a floating-point value with three decimal places.
pub fn f3(value: f64) -> String {
    format!("{value:.3}")
}

/// Format a floating-point value with four decimal places.
pub fn f4(value: f64) -> String {
    format!("{value:.4}")
}
