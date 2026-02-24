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

use std::collections::BTreeSet;

use crate::OutputFormat;
use crate::util::{log, pct, sort_rows, to_row_map};

/// A formatted comparison row used for pretty-table output.
struct ComparisonRow {
    benchmark: String,
    name: String,
    total: String,
    total_delta: String,
    count: String,
    count_delta: String,
    bytes: String,
    bytes_delta: String,
}

/// Aggregated per-row statistics across repeated comparisons.
struct RepeatStatsRow {
    benchmark: String,
    name: String,
    total_median: String,
    total_min: String,
    total_max: String,
    count_median: String,
    bytes_median: String,
    repeats: String,
}

/// Parsed benchmark summary metrics for one benchmark/name pair.
#[derive(Debug, Clone)]
pub struct SummaryRow {
    benchmark: String,
    name: String,
    total_ms: f64,
    alloc_count: u64,
    alloc_bytes: u64,
}

impl SummaryRow {
    /// Build a new summary row.
    pub fn new(
        benchmark: impl Into<String>,
        name: impl Into<String>,
        total_ms: f64,
        alloc_count: u64,
        alloc_bytes: u64,
    ) -> Self {
        Self {
            benchmark: benchmark.into(),
            name: name.into(),
            total_ms,
            alloc_count,
            alloc_bytes,
        }
    }

    /// Benchmark group name.
    pub fn benchmark(&self) -> &str {
        &self.benchmark
    }

    /// Benchmark row name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Print a single-run summary in the selected output format.
pub fn print_single_run(output_format: OutputFormat, rows: &[SummaryRow]) {
    let sorted = sort_rows(rows);
    match output_format {
        OutputFormat::Tsv => {
            for row in sorted {
                println!(
                    "{}\t{}\t{:.3}\t{}\t{}",
                    row.benchmark, row.name, row.total_ms, row.alloc_count, row.alloc_bytes
                );
            }
        }
        OutputFormat::Summary | OutputFormat::Raw => {
            let benchmark_header = "benchmark";
            let name_header = "name";
            let benchmark_w = sorted
                .iter()
                .map(|row| row.benchmark().len())
                .max()
                .unwrap_or(benchmark_header.len())
                .max(benchmark_header.len())
                + 2;
            let name_w = sorted
                .iter()
                .map(|row| row.name().len())
                .max()
                .unwrap_or(name_header.len())
                .max(name_header.len())
                + 2;

            println!();
            log("Run summary");
            println!(
                "{:<benchmark_w$}{:<name_w$}{:>12}  {:>12}  {:>12}",
                benchmark_header,
                name_header,
                "total_ms",
                "alloc_count",
                "alloc_bytes",
                benchmark_w = benchmark_w,
                name_w = name_w,
            );
            for row in sorted {
                println!(
                    "{:<benchmark_w$}{:<name_w$}{:>12.3}  {:>12}  {:>12}",
                    row.benchmark,
                    row.name,
                    row.total_ms,
                    row.alloc_count,
                    row.alloc_bytes,
                    benchmark_w = benchmark_w,
                    name_w = name_w,
                );
            }
        }
    }
}

/// Print a base vs target comparison in the selected output format.
pub fn print_comparison(
    output_format: OutputFormat,
    base_label: &str,
    target_label: &str,
    base_rows: &[SummaryRow],
    target_rows: &[SummaryRow],
) {
    let base_map = to_row_map(base_rows);
    let target_map = to_row_map(target_rows);

    let mut keys = BTreeSet::new();
    for key in base_map.keys() {
        if target_map.contains_key(key) {
            keys.insert(key.clone());
        }
    }

    if output_format == OutputFormat::Tsv {
        for (benchmark, name) in keys {
            let base = &base_map[&(benchmark.clone(), name.clone())];
            let target = &target_map[&(benchmark.clone(), name.clone())];
            println!(
                "{}\t{}\t{:.3}\t{:.3}\t{:.3}\t{:.4}\t{}\t{}\t{}\t{:.4}\t{}\t{}\t{}\t{:.4}",
                benchmark,
                name,
                base.total_ms,
                target.total_ms,
                target.total_ms - base.total_ms,
                pct(base.total_ms, target.total_ms),
                base.alloc_count,
                target.alloc_count,
                target.alloc_count as i128 - base.alloc_count as i128,
                pct(base.alloc_count as f64, target.alloc_count as f64),
                base.alloc_bytes,
                target.alloc_bytes,
                target.alloc_bytes as i128 - base.alloc_bytes as i128,
                pct(base.alloc_bytes as f64, target.alloc_bytes as f64)
            );
        }
        return;
    }

    let mut rows: Vec<ComparisonRow> = Vec::new();
    let mut benchmark_w = "benchmark".len();
    let mut name_w = "name".len();
    let mut total_w = "total(ms) b/t".len();
    let mut total_delta_w = "Δ".len();
    let mut count_w = "alloc_count b/t".len();
    let mut count_delta_w = "Δ".len();
    let mut bytes_w = "alloc_bytes b/t".len();
    let mut bytes_delta_w = "Δ".len();

    for (benchmark, name) in keys {
        let base = &base_map[&(benchmark.clone(), name.clone())];
        let target = &target_map[&(benchmark.clone(), name.clone())];

        let total = format!("{:.3}/{:.3}", base.total_ms, target.total_ms);
        let total_delta = format!("{:+.1}%", pct(base.total_ms, target.total_ms));
        let count = format!("{}/{}", base.alloc_count, target.alloc_count);
        let count_delta = format!(
            "{:+.1}%",
            pct(base.alloc_count as f64, target.alloc_count as f64)
        );
        let bytes = format!("{}/{}", base.alloc_bytes, target.alloc_bytes);
        let bytes_delta = format!(
            "{:+.1}%",
            pct(base.alloc_bytes as f64, target.alloc_bytes as f64)
        );

        benchmark_w = benchmark_w.max(benchmark.len());
        name_w = name_w.max(name.len());
        total_w = total_w.max(total.len());
        total_delta_w = total_delta_w.max(total_delta.len());
        count_w = count_w.max(count.len());
        count_delta_w = count_delta_w.max(count_delta.len());
        bytes_w = bytes_w.max(bytes.len());
        bytes_delta_w = bytes_delta_w.max(bytes_delta.len());

        rows.push(ComparisonRow {
            benchmark,
            name,
            total,
            total_delta,
            count,
            count_delta,
            bytes,
            bytes_delta,
        });
    }

    println!();
    log("Comparison summary");
    println!("values: {base_label} / {target_label} / %delta");
    let divider = "-".repeat(
        benchmark_w
            + 2
            + name_w
            + 2
            + total_w
            + 2
            + total_delta_w
            + 2
            + count_w
            + 2
            + count_delta_w
            + 2
            + bytes_w
            + 2
            + bytes_delta_w,
    );
    println!(
        "{:<benchmark_w$}  {:<name_w$}  {:>total_w$}  {:>total_delta_w$}  {:>count_w$}  {:>count_delta_w$}  {:>bytes_w$}  {:>bytes_delta_w$}",
        "benchmark",
        "name",
        "total(ms) b/t",
        "Δ",
        "alloc_count b/t",
        "Δ",
        "alloc_bytes b/t",
        "Δ",
        benchmark_w = benchmark_w,
        name_w = name_w,
        total_w = total_w,
        total_delta_w = total_delta_w,
        count_w = count_w,
        count_delta_w = count_delta_w,
        bytes_w = bytes_w,
        bytes_delta_w = bytes_delta_w,
    );
    println!("{divider}");

    let mut current_benchmark: Option<String> = None;
    for row in rows {
        if let Some(prev) = &current_benchmark
            && prev != &row.benchmark
        {
            println!("{divider}");
        }
        println!(
            "{:<benchmark_w$}  {:<name_w$}  {:>total_w$}  {:>total_delta_w$}  {:>count_w$}  {:>count_delta_w$}  {:>bytes_w$}  {:>bytes_delta_w$}",
            &row.benchmark,
            row.name,
            row.total,
            row.total_delta,
            row.count,
            row.count_delta,
            row.bytes,
            row.bytes_delta,
            benchmark_w = benchmark_w,
            name_w = name_w,
            total_w = total_w,
            total_delta_w = total_delta_w,
            count_w = count_w,
            count_delta_w = count_delta_w,
            bytes_w = bytes_w,
            bytes_delta_w = bytes_delta_w,
        );
        current_benchmark = Some(row.benchmark);
    }
    println!("{divider}");
}

/// Print median/min/max repeat statistics for comparison runs.
pub fn print_repeated_comparison_stats(
    output_format: OutputFormat,
    base_label: &str,
    target_label: &str,
    repeated_rows: &[(Vec<SummaryRow>, Vec<SummaryRow>)],
    jitter_threshold_pct: f64,
) {
    if repeated_rows.is_empty() {
        return;
    }

    let mut keys: BTreeSet<(String, String)> = {
        let (base_rows, target_rows) = &repeated_rows[0];
        let base_map = to_row_map(base_rows);
        let target_map = to_row_map(target_rows);
        base_map
            .keys()
            .filter(|key| target_map.contains_key(*key))
            .cloned()
            .collect()
    };

    for (base_rows, target_rows) in repeated_rows.iter().skip(1) {
        let base_map = to_row_map(base_rows);
        let target_map = to_row_map(target_rows);
        keys.retain(|key| base_map.contains_key(key) && target_map.contains_key(key));
    }

    if keys.is_empty() {
        return;
    }

    if output_format == OutputFormat::Tsv {
        println!(
            "repeat-stats\tbenchmark\tname\tmetric\tmedian_delta_pct\tmin_delta_pct\tmax_delta_pct\trepeats"
        );
        for (benchmark, name) in &keys {
            let mut total_deltas = Vec::with_capacity(repeated_rows.len());
            let mut count_deltas = Vec::with_capacity(repeated_rows.len());
            let mut bytes_deltas = Vec::with_capacity(repeated_rows.len());

            for (base_rows, target_rows) in repeated_rows {
                let base_map = to_row_map(base_rows);
                let target_map = to_row_map(target_rows);
                let base = &base_map[&(benchmark.clone(), name.clone())];
                let target = &target_map[&(benchmark.clone(), name.clone())];

                total_deltas.push(pct(base.total_ms, target.total_ms));
                count_deltas.push(pct(base.alloc_count as f64, target.alloc_count as f64));
                bytes_deltas.push(pct(base.alloc_bytes as f64, target.alloc_bytes as f64));
            }

            let (total_median, total_min, total_max) = median_min_max(&total_deltas);
            let (count_median, count_min, count_max) = median_min_max(&count_deltas);
            let (bytes_median, bytes_min, bytes_max) = median_min_max(&bytes_deltas);

            println!(
                "repeat-stats\t{}\t{}\ttotal_ms\t{:.4}\t{:.4}\t{:.4}\t{}",
                benchmark,
                name,
                total_median,
                total_min,
                total_max,
                repeated_rows.len()
            );
            println!(
                "repeat-stats\t{}\t{}\talloc_count\t{:.4}\t{:.4}\t{:.4}\t{}",
                benchmark,
                name,
                count_median,
                count_min,
                count_max,
                repeated_rows.len()
            );
            println!(
                "repeat-stats\t{}\t{}\talloc_bytes\t{:.4}\t{:.4}\t{:.4}\t{}",
                benchmark,
                name,
                bytes_median,
                bytes_min,
                bytes_max,
                repeated_rows.len()
            );
        }
        print_repeat_confidence_summary(
            output_format,
            base_label,
            target_label,
            &keys,
            repeated_rows,
            jitter_threshold_pct,
        );
        return;
    }

    let mut rows: Vec<RepeatStatsRow> = Vec::new();
    let mut benchmark_w = "benchmark".len();
    let mut name_w = "name".len();
    let mut total_median_w = "total Δ med".len();
    let mut total_min_w = "total Δ min".len();
    let mut total_max_w = "total Δ max".len();
    let mut count_median_w = "count Δ med".len();
    let mut bytes_median_w = "bytes Δ med".len();

    for (benchmark, name) in &keys {
        let mut total_deltas = Vec::with_capacity(repeated_rows.len());
        let mut count_deltas = Vec::with_capacity(repeated_rows.len());
        let mut bytes_deltas = Vec::with_capacity(repeated_rows.len());

        for (base_rows, target_rows) in repeated_rows {
            let base_map = to_row_map(base_rows);
            let target_map = to_row_map(target_rows);
            let base = &base_map[&(benchmark.clone(), name.clone())];
            let target = &target_map[&(benchmark.clone(), name.clone())];

            total_deltas.push(pct(base.total_ms, target.total_ms));
            count_deltas.push(pct(base.alloc_count as f64, target.alloc_count as f64));
            bytes_deltas.push(pct(base.alloc_bytes as f64, target.alloc_bytes as f64));
        }

        let (total_median, total_min, total_max) = median_min_max(&total_deltas);
        let (count_median, _, _) = median_min_max(&count_deltas);
        let (bytes_median, _, _) = median_min_max(&bytes_deltas);

        let total_median_cell = format!("{:+.1}%", total_median);
        let total_min_cell = format!("{:+.1}%", total_min);
        let total_max_cell = format!("{:+.1}%", total_max);
        let count_median_cell = format!("{:+.1}%", count_median);
        let bytes_median_cell = format!("{:+.1}%", bytes_median);
        let repeats_cell = repeated_rows.len().to_string();

        benchmark_w = benchmark_w.max(benchmark.len());
        name_w = name_w.max(name.len());
        total_median_w = total_median_w.max(total_median_cell.len());
        total_min_w = total_min_w.max(total_min_cell.len());
        total_max_w = total_max_w.max(total_max_cell.len());
        count_median_w = count_median_w.max(count_median_cell.len());
        bytes_median_w = bytes_median_w.max(bytes_median_cell.len());

        rows.push(RepeatStatsRow {
            benchmark: benchmark.to_string(),
            name: name.to_string(),
            total_median: total_median_cell,
            total_min: total_min_cell,
            total_max: total_max_cell,
            count_median: count_median_cell,
            bytes_median: bytes_median_cell,
            repeats: repeats_cell,
        });
    }

    println!();
    log("Repeated comparison stats");
    println!(
        "values: {base_label} / {target_label} / median/min/max %delta across {} repeats",
        repeated_rows.len()
    );

    let divider = "-".repeat(
        benchmark_w
            + 2
            + name_w
            + 2
            + total_median_w
            + 2
            + total_min_w
            + 2
            + total_max_w
            + 2
            + count_median_w
            + 2
            + bytes_median_w
            + 2
            + "repeats".len(),
    );

    println!(
        "{:<benchmark_w$}  {:<name_w$}  {:>total_median_w$}  {:>total_min_w$}  {:>total_max_w$}  {:>count_median_w$}  {:>bytes_median_w$}  {:>7}",
        "benchmark",
        "name",
        "total Δ med",
        "total Δ min",
        "total Δ max",
        "count Δ med",
        "bytes Δ med",
        "repeats",
        benchmark_w = benchmark_w,
        name_w = name_w,
        total_median_w = total_median_w,
        total_min_w = total_min_w,
        total_max_w = total_max_w,
        count_median_w = count_median_w,
        bytes_median_w = bytes_median_w,
    );
    println!("{divider}");

    for row in rows {
        println!(
            "{:<benchmark_w$}  {:<name_w$}  {:>total_median_w$}  {:>total_min_w$}  {:>total_max_w$}  {:>count_median_w$}  {:>bytes_median_w$}  {:>7}",
            row.benchmark,
            row.name,
            row.total_median,
            row.total_min,
            row.total_max,
            row.count_median,
            row.bytes_median,
            row.repeats,
            benchmark_w = benchmark_w,
            name_w = name_w,
            total_median_w = total_median_w,
            total_min_w = total_min_w,
            total_max_w = total_max_w,
            count_median_w = count_median_w,
            bytes_median_w = bytes_median_w,
        );
    }
    println!("{divider}");

    print_repeat_confidence_summary(
        output_format,
        base_label,
        target_label,
        &keys,
        repeated_rows,
        jitter_threshold_pct,
    );
}

/// Print a confidence summary highlighting high-jitter rows.
fn print_repeat_confidence_summary(
    output_format: OutputFormat,
    base_label: &str,
    target_label: &str,
    keys: &BTreeSet<(String, String)>,
    repeated_rows: &[(Vec<SummaryRow>, Vec<SummaryRow>)],
    jitter_threshold_pct: f64,
) {
    if keys.is_empty() || repeated_rows.is_empty() {
        return;
    }

    let mut jitter_rows: Vec<(String, String, f64, f64, f64, f64)> = Vec::new();
    let mut stable_rows = 0usize;

    for (benchmark, name) in keys {
        let mut total_deltas = Vec::with_capacity(repeated_rows.len());

        for (base_rows, target_rows) in repeated_rows {
            let base_map = to_row_map(base_rows);
            let target_map = to_row_map(target_rows);
            let base = &base_map[&(benchmark.clone(), name.clone())];
            let target = &target_map[&(benchmark.clone(), name.clone())];
            total_deltas.push(pct(base.total_ms, target.total_ms));
        }

        let (median, min, max) = median_min_max(&total_deltas);
        let spread = max - min;
        let straddles_zero = min < 0.0 && max > 0.0;
        let high_jitter = straddles_zero && spread >= jitter_threshold_pct;

        if high_jitter {
            jitter_rows.push((
                benchmark.to_string(),
                name.to_string(),
                median,
                min,
                max,
                spread,
            ));
        } else {
            stable_rows += 1;
        }
    }

    jitter_rows.sort_by(|a, b| b.5.total_cmp(&a.5));

    if output_format == OutputFormat::Tsv {
        println!(
            "repeat-confidence\tsummary\tbase\ttarget\ttotal_rows\tstable_rows\thigh_jitter_rows\trepeats"
        );
        println!(
            "repeat-confidence\tsummary\t{}\t{}\t{}\t{}\t{}\t{}",
            base_label,
            target_label,
            keys.len(),
            stable_rows,
            jitter_rows.len(),
            repeated_rows.len()
        );
        println!(
            "repeat-confidence\tconfig\tjitter_threshold_pct\t{:.4}",
            jitter_threshold_pct
        );
        println!(
            "repeat-confidence\tbenchmark\tname\tmedian_delta_pct\tmin_delta_pct\tmax_delta_pct\tspread_pct\tclassification"
        );
        for (benchmark, name, median, min, max, spread) in jitter_rows.iter().take(10) {
            println!(
                "repeat-confidence\t{}\t{}\t{:.4}\t{:.4}\t{:.4}\t{:.4}\thigh-jitter",
                benchmark, name, median, min, max, spread
            );
        }
        return;
    }

    println!();
    log("Repeat confidence summary");
    println!(
        "values: {base_label} / {target_label} / total_ms stability across {} repeats",
        repeated_rows.len()
    );
    println!(
        "rows: total={} stable={} high-jitter={} (high-jitter means min<0<max and spread>={:.1}%)",
        keys.len(),
        stable_rows,
        jitter_rows.len(),
        jitter_threshold_pct,
    );

    if jitter_rows.is_empty() {
        println!("high-jitter rows: none");
        return;
    }

    println!("top high-jitter rows (by spread):");
    for (benchmark, name, median, min, max, spread) in jitter_rows.iter().take(10) {
        println!(
            "  {} / {}  median={:+.1}%  min={:+.1}%  max={:+.1}%  spread={:.1}%",
            benchmark, name, median, min, max, spread
        );
    }
}

/// Return median, minimum, and maximum values for a non-empty slice.
fn median_min_max(values: &[f64]) -> (f64, f64, f64) {
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
