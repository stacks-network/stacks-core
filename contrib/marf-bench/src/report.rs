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

//! Reporting utilities for marf-bench, including summary and comparison rendering in both
//! pretty table and TSV formats, as well as repeat run comparison and jitter classification logic.
//!
//! TSV output is included for machine parsing (e.g. in CI).

use std::collections::BTreeSet;

use crate::table::{Align, Column, Table};
use crate::util::{f3, f4, log, median_min_max, pct, sort_rows, to_row_map};
use crate::{OutputFormat, tsv};
/// Parsed benchmark summary metrics for one benchmark/name pair.
#[derive(Debug, Clone)]
pub struct SummaryRow {
    benchmark: String,
    name: String,
    total_ms: f64,
    alloc_count: u64,
    alloc_bytes: u64,
}

/// Canonical key type used to join benchmark rows across repeated runs.
type BenchKey = (String, String);

/// Canonical jitter tuple: `(benchmark, name, median, min, max, spread_or_spread_pct)`.
type JitterRow = (String, String, f64, f64, f64, f64);

/// Rendering modes for repeat-stat tables and TSV streams.
#[derive(Clone, Copy)]
enum RepeatStatsMode {
    ComparisonDelta,
    RunAbsolute,
}

/// Fully computed repeat metrics for one `(benchmark, name)` key.
struct RepeatComputedRow {
    benchmark: String,
    name: String,
    total_median: f64,
    total_min: f64,
    total_max: f64,
    count_median: f64,
    count_min: f64,
    count_max: f64,
    bytes_median: f64,
    bytes_min: f64,
    bytes_max: f64,
}

struct ConfidenceRenderContext<'a> {
    labels: Option<(&'a str, &'a str)>,
    total_rows: usize,
    stable_rows: usize,
    jitter_rows: &'a [JitterRow],
    repeats: usize,
    jitter_threshold_pct: f64,
}

impl RepeatStatsMode {
    fn tsv_header(self, prefix: &str) -> &'static str {
        match (self, prefix) {
            (Self::ComparisonDelta, "repeat-stats") => {
                "repeat-stats\tbenchmark\tname\tmetric\tmedian_delta_pct\tmin_delta_pct\tmax_delta_pct\trepeats"
            }
            (Self::RunAbsolute, "run-repeat-stats") => {
                "run-repeat-stats\tbenchmark\tname\tmetric\tmedian\tmin\tmax\trepeats"
            }
            _ => unreachable!("invalid repeat stats prefix/mode combination"),
        }
    }

    fn table_columns(self) -> Vec<Column> {
        match self {
            Self::ComparisonDelta => vec![
                Column::new("benchmark", Align::Left),
                Column::new("name", Align::Left),
                Column::new("total Δ med", Align::Right),
                Column::new("total Δ min", Align::Right),
                Column::new("total Δ max", Align::Right),
                Column::new("count Δ med", Align::Right),
                Column::new("bytes Δ med", Align::Right),
                Column::new("repeats", Align::Right),
            ],
            Self::RunAbsolute => vec![
                Column::new("benchmark", Align::Left),
                Column::new("name", Align::Left),
                Column::new("total med", Align::Right),
                Column::new("total min", Align::Right),
                Column::new("total max", Align::Right),
                Column::new("count med", Align::Right),
                Column::new("bytes med", Align::Right),
                Column::new("repeats", Align::Right),
            ],
        }
    }

    fn format_total(self, value: f64) -> String {
        match self {
            Self::ComparisonDelta => format!("{:+.1}%", value),
            Self::RunAbsolute => format!("{:.3}", value),
        }
    }

    fn format_count_median(self, value: f64) -> String {
        match self {
            Self::ComparisonDelta => format!("{:+.1}%", value),
            Self::RunAbsolute => format!("{:.0}", value),
        }
    }

    fn format_bytes_median(self, value: f64) -> String {
        match self {
            Self::ComparisonDelta => format!("{:+.1}%", value),
            Self::RunAbsolute => format!("{:.0}", value),
        }
    }
}

/// Print three TSV metric lines (total/count/bytes) for one benchmark key.
fn print_tsv_three_metrics(prefix: &str, row: &RepeatComputedRow, repeats: usize) {
    crate::tsv_line!(
        prefix,
        row.benchmark,
        row.name,
        "total_ms",
        f4(row.total_median),
        f4(row.total_min),
        f4(row.total_max),
        repeats,
    );
    crate::tsv_line!(
        prefix,
        row.benchmark,
        row.name,
        "alloc_count",
        f4(row.count_median),
        f4(row.count_min),
        f4(row.count_max),
        repeats,
    );
    crate::tsv_line!(
        prefix,
        row.benchmark,
        row.name,
        "alloc_bytes",
        f4(row.bytes_median),
        f4(row.bytes_min),
        f4(row.bytes_max),
        repeats,
    );
}

/// Print TSV jitter detail header and top rows for either run or comparison mode.
fn print_tsv_jitter_rows(prefix: &str, mode: RepeatStatsMode, jitter_rows: &[JitterRow]) {
    let mut header = vec![prefix, "benchmark", "name"];
    match mode {
        RepeatStatsMode::RunAbsolute => header.extend([
            "median_total_ms",
            "min_total_ms",
            "max_total_ms",
            "spread_pct_of_median",
        ]),
        RepeatStatsMode::ComparisonDelta => header.extend([
            "median_delta_pct",
            "min_delta_pct",
            "max_delta_pct",
            "spread_pct",
        ]),
    }
    header.push("classification");
    tsv::print_line(header);

    for (benchmark, name, median, min, max, spread) in jitter_rows.iter().take(10) {
        crate::tsv_line!(
            prefix,
            benchmark,
            name,
            f4(*median),
            f4(*min),
            f4(*max),
            f4(*spread),
            "high-jitter",
        );
    }
}

/// Compute common benchmark keys present in all repeated base/target row sets.
fn common_keys_for_comparison_runs(
    repeated_rows: &[(Vec<SummaryRow>, Vec<SummaryRow>)],
) -> BTreeSet<BenchKey> {
    if repeated_rows.is_empty() {
        return BTreeSet::new();
    }

    let mut keys: BTreeSet<BenchKey> = {
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

    keys
}

/// Compute common benchmark keys present in all repeated single-run row sets.
fn common_keys_for_run_repeats(repeated_rows: &[Vec<SummaryRow>]) -> BTreeSet<BenchKey> {
    if repeated_rows.is_empty() {
        return BTreeSet::new();
    }

    let mut keys: BTreeSet<BenchKey> = {
        let rows = &repeated_rows[0];
        to_row_map(rows).keys().cloned().collect()
    };

    for rows in repeated_rows.iter().skip(1) {
        let row_map = to_row_map(rows);
        keys.retain(|key| row_map.contains_key(key));
    }

    keys
}

/// Collect `%delta` metric series for one key across repeated comparison runs.
fn collect_delta_series_for_key(
    repeated_rows: &[(Vec<SummaryRow>, Vec<SummaryRow>)],
    benchmark: &str,
    name: &str,
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut total_deltas = Vec::with_capacity(repeated_rows.len());
    let mut count_deltas = Vec::with_capacity(repeated_rows.len());
    let mut bytes_deltas = Vec::with_capacity(repeated_rows.len());

    for (base_rows, target_rows) in repeated_rows {
        let base_map = to_row_map(base_rows);
        let target_map = to_row_map(target_rows);
        let key = (benchmark.to_string(), name.to_string());
        let base = &base_map[&key];
        let target = &target_map[&key];

        total_deltas.push(pct(base.total_ms, target.total_ms));
        count_deltas.push(pct(base.alloc_count as f64, target.alloc_count as f64));
        bytes_deltas.push(pct(base.alloc_bytes as f64, target.alloc_bytes as f64));
    }

    (total_deltas, count_deltas, bytes_deltas)
}

/// Collect absolute metric series for one key across repeated single-tree runs.
fn collect_absolute_series_for_key(
    repeated_rows: &[Vec<SummaryRow>],
    benchmark: &str,
    name: &str,
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let mut totals = Vec::with_capacity(repeated_rows.len());
    let mut counts = Vec::with_capacity(repeated_rows.len());
    let mut bytes = Vec::with_capacity(repeated_rows.len());

    for rows in repeated_rows {
        let row_map = to_row_map(rows);
        let key = (benchmark.to_string(), name.to_string());
        let row = &row_map[&key];
        totals.push(row.total_ms);
        counts.push(row.alloc_count as f64);
        bytes.push(row.alloc_bytes as f64);
    }

    (totals, counts, bytes)
}

/// Classify high-jitter rows for comparison repeats using `%delta` spread semantics.
fn classify_comparison_jitter_rows(
    keys: &BTreeSet<BenchKey>,
    repeated_rows: &[(Vec<SummaryRow>, Vec<SummaryRow>)],
    jitter_threshold_pct: f64,
) -> (Vec<JitterRow>, usize) {
    let mut jitter_rows: Vec<JitterRow> = Vec::new();
    let mut stable_rows = 0usize;

    for (benchmark, name) in keys {
        let (total_deltas, _, _) = collect_delta_series_for_key(repeated_rows, benchmark, name);
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
    (jitter_rows, stable_rows)
}

/// Classify high-jitter rows for run repeats using absolute `total_ms` spread/median semantics.
fn classify_run_jitter_rows(
    keys: &BTreeSet<BenchKey>,
    repeated_rows: &[Vec<SummaryRow>],
    jitter_threshold_pct: f64,
) -> (Vec<JitterRow>, usize) {
    let mut jitter_rows: Vec<JitterRow> = Vec::new();
    let mut stable_rows = 0usize;

    for (benchmark, name) in keys {
        let (totals, _, _) = collect_absolute_series_for_key(repeated_rows, benchmark, name);
        let (median, min, max) = median_min_max(&totals);
        let spread = max - min;
        let spread_pct = if median.abs() <= f64::EPSILON {
            if spread <= f64::EPSILON {
                0.0
            } else {
                f64::INFINITY
            }
        } else {
            (spread / median.abs()) * 100.0
        };

        if spread_pct >= jitter_threshold_pct {
            jitter_rows.push((
                benchmark.to_string(),
                name.to_string(),
                median,
                min,
                max,
                spread_pct,
            ));
        } else {
            stable_rows += 1;
        }
    }

    jitter_rows.sort_by(|a, b| b.5.total_cmp(&a.5));
    (jitter_rows, stable_rows)
}

/// Build fully-computed repeat rows from comparison `%delta` series.
fn compute_repeat_rows_for_comparison(
    keys: &BTreeSet<BenchKey>,
    repeated_rows: &[(Vec<SummaryRow>, Vec<SummaryRow>)],
) -> Vec<RepeatComputedRow> {
    let mut rows = Vec::with_capacity(keys.len());

    for (benchmark, name) in keys {
        let (total_deltas, count_deltas, bytes_deltas) =
            collect_delta_series_for_key(repeated_rows, benchmark, name);

        let (total_median, total_min, total_max) = median_min_max(&total_deltas);
        let (count_median, count_min, count_max) = median_min_max(&count_deltas);
        let (bytes_median, bytes_min, bytes_max) = median_min_max(&bytes_deltas);

        rows.push(RepeatComputedRow {
            benchmark: benchmark.to_string(),
            name: name.to_string(),
            total_median,
            total_min,
            total_max,
            count_median,
            count_min,
            count_max,
            bytes_median,
            bytes_min,
            bytes_max,
        });
    }

    rows
}

/// Build fully-computed repeat rows from absolute run series.
fn compute_repeat_rows_for_run(
    keys: &BTreeSet<BenchKey>,
    repeated_rows: &[Vec<SummaryRow>],
) -> Vec<RepeatComputedRow> {
    let mut rows = Vec::with_capacity(keys.len());

    for (benchmark, name) in keys {
        let (totals, counts, bytes) =
            collect_absolute_series_for_key(repeated_rows, benchmark, name);

        let (total_median, total_min, total_max) = median_min_max(&totals);
        let (count_median, count_min, count_max) = median_min_max(&counts);
        let (bytes_median, bytes_min, bytes_max) = median_min_max(&bytes);

        rows.push(RepeatComputedRow {
            benchmark: benchmark.to_string(),
            name: name.to_string(),
            total_median,
            total_min,
            total_max,
            count_median,
            count_min,
            count_max,
            bytes_median,
            bytes_min,
            bytes_max,
        });
    }

    rows
}

/// Emit TSV repeat rows for either comparison-delta or absolute-run mode.
fn print_repeat_rows_tsv(
    prefix: &str,
    mode: RepeatStatsMode,
    rows: &[RepeatComputedRow],
    repeats: usize,
) {
    println!("{}", mode.tsv_header(prefix));
    for row in rows {
        print_tsv_three_metrics(prefix, row, repeats);
    }
}

/// Emit pretty table repeat rows for either comparison-delta or absolute-run mode.
fn print_repeat_rows_table(mode: RepeatStatsMode, rows: &[RepeatComputedRow], repeats: usize) {
    let mut table = Table::new(mode.table_columns());
    for row in rows {
        table.push_row(vec![
            row.benchmark.clone(),
            row.name.clone(),
            mode.format_total(row.total_median),
            mode.format_total(row.total_min),
            mode.format_total(row.total_max),
            mode.format_count_median(row.count_median),
            mode.format_bytes_median(row.bytes_median),
            repeats.to_string(),
        ]);
    }
    table.print(false);
}

/// Render confidence output (TSV or human-readable) for either comparison or run repeat mode.
fn print_confidence_output(
    output_format: OutputFormat,
    mode: RepeatStatsMode,
    context: ConfidenceRenderContext<'_>,
) {
    let tsv_prefix = match mode {
        RepeatStatsMode::ComparisonDelta => "repeat-confidence",
        RepeatStatsMode::RunAbsolute => "run-repeat-confidence",
    };

    if output_format == OutputFormat::Tsv {
        let mut summary_header = vec![tsv_prefix.to_string(), "summary".to_string()];
        let mut summary_values = vec![tsv_prefix.to_string(), "summary".to_string()];

        if let RepeatStatsMode::ComparisonDelta = mode {
            let (base_label, target_label) = context
                .labels
                .expect("comparison confidence output requires base/target labels");
            summary_header.extend(["base", "target"].into_iter().map(str::to_string));
            summary_values.extend([base_label, target_label].into_iter().map(str::to_string));
        }

        summary_header.extend(
            ["total_rows", "stable_rows", "high_jitter_rows", "repeats"]
                .into_iter()
                .map(str::to_string),
        );
        summary_values.extend([
            context.total_rows.to_string(),
            context.stable_rows.to_string(),
            context.jitter_rows.len().to_string(),
            context.repeats.to_string(),
        ]);

        tsv::print_line(summary_header);
        tsv::print_line(summary_values);

        crate::tsv_line!(
            tsv_prefix,
            "config",
            "jitter_threshold_pct",
            f4(context.jitter_threshold_pct)
        );
        print_tsv_jitter_rows(tsv_prefix, mode, context.jitter_rows);
        return;
    }

    println!();
    match mode {
        RepeatStatsMode::ComparisonDelta => log("Repeat confidence summary"),
        RepeatStatsMode::RunAbsolute => log("Run repeat confidence summary"),
    }

    if let Some((base_label, target_label)) = context.labels {
        println!("baseline: {base_label}");
        println!("comparison: {target_label}");
    }

    println!(
        "values: total_ms stability across {} repeats",
        context.repeats
    );
    let num_jitter_rows = context.jitter_rows.len();
    let jitter_preamble = format!(
        "rows: total={} stable={} high-jitter={num_jitter_rows} ",
        context.total_rows, context.stable_rows
    );
    match mode {
        RepeatStatsMode::ComparisonDelta => println!(
            "{jitter_preamble} (high-jitter means min<0<max and spread>={:.1}%)",
            context.jitter_threshold_pct,
        ),
        RepeatStatsMode::RunAbsolute => println!(
            "{jitter_preamble} (high-jitter means spread/median>={:.1}%)",
            context.jitter_threshold_pct,
        ),
    }

    if context.jitter_rows.is_empty() {
        println!("high-jitter rows: none");
        return;
    }

    match mode {
        RepeatStatsMode::ComparisonDelta => println!("top high-jitter rows (by spread):"),
        RepeatStatsMode::RunAbsolute => println!("top high-jitter rows (by spread/median):"),
    }

    for (benchmark, name, median, min, max, spread) in context.jitter_rows.iter().take(10) {
        match mode {
            RepeatStatsMode::ComparisonDelta => println!(
                "  {benchmark} / {name}  median={median:+.1}%  min={min:+.1}%  max={max:+.1}%  spread={spread:.1}%",
            ),
            RepeatStatsMode::RunAbsolute => println!(
                "  {benchmark} / {name}  median={median:.3}ms  min={min:.3}ms  max={max:.3}ms  spread/median={spread:.1}%",
            ),
        }
    }
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
                crate::tsv_line!(
                    row.benchmark,
                    row.name,
                    f3(row.total_ms),
                    row.alloc_count,
                    row.alloc_bytes,
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
                "{benchmark_header:<benchmark_w$}{name_header:<name_w$}{:>12}  {:>12}  {:>12}",
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
            crate::tsv_line!(
                benchmark,
                name,
                f3(base.total_ms),
                f3(target.total_ms),
                f3(target.total_ms - base.total_ms),
                f4(pct(base.total_ms, target.total_ms)),
                base.alloc_count,
                target.alloc_count,
                target.alloc_count as i128 - base.alloc_count as i128,
                f4(pct(base.alloc_count as f64, target.alloc_count as f64)),
                base.alloc_bytes,
                target.alloc_bytes,
                target.alloc_bytes as i128 - base.alloc_bytes as i128,
                f4(pct(base.alloc_bytes as f64, target.alloc_bytes as f64)),
            );
        }
        return;
    }

    let mut table = Table::new(vec![
        Column::new("benchmark", Align::Left),
        Column::new("name", Align::Left),
        Column::new("total(ms) b/t", Align::Right),
        Column::new("Δ", Align::Right),
        Column::new("alloc_count b/t", Align::Right),
        Column::new("Δ", Align::Right),
        Column::new("alloc_bytes b/t", Align::Right),
        Column::new("Δ", Align::Right),
    ]);

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

        table.push_row(vec![
            benchmark,
            name,
            total,
            total_delta,
            count,
            count_delta,
            bytes,
            bytes_delta,
        ]);
    }

    println!();
    log("Comparison summary");
    println!("values: {base_label} / {target_label} / %delta");
    table.print(true);
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

    let keys = common_keys_for_comparison_runs(repeated_rows);

    if keys.is_empty() {
        return;
    }

    let computed_rows = compute_repeat_rows_for_comparison(&keys, repeated_rows);

    if output_format == OutputFormat::Tsv {
        print_repeat_rows_tsv(
            "repeat-stats",
            RepeatStatsMode::ComparisonDelta,
            &computed_rows,
            repeated_rows.len(),
        );
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

    println!();
    log("Repeated comparison stats");
    println!("baseline: {base_label}");
    println!("comparison: {target_label}");
    println!(
        "values: median/min/max %delta across {} repeats",
        repeated_rows.len()
    );

    print_repeat_rows_table(
        RepeatStatsMode::ComparisonDelta,
        &computed_rows,
        repeated_rows.len(),
    );

    print_repeat_confidence_summary(
        output_format,
        base_label,
        target_label,
        &keys,
        repeated_rows,
        jitter_threshold_pct,
    );
}

/// Print median/min/max repeat statistics for single-run repeats.
pub fn print_repeated_run_stats(
    output_format: OutputFormat,
    repeated_rows: &[Vec<SummaryRow>],
    jitter_threshold_pct: f64,
) {
    if repeated_rows.is_empty() {
        return;
    }

    let keys = common_keys_for_run_repeats(repeated_rows);

    if keys.is_empty() {
        return;
    }

    let computed_rows = compute_repeat_rows_for_run(&keys, repeated_rows);

    if output_format == OutputFormat::Tsv {
        print_repeat_rows_tsv(
            "run-repeat-stats",
            RepeatStatsMode::RunAbsolute,
            &computed_rows,
            repeated_rows.len(),
        );

        print_run_repeat_confidence_summary(
            output_format,
            &keys,
            repeated_rows,
            jitter_threshold_pct,
        );
        return;
    }

    println!();
    log("Run repeat stats");
    println!(
        "values: median/min/max absolute values across {} repeats",
        repeated_rows.len()
    );

    print_repeat_rows_table(
        RepeatStatsMode::RunAbsolute,
        &computed_rows,
        repeated_rows.len(),
    );

    print_run_repeat_confidence_summary(output_format, &keys, repeated_rows, jitter_threshold_pct);
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

    let (jitter_rows, stable_rows) =
        classify_comparison_jitter_rows(keys, repeated_rows, jitter_threshold_pct);

    print_confidence_output(
        output_format,
        RepeatStatsMode::ComparisonDelta,
        ConfidenceRenderContext {
            labels: Some((base_label, target_label)),
            total_rows: keys.len(),
            stable_rows,
            jitter_rows: &jitter_rows,
            repeats: repeated_rows.len(),
            jitter_threshold_pct,
        },
    );
}

/// Print a confidence summary for absolute run-repeat stability.
fn print_run_repeat_confidence_summary(
    output_format: OutputFormat,
    keys: &BTreeSet<(String, String)>,
    repeated_rows: &[Vec<SummaryRow>],
    jitter_threshold_pct: f64,
) {
    if keys.is_empty() || repeated_rows.is_empty() {
        return;
    }

    let (jitter_rows, stable_rows) =
        classify_run_jitter_rows(keys, repeated_rows, jitter_threshold_pct);

    print_confidence_output(
        output_format,
        RepeatStatsMode::RunAbsolute,
        ConfidenceRenderContext {
            labels: None,
            total_rows: keys.len(),
            stable_rows,
            jitter_rows: &jitter_rows,
            repeats: repeated_rows.len(),
            jitter_threshold_pct,
        },
    );
}
