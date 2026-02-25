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

mod allocator;
mod common;
mod patch;
mod primitives;
mod read;
mod utils;
mod write;

/// Output mode selected by `OUTPUT_FORMAT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    /// Emit only normalized summary rows.
    Summary,
    /// Emit detailed benchmark lines in addition to summaries.
    Raw,
}

impl OutputMode {
    /// Return true when detailed/raw output is enabled.
    fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }
}

/// A single summary row emitted by a subcommand benchmark run.
#[derive(Clone, Debug)]
struct SummaryLine {
    pub name: String,
    pub total_ms: f64,
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

/// Grouped summary output for one benchmark subcommand.
#[derive(Clone, Debug)]
struct Summary {
    pub title: &'static str,
    pub lines: Vec<SummaryLine>,
}

impl Summary {
    /// Create an empty summary with a preallocated number of rows.
    fn new(title: &'static str, capacity: usize) -> Self {
        Self {
            title,
            lines: Vec::with_capacity(capacity),
        }
    }

    /// Append one measured case to the summary table.
    fn push_line(
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
fn parse_output_mode() -> OutputMode {
    match std::env::var("OUTPUT_FORMAT").ok().as_deref() {
        Some("raw") => OutputMode::Raw,
        _ => OutputMode::Summary,
    }
}

/// Print unified summary lines in tab-separated format.
fn print_summary(summary: &Summary) {
    println!("summary\tbenchmark\tname\ttotal_ms\talloc_count\talloc_bytes");
    for line in &summary.lines {
        println!(
            "summary\t{}\t{}\t{:.3}\t{}\t{}",
            summary.title, line.name, line.total_ms, line.alloc_count, line.alloc_bytes
        );
    }
}

/// Print usage/help for the `marf` harness.
#[rustfmt::skip]
fn print_usage() {
    println!("marf: MARF allocation/timing profilers");
    println!();
    println!("Usage:");
    println!("  cargo bench -p stackslib --bench marf -- <subcommand> [--help]");
    println!();
    println!("Subcommands:");
    println!("  primitives    Primitive microbench profile (codec + trie/storage)");
    println!("  read          Read-heavy MARF::get profile");
    println!("  write         Write workflow profile");
    println!("  patch         TrieNodePatch construction/application profile");
    println!();
    println!("Environment variables:");
    println!("  OUTPUT_FORMAT");
    println!("                Output mode [default: summary]");
    println!("                  - 'summary': emit unified summary rows only");
    println!("                  - 'raw': emit detailed benchmark output + unified summary rows");
}

/// Main entry point for the `marf` harness, which dispatches to the appropriate subcommand.
fn main() {
    // SAFETY: This is the first thing we do in the process, before any
    // potential threads are spawned or any FFI into C libraries that might read
    // the environment.
    unsafe {
        std::env::set_var("STACKS_LOG_CRITONLY", "1");
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let cmd = args[1].as_str();
    let sub_args = &args[2..];
    let output_mode = parse_output_mode();

    let summary = match cmd {
        "primitives" => primitives::run(sub_args, output_mode),
        "read" => read::run(sub_args, output_mode),
        "write" => write::run(sub_args, output_mode),
        "patch" => patch::run(sub_args, output_mode),
        "-h" | "--help" | "help" => {
            print_usage();
            None
        }
        _ => {
            eprintln!("Unknown subcommand: {cmd}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Some(summary) = summary {
        print_summary(&summary);
    }
}
