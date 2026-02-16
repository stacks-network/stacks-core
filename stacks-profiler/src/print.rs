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

//! Tree-formatted output for [`ProfileStats`].
//!
//! Provides a [`TreeFormatter`] trait and a built-in [`PrettyPrinter`] (ANSI-coloured).
//! Plug in custom formatters via [`ProfileStats::print_with`].

use std::fmt::Write;

use crate::{ProfileStats, Tag};

/// ANSI escape sequences for terminal colouring.
struct Style;

#[allow(unused)]
impl Style {
    const RESET: &str = "\x1b[0m";
    const BOLD: &str = "\x1b[1m";
    const GRAY: &str = "\x1b[90m";
    const RED: &str = "\x1b[31m";
    const DIM: &str = "\x1b[2m";
    const GREEN: &str = "\x1b[32m";
    const YELLOW: &str = "\x1b[33m";
    const CYAN: &str = "\x1b[36m";
    const BLUE: &str = "\x1b[34m";
    const WHITE: &str = "\x1b[37m";
}

/// Context passed to the formatter for the current node being visited.
pub struct NodeContext<'a> {
    pub stats: &'a ProfileStats,
    pub depth: usize,
    pub is_last_sibling: bool,
    pub is_root: bool,
    /// The visual prefix string (e.g., "│   ├── ") built by the traversal logic.
    pub prefix: &'a str,
    /// The connector string (e.g., "├── " or "└── ") for this specific node.
    pub connector: &'a str,
}

/// Trait for customizing how the profile tree is rendered.
pub trait TreeFormatter {
    /// Called for every node in the tree during traversal.
    ///
    /// Implementors should write a single line representing the node to `writer`.
    fn format_node<W: Write>(&self, ctx: &NodeContext, writer: &mut W) -> std::fmt::Result;
}

/// Default formatter — produces an ANSI-coloured tree with wall, CPU, and wait times in
/// milliseconds, call counts, and source locations.
pub struct PrettyPrinter;

impl TreeFormatter for PrettyPrinter {
    fn format_node<W: Write>(&self, ctx: &NodeContext, writer: &mut W) -> std::fmt::Result {
        let reset = Style::RESET;
        let gray = Style::GRAY;
        let bold = Style::BOLD;
        let cyan = Style::CYAN;
        let dim = Style::DIM;
        let white = Style::WHITE;
        let red = Style::RED;
        let green = Style::GREEN;
        let yellow = Style::YELLOW;

        let stats = ctx.stats;
        let name = stats.id.name;
        let file = stats.id.file;
        let line = stats.id.line;

        // Icon & Name
        let name_icon = if ctx.is_root { "" } else { "▶" };

        // Tag
        let tag_display = if let Some(t) = stats.tag {
            match t {
                Tag::U64(v) => format!(" {cyan}#{v}{reset}"),
                Tag::I64(v) => format!(" {cyan}#{v}{reset}"),
                Tag::Usize(v) => format!(" {cyan}#{v}{reset}"),
                Tag::Str(v) => format!(" {cyan}[{v}]{reset}"),
            }
        } else {
            String::new()
        };

        // Metrics
        let wall_ms = stats.wall_time_ns as f64 / 1_000_000.0;
        let cpu_ms = stats.cpu_time_ns as f64 / 1_000_000.0;
        let wait_ns = stats.wait_time_ns();
        let wait_ms = wait_ns as f64 / 1_000_000.0;
        let count = stats.entered_count;

        let wait_color = if wait_ns > stats.cpu_time_ns {
            red
        } else {
            gray
        };

        let metrics = format!(
            "{reset}{dim}[total: {cyan}{wall_ms:.3}ms {reset}{dim}| busy: {cyan}{cpu_ms:.3}ms{reset} {dim}| wait: {reset}{wait_color}{wait_ms:.3}ms{reset}{dim}]{reset} {gray}(x{count}){reset}"
        );

        let source_loc = format!("{reset}{dim}{gray}@ {file}:{line}{reset}");

        // Write main line
        if ctx.is_root {
            writeln!(
                writer,
                "{bold}{white}{name}{tag_display} {metrics} {source_loc}"
            )?;
        } else {
            writeln!(
                writer,
                "{gray}{}{}{reset}{gray}{name_icon}{reset} {bold}{white}{name}{tag_display} {metrics} {source_loc}",
                ctx.prefix, ctx.connector
            )?;
        }

        // Records & Counters (indented detail lines below the node)
        let has_details = !stats.records.is_empty() || !stats.counters.is_empty();
        if has_details {
            // Build the continuation prefix: same indent as children would use, but with a thin
            // vertical line to visually group the details.
            let detail_prefix = if ctx.is_root {
                String::from("  ")
            } else {
                let continuation = if ctx.is_last_sibling {
                    "    "
                } else {
                    "│   "
                };
                format!("{gray}{}{continuation}{reset}", ctx.prefix)
            };

            for record in &stats.records {
                writeln!(
                    writer,
                    "{detail_prefix}{dim}{green}⊕ {reset}{green}{}{reset}{dim} = {reset}{}{reset}",
                    record.key, record.value
                )?;
            }
            for counter in &stats.counters {
                writeln!(
                    writer,
                    "{detail_prefix}{dim}{yellow}∑ {reset}{yellow}{}{reset}{dim} = {reset}{}{reset}",
                    counter.key,
                    format_counter_value(counter.value)
                )?;
            }
        }

        Ok(())
    }
}

/// Format a counter value with thousands separators for readability.
fn format_counter_value(value: u64) -> String {
    if value < 1_000 {
        return value.to_string();
    }
    // Build with thousands separators
    let s = value.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Render a [`ProfileStats`] tree to stdout using the given formatter.
pub fn print_tree<F: TreeFormatter>(stats: &ProfileStats, formatter: &F) {
    let mut buffer = String::new();
    // Handle #[must_use] -- the recursive function returns a fmt::Result, but we ignore it since
    // we're writing to a String.
    let _ = write_tree_recursive(stats, formatter, &mut buffer, "", "", true, 0);
    print!("{}", buffer);
}

fn write_tree_recursive<F: TreeFormatter, W: Write>(
    stats: &ProfileStats,
    formatter: &F,
    writer: &mut W,
    prefix: &str,
    connector: &str,
    is_root: bool,
    depth: usize,
) -> std::fmt::Result {
    // Format current node
    let ctx = NodeContext {
        stats,
        depth,
        is_last_sibling: connector == "└── ",
        is_root,
        prefix,
        connector,
    };
    formatter.format_node(&ctx, writer)?;

    // Recurse children
    let len = stats.children.len();
    for (i, child) in stats.children.iter().enumerate() {
        let is_last = i == len - 1;
        let child_connector = if is_last { "└── " } else { "├── " };

        // Calculate new prefix for the child:
        // - If we are root, we don't add prefix yet.
        // - If we are not root:
        //   - If we were the last sibling, our children don't see our pipe "│"
        //   - If we were NOT the last sibling, our children see our pipe "│"
        let child_prefix_segment = if is_root {
            ""
        } else if connector == "└── " {
            "    "
        } else {
            "│   "
        };

        let child_prefix = format!("{}{}", prefix, child_prefix_segment);

        write_tree_recursive(
            child,
            formatter,
            writer,
            &child_prefix,
            child_connector,
            false,
            depth + 1,
        )?;
    }
    Ok(())
}
