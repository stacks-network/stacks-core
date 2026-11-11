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

const TREE_BRANCH_CONNECTOR: &str = "├── ";
const TREE_LAST_CONNECTOR: &str = "└── ";
const TREE_VERTICAL_PREFIX: &str = "│   ";
const TREE_EMPTY_PREFIX: &str = "    ";
const DETAIL_ROOT_INDENT: usize = 2;
const NON_ROOT_NAME_ICON: &str = "▶";
const NANOS_PER_MILLI: f64 = 1_000_000.0;

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
        let name_icon = if ctx.is_root { "" } else { NON_ROOT_NAME_ICON };

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
        let wall_ms = stats.wall_time_ns as f64 / NANOS_PER_MILLI;
        let cpu_ms = stats.cpu_time_ns as f64 / NANOS_PER_MILLI;
        let wait_ns = stats.wait_time_ns();
        let wait_ms = wait_ns as f64 / NANOS_PER_MILLI;
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
                " ".repeat(DETAIL_ROOT_INDENT)
            } else {
                let continuation = if ctx.is_last_sibling {
                    TREE_EMPTY_PREFIX
                } else {
                    TREE_VERTICAL_PREFIX
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
    let _ = write_tree_recursive(stats, formatter, &mut buffer, "", "", true, true, 0);
    print!("{}", buffer);
}

#[allow(clippy::too_many_arguments)]
fn write_tree_recursive<F: TreeFormatter, W: Write>(
    stats: &ProfileStats,
    formatter: &F,
    writer: &mut W,
    prefix: &str,
    connector: &str,
    is_root: bool,
    is_last_sibling: bool,
    depth: usize,
) -> std::fmt::Result {
    // Format current node
    let ctx = NodeContext {
        stats,
        depth,
        is_last_sibling,
        is_root,
        prefix,
        connector,
    };
    formatter.format_node(&ctx, writer)?;

    // Recurse children
    let len = stats.children.len();
    for (i, child) in stats.children.iter().enumerate() {
        let is_last = i == len - 1;
        let child_connector = if is_last {
            TREE_LAST_CONNECTOR
        } else {
            TREE_BRANCH_CONNECTOR
        };

        // Calculate new prefix for the child:
        // - If we are root, we don't add prefix yet.
        // - If we are not root, children either inherit our vertical prefix or an empty prefix
        //   depending on whether more siblings follow us.
        let child_prefix_segment = if is_root {
            ""
        } else if is_last_sibling {
            TREE_EMPTY_PREFIX
        } else {
            TREE_VERTICAL_PREFIX
        };

        let child_prefix = format!("{}{}", prefix, child_prefix_segment);

        write_tree_recursive(
            child,
            formatter,
            writer,
            &child_prefix,
            child_connector,
            false,
            is_last,
            depth + 1,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fmt::Write;

    use super::{
        PrettyPrinter, TREE_BRANCH_CONNECTOR, TREE_LAST_CONNECTOR, TREE_VERTICAL_PREFIX,
        TreeFormatter, format_counter_value, print_tree, write_tree_recursive,
    };
    use crate::{Counter, ProfileStats, Record, RecordValue, SpanId, Tag};

    static ROOT_ID: SpanId = SpanId {
        name: "root",
        context: Some("print_tests"),
        file: "root.rs",
        line: 10,
    };

    static CHILD_ID: SpanId = SpanId {
        name: "child",
        context: Some("print_tests"),
        file: "child.rs",
        line: 20,
    };

    static LAST_CHILD_ID: SpanId = SpanId {
        name: "last_child",
        context: Some("print_tests"),
        file: "last_child.rs",
        line: 30,
    };

    static GRANDCHILD_ID: SpanId = SpanId {
        name: "grandchild",
        context: Some("print_tests"),
        file: "grandchild.rs",
        line: 40,
    };

    static NO_TAG_ID: SpanId = SpanId {
        name: "no_tag",
        context: Some("print_tests"),
        file: "no_tag.rs",
        line: 50,
    };

    static LAST_GRANDCHILD_ID: SpanId = SpanId {
        name: "last_grandchild",
        context: Some("print_tests"),
        file: "last_grandchild.rs",
        line: 60,
    };

    fn stats_tree() -> ProfileStats {
        ProfileStats {
            id: &ROOT_ID,
            tag: Some(Tag::U64(42)),
            wall_time_ns: 2_000_000,
            cpu_time_ns: 1_000_000,
            children: vec![
                ProfileStats {
                    id: &CHILD_ID,
                    tag: Some(Tag::Str("alpha")),
                    wall_time_ns: 5_000_000,
                    cpu_time_ns: 2_000_000,
                    children: vec![
                        ProfileStats {
                            id: &GRANDCHILD_ID,
                            tag: Some(Tag::Usize(3)),
                            wall_time_ns: 1_000_000,
                            cpu_time_ns: 500_000,
                            children: Vec::new(),
                            entered_count: 1,
                            sampled_count: 1,
                            records: Vec::new(),
                            counters: Vec::new(),
                        },
                        ProfileStats {
                            id: &NO_TAG_ID,
                            tag: None,
                            wall_time_ns: 1_000_000,
                            cpu_time_ns: 500_000,
                            children: Vec::new(),
                            entered_count: 1,
                            sampled_count: 1,
                            records: Vec::new(),
                            counters: Vec::new(),
                        },
                    ],
                    entered_count: 2,
                    sampled_count: 2,
                    records: vec![Record {
                        key: "record",
                        value: RecordValue::Bytes(vec![0xab, 0xcd].into_boxed_slice()),
                    }],
                    counters: vec![Counter {
                        key: "counter",
                        value: 12_345,
                    }],
                },
                ProfileStats {
                    id: &LAST_CHILD_ID,
                    tag: Some(Tag::I64(-1)),
                    wall_time_ns: 500_000,
                    cpu_time_ns: 250_000,
                    children: vec![ProfileStats {
                        id: &LAST_GRANDCHILD_ID,
                        tag: None,
                        wall_time_ns: 250_000,
                        cpu_time_ns: 125_000,
                        children: Vec::new(),
                        entered_count: 1,
                        sampled_count: 1,
                        records: Vec::new(),
                        counters: Vec::new(),
                    }],
                    entered_count: 1,
                    sampled_count: 1,
                    records: Vec::new(),
                    counters: Vec::new(),
                },
            ],
            entered_count: 1,
            sampled_count: 1,
            records: vec![Record {
                key: "root_record",
                value: RecordValue::Str("value".into()),
            }],
            counters: vec![Counter {
                key: "root_counter",
                value: 999,
            }],
        }
    }

    #[test]
    fn formats_counter_values_with_separators() {
        assert_eq!(format_counter_value(0), "0");
        assert_eq!(format_counter_value(999), "999");
        assert_eq!(format_counter_value(1_000), "1,000");
        assert_eq!(format_counter_value(1_234_567), "1,234,567");
    }

    #[test]
    fn pretty_printer_renders_nodes_details_and_tags() {
        let stats = stats_tree();
        let mut output = String::new();

        write_tree_recursive(&stats, &PrettyPrinter, &mut output, "", "", true, true, 0).unwrap();

        assert!(output.contains("root"));
        assert!(output.contains("#42"));
        assert!(output.contains("child"));
        assert!(output.contains("[alpha]"));
        assert!(output.contains("grandchild"));
        assert!(output.contains("#3"));
        assert!(output.contains("no_tag"));
        assert!(output.contains(TREE_BRANCH_CONNECTOR));
        assert!(output.contains(TREE_LAST_CONNECTOR));
        assert!(output.contains(TREE_VERTICAL_PREFIX));
        assert!(output.contains("root_record"));
        assert!(output.contains("root_counter"));
        assert!(output.contains("record"));
        assert!(output.contains("0xabcd"));
        assert!(output.contains("12,345"));
    }

    #[test]
    fn traversal_passes_context_to_custom_formatter() {
        struct CaptureFormatter {
            seen: RefCell<Vec<String>>,
        }

        impl TreeFormatter for CaptureFormatter {
            fn format_node<W: Write>(
                &self,
                ctx: &super::NodeContext,
                writer: &mut W,
            ) -> std::fmt::Result {
                self.seen.borrow_mut().push(format!(
                    "{}:{}:{}:{}:{}:{}",
                    ctx.stats.name(),
                    ctx.depth,
                    ctx.is_root,
                    ctx.is_last_sibling,
                    ctx.prefix,
                    ctx.connector
                ));
                writeln!(writer, "{}", ctx.stats.name())
            }
        }

        let formatter = CaptureFormatter {
            seen: RefCell::new(Vec::new()),
        };
        let stats = stats_tree();
        let mut output = String::new();

        write_tree_recursive(&stats, &formatter, &mut output, "", "", true, true, 0).unwrap();

        assert_eq!(
            formatter.seen.into_inner(),
            vec![
                "root:0:true:true::",
                "child:1:false:false::├── ",
                "grandchild:2:false:false:│   :├── ",
                "no_tag:2:false:true:│   :└── ",
                "last_child:1:false:true::└── ",
                "last_grandchild:2:false:true:    :└── ",
            ]
        );
        assert_eq!(output.lines().count(), 6);
    }

    #[test]
    fn public_print_tree_entrypoint_runs() {
        print_tree(&stats_tree(), &PrettyPrinter);
    }
}
