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

use std::fmt;

use anyhow::Result;

/// Column alignment.
#[derive(Debug, Clone, Copy)]
pub enum Align {
    Left,
    Right,
}

impl Align {
    fn to_console(self) -> console::Alignment {
        match self {
            Align::Left => console::Alignment::Left,
            Align::Right => console::Alignment::Right,
        }
    }
}

/// A simple table builder that handles dynamic column widths, styled
/// headers, and ANSI-aware cell padding.
///
/// Cells may contain ANSI escape codes (e.g. from [`console::style`]); the
/// builder uses [`console::measure_text_width`] so invisible escapes don't
/// throw off alignment.
pub struct Table {
    columns: Vec<TableColumn>,
    rows: Vec<Vec<String>>,
}

struct TableColumn {
    header: String,
    align: Align,
    min_width: usize,
    max_width: Option<usize>,
}

impl Table {
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Add a column with the given header and alignment.
    pub fn col(mut self, header: &str, align: Align) -> Self {
        self.columns.push(TableColumn {
            header: header.to_string(),
            align,
            min_width: 0,
            max_width: None,
        });
        self
    }

    /// Add a column with explicit minimum and/or maximum display width.
    pub fn col_with(
        mut self,
        header: &str,
        align: Align,
        min_width: usize,
        max_width: Option<usize>,
    ) -> Self {
        self.columns.push(TableColumn {
            header: header.to_string(),
            align,
            min_width,
            max_width: max_width.map(|m| m.max(min_width)),
        });
        self
    }

    /// Append a row of cell values. The number of cells must match the
    /// number of columns.
    pub fn row(&mut self, cells: Vec<String>) {
        debug_assert_eq!(
            cells.len(),
            self.columns.len(),
            "row has {} cells but table has {} columns",
            cells.len(),
            self.columns.len(),
        );
        self.rows.push(cells);
    }

    /// Print the table followed by a footer line like `"3 runs"` or
    /// `"50 chainstates (limit 50; use --limit to show more)"`.
    pub fn print_with_footer(&self, noun: &str, limit: usize) -> Result<()> {
        self.render_rows();

        let count = self.rows.len();
        let suffix = if count == limit {
            format!(" (limit {limit}; use --limit to show more)")
        } else {
            String::new()
        };
        cliclack::log::info(format!(
            "{count} {noun}{s}{suffix}",
            s = if count == 1 { "" } else { "s" }
        ))?;
        Ok(())
    }

    /// Render the header and all rows to stdout.
    fn render_rows(&self) {
        let widths = self.compute_widths();

        // Header
        let header_parts: Vec<String> = self
            .columns
            .iter()
            .zip(&widths)
            .map(|(col, &w)| {
                let padded = console::pad_str(&col.header, w, col.align.to_console(), None);
                console::style(padded).bold().underlined().to_string()
            })
            .collect();
        println!();
        println!("  {}", header_parts.join("  "));

        // Rows
        for row in &self.rows {
            let parts: Vec<String> = row
                .iter()
                .zip(&self.columns)
                .zip(&widths)
                .map(|((cell, col), &w)| {
                    if let Some(max) = col.max_width
                        && console::measure_text_width(cell) > max
                    {
                        return console::truncate_str(cell, max, "…").into_owned();
                    }
                    console::pad_str(cell, w, col.align.to_console(), None).into_owned()
                })
                .collect();
            println!("  {}", parts.join("  "));
        }
        println!();
    }

    /// Total display width of the rendered table (sum of column widths plus
    /// two-character gaps between columns).
    pub fn display_width(&self) -> usize {
        let widths = self.compute_widths();
        let cols: usize = widths.iter().sum();
        let gaps = if widths.len() > 1 {
            (widths.len() - 1) * 2
        } else {
            0
        };
        cols + gaps
    }

    fn compute_widths(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let header_w = console::measure_text_width(&col.header);
                let data_w = self
                    .rows
                    .iter()
                    .map(|row| console::measure_text_width(&row[i]))
                    .max()
                    .unwrap_or(0);
                let w = header_w.max(data_w).max(col.min_width);
                match col.max_width {
                    Some(max) => w.min(max),
                    None => w,
                }
            })
            .collect()
    }
}

/// Renders the table as plain text with an underlined header row (no ANSI
/// colour, no leading indentation). Suitable for embedding in a
/// `cliclack::note` body.
impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let widths = self.compute_widths();

        // Header (underlined)
        let header_parts: Vec<String> = self
            .columns
            .iter()
            .zip(&widths)
            .map(|(col, &w)| {
                console::pad_str(&col.header, w, col.align.to_console(), None).into_owned()
            })
            .collect();
        let header_line = header_parts.join("  ");
        writeln!(f, "{header_line}")?;
        // Underline each column individually, joined by two-space gaps.
        let underline_parts: Vec<String> = widths.iter().map(|&w| "\u{2500}".repeat(w)).collect();
        writeln!(f, "{}", underline_parts.join("  "))?;

        // Rows
        for (i, row) in self.rows.iter().enumerate() {
            let parts: Vec<String> = row
                .iter()
                .zip(&self.columns)
                .zip(&widths)
                .map(|((cell, col), &w)| {
                    if let Some(max) = col.max_width
                        && console::measure_text_width(cell) > max
                    {
                        return console::truncate_str(cell, max, "…").into_owned();
                    }
                    console::pad_str(cell, w, col.align.to_console(), None).into_owned()
                })
                .collect();
            if i < self.rows.len() - 1 {
                writeln!(f, "{}", parts.join("  "))?;
            } else {
                write!(f, "{}", parts.join("  "))?;
            }
        }

        Ok(())
    }
}
