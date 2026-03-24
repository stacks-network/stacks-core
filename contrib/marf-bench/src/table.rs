/// Column alignment for table rendering.
#[derive(Debug, Clone, Copy)]
pub enum Align {
    Left,
    Right,
}

/// One table column definition.
pub struct Column {
    header: String,
    align: Align,
}

impl Column {
    /// Build a column from a header label and alignment.
    pub fn new(header: impl Into<String>, align: Align) -> Self {
        Self {
            header: header.into(),
            align,
        }
    }
}

/// Plain-text table with dynamic column width calculation.
pub struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Create a new table with fixed column definitions.
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    /// Append one row; cell count must match column count.
    pub fn push_row(&mut self, row: Vec<String>) {
        assert_eq!(
            row.len(),
            self.columns.len(),
            "table row had {} cells but expected {}",
            row.len(),
            self.columns.len()
        );
        self.rows.push(row);
    }

    /// Print table header and rows, with optional divider insertion when benchmark changes.
    pub fn print(&self, group_by_first_column: bool) {
        let widths = self.compute_widths();
        let divider = "-".repeat(
            widths.iter().sum::<usize>()
                + if widths.len() > 1 {
                    (widths.len() - 1) * 2
                } else {
                    0
                },
        );

        let header = self
            .columns
            .iter()
            .zip(widths.iter())
            .map(|(column, width)| Self::format_cell(&column.header, *width, column.align))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{header}");
        println!("{divider}");

        let mut prev_group: Option<&str> = None;
        for row in &self.rows {
            if group_by_first_column {
                let current = row.first().map(String::as_str).unwrap_or("");
                if let Some(previous) = prev_group
                    && previous != current
                {
                    println!("{divider}");
                }
                prev_group = Some(current);
            }

            let line = row
                .iter()
                .zip(self.columns.iter())
                .zip(widths.iter())
                .map(|((cell, column), width)| Self::format_cell(cell, *width, column.align))
                .collect::<Vec<_>>()
                .join("  ");
            println!("{line}");
        }

        println!("{divider}");
    }

    fn compute_widths(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(ix, column)| {
                let header_w = column.header.len();
                let row_w = self
                    .rows
                    .iter()
                    .map(|row| row.get(ix).map_or(0, String::len))
                    .max()
                    .unwrap_or(0);
                header_w.max(row_w)
            })
            .collect()
    }

    fn format_cell(value: &str, width: usize, align: Align) -> String {
        match align {
            Align::Left => format!("{value:<width$}"),
            Align::Right => format!("{value:>width$}"),
        }
    }
}
