use std::fmt::Display;

/// Print one TSV record from displayable fields.
pub fn print_line<I, S>(fields: I)
where
    I: IntoIterator<Item = S>,
    S: Display,
{
    let mut first = true;
    for field in fields {
        if !first {
            print!("\t");
        }
        first = false;
        print!("{field}");
    }
    println!();
}

/// Print one TSV line from heterogeneous `Display` values.
#[macro_export]
macro_rules! tsv_line {
    ($($field:expr),+ $(,)?) => {{
        let fields: &[&dyn std::fmt::Display] = &[$(&$field as &dyn std::fmt::Display),+];
        $crate::tsv::print_line(fields);
    }};
}
