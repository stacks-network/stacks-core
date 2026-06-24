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

use anyhow::{Result, bail};
use chrono::{NaiveDateTime, Utc};
use stacks_bench::db::app::models::BenchmarkRun;

/// Parse a human-friendly duration string like `10m`, `2h`, `1d6h`, `1d12h30m`.
///
/// Supported units: `d` (days), `h` (hours), `m` (minutes).
pub fn parse_since(s: &str) -> Result<chrono::Duration> {
    let mut total_minutes: i64 = 0;
    let mut buf = String::new();
    for ch in s.chars() {
        match ch {
            'd' => {
                let n: i64 = buf
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid number before 'd': '{buf}'"))?;
                total_minutes += n * 24 * 60;
                buf.clear();
            }
            'h' => {
                let n: i64 = buf
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid number before 'h': '{buf}'"))?;
                total_minutes += n * 60;
                buf.clear();
            }
            'm' => {
                let n: i64 = buf
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid number before 'm': '{buf}'"))?;
                total_minutes += n;
                buf.clear();
            }
            c if c.is_ascii_digit() => buf.push(c),
            _ => bail!("unexpected character '{}' in --since value", ch),
        }
    }
    // Bare number without unit → treat as minutes
    if !buf.is_empty() {
        let n: i64 = buf
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid trailing number in --since: '{buf}'"))?;
        total_minutes += n;
    }
    if total_minutes == 0 {
        bail!("--since value resolves to zero duration");
    }
    Ok(chrono::Duration::minutes(total_minutes))
}

/// Format a `NaiveDateTime` as a human-friendly relative string like "2h 13m ago".
pub fn fmt_relative_time(ts: NaiveDateTime) -> String {
    let now = Utc::now().naive_utc();
    let delta = now.signed_duration_since(ts);
    if delta.num_seconds() < 60 {
        return "just now".to_string();
    }
    let mut parts = Vec::new();
    let days = delta.num_days();
    let hours = delta.num_hours() % 24;
    let minutes = delta.num_minutes() % 60;
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if parts.is_empty() {
        "just now".to_string()
    } else {
        format!("{} ago", parts.join(" "))
    }
}

/// Format a duration between two timestamps as a compact string.
pub fn fmt_duration(start: NaiveDateTime, end: NaiveDateTime) -> String {
    let secs = end.signed_duration_since(start).num_seconds().max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Format a benchmark run for display in interactive select / multiselect lists.
///
/// Returns something like: `✔ my-run  —  2026-02-11 14:30:00`
pub fn fmt_run_label(run: &BenchmarkRun) -> String {
    let status = if run.end_time.is_some() {
        console::style("✔").green().to_string()
    } else {
        console::style("…").yellow().to_string()
    };
    let name = run.run_name.as_deref().unwrap_or("(unnamed)");
    format!(
        "{status} {name}  —  {}",
        run.start_time.format("%Y-%m-%d %H:%M:%S"),
    )
}

/// Format a run's name as a bold parenthetical suffix for log messages.
///
/// Returns `" (name)"` (with bold styling) when a name exists, or `""` otherwise.
pub fn fmt_run_name_suffix(run: &BenchmarkRun) -> String {
    run.run_name
        .as_deref()
        .map(|n| format!(" ({})", console::style(n).bold()))
        .unwrap_or_default()
}

/// Format a `u64` with comma thousands separators (e.g. `1,234,567`).
pub fn fmt_u64_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_since_basic() {
        assert_eq!(parse_since("10m").unwrap().num_minutes(), 10);
        assert_eq!(parse_since("2h").unwrap().num_minutes(), 120);
        assert_eq!(parse_since("1d").unwrap().num_minutes(), 1440);
        assert_eq!(parse_since("1d6h").unwrap().num_minutes(), 1800);
        assert_eq!(parse_since("1d12h30m").unwrap().num_minutes(), 2190);
    }

    #[test]
    fn parse_since_bare_number_is_minutes() {
        assert_eq!(parse_since("30").unwrap().num_minutes(), 30);
    }

    #[test]
    fn parse_since_errors() {
        assert!(parse_since("").is_err());
        assert!(parse_since("0m").is_err());
        assert!(parse_since("abc").is_err());
    }
}
