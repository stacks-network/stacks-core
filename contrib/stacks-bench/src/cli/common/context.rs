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

use std::future::Future;
use std::io::IsTerminal;

use anyhow::Result;
use serde::Serialize;
use stacks_bench::db::app::AppDb;

/// A type-erased serializable command output.
///
/// Intermediate dispatchers use this as their [`ExecCommand::Output`] type
/// to hold heterogeneous leaf results without knowing their concrete types.
/// Serialization is deferred until [`Cli::exec`] wraps the result in the
/// [`CommandResult`] envelope.
pub type BoxedOutput = Box<dyn erased_serde::Serialize + Send>;

/// Trait implemented by every command (leaf or intermediate) to provide a
/// single execution entry point with a typed, serializable result.
///
/// Commands check `ctx.interactive()` internally to decide whether to emit
/// interactive UI (spinners, tables, progress bars) alongside computing
/// their result. The result is always returned regardless of output mode.
///
/// Leaf commands set `Output` to their own concrete type (e.g.
/// `Vec<RunJson>`). Intermediate dispatchers set `Output` to
/// [`BoxedOutput`] and wrap leaf results with [`boxed`].
pub trait ExecCommand: Sync {
    type Output: erased_serde::Serialize + Send;
    fn exec(&self, ctx: &CliContext) -> impl Future<Output = Result<Self::Output>> + Send;
}

/// Wrap a concrete [`ExecCommand::Output`] into a [`BoxedOutput`] for use by
/// intermediate dispatchers.
pub fn boxed<T: erased_serde::Serialize + Send + 'static>(value: T) -> BoxedOutput {
    Box::new(value)
}

/// Envelope for structured JSON output in `--json` mode.
///
/// Every command's result is wrapped in this consistent structure so that
/// agents can rely on a predictable top-level schema regardless of which
/// subcommand was invoked.
#[derive(Serialize)]
pub struct CommandResult {
    pub success: bool,
    pub duration_secs: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl CommandResult {
    /// Wrap a successful command output in the envelope.
    pub fn ok(data: &dyn erased_serde::Serialize, duration_secs: f64) -> Result<Self> {
        Ok(Self {
            success: true,
            duration_secs,
            error: None,
            data: Some(serialize_erased(data)?),
        })
    }

    /// Wrap an error in the envelope.
    pub fn err(error: &anyhow::Error, duration_secs: f64) -> Self {
        Self {
            success: false,
            duration_secs,
            error: Some(format!("{error:#}")),
            data: None,
        }
    }

    /// Serialize and print this envelope to stdout.
    pub fn print(&self) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }
}

/// Serialize a `dyn erased_serde::Serialize` to a `serde_json::Value`.
pub fn serialize_erased(data: &dyn erased_serde::Serialize) -> Result<serde_json::Value> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::new(&mut buf);
    data.erased_serialize(&mut <dyn erased_serde::Serializer>::erase(&mut ser))
        .map_err(|e| anyhow::anyhow!("Failed to serialize command output: {e}"))?;
    Ok(serde_json::from_slice(&buf)?)
}

pub struct CliContext {
    /// The application database.
    app_db: AppDb,
    /// When true, commands emit structured JSON and suppress interactive UI.
    json: bool,
    /// When true, the process is running as an MCP stdio server. Interactive
    /// UI is suppressed but output is handled by MCP, not `--json` envelopes.
    mcp: bool,
    /// Whether stdin/stdout are connected to a terminal. Computed once at
    /// construction time.
    tty: bool,
}

pub const SUCCESS_ICON: &str = "✔";
#[allow(unused)]
pub const FAILURE_ICON: &str = "✘";

macro_rules! fmt_success {
    ($($arg:tt)*) => {{
        format!(
            "{} {}",
            ::console::style($crate::cli::common::SUCCESS_ICON).green(),
            format_args!($($arg)*)
        )
    }};
}

#[allow(unused)]
macro_rules! fmt_failure {
    ($($arg:tt)*) => {{
        format!(
            "{} {}",
            ::console::style($crate::cli::common::FAILURE_ICON).red(),
            format_args!($($arg)*)
        )
    }};
}

impl CliContext {
    pub fn new(app_db: AppDb, json: bool) -> Self {
        Self {
            app_db,
            json,
            mcp: false,
            tty: std::io::stdout().is_terminal() && std::io::stdin().is_terminal(),
        }
    }

    #[allow(dead_code)] // Will be used by the future MCP server
    pub fn new_mcp(app_db: AppDb) -> Self {
        Self {
            app_db,
            json: false,
            mcp: true,
            tty: false,
        }
    }

    pub fn app_db(&self) -> AppDb {
        self.app_db.clone()
    }

    /// Returns true when structured JSON output mode is active.
    pub fn json(&self) -> bool {
        self.json
    }

    /// Returns true when running as an MCP stdio server.
    #[allow(dead_code)] // Will be used by the future MCP server
    pub fn mcp(&self) -> bool {
        self.mcp
    }

    /// Returns true when the terminal is available for interactive UI
    /// (spinners, progress bars, prompts, selectors).
    ///
    /// False when `--json` is set, when running as an MCP server, when
    /// stdin/stdout are not a TTY (e.g. piped), or when the `CI`
    /// environment variable is set.
    pub fn interactive(&self) -> bool {
        !self.json && !self.mcp && self.tty && std::env::var_os("CI").is_none()
    }
}
