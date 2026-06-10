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

// Macros must be defined before submodules that use them, so `context`
// (which contains the macro definitions) comes first.
#[macro_use]
mod context;
mod cleanup;
mod format;
mod progress;
mod table;

pub use cleanup::run_db_cleanup;
#[allow(unused_imports)] // FAILURE_ICON referenced by fmt_failure! macro
pub use context::{
    BoxedOutput, CliContext, CommandResult, ExecCommand, FAILURE_ICON, SUCCESS_ICON, boxed,
    serialize_erased,
};
pub use format::{
    fmt_duration, fmt_relative_time, fmt_run_label, fmt_run_name_suffix, fmt_u64_thousands,
    parse_since,
};
pub use progress::run_indexer_progress_ui;
pub use table::{Align, Table};
