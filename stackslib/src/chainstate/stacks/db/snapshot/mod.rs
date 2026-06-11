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

//! Offline copy of canonical chainstate data into a squashed destination
//! database, driven by the squashed MARF's `marf_squashed_blocks` metadata.
//!
//! Every copy in this module assumes the marf-squash preconditions:
//! - the snapshot contains nothing above the squash height;
//! - the squash height is post-epoch-3.4, so the canonical tip is a
//!   Nakamoto block;
//! - the snapshot contains canonical data only (no orphaned/fork rows).
//!
//! Detectable violations surface as `CorruptionError`s.

mod clarity;
pub(crate) mod common;
pub(crate) mod fork_storage;
mod index;

#[cfg(test)]
mod tests;

pub use clarity::{copy_clarity_side_tables, ClaritySideTableStats};
pub use index::{copy_index_side_tables, IndexSideTableStats};
