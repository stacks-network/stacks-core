// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! The Merkleized Adaptive Radix Forest (MARF): the authenticated key/value
//! store backing the Stacks chainstate, sortition and Clarity databases.
//!
//! The crate owns the on-disk trie format (`bits`, `node`, `blob_layout`), its
//! SQLite-backed storage layer (`storage`, `trie_sql`, `file`), the forest
//! itself (`marf`, `trie`), Merkle proofs (`proofs`) and squashing (`squash`).
//! It depends only on `stacks-common` and `rusqlite` -- nothing from `stackslib`.
//!
//! The sources themselves still live in `stackslib::chainstate::stacks::index`
//! at this point; they move here in a follow-up patch.
