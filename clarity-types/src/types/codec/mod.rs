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

//! Non-consensus codecs for local Clarity value storage.

#![deny(missing_docs)]

// TODO: Move the Clarity consensus value codec from `types::serialization` to
// `types::codec::consensus` in a focused follow-up. Decide how this relates to the `stacks-codec`
// crate.

pub mod packed;
