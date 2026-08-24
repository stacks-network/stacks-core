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

//! Binary consensus serialization codec for the Stacks blockchain.
//!
//! The trait, error type, and primitive impls live in `stacks_common::codec`;
//! this crate re-exports them for callers that want to depend only on the
//! codec surface, and will host the higher-level codec types (e.g.
//! `StacksTransaction`) as they are lowered out of `stackslib`.

pub mod strings;
pub mod transaction;

pub use stacks_common::codec::*;
pub use stacks_common::{
    impl_byte_array_message_codec, impl_stacks_message_codec_for_int, BITVEC_LEN,
};
