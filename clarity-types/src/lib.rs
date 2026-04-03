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
#[doc = include_str!("../README.md")]
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate stacks_common;

pub use stacks_common::{
    codec, consts, impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_message_codec,
    impl_byte_array_serde, types as stacks_types, util,
};

pub mod errors;
pub mod representations;
pub mod types;

pub use errors::{ClarityTypeError, IncomparableError};
pub use representations::{ClarityName, ContractName};
use stacks_common::types::StacksEpochId;
pub use types::Value;

/// Max call stack depth for Epoch 3.4+.
const MAX_CALL_STACK_DEPTH: u64 = 128;
/// Max call stack depth for pre‑3.4 epochs.
const MAX_CALL_STACK_DEPTH_LEGACY: u64 = 64;

pub fn max_call_stack_depth_for_epoch(epoch_id: StacksEpochId) -> u64 {
    if epoch_id >= StacksEpochId::Epoch34 {
        MAX_CALL_STACK_DEPTH
    } else {
        MAX_CALL_STACK_DEPTH_LEGACY
    }
}

#[cfg(test)]
pub mod tests;
