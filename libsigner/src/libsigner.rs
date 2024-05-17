// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

#![forbid(missing_docs)]
/*!
# libsigner: a library for creating and operating a Stacks Nakamato compliant signer.

Usage documentation can be found in the [README](https://github.com/stacks-network/stacks-blockchain/libsigner/README.md).
*/

#![allow(unused_imports)]
#![allow(dead_code)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate stacks_common;
extern crate clarity;
extern crate libc;

#[cfg(test)]
mod tests;

mod error;
mod events;
mod http;
mod runloop;
mod session;
mod signer_set;
/// v0 signer related code
pub mod v0;
/// v1 signer related code
pub mod v1;

pub use crate::error::{EventError, RPCError};
pub use crate::events::{
    BlockProposal, EventReceiver, EventStopSignaler, SignerEvent, SignerEventReceiver,
    SignerEventTrait, SignerStopSignaler,
};
pub use crate::runloop::{RunningSigner, Signer, SignerRunLoop};
pub use crate::session::{SignerSession, StackerDBSession};
pub use crate::signer_set::{Error as ParseSignerEntriesError, SignerEntries};
