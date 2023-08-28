// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

pub use crate::session::{SignerSession, StackerDBSession};

pub use crate::error::{EventError, RPCError};

pub use crate::runloop::{RunningSigner, Signer, SignerRunLoop};

pub use crate::events::{
    EventReceiver, EventStopSignaler, StackerDBChunksEvent, StackerDBEventReceiver,
    StackerDBStopSignaler,
};
