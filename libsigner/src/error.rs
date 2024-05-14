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

use std::io;

use clarity::vm::types::QualifiedContractIdentifier;

/// Errors originating from doing an RPC request to the Stacks node
#[derive(thiserror::Error, Debug)]
pub enum RPCError {
    /// IO error
    #[error("{0}")]
    IO(#[from] io::Error),
    /// Deserialization error
    #[error("{0}")]
    Deserialize(String),
    /// RPC request when not connected
    #[error("Not connected")]
    NotConnected,
    /// Malformed request
    #[error("Malformed request: {0}")]
    MalformedRequest(String),
    /// Malformed response
    #[error("Malformed response: {0}")]
    MalformedResponse(String),
    /// HTTP error
    #[error("HTTP code {0}")]
    HttpError(u32),
}

/// Errors originating from receiving event data from the Stacks node
#[derive(thiserror::Error, Debug)]
pub enum EventError {
    /// IO Error
    #[error("{0}")]
    IO(#[from] io::Error),
    /// Deserialization error
    #[error("{0}")]
    Deserialize(String),
    /// Malformed request
    #[error("Malformed request: {0}")]
    MalformedRequest(String),
    /// Not bound to a port error
    #[error("Not bound to a port yet")]
    NotBound,
    /// Listener terminated error
    #[error("Listener is terminated")]
    Terminated,
    /// Thread already running error
    #[error("Thread already running")]
    AlreadyRunning,
    /// Failed to start thread error
    #[error("Failed to start thread")]
    FailedToStart,
    /// Unrecognized event error
    #[error("Unrecognized event: {0}")]
    UnrecognizedEvent(String),
    /// Unrecognized stacker DB contract error
    #[error("Unrecognized StackerDB contract: {0}")]
    UnrecognizedStackerDBContract(QualifiedContractIdentifier),
    /// Empty chunks event
    #[error("Empty chunks event")]
    EmptyChunksEvent,
}
