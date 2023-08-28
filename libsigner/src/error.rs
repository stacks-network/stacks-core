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

use std::error;
use std::fmt;
use std::io;

/// Errors originating from doing an RPC request to the Stacks node
#[derive(Debug)]
pub enum RPCError {
    IO(io::Error),
    Deserialize(String),
    NotConnected,
    MalformedRequest(String),
    MalformedResponse(String),
    HttpError(u32),
}

impl fmt::Display for RPCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RPCError::IO(ref s) => fmt::Display::fmt(s, f),
            RPCError::Deserialize(ref s) => fmt::Display::fmt(s, f),
            RPCError::HttpError(ref s) => {
                write!(f, "HTTP code {}", s)
            }
            RPCError::MalformedRequest(ref s) => {
                write!(f, "Malformed request: {}", s)
            }
            RPCError::MalformedResponse(ref s) => {
                write!(f, "Malformed response: {}", s)
            }
            RPCError::NotConnected => {
                write!(f, "Not connected")
            }
        }
    }
}

impl error::Error for RPCError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            RPCError::IO(ref s) => Some(s),
            RPCError::Deserialize(..) => None,
            RPCError::HttpError(..) => None,
            RPCError::MalformedRequest(..) => None,
            RPCError::MalformedResponse(..) => None,
            RPCError::NotConnected => None,
        }
    }
}

impl From<io::Error> for RPCError {
    fn from(e: io::Error) -> RPCError {
        RPCError::IO(e)
    }
}

/// Errors originating from receiving event data from the Stacks node
#[derive(Debug)]
pub enum EventError {
    IO(io::Error),
    Deserialize(String),
    MalformedRequest(String),
    NotBound,
    Terminated,
    AlreadyRunning,
    FailedToStart,
    UnrecognizedEvent(String),
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EventError::IO(ref s) => fmt::Display::fmt(s, f),
            EventError::Deserialize(ref s) => fmt::Display::fmt(s, f),
            EventError::MalformedRequest(ref s) => {
                write!(f, "Malformed request: {}", s)
            }
            EventError::NotBound => {
                write!(f, "Not bound to a port yet")
            }
            EventError::Terminated => {
                write!(f, "Listener is terminated")
            }
            EventError::AlreadyRunning => {
                write!(f, "Thread already running")
            }
            EventError::FailedToStart => {
                write!(f, "Failed to start thread")
            }
            EventError::UnrecognizedEvent(ref ev) => {
                write!(f, "Unrecognized event '{}'", &ev)
            }
        }
    }
}

impl error::Error for EventError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            EventError::IO(ref s) => Some(s),
            EventError::Deserialize(..) => None,
            EventError::MalformedRequest(..) => None,
            EventError::NotBound => None,
            EventError::Terminated => None,
            EventError::AlreadyRunning => None,
            EventError::FailedToStart => None,
            EventError::UnrecognizedEvent(..) => None,
        }
    }
}

impl From<io::Error> for EventError {
    fn from(e: io::Error) -> EventError {
        EventError::IO(e)
    }
}
