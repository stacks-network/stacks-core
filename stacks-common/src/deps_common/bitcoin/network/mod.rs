// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Network Support
//!
//! This module defines support for (de)serialization and network transport
//! of Bitcoin data and network messages.
//!

use std::{error, fmt, io};

pub mod address;
pub mod constants;
pub mod encodable;
pub mod serialize;

pub mod message;
pub mod message_blockdata;
pub mod message_network;

/// Network error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// And I/O error
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Socket mutex was poisoned
    #[error("socket mutex was poisoned")]
    SocketMutexPoisoned,
    /// Not connected to peer
    #[error("not connected to peer")]
    SocketNotConnectedToPeer,
}
