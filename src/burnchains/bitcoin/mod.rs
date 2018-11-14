/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

// This module is concerned with the implementation of the BitcoinIndexer
// structure and its methods and traits.

pub mod messages;
pub mod indexer;
pub mod network;
pub mod rpc;
pub mod spv;

use std::fmt;
use std::io;
use std::error;

use bitcoin::network::serialize::Error as btc_serialize_error;
use bitcoin::util::hash::HexError as btc_hex_error;
use jsonrpc::Error as jsonrpc_error;

// Borrowed from Andrew Poelstra's rust-bitcoin 

/// Network error
#[derive(Debug)]
pub enum Error {
    /// I/O error
    Io(io::Error),
    /// Socket mutex was poisoned
    SocketMutexPoisoned,
    /// Not connected to peer
    SocketNotConnectedToPeer,
    /// Serialization error 
    SerializationError(btc_serialize_error),
    /// Invalid Message to peer
    InvalidMessage,
    /// Invalid Reply from peer
    InvalidReply,
    /// Invalid magic 
    InvalidMagic,
    /// Unhandled message 
    UnhandledMessage,
    /// Functionality not implemented 
    NotImplemented,
    /// Connection is broken and ought to be re-established
    ConnectionBroken,
    /// general filesystem error
    FilesystemError(io::Error),
    /// Hashing error
    HashError(btc_hex_error),
    /// Non-contiguous header 
    NoncontiguousHeader,
    /// Missing header
    MissingHeader,
    /// Invalid target 
    InvalidPoW,
    /// RPC error with bitcoin 
    JSONRPCError(jsonrpc_error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::SocketMutexPoisoned | Error::SocketNotConnectedToPeer => f.write_str(error::Error::description(self)),
            Error::SerializationError(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidMessage => f.write_str(error::Error::description(self)),
            Error::InvalidReply => f.write_str(error::Error::description(self)),
            Error::InvalidMagic => f.write_str(error::Error::description(self)),
            Error::UnhandledMessage => f.write_str(error::Error::description(self)),
            Error::NotImplemented => f.write_str(error::Error::description(self)),
            Error::ConnectionBroken => f.write_str(error::Error::description(self)),
            Error::FilesystemError(ref e) => fmt::Display::fmt(e, f),
            Error::HashError(ref e) => fmt::Display::fmt(e, f),
            Error::NoncontiguousHeader => f.write_str(error::Error::description(self)),
            Error::MissingHeader => f.write_str(error::Error::description(self)),
            Error::InvalidPoW => f.write_str(error::Error::description(self)),
            Error::JSONRPCError(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::SocketMutexPoisoned | Error::SocketNotConnectedToPeer => None,
            Error::SerializationError(ref e) => Some(e),
            Error::InvalidMessage => None,
            Error::InvalidReply => None,
            Error::InvalidMagic => None,
            Error::UnhandledMessage => None,
            Error::NotImplemented => None,
            Error::ConnectionBroken => None,
            Error::FilesystemError(ref e) => Some(e),
            Error::HashError(ref e) => Some(e),
            Error::NoncontiguousHeader => None,
            Error::MissingHeader => None,
            Error::InvalidPoW => None,
            Error::JSONRPCError(ref e) => Some(e)
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Io(ref e) => e.description(),
            Error::SocketMutexPoisoned => "socket mutex was poisoned",
            Error::SocketNotConnectedToPeer => "not connected to peer",
            Error::SerializationError(ref e) => e.description(),
            Error::InvalidMessage => "invalid message to send",
            Error::InvalidReply => "invalid reply for given message",
            Error::InvalidMagic => "invalid network magic",
            Error::UnhandledMessage => "unable to handle message",
            Error::NotImplemented => "functionality not implemented",
            Error::ConnectionBroken => "connection to peer node is broken",
            Error::FilesystemError(ref e) => e.description(),
            Error::HashError(ref e) => e.description(),
            Error::NoncontiguousHeader => "Non-contiguous header",
            Error::MissingHeader => "Missing header",
            Error::InvalidPoW => "Invalid proof of work",
            Error::JSONRPCError(ref e) => e.description()
        }
    }
}
