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

//! Network Serialization
//!
//! This module defines the `Serializable` trait which is used for
//! (de)serializing Bitcoin objects for transmission on the network.
//! It also defines (de)serialization routines for many primitives.
//!

use std::io::{Cursor, Read, Write};
use std::{error, fmt, io};

use crate::address;
use crate::deps_common::bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use crate::deps_common::bitcoin::util::hash::Sha256dHash;
use crate::util::hash::to_hex as hex_encode;

/// Serialization error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// And I/O error
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Base58 encoding error
    #[error("{0}")]
    Base58(#[from] address::Error),
    /// Network magic was not expected
    #[error("unexpected network magic: expected {expected}, actual {actual}")]
    UnexpectedNetworkMagic {
        /// The expected network magic
        expected: u32,
        /// The unexpected network magic
        actual: u32,
    },
    /// Tried to allocate an oversized vector
    #[error("allocation of oversized vector requested: requested {requested}, maximum {max}")]
    OversizedVectorAllocation {
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Checksum was invalid
    #[error("invalid checksum: expected {expected:?}, actual {actual:?}")]
    InvalidChecksum {
        /// The expected checksum
        expected: [u8; 4],
        /// The invalid checksum
        actual: [u8; 4],
    },
    /// Network magic was unknown
    #[error("unknown network magic: {0}")]
    UnknownNetworkMagic(u32),
    /// Parsing error
    #[error("parse failed: {0}")]
    ParseFailed(&'static str),
    /// Unsupported witness version
    #[error("unsupported witness version: {0}")]
    UnsupportedWitnessVersion(u8),
    /// Unsupported Segwit flag
    #[error("unsupported segwit version: {0}")]
    UnsupportedSegwitFlag(u8),
    /// Unrecognized network command
    #[error("unrecognized network command: {0}")]
    UnrecognizedNetworkCommand(String),
    /// Unexpected hex digit
    #[error("unexpected hex digit: {0}")]
    UnexpectedHexDigit(char),
}

/// Objects which are referred to by hash
pub trait BitcoinHash {
    /// Produces a Sha256dHash which can be used to refer to the object
    fn bitcoin_hash(&self) -> Sha256dHash;
}

impl BitcoinHash for Vec<u8> {
    #[inline]
    fn bitcoin_hash(&self) -> Sha256dHash {
        Sha256dHash::from_data(&self[..])
    }
}

/// Encode an object into a vector
pub fn serialize<T: ?Sized>(data: &T) -> Result<Vec<u8>, Error>
where
    T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>>,
{
    let mut encoder = RawEncoder::new(Cursor::new(vec![]));
    data.consensus_encode(&mut encoder)?;
    Ok(encoder.into_inner().into_inner())
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: ?Sized>(data: &T) -> Result<String, Error>
where
    T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>>,
{
    let serial = serialize(data)?;
    Ok(hex_encode(&serial[..]))
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<'a, T>(data: &'a [u8]) -> Result<T, Error>
where
    T: ConsensusDecodable<RawDecoder<Cursor<&'a [u8]>>>,
{
    let mut decoder = RawDecoder::new(Cursor::new(data));
    let rv = ConsensusDecodable::consensus_decode(&mut decoder)?;

    // Fail if data is not consumed entirely.
    if decoder.into_inner().position() == data.len() as u64 {
        Ok(rv)
    } else {
        Err(Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        ))
    }
}

/// An encoder for raw binary data
pub struct RawEncoder<W> {
    writer: W,
}

/// An decoder for raw binary data
pub struct RawDecoder<R> {
    reader: R,
}

impl<W: Write> RawEncoder<W> {
    /// Constructor
    pub fn new(writer: W) -> RawEncoder<W> {
        RawEncoder { writer }
    }
    /// Returns the underlying Writer
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<R: Read> RawDecoder<R> {
    /// Constructor
    pub fn new(reader: R) -> RawDecoder<R> {
        RawDecoder { reader }
    }
    /// Returns the underlying Reader
    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// A simple Encoder trait
pub trait SimpleEncoder {
    /// Output a 64-bit uint
    fn emit_u64(&mut self, v: u64) -> Result<(), Error>;
    /// Output a 32-bit uint
    fn emit_u32(&mut self, v: u32) -> Result<(), Error>;
    /// Output a 16-bit uint
    fn emit_u16(&mut self, v: u16) -> Result<(), Error>;
    /// Output a 8-bit uint
    fn emit_u8(&mut self, v: u8) -> Result<(), Error>;

    /// Output a 64-bit int
    fn emit_i64(&mut self, v: i64) -> Result<(), Error>;
    /// Output a 32-bit int
    fn emit_i32(&mut self, v: i32) -> Result<(), Error>;
    /// Output a 16-bit int
    fn emit_i16(&mut self, v: i16) -> Result<(), Error>;
    /// Output a 8-bit int
    fn emit_i8(&mut self, v: i8) -> Result<(), Error>;

    /// Output a boolean
    fn emit_bool(&mut self, v: bool) -> Result<(), Error>;
}

/// A simple Decoder trait
pub trait SimpleDecoder {
    /// Read a 64-bit uint
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Read a 32-bit uint
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Read a 16-bit uint
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Read a 8-bit uint
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Read a 64-bit int
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Read a 32-bit int
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Read a 16-bit int
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Read a 8-bit int
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Read a boolean
    fn read_bool(&mut self) -> Result<bool, Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), Error> {
            self.writer.write_all(&v.to_le_bytes()).map_err(Error::Io)
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $type_size:literal) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            let mut buff = [0; $type_size];
            self.reader.read_exact(&mut buff).map_err(Error::Io)?;
            Ok(<$val_type>::from_le_bytes(buff))
        }
    };
}

impl<W: Write> SimpleEncoder for RawEncoder<W> {
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);
    encoder_fn!(emit_i8, i8);
    encoder_fn!(emit_u8, u8);

    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), Error> {
        self.emit_i8(if v { 1 } else { 0 })
    }
}

impl<R: Read> SimpleDecoder for RawDecoder<R> {
    decoder_fn!(read_u64, u64, 8);
    decoder_fn!(read_u32, u32, 4);
    decoder_fn!(read_u16, u16, 2);
    decoder_fn!(read_i64, i64, 8);
    decoder_fn!(read_i32, i32, 4);
    decoder_fn!(read_i16, i16, 2);
    decoder_fn!(read_u8, u8, 1);
    decoder_fn!(read_i8, i8, 1);

    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        self.read_i8().map(|bit| bit != 0)
    }
}

// Aren't really any tests here.. the main functions are serialize and
// deserialize, which get the crap tested out of them it every other
// module.
