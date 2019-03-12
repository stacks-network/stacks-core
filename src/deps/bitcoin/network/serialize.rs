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

use std::error;
use std::fmt;
use std::io;
use std::io::{Cursor, Read, Write};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use util::hash::to_hex as hex_encode;

use address;

use deps::bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use deps::bitcoin::util::hash::Sha256dHash;

/// Serialization error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// Base58 encoding error
    Base58(address::Error),
    /// Error from the `byteorder` crate
    ByteOrder(io::Error),
    /// Network magic was not expected
    UnexpectedNetworkMagic {
        /// The expected network magic
        expected: u32,
        /// The unexpected network magic
        actual: u32,
    },
    /// Tried to allocate an oversized vector
    OversizedVectorAllocation{
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Checksum was invalid
    InvalidChecksum {
        /// The expected checksum
        expected: [u8; 4],
        /// The invalid checksum
        actual: [u8; 4],
    },
    /// Network magic was unknown
    UnknownNetworkMagic(u32),
    /// Parsing error
    ParseFailed(&'static str),
    /// Unsupported witness version
    UnsupportedWitnessVersion(u8),
    /// Unsupported Segwit flag
    UnsupportedSegwitFlag(u8),
    /// Unrecognized network command
    UnrecognizedNetworkCommand(String),
    /// Unexpected hex digit
    UnexpectedHexDigit(char),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => fmt::Display::fmt(e, f),
            Error::Base58(ref e) => fmt::Display::fmt(e, f),
            Error::ByteOrder(ref e) => fmt::Display::fmt(e, f),
            Error::UnexpectedNetworkMagic { expected: ref e, actual: ref a } => write!(f, "{}: expected {}, actual {}", error::Error::description(self), e, a),
            Error::OversizedVectorAllocation { requested: ref r, max: ref m } => write!(f, "{}: requested {}, maximum {}", error::Error::description(self), r, m),
            Error::InvalidChecksum { expected: ref e, actual: ref a } => write!(f, "{}: expected {}, actual {}", error::Error::description(self), hex_encode(e), hex_encode(a)),
            Error::UnknownNetworkMagic(ref m) => write!(f, "{}: {}", error::Error::description(self), m),
            Error::ParseFailed(ref e) => write!(f, "{}: {}", error::Error::description(self), e),
            Error::UnsupportedWitnessVersion(ref wver) => write!(f, "{}: {}", error::Error::description(self), wver),
            Error::UnsupportedSegwitFlag(ref swflag) => write!(f, "{}: {}", error::Error::description(self), swflag),
            Error::UnrecognizedNetworkCommand(ref nwcmd) => write!(f, "{}: {}", error::Error::description(self), nwcmd),
            Error::UnexpectedHexDigit(ref d) => write!(f, "{}: {}", error::Error::description(self), d),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::Base58(ref e) => Some(e),
            Error::ByteOrder(ref e) => Some(e),
            Error::UnexpectedNetworkMagic { .. }
            | Error::OversizedVectorAllocation { .. }
            | Error::InvalidChecksum { .. }
            | Error::UnknownNetworkMagic(..)
            | Error::ParseFailed(..)
            | Error::UnsupportedWitnessVersion(..)
            | Error::UnsupportedSegwitFlag(..)
            | Error::UnrecognizedNetworkCommand(..)
            | Error::UnexpectedHexDigit(..) => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::Io(ref e) => e.description(),
            Error::Base58(ref e) => e.description(),
            Error::ByteOrder(ref e) => e.description(),
            Error::UnexpectedNetworkMagic { .. } => "unexpected network magic",
            Error::OversizedVectorAllocation { .. } => "allocation of oversized vector requested",
            Error::InvalidChecksum { .. } => "invalid checksum",
            Error::UnknownNetworkMagic(..) => "unknown network magic",
            Error::ParseFailed(..) => "parse failed",
            Error::UnsupportedWitnessVersion(..) => "unsupported witness version",
            Error::UnsupportedSegwitFlag(..) => "unsupported segwit version",
            Error::UnrecognizedNetworkCommand(..) => "unrecognized network command",
            Error::UnexpectedHexDigit(..) => "unexpected hex digit",
        }
    }
}

#[doc(hidden)]
impl From<address::Error> for Error {
    fn from(e: address::Error) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
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
     where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>>,
{
    let mut encoder = RawEncoder::new(Cursor::new(vec![]));
    data.consensus_encode(&mut encoder)?;
    Ok(encoder.into_inner().into_inner())
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: ?Sized>(data: &T) -> Result<String, Error>
     where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>>
{
    let serial = serialize(data)?;
    Ok(hex_encode(&serial[..]))
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<'a, T>(data: &'a [u8]) -> Result<T, Error>
     where T: ConsensusDecodable<RawDecoder<Cursor<&'a [u8]>>>
{
    let mut decoder = RawDecoder::new(Cursor::new(data));
    let rv = ConsensusDecodable::consensus_decode(&mut decoder)?;

    // Fail if data is not consumed entirely.
    if decoder.into_inner().position() == data.len() as u64 {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}

/// An encoder for raw binary data
pub struct RawEncoder<W> {
    writer: W
}

/// An decoder for raw binary data
pub struct RawDecoder<R> {
    reader: R
}

impl<W: Write> RawEncoder<W> {
    /// Constructor
    pub fn new(writer: W) -> RawEncoder<W> { RawEncoder { writer: writer } }
    /// Returns the underlying Writer
    pub fn into_inner(self) -> W { self.writer }
}

impl<R: Read> RawDecoder<R> {
  /// Constructor
  pub fn new(reader: R) -> RawDecoder<R> { RawDecoder { reader: reader } }
  /// Returns the underlying Reader
  pub fn into_inner(self) -> R { self.reader }
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
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), Error> {
            self.writer.$writefn::<LittleEndian>(v).map_err(Error::Io)
        }
    }
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            self.reader.$readfn::<LittleEndian>().map_err(Error::Io)
        }
    }
}

impl<W: Write> SimpleEncoder for RawEncoder<W> {
    encoder_fn!(emit_u64, u64, write_u64);
    encoder_fn!(emit_u32, u32, write_u32);
    encoder_fn!(emit_u16, u16, write_u16);
    encoder_fn!(emit_i64, i64, write_i64);
    encoder_fn!(emit_i32, i32, write_i32);
    encoder_fn!(emit_i16, i16, write_i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), Error> {
        self.writer.write_i8(v).map_err(Error::Io)
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), Error> {
        self.writer.write_u8(v).map_err(Error::Io)
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), Error> {
        self.writer.write_i8(if v {1} else {0}).map_err(Error::Io)
    }
}

impl<R: Read> SimpleDecoder for RawDecoder<R> {
    decoder_fn!(read_u64, u64, read_u64);
    decoder_fn!(read_u32, u32, read_u32);
    decoder_fn!(read_u16, u16, read_u16);
    decoder_fn!(read_i64, i64, read_i64);
    decoder_fn!(read_i32, i32, read_i32);
    decoder_fn!(read_i16, i16, read_i16);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        self.reader.read_u8().map_err(Error::Io)
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        self.reader.read_i8().map_err(Error::Io)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        match self.reader.read_i8() {
            Ok(bit) => Ok(bit != 0),
            Err(e) => Err(Error::Io(e))
        }
    }
}

// Aren't really any tests here.. the main functions are serialize and
// deserialize, which get the crap tested out of them it every other
// module.

