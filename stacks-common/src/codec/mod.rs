use std::io::{Read, Write};
use std::{error, fmt, io, mem};

// use crate::types::chainstate::MARFValue;
use crate::types::chainstate::SortitionId;
use crate::util::hash::HASH160_ENCODED_SIZE;
use crate::util::secp256k1::MESSAGE_SIGNATURE_ENCODED_SIZE;

#[macro_use]
pub mod macros;

#[derive(Debug)]
pub enum Error {
    /// Failed to encode
    SerializeError(String),
    /// Failed to read
    ReadError(io::Error),
    /// Failed to decode
    DeserializeError(String),
    /// Failed to write
    WriteError(io::Error),
    /// Underflow -- not enough bytes to form the message
    UnderflowError(String),
    /// Overflow -- message too big
    OverflowError(String),
    /// Array is too big
    ArrayTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SerializeError(ref s) => fmt::Display::fmt(s, f),
            Error::DeserializeError(ref s) => fmt::Display::fmt(s, f),
            Error::ReadError(ref io) => fmt::Display::fmt(io, f),
            Error::WriteError(ref io) => fmt::Display::fmt(io, f),
            Error::UnderflowError(ref s) => fmt::Display::fmt(s, f),
            Error::OverflowError(ref s) => fmt::Display::fmt(s, f),
            Error::ArrayTooLong => write!(f, "Array too long"),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::SerializeError(ref _s) => None,
            Error::ReadError(ref io) => Some(io),
            Error::DeserializeError(ref _s) => None,
            Error::WriteError(ref io) => Some(io),
            Error::UnderflowError(ref _s) => None,
            Error::OverflowError(ref _s) => None,
            Error::ArrayTooLong => None,
        }
    }
}

/// Helper trait for various primitive types that make up Stacks messages
pub trait StacksMessageCodec {
    /// serialize implementors _should never_ error unless there is an underlying
    ///   failure in writing to the `fd`
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error>
    where
        Self: Sized;
    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, Error>
    where
        Self: Sized;
    /// Convenience for serialization to a vec.
    ///  this function unwraps any underlying serialization error
    fn serialize_to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: serialization to buffer failed.");
        bytes
    }
}

// impl_byte_array_message_codec!(MARFValue, 40);
impl_byte_array_message_codec!(SortitionId, 32);

impl_stacks_message_codec_for_int!(u8; [0; 1]);
impl_stacks_message_codec_for_int!(u16; [0; 2]);
impl_stacks_message_codec_for_int!(u32; [0; 4]);
impl_stacks_message_codec_for_int!(u64; [0; 8]);
impl_stacks_message_codec_for_int!(i64; [0; 8]);

impl StacksMessageCodec for [u8; 32] {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        fd.write_all(self).map_err(Error::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<[u8; 32], Error> {
        let mut buf = [0u8; 32];
        fd.read_exact(&mut buf).map_err(Error::ReadError)?;
        Ok(buf)
    }
}

pub fn write_next<T: StacksMessageCodec, W: Write>(fd: &mut W, item: &T) -> Result<(), Error> {
    item.consensus_serialize(fd)
}

pub fn read_next<T: StacksMessageCodec, R: Read>(fd: &mut R) -> Result<T, Error> {
    let item: T = T::consensus_deserialize(fd)?;
    Ok(item)
}

fn read_next_vec<T: StacksMessageCodec + Sized, R: Read>(
    fd: &mut R,
    num_items: u32,
    max_items: u32,
) -> Result<Vec<T>, Error> {
    let len = u32::consensus_deserialize(fd)?;

    if max_items > 0 {
        if len > max_items {
            // too many items
            return Err(Error::DeserializeError(format!(
                "Array has too many items ({} > {}",
                len, max_items
            )));
        }
    } else {
        if len != num_items {
            // inexact item count
            return Err(Error::DeserializeError(format!(
                "Array has incorrect number of items ({} != {})",
                len, num_items
            )));
        }
    }

    if (mem::size_of::<T>() as u128) * (len as u128) > MAX_MESSAGE_LEN as u128 {
        return Err(Error::DeserializeError(format!(
            "Message occupies too many bytes (tried to allocate {}*{}={})",
            mem::size_of::<T>() as u128,
            len,
            (mem::size_of::<T>() as u128) * (len as u128)
        )));
    }

    let mut ret = Vec::with_capacity(len as usize);
    for _i in 0..len {
        let next_item = T::consensus_deserialize(fd)?;
        ret.push(next_item);
    }

    Ok(ret)
}

pub fn read_next_at_most<R: Read, T: StacksMessageCodec + Sized>(
    fd: &mut R,
    max_items: u32,
) -> Result<Vec<T>, Error> {
    read_next_vec::<T, R>(fd, 0, max_items)
}

pub fn read_next_exact<R: Read, T: StacksMessageCodec + Sized>(
    fd: &mut R,
    num_items: u32,
) -> Result<Vec<T>, Error> {
    read_next_vec::<T, R>(fd, num_items, 0)
}

impl<T> StacksMessageCodec for Vec<T>
where
    T: StacksMessageCodec + Sized,
{
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        let len = self.len() as u32;
        write_next(fd, &len)?;
        for i in 0..self.len() {
            write_next(fd, &self[i])?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Vec<T>, Error> {
        read_next_at_most::<R, T>(fd, u32::MAX)
    }
}

// messages can't be bigger than 16MB plus the preamble and relayers
pub const MAX_PAYLOAD_LEN: u32 = 1 + 16 * 1024 * 1024;
pub const MAX_MESSAGE_LEN: u32 =
    MAX_PAYLOAD_LEN + (PREAMBLE_ENCODED_SIZE + MAX_RELAYERS_LEN * RELAY_DATA_ENCODED_SIZE);

/// P2P preamble length (addands correspond to fields above)
pub const PREAMBLE_ENCODED_SIZE: u32 = 4
    + 4
    + 4
    + 8
    + BURNCHAIN_HEADER_HASH_ENCODED_SIZE
    + 8
    + BURNCHAIN_HEADER_HASH_ENCODED_SIZE
    + 4
    + MESSAGE_SIGNATURE_ENCODED_SIZE
    + 4;

pub const BURNCHAIN_HEADER_HASH_ENCODED_SIZE: u32 = 32;

// maximum number of relayers that can be included in a message
pub const MAX_RELAYERS_LEN: u32 = 16;

pub const RELAY_DATA_ENCODED_SIZE: u32 = NEIGHBOR_ADDRESS_ENCODED_SIZE + 4;

pub const NEIGHBOR_ADDRESS_ENCODED_SIZE: u32 = PEER_ADDRESS_ENCODED_SIZE + 2 + HASH160_ENCODED_SIZE;
pub const PEER_ADDRESS_ENCODED_SIZE: u32 = 16;
