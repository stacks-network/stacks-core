// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! The interface of a module (ABI 4.1).
//!
//! The `abi.interface` custom section records what the chain acts on: which
//! functions exist and how each may be called, which tokens the contract
//! defines, and which events it emits. An interface has exactly one
//! encoding, so [`Interface::decode`] accepts exactly the bytes
//! [`Interface::encode`] writes, and its hash identifies it.

use std::fmt;

use clarity_types::util::hash::Sha512Trunc256Sum;

use crate::names::{NAME_MAX_LEN, Name, NameError};

/// The ABI version this crate defines. A module states the version it
/// targets twice, and the two must agree (ABI 11): in the name of the module
/// it imports from ([`crate::host::IMPORT_MODULE`]) and in its interface.
pub const ABI_VERSION: u32 = 1;

/// How a function may be called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FunctionKind {
    /// Callable by a transaction or a contract; may change state.
    Public,
    /// Runs in a read-only frame (ABI 7.4).
    ReadOnly,
}

impl FunctionKind {
    /// The byte the kind is encoded as.
    pub const fn byte(self) -> u8 {
        match self {
            FunctionKind::Public => 0,
            FunctionKind::ReadOnly => 1,
        }
    }

    /// The kind a byte encodes.
    pub const fn from_byte(byte: u8) -> Option<FunctionKind> {
        match byte {
            0 => Some(FunctionKind::Public),
            1 => Some(FunctionKind::ReadOnly),
            _ => None,
        }
    }
}

/// A function of an interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Function {
    pub name: Name,
    pub kind: FunctionKind,
}

/// Why bytes are not the encoding of an interface, or lists are not those of
/// one.
///
/// Decoding reads the bytes front to back and stops at the first field that
/// is missing or invalid, so every invalid input has exactly one reason. A
/// name length over the limit is rejected before the name's bytes are read,
/// a name's place in its list is judged before the field after it, and bytes
/// that follow the encoding are judged last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceError {
    /// The bytes end before the encoding does.
    Truncated,
    /// A name is not valid.
    BadName(NameError),
    /// A name sorts before the one it follows in its list.
    Unsorted,
    /// A name equals the one it follows in its list.
    Duplicate,
    /// A function's kind byte is neither `0` nor `1`.
    BadKind,
    /// Bytes follow the encoding.
    TrailingBytes,
}

impl InterfaceError {
    /// Every reason.
    pub const ALL: [InterfaceError; 9] = [
        InterfaceError::Truncated,
        InterfaceError::BadName(NameError::Empty),
        InterfaceError::BadName(NameError::TooLong),
        InterfaceError::BadName(NameError::BadByte),
        InterfaceError::BadName(NameError::BadStart),
        InterfaceError::Unsorted,
        InterfaceError::Duplicate,
        InterfaceError::BadKind,
        InterfaceError::TrailingBytes,
    ];

    /// A stable identifier for the reason, used by the vectors.
    pub const fn as_str(self) -> &'static str {
        match self {
            InterfaceError::Truncated => "truncated",
            InterfaceError::BadName(NameError::Empty) => "name-empty",
            InterfaceError::BadName(NameError::TooLong) => "name-too-long",
            InterfaceError::BadName(NameError::BadByte) => "name-bad-byte",
            InterfaceError::BadName(NameError::BadStart) => "name-bad-start",
            InterfaceError::Unsorted => "unsorted",
            InterfaceError::Duplicate => "duplicate",
            InterfaceError::BadKind => "bad-kind",
            InterfaceError::TrailingBytes => "trailing-bytes",
        }
    }
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for InterfaceError {}

/// A valid interface: in each list the names are in strictly ascending byte
/// order, so a token or an event is addressed by its index in its list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    abi_version: u32,
    functions: Vec<Function>,
    fts: Vec<Name>,
    nfts: Vec<Name>,
    events: Vec<Name>,
}

/// Checks that `name` may follow `previous` in a list.
fn check_order(previous: Option<&Name>, name: &Name) -> Result<(), InterfaceError> {
    match previous {
        Some(previous) if previous > name => Err(InterfaceError::Unsorted),
        Some(previous) if previous == name => Err(InterfaceError::Duplicate),
        _ => Ok(()),
    }
}

fn check_list<'a>(names: impl Iterator<Item = &'a Name>) -> Result<(), InterfaceError> {
    let mut previous = None;
    for name in names {
        check_order(previous, name)?;
        previous = Some(name);
    }
    Ok(())
}

impl Interface {
    /// An interface of the given lists. Fails with
    /// [`InterfaceError::Unsorted`] or [`InterfaceError::Duplicate`] unless
    /// each list is in strictly ascending order of name.
    ///
    /// Any `abi_version` is accepted, as it is by [`Interface::decode`]:
    /// whether a module's version is one the chain runs is a separate rule,
    /// with its own rejection reason.
    pub fn new(
        abi_version: u32,
        functions: Vec<Function>,
        fts: Vec<Name>,
        nfts: Vec<Name>,
        events: Vec<Name>,
    ) -> Result<Interface, InterfaceError> {
        check_list(functions.iter().map(|function| &function.name))?;
        for list in [&fts, &nfts, &events] {
            check_list(list.iter())?;
        }
        Ok(Interface {
            abi_version,
            functions,
            fts,
            nfts,
            events,
        })
    }

    /// The ABI version the module targets.
    pub fn abi_version(&self) -> u32 {
        self.abi_version
    }

    /// The functions, in ascending order of name.
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// The fungible tokens; a token's index is its handle in the module.
    pub fn fts(&self) -> &[Name] {
        &self.fts
    }

    /// The non-fungible tokens; a token's index is its handle in the module.
    pub fn nfts(&self) -> &[Name] {
        &self.nfts
    }

    /// The events; an event's index is its handle in the module.
    pub fn events(&self) -> &[Name] {
        &self.events
    }

    /// Decodes an interface, accepting exactly its one encoding.
    pub fn decode(bytes: &[u8]) -> Result<Interface, InterfaceError> {
        let mut reader = Reader(bytes);
        let abi_version = reader.u32()?;
        // A count is not trusted for an allocation: the bytes may end long
        // before it is reached.
        let mut functions: Vec<Function> = Vec::new();
        for _ in 0..reader.u32()? {
            let name = reader.name(functions.last().map(|function| &function.name))?;
            let kind = FunctionKind::from_byte(reader.u8()?).ok_or(InterfaceError::BadKind)?;
            functions.push(Function { name, kind });
        }
        let fts = reader.names()?;
        let nfts = reader.names()?;
        let events = reader.names()?;
        if !reader.0.is_empty() {
            return Err(InterfaceError::TrailingBytes);
        }
        Ok(Interface {
            abi_version,
            functions,
            fts,
            nfts,
            events,
        })
    }

    /// Encodes the interface: the bytes of the `abi.interface` section.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.abi_version.to_be_bytes());
        write_count(&mut bytes, self.functions.len());
        for function in &self.functions {
            write_name(&mut bytes, &function.name);
            bytes.push(function.kind.byte());
        }
        for list in [&self.fts, &self.nfts, &self.events] {
            write_count(&mut bytes, list.len());
            for name in list {
                write_name(&mut bytes, name);
            }
        }
        bytes
    }

    /// The hash of the interface: `sha512/256` of its encoding.
    pub fn hash(&self) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum::from_data(&self.encode())
    }
}

fn write_count(bytes: &mut Vec<u8>, count: usize) {
    // A list has a name of at least one byte per entry, so a count that did
    // not fit would need more than 4 GiB of names in memory.
    bytes.extend_from_slice(&(count as u32).to_be_bytes());
}

fn write_name(bytes: &mut Vec<u8>, name: &Name) {
    // A valid name is at most 128 bytes.
    bytes.push(name.as_bytes().len() as u8);
    bytes.extend_from_slice(name.as_bytes());
}

/// The bytes of an encoding that are still to be read.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, InterfaceError> {
        let (byte, rest) = self.0.split_first().ok_or(InterfaceError::Truncated)?;
        self.0 = rest;
        Ok(*byte)
    }

    fn u32(&mut self) -> Result<u32, InterfaceError> {
        let (bytes, rest) = self
            .0
            .split_first_chunk::<4>()
            .ok_or(InterfaceError::Truncated)?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*bytes))
    }

    /// Reads a name that may follow `previous` in its list.
    fn name(&mut self, previous: Option<&Name>) -> Result<Name, InterfaceError> {
        let len = usize::from(self.u8()?);
        // The length byte alone decides this, whatever bytes follow it.
        if len > NAME_MAX_LEN {
            return Err(InterfaceError::BadName(NameError::TooLong));
        }
        let (name, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(InterfaceError::Truncated)?;
        self.0 = rest;
        let name = Name::try_from(name).map_err(InterfaceError::BadName)?;
        check_order(previous, &name)?;
        Ok(name)
    }

    /// Reads a count and that many names.
    fn names(&mut self) -> Result<Vec<Name>, InterfaceError> {
        let mut names = Vec::new();
        for _ in 0..self.u32()? {
            let name = self.name(names.last())?;
            names.push(name);
        }
        Ok(names)
    }
}
