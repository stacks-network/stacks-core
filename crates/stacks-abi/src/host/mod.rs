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

//! The host interface (ABI 6).
//!
//! [`HOST_FUNCTIONS`] is the one definition of the functions a module may
//! import: each function's group, parameters, result, status codes and
//! charge formula. Deploy validation, linking, the fuel schedule and the
//! tools derive from it. Its tests check the rules every entry must keep.

mod table;
#[cfg(test)]
mod tests;

pub use table::HOST_FUNCTIONS;

/// The module every host function is imported from (ABI 3.2).
pub const IMPORT_MODULE: &str = "stacks-abi-v1";

/// A group of host functions: a heading of ABI 6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// Boundary and control.
    Boundary,
    /// Transaction and block context.
    Context,
    /// Lookups of blocks, tenures and burn blocks by height.
    BlockData,
    /// The contract's key-value store.
    Storage,
    /// Fungible tokens, non-fungible tokens and STX.
    Assets,
    /// Frames.
    Frames,
    /// Calls and principals.
    Calls,
    /// Events.
    Events,
    /// Cryptography.
    Crypto,
}

/// A Wasm value type the host interface uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValType {
    I32,
    I64,
}

/// The kind of a parameter (ABI 6.1). Each expands to a fixed sequence of
/// Wasm parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamKind {
    /// `i32`: an integer.
    I32,
    /// `u128`: an unsigned 128-bit integer, low 64 bits first.
    U128,
    /// `principal`: the pointer and length of a principal's encoding.
    Principal,
    /// `bytes`: the pointer and length of raw bytes.
    Bytes,
    /// `bytes<N>`: a pointer to exactly `N` raw bytes.
    FixedBytes(u32),
    /// `out<N>`: a pointer the host writes exactly `N` bytes to.
    Out(u32),
    /// `buf`: a pointer and capacity the host writes at most `cap` bytes to.
    Buf,
}

impl ParamKind {
    /// The Wasm parameters the kind expands to.
    pub const fn wasm(self) -> &'static [ValType] {
        match self {
            ParamKind::I32 | ParamKind::FixedBytes(_) | ParamKind::Out(_) => &[ValType::I32],
            ParamKind::U128 => &[ValType::I64, ValType::I64],
            ParamKind::Principal | ParamKind::Bytes | ParamKind::Buf => {
                &[ValType::I32, ValType::I32]
            }
        }
    }
}

/// The kind of a result (ABI 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultKind {
    /// No result.
    None,
    /// `i32`: an integer, as the function describes.
    I32,
    /// `len`: the number of bytes written to a `buf`.
    Len,
    /// `status`: `0` for success, otherwise one of these codes, which are
    /// those of the function's type in [`crate::status`].
    Status(&'static [i32]),
    /// `bool`: `1` for true, `0` for false.
    Bool,
}

impl ResultKind {
    /// The Wasm result the kind expands to.
    pub const fn wasm(self) -> Option<ValType> {
        match self {
            ResultKind::None => None,
            _ => Some(ValType::I32),
        }
    }
}

/// A parameter of a host function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    pub name: &'static str,
    pub kind: ParamKind,
}

/// One term of a charge formula (ABI 9.2): a price of the fuel schedule,
/// times a quantity. A function is charged the sum of its terms.
///
/// The schedule has the prices of `Base`, `Input` and `Output` per function,
/// and those of the storage terms once. `Read` and `Write` price an access,
/// whatever the size of its value: finding the entry in the chain's state
/// and, for a write, the state the chain adds to hold the entry. `ReadBytes`
/// and `WrittenBytes` price the value's bytes. Reading and writing have
/// separate prices, so the schedule can price growth of the chain's state
/// apart from access to it.
///
/// A formula names every `bytes` and `principal` parameter in an `Input`
/// term and every `buf` in an `Output` term; parameters of a fixed size are
/// part of `Base`. `Read` and `Write` count accesses to contract and account
/// state; looking up a block, a tenure, a burn block or a contract's module
/// is part of `Base`. An access to a value of bounded size (a balance, a
/// supply, an owner) has no per-byte storage term: its bytes are part of the
/// price of the access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Charge {
    /// The function's base charge, which covers all work that does not
    /// depend on its arguments. Always the first term.
    Base,
    /// The function's price per input byte, times the length of the named
    /// `bytes` or `principal` parameter.
    Input(&'static str),
    /// The function's price per output byte, times the length of what the
    /// function produces for the named `buf` parameter, whether or not it
    /// fits, or times the unsigned value of the named `i32` parameter.
    Output(&'static str),
    /// The price of a storage read, times this number.
    Read(u32),
    /// The price of a storage write, times this number.
    Write(u32),
    /// The price per byte read from storage, times the length of the value
    /// read into the named `buf`, whether or not it fits. Only next to a
    /// `Read`.
    ReadBytes(&'static str),
    /// The price per byte written to storage, times the length of the value
    /// written from the named `bytes`. Only next to a `Write`.
    WrittenBytes(&'static str),
}

/// A host function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFunction {
    /// The name it is imported under.
    pub name: &'static str,
    pub group: Group,
    pub params: &'static [Param],
    pub result: ResultKind,
    /// The terms of the charge formula.
    pub charges: &'static [Charge],
}

impl HostFunction {
    /// The Wasm parameters of the import: the expansion of `params`.
    pub fn wasm_params(&self) -> Vec<ValType> {
        let expand = |param: &Param| param.kind.wasm();
        self.params.iter().flat_map(expand).copied().collect()
    }

    /// The parameter with the given name.
    pub fn param(&self, name: &str) -> Option<&'static Param> {
        self.params.iter().find(|param| param.name == name)
    }
}

/// The host function with the given name.
pub fn host_function(name: &str) -> Option<&'static HostFunction> {
    HOST_FUNCTIONS.iter().find(|function| function.name == name)
}
