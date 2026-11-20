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

//! Limits (ABI 9.3).
//!
//! The limits are fixed by an ABI version: they never change under a module
//! that targets it. They are not part of the fuel schedule, which may change
//! at an epoch. Two bounds of ABI 9.3 are deliberately absent because they
//! are not fixed by the ABI version: the fuel limit of a tenure, which is
//! schedule data, and the fuel limit of a read-only query, which each node
//! sets.

const KIB: u32 = 1024;
const MIB: u32 = 1024 * KIB;

/// The limits of one ABI version. Sizes are in bytes unless stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Contract-call depth: frames the host opens for calls (ABI 7.3).
    pub call_depth: u32,
    /// Memory of one instance.
    pub instance_memory: u32,
    /// Initial entries of a module's table.
    pub table_entries: u32,
    /// Memory of a transaction, summed over its live instances.
    pub transaction_memory: u32,
    /// Wasm stack of one contract frame, in the ABI's own units.
    pub wasm_stack: u32,
    /// Size of a module, the only bound on a contract's size.
    pub module_size: u32,
    /// Size of one NFT identifier.
    pub nft_identifier: u32,
    /// Size of one storage key.
    pub storage_key: u32,
    /// Size of one storage value.
    pub storage_value: u32,
    /// Size of the arguments of a transaction, query, or `call`.
    pub arguments: u32,
    /// Size of the result of one `result_set`.
    pub result: u32,
    /// Size of the data of one `emit`.
    pub event_data: u32,
    /// Allowances in one allowance frame (ABI 7.2).
    pub allowances: u32,
    /// Event bytes of a transaction, counting live events only (ABI 8.3).
    pub transaction_event_bytes: u32,
}

impl Limits {
    /// The limits of ABI version 1.
    ///
    /// All values are provisional until the ABI is frozen.
    pub const V1: Limits = Limits {
        call_depth: 64,
        instance_memory: 16 * MIB,
        table_entries: 16 * KIB,
        transaction_memory: 64 * MIB,
        wasm_stack: 64 * KIB,
        module_size: MIB,
        nft_identifier: MIB,
        storage_key: KIB,
        storage_value: MIB,
        arguments: MIB,
        result: MIB,
        event_data: MIB,
        allowances: 128,
        transaction_event_bytes: 4 * MIB,
    };
}
