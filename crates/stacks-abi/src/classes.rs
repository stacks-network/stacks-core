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

//! Runtime error classes (ABI 10.2).
//!
//! The receipt of an aborted transaction names one class.

stacks_common::define_named_enum!(
    /// The class of a runtime error. Its name is the one a receipt carries.
    /// The serde form is the Rust variant name, not that name: a receipt
    /// carries `get_name_str()`.
    #[derive(Copy)]
    ErrorClass {
        /// The transaction consumed its `fuel-limit` (ABI 9.1).
        BudgetExceeded("budget-exceeded"),
        /// Instance or transaction memory.
        MemoryExceeded("memory-exceeded"),
        /// The Wasm stack limit.
        StackExceeded("stack-exceeded"),
        /// Contract-call depth.
        DepthExceeded("depth-exceeded"),
        /// The transaction's event bytes (ABI 8.3).
        EventsExceeded("events-exceeded"),
        /// A call into a contract that already has an active frame (ABI 7.3).
        Reentrancy("reentrancy"),
        /// A mutation, or a call to a public function, in a read-only frame
        /// (ABI 7.4).
        ReadOnlyViolation("read-only-violation"),
        /// A call that names a missing function or contract (ABI 5.1, 5.3).
        NoSuchFunction("no-such-function"),
        /// An entry point returned without calling `result_set` (ABI 5.2).
        NoResult("no-result"),
        /// An argument a host function rejects (ABI 6.1).
        BadHostArgument("bad-host-argument"),
        /// A frame closed that the module did not open, or left open when an
        /// export ends (ABI 7.1).
        UnbalancedFrame("unbalanced-frame"),
        /// Any Wasm trap.
        Trap("trap"),
        /// `abort(code, msg)`; the receipt also carries the code and message.
        ModuleAbort("module-abort"),
        /// An `ft_mint` past the token's supply cap, or a supply past `u128`.
        SupplyExceeded("supply-exceeded"),
        /// An argument or runtime error of a legacy callee in a Wasm transaction.
        LegacyError("legacy-error"),
    }
);
