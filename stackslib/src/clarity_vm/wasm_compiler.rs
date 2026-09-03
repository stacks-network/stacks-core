// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Just-in-time Wasm compilation for contracts which are already on chain.
//!
//! Contracts are normally compiled to Wasm when they are deployed, and the compiled module is
//! stored with the contract. Some contracts have no stored module: the boot contracts, and any
//! contract which was deployed before Wasm compilation was enabled. When one of those is called,
//! the Clarity VM compiles it first, through the hook installed by
//! [`ClarityBackingStore::get_wasm_compiler`], so that a contract-call is always executed by the
//! Wasm runtime instead of falling back to the interpreter.
//!
//! The compilation itself lives in `clar2wasm` ([`clar2wasm::compile_deployed_contract`]); this
//! module only adapts it to the [`WasmCompiler`] hook signature. The [`ClarityDatabase`] of the
//! running transaction serves as the [`clar2wasm::AnalysisLookup`], so the compile sees the
//! contract source and dependency analyses through the rollback-aware metadata layer.

use clarity::vm::database::{ClarityDatabase, WasmCompilation};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ClarityVersion;
use stacks_common::types::StacksEpochId;

/// Compile the already-deployed contract `contract_identifier` to a Wasm binary, and return it
/// together with the analysis it was compiled with.
///
/// The contract is compiled from its stored source, with the `clarity_version` and `epoch` it was
/// deployed with, so that the generated code matches the analysis the contract was accepted with.
/// Compilation is not charged to the caller, so a free cost tracker is used throughout.
pub fn compile_deployed_contract(
    db: &mut ClarityDatabase,
    contract_identifier: &QualifiedContractIdentifier,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<WasmCompilation, String> {
    let compiled =
        clar2wasm::compile_deployed_contract(db, contract_identifier, clarity_version, epoch)
            .map_err(|e| e.to_string())?;

    let mut module = compiled.module;
    Ok(WasmCompilation {
        module: module.emit_wasm(),
        analysis: compiled.contract_analysis,
    })
}
