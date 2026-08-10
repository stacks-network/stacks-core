// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use clarity::vm::contexts::GlobalContext;
use clarity::vm::database::SpecialCaseHandlerFn;
use clarity::vm::errors::VmExecutionError;
use clarity::vm::special_case::{KernelSpecialCaseHandlerFn, SpecialCaseContext};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};

/// The [`SpecialCaseHandlerFn`] token returned by this crate's backing-store
/// implementations from `get_cc_special_cases_handler`. The kernel carries it
/// opaquely; the VM downcasts it back to `SpecialCaseHandlerFn` at the
/// contract-call site.
pub static SPECIAL_CASE_HANDLER: SpecialCaseHandlerFn =
    SpecialCaseHandlerFn(handle_contract_call_special_cases);

/// The kernel-typed hook returned by this crate's backing stores from
/// `get_kernel_cc_special_cases_handler`. Every engine can invoke this one, so
/// it carries the handling that needs no Clarity evaluation -- notably `.pox-5`
/// lock-ups, which the Clarity 6 engine applies because `.pox-5` is itself a
/// Clarity 6 contract.
pub static KERNEL_SPECIAL_CASE_HANDLER: KernelSpecialCaseHandlerFn =
    KernelSpecialCaseHandlerFn(handle_kernel_contract_call_special_cases);

/// Handle special cases of contract-calls that touch only kernel state.
pub fn handle_kernel_contract_call_special_cases(
    ctx: &mut SpecialCaseContext,
    sender: Option<&PrincipalData>,
    sponsor: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    result: &Value,
) -> Result<(), VmExecutionError> {
    pox_locking::handle_kernel_contract_call_special_cases(
        ctx,
        sender,
        sponsor,
        contract_id,
        function_name,
        args,
        result,
    )
}

/// Handle special cases of contract-calls -- namely, those into PoX that should lock up STX
pub fn handle_contract_call_special_cases(
    global_context: &mut GlobalContext,
    sender: Option<&PrincipalData>,
    sponsor: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    result: &Value,
) -> Result<(), VmExecutionError> {
    pox_locking::handle_contract_call_special_cases(
        global_context,
        sender,
        sponsor,
        contract_id,
        function_name,
        args,
        result,
    )
}
