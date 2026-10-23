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
use clarity::vm::database::SpecialCaseHandler;
use clarity::vm::errors::VmExecutionError;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};

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

/// The contract-call special-case handler for calls into `contract`, if it can act on
/// them. Other calls get `None`, so the VM does not keep a copy of their arguments.
pub fn special_cases_handler_for(
    contract: &QualifiedContractIdentifier,
) -> Option<SpecialCaseHandler> {
    if pox_locking::has_contract_call_special_cases(contract) {
        Some(&handle_contract_call_special_cases)
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use clarity::boot_util::boot_code_id;
    use clarity::vm::types::QualifiedContractIdentifier;
    use rstest::rstest;

    use super::special_cases_handler_for;
    use crate::chainstate::stacks::boot::SIGNERS_NAME;

    /// Every PoX contract gets the handler, on both networks. The names are written out
    /// rather than taken from `PoxVersions`, so a wrong name there fails here.
    #[rstest]
    fn test_pox_contracts_get_the_handler(
        #[values("pox", "pox-2", "pox-3", "pox-4", "pox-5")] name: &str,
        #[values(true, false)] mainnet: bool,
    ) {
        assert!(special_cases_handler_for(&boot_code_id(name, mainnet)).is_some());
    }

    /// Contracts the handler ignores do not get it.
    #[rstest]
    #[case::boot_contract_other_than_pox(boot_code_id(SIGNERS_NAME, false))]
    #[case::user_contract_named_like_pox(QualifiedContractIdentifier::local("pox-4").unwrap())]
    fn test_other_contracts_do_not_get_the_handler(#[case] contract: QualifiedContractIdentifier) {
        assert!(special_cases_handler_for(&contract).is_none());
    }
}
