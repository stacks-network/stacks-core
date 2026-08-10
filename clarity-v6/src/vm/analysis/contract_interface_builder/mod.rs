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

use crate::vm::analysis::StaticCheckError;
use crate::vm::analysis::types::ContractAnalysis;

pub fn build_contract_interface(
    contract_analysis: &ContractAnalysis,
) -> Result<ContractInterface, StaticCheckError> {
    let mut contract_interface =
        ContractInterface::new(contract_analysis.epoch, contract_analysis.clarity_version);

    let ContractAnalysis {
        private_function_types,
        public_function_types,
        read_only_function_types,
        variable_types,
        persisted_variable_types,
        map_types,
        fungible_tokens,
        non_fungible_tokens,
        epoch: _,
        clarity_version: _,
        defined_traits: _,
        implemented_traits: _,
        expressions: _,
        contract_identifier: _,
        type_map: _,
        cost_track: _,
        contract_interface: _,
        is_cost_contract_eligible: _,
    } = contract_analysis;

    contract_interface
        .functions
        .append(&mut ContractInterfaceFunction::from_map(
            private_function_types,
            ContractInterfaceFunctionAccess::private,
        )?);

    contract_interface
        .functions
        .append(&mut ContractInterfaceFunction::from_map(
            public_function_types,
            ContractInterfaceFunctionAccess::public,
        )?);

    contract_interface
        .functions
        .append(&mut ContractInterfaceFunction::from_map(
            read_only_function_types,
            ContractInterfaceFunctionAccess::read_only,
        )?);

    contract_interface
        .variables
        .append(&mut ContractInterfaceVariable::from_map(
            variable_types,
            ContractInterfaceVariableAccess::constant,
        ));

    contract_interface
        .variables
        .append(&mut ContractInterfaceVariable::from_map(
            persisted_variable_types,
            ContractInterfaceVariableAccess::variable,
        ));

    contract_interface
        .maps
        .append(&mut ContractInterfaceMap::from_map(map_types));

    contract_interface.non_fungible_tokens.append(
        &mut ContractInterfaceNonFungibleTokens::from_map(non_fungible_tokens),
    );

    contract_interface
        .fungible_tokens
        .append(&mut ContractInterfaceFungibleTokens::from_set(
            fungible_tokens,
        ));

    Ok(contract_interface)
}

pub use clarity_kernel::contract_interface::*;
