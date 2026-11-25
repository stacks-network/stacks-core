// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

//! Standard and contract principals.

use clarity_types::ContractName;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use proptest::prelude::*;

use super::names::{contract_name_strategy, writable_contract_name_strategy};

/// Standard principals with any valid address version (`0..32`) and a random hash.
pub fn standard_principal_strategy() -> impl Strategy<Value = StandardPrincipalData> {
    (0u8..32, any::<[u8; 20]>()).prop_map(|(version, bytes)| {
        StandardPrincipalData::new(version, bytes).expect("version is below 32")
    })
}

/// Contract principals: a standard issuer and any valid contract name.
pub fn contract_principal_strategy() -> impl Strategy<Value = QualifiedContractIdentifier> {
    contract_principal_with(contract_name_strategy())
}

/// Contract principals that can be written in Clarity source; see
/// [`writable_contract_name_strategy`].
pub fn writable_contract_principal_strategy() -> impl Strategy<Value = QualifiedContractIdentifier>
{
    contract_principal_with(writable_contract_name_strategy())
}

/// Standard or contract principals, equally weighted.
pub fn principal_strategy() -> impl Strategy<Value = PrincipalData> {
    principal_with(contract_principal_strategy())
}

/// Standard or contract principals that can be written in Clarity source, equally weighted.
pub fn writable_principal_strategy() -> impl Strategy<Value = PrincipalData> {
    principal_with(writable_contract_principal_strategy())
}

fn contract_principal_with(
    names: impl Strategy<Value = ContractName>,
) -> impl Strategy<Value = QualifiedContractIdentifier> {
    (standard_principal_strategy(), names)
        .prop_map(|(issuer, name)| QualifiedContractIdentifier::new(issuer, name))
}

fn principal_with(
    contracts: impl Strategy<Value = QualifiedContractIdentifier>,
) -> impl Strategy<Value = PrincipalData> {
    prop_oneof![
        standard_principal_strategy().prop_map(PrincipalData::Standard),
        contracts.prop_map(PrincipalData::Contract),
    ]
}
