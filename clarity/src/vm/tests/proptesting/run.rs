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

//! Run Clarity snippets in a fresh global context with funded sender and contract accounts.

use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity_types::{ContractName, Value};
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksPrivateKey;

use crate::vm::contexts::GlobalContext;
use crate::vm::database::STXBalance;
use crate::vm::errors::{ClarityEvalError, VmExecutionError};
use crate::vm::{ClarityVersion, execute_with_parameters_and_call_in_global_context};

const DEFAULT_EPOCH: StacksEpochId = StacksEpochId::latest();
const DEFAULT_CLARITY_VERSION: ClarityVersion = ClarityVersion::latest();
const INITIAL_BALANCE: u128 = 1_000_000_000;

fn initialize_balances(
    g: &mut GlobalContext,
    sender: &StandardPrincipalData,
) -> Result<(), VmExecutionError> {
    let sender_principal = PrincipalData::Standard(sender.clone());
    let contract_principal = PrincipalData::Contract(QualifiedContractIdentifier::new(
        sender.clone(),
        ContractName::from_literal("contract"),
    ));
    let balance = STXBalance::initial(INITIAL_BALANCE);

    let mut sender_snapshot = g
        .database
        .get_stx_balance_snapshot_genesis(&sender_principal)
        .unwrap();
    sender_snapshot.set_balance(balance.clone());
    sender_snapshot.save().unwrap();

    let mut contract_snapshot = g
        .database
        .get_stx_balance_snapshot_genesis(&contract_principal)
        .unwrap();
    contract_snapshot.set_balance(balance);
    contract_snapshot.save().unwrap();

    g.database
        .increment_ustx_liquid_supply(INITIAL_BALANCE * 2)
        .unwrap();
    Ok(())
}

/// Execute a Clarity code snippet in a fresh global context with default
/// parameters, setting up initial balances.
pub fn execute(snippet: &str) -> Result<Option<Value>, ClarityEvalError> {
    execute_versioned(snippet, DEFAULT_CLARITY_VERSION)
}

/// Execute a Clarity code snippet with the specified Clarity version in a
/// fresh global context with default parameters, setting up initial balances.
pub fn execute_versioned(
    snippet: &str,
    version: ClarityVersion,
) -> Result<Option<Value>, ClarityEvalError> {
    let sender_pk = StacksPrivateKey::random();
    let sender: StandardPrincipalData = (&sender_pk).into();
    let sender_for_init = sender.clone();
    execute_with_parameters_and_call_in_global_context(
        snippet,
        version,
        DEFAULT_EPOCH,
        false,
        sender,
        move |g| initialize_balances(g, &sender_for_init),
        |_| Ok(()),
    )
}

pub fn execute_with_epoch(
    snippet: &str,
    epoch: StacksEpochId,
) -> Result<Option<Value>, ClarityEvalError> {
    execute_with_version_and_epoch(snippet, ClarityVersion::latest(), epoch)
}

/// Execute a Clarity code snippet with the given Clarity version and epoch in a
/// fresh global context, setting up initial balances.
pub fn execute_with_version_and_epoch(
    snippet: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<Option<Value>, ClarityEvalError> {
    let sender = StandardPrincipalData::transient();
    let sender_for_init = sender.clone();
    execute_with_parameters_and_call_in_global_context(
        snippet,
        version,
        epoch,
        false,
        sender,
        move |g| initialize_balances(g, &sender_for_init),
        |_| Ok(()),
    )
}

/// Execute a Clarity code snippet in a fresh global context with default
/// parameters, setting up initial balances, returning the resulting value
/// along with the final asset map.
pub fn execute_and_check<F>(
    snippet: &str,
    sender: StandardPrincipalData,
    check: F,
) -> Result<Option<Value>, ClarityEvalError>
where
    F: FnMut(&mut GlobalContext) -> Result<(), VmExecutionError>,
{
    execute_and_check_versioned(snippet, DEFAULT_CLARITY_VERSION, sender, check)
}

/// Execute a Clarity code snippet with the specified Clarity version in a
/// fresh global context with default parameters, setting up initial balances,
/// returning the resulting value along with the final asset map.
pub fn execute_and_check_versioned<F>(
    snippet: &str,
    version: ClarityVersion,
    sender: StandardPrincipalData,
    mut check: F,
) -> Result<Option<Value>, ClarityEvalError>
where
    F: FnMut(&mut GlobalContext) -> Result<(), VmExecutionError>,
{
    let sender_for_init = sender.clone();
    execute_with_parameters_and_call_in_global_context(
        snippet,
        version,
        DEFAULT_EPOCH,
        false,
        sender,
        move |g| initialize_balances(g, &sender_for_init),
        move |g| check(g),
    )
}
