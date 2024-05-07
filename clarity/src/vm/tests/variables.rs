// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

#[cfg(any(test, feature = "testing"))]
use rstest::rstest;
use stacks_common::types::StacksEpochId;

#[cfg(test)]
use crate::vm::analysis::type_checker::v2_1::tests::contracts::type_check_version;
use crate::vm::analysis::{run_analysis, CheckError};
use crate::vm::ast::{parse, ASTRules};
use crate::vm::database::MemoryBackingStore;
use crate::vm::errors::{CheckErrors, Error};
use crate::vm::tests::{test_clarity_versions, tl_env_factory, TopLevelMemoryEnvironmentGenerator};
use crate::vm::types::{QualifiedContractIdentifier, Value};
use crate::vm::{ClarityVersion, ContractContext};

#[apply(test_clarity_versions)]
fn test_block_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) block-height)";

    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, &contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version >= ClarityVersion::Clarity3 {
        let err = analysis.unwrap_err();
        assert_eq!(
            CheckErrors::UndefinedVariable("block-height".to_string()),
            err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // If we're testing epoch 3, we need to simulate the tenure height being
    // set at the transition.
    if epoch >= StacksEpochId::Epoch30 {
        owned_env.set_tenure_height(1);
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
        ASTRules::PrecheckSize,
    );

    let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version >= ClarityVersion::Clarity3 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            Error::Unchecked(CheckErrors::UndefinedVariable("block-height".to_string(),)),
            err
        );
    } else {
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}

#[apply(test_clarity_versions)]
fn test_stacks_block_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) stacks-block-height)";

    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, &contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version < ClarityVersion::Clarity3 {
        let err = analysis.unwrap_err();
        assert_eq!(
            CheckErrors::UndefinedVariable("stacks-block-height".to_string()),
            err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // If we're testing epoch 3, we need to simulate the tenure height being
    // set at the transition.
    if epoch >= StacksEpochId::Epoch30 {
        owned_env.set_tenure_height(1);
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
        ASTRules::PrecheckSize,
    );

    let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version < ClarityVersion::Clarity3 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            Error::Unchecked(CheckErrors::UndefinedVariable(
                "stacks-block-height".to_string(),
            )),
            err
        );
    } else {
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}

#[apply(test_clarity_versions)]
fn test_tenure_height(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contract = "(define-read-only (test-func) tenure-height)";

    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();

    let mut exprs = parse(&contract_identifier, &contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let analysis = db.execute(|db| {
        type_check_version(&contract_identifier, &mut exprs, db, true, epoch, version)
    });
    if version < ClarityVersion::Clarity3 {
        let err = analysis.unwrap_err();
        assert_eq!(
            CheckErrors::UndefinedVariable("tenure-height".to_string()),
            err.err
        );
    } else {
        assert!(analysis.is_ok());
    }

    // If we're testing epoch 3, we need to simulate the tenure height being
    // set at the transition.
    if epoch >= StacksEpochId::Epoch30 {
        owned_env.set_tenure_height(1);
    }

    // Initialize the contract
    // Note that we're ignoring the analysis failure here so that we can test
    // the runtime behavior. In Clarity 3, if this case somehow gets past the
    // analysis, it should fail at runtime.
    let result = owned_env.initialize_versioned_contract(
        contract_identifier.clone(),
        version,
        contract,
        None,
        ASTRules::PrecheckSize,
    );

    let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);

    // Call the function
    let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
    // In Clarity 3, this should trigger a runtime error
    if version < ClarityVersion::Clarity3 {
        let err = eval_result.unwrap_err();
        assert_eq!(
            Error::Unchecked(CheckErrors::UndefinedVariable("tenure-height".to_string(),)),
            err
        );
    } else {
        assert_eq!(Ok(Value::UInt(1)), eval_result);
    }
}
