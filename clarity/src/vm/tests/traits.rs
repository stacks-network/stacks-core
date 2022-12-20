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

use stacks_common::types::StacksEpochId;

use crate::vm::analysis::errors::CheckError;
use crate::vm::ast::ASTRules;
use crate::vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use crate::vm::errors::{CheckErrors, Error, RuntimeErrorType};
use crate::vm::execute as vm_execute;
use crate::vm::tests::{
    execute, symbols_from_values, with_memory_environment, with_versioned_memory_environment,
};
use crate::vm::types::{
    PrincipalData, QualifiedContractIdentifier, ResponseData, TypeSignature, Value,
};
use std::convert::TryInto;

use crate::vm::version::ClarityVersion;
use crate::vm::ContractContext;

#[template]
#[rstest]
#[case(ClarityVersion::Clarity1, StacksEpochId::Epoch2_05)]
#[case(ClarityVersion::Clarity1, StacksEpochId::Epoch21)]
#[case(ClarityVersion::Clarity2, StacksEpochId::Epoch21)]
fn test_epoch_clarity_versions(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {}

#[apply(test_epoch_clarity_versions)]
fn test_trait_basics(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let to_test = [
        test_dynamic_dispatch_pass_trait_nested_in_let,
        test_dynamic_dispatch_pass_trait,
        test_dynamic_dispatch_intra_contract_call,
        test_dynamic_dispatch_by_defining_trait,
        test_dynamic_dispatch_by_implementing_imported_trait,
        test_dynamic_dispatch_by_importing_trait,
        test_dynamic_dispatch_including_nested_trait,
        test_dynamic_dispatch_mismatched_args,
        test_dynamic_dispatch_mismatched_returned,
        test_reentrant_dynamic_dispatch,
        test_readwrite_dynamic_dispatch,
        test_readwrite_violation_dynamic_dispatch,
        test_bad_call_with_trait,
        test_good_call_with_trait,
        test_good_call_2_with_trait,
        test_contract_of_value,
        test_contract_of_no_impl,
        test_dynamic_dispatch_by_implementing_imported_trait_mul_funcs,
        test_dynamic_dispatch_pass_literal_principal_as_trait_in_user_defined_functions,
        test_return_trait_with_contract_of,
        test_return_trait_with_contract_of_wrapped_in_begin,
        test_return_trait_with_contract_of_wrapped_in_let,
    ];
    for test in to_test.iter() {
        with_versioned_memory_environment(test, epoch, version, false);
    }
}

#[test]
fn test_clarity2() {
    let to_test = [
        test_pass_principal_literal_to_trait,
        test_pass_trait_to_subtrait,
        test_embedded_trait,
        test_pass_embedded_trait_to_subtrait_optional,
        test_pass_embedded_trait_to_subtrait_ok,
        test_pass_embedded_trait_to_subtrait_err,
        test_pass_embedded_trait_to_subtrait_list,
        test_pass_embedded_trait_to_subtrait_list_option,
        test_pass_embedded_trait_to_subtrait_option_list,
        test_let_trait,
        test_let3_trait,
    ];
    for test in to_test.iter() {
        with_memory_environment(test, StacksEpochId::latest(), false);
    }
}

fn test_dynamic_dispatch_by_defining_trait(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_pass_trait_nested_in_let(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (let ((amount u0))
              (internal-get-1 contract)))
        (define-public (internal-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_pass_trait(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
              (internal-get-1 contract))
        (define-public (internal-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_intra_contract_call(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))
        (define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-trait").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        let err_result = env
            .execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false,
            )
            .unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::CircularReference(_)) => {}
            _ => panic!("{:?}", err_result),
        }
    }
}

fn test_dynamic_dispatch_by_implementing_imported_trait(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-trait").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_by_implementing_imported_trait_mul_funcs(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))
        (define-public (get-2 (x uint)) (ok u2))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-trait").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_by_importing_trait(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .contract-defining-trait.trait-1)
         (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-trait").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_including_nested_trait(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let contract_defining_nested_trait = "(define-trait trait-a (
        (get-a (uint) (response uint uint))))";
    let contract_defining_trait = "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-trait trait-1 (
            (get-1 (<trait-a>) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .contract-defining-trait.trait-1)
         (use-trait trait-a .contract-defining-nested-trait.trait-a)
         (define-public (wrapped-get-1 (contract <trait-1>) (nested-contract <trait-a>))
            (contract-call? contract get-1 nested-contract))";
    let target_contract = "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-public (get-1 (nested-contract <trait-a>))
            (contract-call? nested-contract get-a u0))";
    let target_nested_contract = "(define-public (get-a (x uint)) (ok u99))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-nested-trait").unwrap(),
            contract_defining_nested_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-trait").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-nested-contract").unwrap(),
            target_nested_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let target_nested_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-nested-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract, target_nested_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(99)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_mismatched_args(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x int)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        let err_result = env
            .execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false,
            )
            .unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::BadTraitImplementation(_, _)) => {}
            _ => panic!("{:?}", err_result),
        }
    }
}

fn test_dynamic_dispatch_mismatched_returned(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x uint)) (ok 1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        let err_result = env
            .execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false,
            )
            .unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::ReturnTypesMustMatch(_, _)) => {}
            _ => panic!("{:?}", err_result),
        }
    }
}

fn test_reentrant_dynamic_dispatch(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (internal-get-1 contract))
        (define-private (internal-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract =
        "(define-public (get-1 (x uint)) (contract-call? .dispatching-contract wrapped-get-1 .target-contract))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        let err_result = env
            .execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false,
            )
            .unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::CircularReference(_)) => {}
            _ => panic!("{:?}", err_result),
        }
    }
}

fn test_readwrite_dynamic_dispatch(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-read-only (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-read-only (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        let err_result = env
            .execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false,
            )
            .unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::TraitBasedContractCallInReadOnly) => {}
            _ => panic!("{:?}", err_result),
        }
    }
}

fn test_readwrite_violation_dynamic_dispatch(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-read-only (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        let err_result = env
            .execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false,
            )
            .unwrap_err();
        match err_result {
            Error::Unchecked(CheckErrors::TraitBasedContractCallInReadOnly) => {}
            _ => panic!("{:?}", err_result),
        }
    }
}

fn test_bad_call_with_trait(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    // This set of contracts should be working in this context,
    // the analysis is not being performed.
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u99))";
    let caller_contract = "(define-constant contract .implem)
        (define-public (foo-bar)
        (contract-call? .dispatch wrapped-get-1 contract))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("defun").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatch").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
            impl_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("call").unwrap(),
            caller_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("call").unwrap(),
                "foo-bar",
                &symbols_from_values(vec![]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(99)).unwrap()
        );
    }
}

fn test_good_call_with_trait(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u99))";
    let caller_contract = "(define-public (foo-bar)
        (contract-call? .dispatch wrapped-get-1 .implem))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("defun").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatch").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
            impl_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("call").unwrap(),
            caller_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("call").unwrap(),
                "foo-bar",
                &symbols_from_values(vec![]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(99)).unwrap()
        );
    }
}

fn test_good_call_2_with_trait(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u99))";
    let caller_contract = "(use-trait trait-2 .defun.trait-1)
        (define-public (foo-bar (contract <trait-2>))
            (contract-call? .dispatch wrapped-get-1 contract))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("defun").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatch").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
            impl_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("call").unwrap(),
            caller_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );

        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("call").unwrap(),
                "foo-bar",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(99)).unwrap()
        );
    }
}

fn test_dynamic_dispatch_pass_literal_principal_as_trait_in_user_defined_functions(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))
        (print (wrapped-get-1 .target-contract))";
    let target_contract = "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-defining-trait").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_contract_of_value(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (ok (contract-of contract)))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u99))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("defun").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatch").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
            impl_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
        ));
        let result_contract = target_contract.clone();
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );

        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatch").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(result_contract).unwrap()
        );
    }
}

fn test_contract_of_no_impl(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (ok (contract-of contract)))";
    let impl_contract =
        // (impl-trait .defun.trait-1)
        "
        (define-public (get-1 (x uint)) (ok u99))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("defun").unwrap(),
            contract_defining_trait,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatch").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
            impl_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("implem").unwrap(),
        ));
        let result_contract = target_contract.clone();
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );

        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatch").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(result_contract).unwrap()
        );
    }
}

fn test_return_trait_with_contract_of_wrapped_in_begin(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (begin
                (unwrap-panic (contract-call? contract get-1 u0))
                (ok (contract-of contract))))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract.clone()]),
                false
            )
            .unwrap(),
            Value::okay(target_contract).unwrap()
        );
    }
}

fn test_return_trait_with_contract_of_wrapped_in_let(
    owned_env: &mut OwnedEnvironment,
    version: ClarityVersion,
) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (let ((val u0))
                (unwrap-panic (contract-call? contract get-1 val))
                (ok (contract-of contract))))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract.clone()]),
                false
            )
            .unwrap(),
            Value::okay(target_contract).unwrap()
        );
    }
}

fn test_return_trait_with_contract_of(owned_env: &mut OwnedEnvironment, version: ClarityVersion) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (ok (contract-of contract)))";
    let target_contract = "(define-public (get-1 (x uint)) (ok u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract.clone()]),
                false
            )
            .unwrap(),
            Value::okay(target_contract).unwrap()
        );
    }
}

fn test_pass_trait_to_subtrait(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-get-1 (contract <trait-12>))
            (internal-get-1 contract))
        (define-public (internal-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u1))";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_embedded_trait(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-public (may-echo (opt (optional <trait-1>)))
            (match opt
                t (contract-call? t echo u42)
                (err u1)
            )
        )";
    let target_contract = "(define-public (echo (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let opt_target = Value::some(target_contract).unwrap();
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "may-echo",
                &symbols_from_values(vec![opt_target]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(42)).unwrap()
        );
    }
}

fn test_pass_embedded_trait_to_subtrait_optional(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-opt-get-1 (contract <trait-12>))
            (wrapped-get-1 (some contract)))
        (define-public (wrapped-get-1 (opt-contract (optional <trait-1>)))
            (match opt-contract
                contract (contract-call? contract get-1 u1)
                (err u1)
            )
        )";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-opt-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_pass_embedded_trait_to_subtrait_ok(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-ok-get-1 (contract <trait-12>))
            (wrapped-get-1 (ok contract)))
        (define-public (wrapped-get-1 (ok-contract (response <trait-1> uint)))
            (match ok-contract
                contract (contract-call? contract get-1 u1)
                e (err e)
            )
        )";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-ok-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_pass_embedded_trait_to_subtrait_err(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-err-get-1 (contract <trait-12>))
            (wrapped-get-1 (err contract)))
        (define-public (wrapped-get-1 (err-contract (response uint <trait-1>)))
            (match err-contract
                v (err v)
                contract (contract-call? contract get-1 u1)
            )
        )";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-err-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_pass_embedded_trait_to_subtrait_list(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-list-get-1 (contract <trait-12>))
            (wrapped-get-1 (list contract)))
        (define-public (wrapped-get-1 (list-contract (list 1 <trait-1>)))
            (match (element-at list-contract u0)
                t (contract-call? t get-1 u1)
                (err u1)
            )
        )";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-list-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_pass_embedded_trait_to_subtrait_list_option(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-list-get-1 (contract <trait-12>))
            (wrapped-get-1 (list (some contract))))
        (define-public (wrapped-get-1 (list-contract (list 1 (optional <trait-1>))))
            (match (element-at list-contract u0)
                opt-t (match opt-t
                    t (contract-call? t get-1 u1)
                    (err u2)
                )
                (err u1)
            )
        )";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-list-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_pass_embedded_trait_to_subtrait_option_list(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-trait trait-12 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
        ))
        (define-public (wrapped-list-get-1 (contract <trait-12>))
            (wrapped-get-1 (some (list contract))))
        (define-public (wrapped-get-1 (opt-list (optional (list 1 <trait-1>))))
            (match opt-list
                list-t (match (element-at list-t u0)
                    t (contract-call? t get-1 u1)
                    (err u2)
                )
                (err u1)
            )
        )";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))
        (define-public (get-2 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-list-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}

fn test_let_trait(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-public (let-echo (t <trait-1>))
            (let ((t1 t))
                (contract-call? t1 echo u42)
            )
        )";
    let target_contract = "(define-public (echo (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "let-echo",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(42)).unwrap()
        );
    }
}

fn test_let3_trait(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-public (let-echo (t <trait-1>))
            (let ((t1 t))
                (let ((t2 t1))
                    (let ((t3 t2))
                        (contract-call? t3 echo u42)
                    )
                )
            )
        )";
    let target_contract = "(define-public (echo (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "let-echo",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(42)).unwrap()
        );
    }
}

fn test_pass_principal_literal_to_trait(owned_env: &mut OwnedEnvironment) {
    let dispatching_contract = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
        ))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u1))";
    let target_contract = "(define-public (get-1 (a uint)) (ok a))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let mut placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &mut placeholder_context);
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
            dispatching_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();

        env.initialize_contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
            target_contract,
            ASTRules::PrecheckSize,
        )
        .unwrap();
    }

    {
        let target_contract = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("target-contract").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal()),
            None,
            &mut placeholder_context,
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatching-contract").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![target_contract]),
                false
            )
            .unwrap(),
            Value::okay(Value::UInt(1)).unwrap()
        );
    }
}
