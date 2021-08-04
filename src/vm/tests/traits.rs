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

use std::convert::TryInto;
use vm::analysis::errors::CheckError;
use vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use vm::errors::{CheckErrors, Error, RuntimeErrorType};
use vm::execute as vm_execute;
use vm::types::{PrincipalData, QualifiedContractIdentifier, ResponseData, TypeSignature, Value};

use vm::tests::{execute, symbols_from_values, with_marfed_environment, with_memory_environment};

#[test]
fn test_all() {
    let to_test = [
        // test_dynamic_dispatch_pass_trait_nested_in_let,
        // test_dynamic_dispatch_pass_trait,
        // test_dynamic_dispatch_intra_contract_call,
        // test_dynamic_dispatch_by_defining_trait,
        // test_dynamic_dispatch_by_implementing_imported_trait,
        // test_dynamic_dispatch_by_importing_trait,
        // test_dynamic_dispatch_including_nested_trait,
        // test_dynamic_dispatch_mismatched_args,
        // test_dynamic_dispatch_mismatched_returned,
        // test_reentrant_dynamic_dispatch,
        // test_readwrite_dynamic_dispatch,
        // test_readwrite_violation_dynamic_dispatch,
        // test_bad_call_with_trait,
        // test_good_call_with_trait,
        // test_good_call_2_with_trait,
        // test_contract_of_value,
        // test_contract_of_no_impl,
        // test_dynamic_dispatch_by_implementing_imported_trait_mul_funcs,
        // test_dynamic_dispatch_pass_literal_principal_as_trait_in_user_defined_functions,
        // test_return_trait_with_contract_of,
        // test_return_trait_with_contract_of_wrapped_in_begin,
        // test_return_trait_with_contract_of_wrapped_in_let,
        test_read_only_trait
    ];
    for test in to_test.iter() {
        with_memory_environment(test, false);
        // with_marfed_environment(test, false);
    }
}

fn test_read_only_trait(owned_env: &mut OwnedEnvironment) {
    let contract_defining_trait = "(define-trait ro-trait-1 (
            (get-1 (uint) (response uint uint) read-only)))";
    let impl_contract = "(impl-trait .definition1.ro-trait-1)
        (define-public (get-1 (x uint)) (ok (+ x 1)))";

    // Big Question: Where does "my-contract" get linked to ro-trait-1?
    let dispatch1ing_contract = "(use-trait ro-trait-1 .definition1.ro-trait-1)
        (define-read-only (wrapped-get-1 (my-contract <ro-trait-1>))
            (contract-call? my-contract get-1 u1))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");

    {
        let mut env = owned_env.get_exec_environment(None, None);
        env.initialize_contract(
            QualifiedContractIdentifier::local("definition1").unwrap(),
            contract_defining_trait,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("implementation1").unwrap(),
            impl_contract,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("dispatch1").unwrap(),
            dispatch1ing_contract,
        )
        .unwrap();
    }

    {
        let impl_contract_instance = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("implementation1").unwrap(),
        ));
        // let impl_contract_instance = Value::from(PrincipalData::Contract(
        //     QualifiedContractIdentifier::local("dispatch1").unwrap(),
        // ));
        let result_contract = impl_contract_instance.clone();
        let mut env = owned_env.get_exec_environment(Some(p1.clone().expect_principal()), None);

        let return_value = 
            env.execute_contract(
                &QualifiedContractIdentifier::local("dispatch1").unwrap(),
                "wrapped-get-1",
                &symbols_from_values(vec![impl_contract_instance.clone()]),
                // &symbols_from_values(vec![]),
                true
            )
            .unwrap();
        warn!("return_value {:?}", return_value);
        warn!("result_contract {:?}", result_contract);
        assert_eq!(
            return_value,
            // Value::okay(result_contract).unwrap()
            Value::okay(impl_contract_instance).unwrap()
        );
    }
}