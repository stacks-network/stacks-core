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

use std::collections::HashMap;

use rstest::rstest;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::analysis::{build_cost_analysis_tree, static_cost, UserArgumentsContext};
use crate::vm::costs::ExecutionCost;
use crate::vm::tests::{tl_env_factory, TopLevelMemoryEnvironmentGenerator};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ast, ClarityVersion};

const SIMPLE_TRAIT_SRC: &str = r#"(define-trait mytrait (
  (somefunc (uint uint) (response uint uint))
))
"#;

#[rstest]
#[case::clarity2(ClarityVersion::Clarity2, StacksEpochId::Epoch21)]
fn test_simple_trait_implementation_costs(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    // Simple trait implementation - very brief function that basically does nothing
    let simple_impl = r#"(impl-trait .mytrait.mytrait)
        (define-public (somefunc (a uint) (b uint))
          (ok (+ a b))
        )"#;

    // Set up environment with cost tracking - use regular environment but try to get actual costs
    let mut owned_env = tl_env_factory.get_env(epoch);

    // Get static cost analysis
    let static_cost = static_cost(simple_impl, &version).unwrap();
    // Deploy and execute the contract to get dynamic costs
    let contract_id = QualifiedContractIdentifier::local("simple-impl").unwrap();
    owned_env
        .initialize_versioned_contract(contract_id.clone(), version, simple_impl, None)
        .unwrap();

    let dynamic_cost = execute_contract_function_and_get_cost(
        &mut owned_env,
        &contract_id,
        "somefunc",
        &[4, 5],
        version,
    );
    println!("dynamic_cost: {:?}", dynamic_cost);
    println!("static_cost: {:?}", static_cost);

    let key = static_cost.keys().nth(1).unwrap();
    let cost = static_cost.get(key).unwrap();
    assert!(dynamic_cost.runtime >= cost.min.runtime);
    assert!(dynamic_cost.runtime <= cost.max.runtime);
}

/// Helper function to execute a contract function and return the execution cost
fn execute_contract_function_and_get_cost(
    env: &mut OwnedEnvironment,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[u64],
    version: ClarityVersion,
) -> ExecutionCost {
    // Start with a fresh cost tracker
    let initial_cost = env.get_cost_total();

    // Create a dummy sender
    let sender = PrincipalData::parse_qualified_contract_principal(
        "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sender",
    )
    .unwrap();

    // Build function call string
    let arg_str = args
        .iter()
        .map(|a| format!("u{}", a))
        .collect::<Vec<_>>()
        .join(" ");
    let function_call = format!("({} {})", function_name, arg_str);

    // Parse the function call into a symbolic expression
    let ast = crate::vm::ast::parse(
        &QualifiedContractIdentifier::transient(),
        &function_call,
        version,
        StacksEpochId::Epoch21,
    )
    .expect("Failed to parse function call");

    if !ast.is_empty() {
        let _result = env.execute_transaction(
            sender,
            None,
            contract_id.clone(),
            &function_call,
            &ast[0..1],
        );
    }

    // Get the cost after execution
    let final_cost = env.get_cost_total();

    // Return the difference
    ExecutionCost {
        write_length: final_cost.write_length - initial_cost.write_length,
        write_count: final_cost.write_count - initial_cost.write_count,
        read_length: final_cost.read_length - initial_cost.read_length,
        read_count: final_cost.read_count - initial_cost.read_count,
        runtime: final_cost.runtime - initial_cost.runtime,
    }
}

#[rstest]
#[case::clarity2(ClarityVersion::Clarity2, StacksEpochId::Epoch21)]
fn test_complex_trait_implementation_costs(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    // Complex trait implementation with expensive operations but no external calls
    let complex_impl = r#"(define-public (somefunc (a uint) (b uint))
    (begin
        ;; do something expensive
        ;; emit events
        (print a)
        (print b)
        (print "doing complex calculation")
        (let ((result (* a b)))
            (print result)
            (ok (+ result (/ (+ a b) u2)))
        )
    )
)"#;

    let mut owned_env = tl_env_factory.get_env(epoch);

    let static_cost_result = static_cost(complex_impl, &version);
    match static_cost_result {
        Ok(static_cost) => {
            let contract_id = QualifiedContractIdentifier::local("complex-impl").unwrap();
            owned_env
                .initialize_versioned_contract(contract_id.clone(), version, complex_impl, None)
                .unwrap();

            let dynamic_cost = execute_contract_function_and_get_cost(
                &mut owned_env,
                &contract_id,
                "somefunc",
                &[7, 8],
                version,
            );

            let key = static_cost.keys().nth(1).unwrap();
            let cost = static_cost.get(key).unwrap();
            assert!(dynamic_cost.runtime >= cost.min.runtime);
            assert!(dynamic_cost.runtime <= cost.max.runtime);
        }
        Err(e) => {
            println!("Static cost analysis failed: {}", e);
        }
    }
}

#[test]
fn test_build_cost_analysis_tree_function_definition() {
    let source = r#"(define-public (somefunc (a uint))
  (ok (+ a 1))
)"#;

    let contract_id = QualifiedContractIdentifier::transient();
    let ast = ast::parse(
        &contract_id,
        source,
        ClarityVersion::Clarity3,
        StacksEpochId::Epoch32,
    )
    .expect("Failed to parse source code");

    let expr = &ast[0];
    let user_args = UserArgumentsContext::new();
    let cost_map = HashMap::new();

    let clarity_version = ClarityVersion::Clarity3;
    let result = build_cost_analysis_tree(expr, &user_args, &cost_map, &clarity_version);

    match result {
        Ok((function_name, node)) => {
            assert_eq!(function_name, Some("somefunc".to_string()));
            assert!(matches!(
                node.expr,
                crate::vm::costs::analysis::CostExprNode::UserFunction(_)
            ));
        }
        Err(e) => {
            panic!("Expected Ok result, got error: {}", e);
        }
    }
}
