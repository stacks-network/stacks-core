// TODO: This needs work to get the dynamic vs static testing working
use std::collections::HashMap;
use std::path::Path;

use rstest::rstest;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::analysis::{
    build_cost_analysis_tree, static_cost_from_ast, static_cost_tree_from_ast, UserArgumentsContext,
};
use crate::vm::costs::ExecutionCost;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ast, ClarityVersion};

#[test]
fn test_build_cost_analysis_tree_function_definition() {
    let src = r#"(define-public (somefunc (a uint))
  (ok (+ a 1))
)"#;

    let contract_id = QualifiedContractIdentifier::transient();
    let ast = ast::parse(
        &contract_id,
        src,
        ClarityVersion::Clarity3,
        StacksEpochId::Epoch32,
    )
    .expect("Failed to parse");

    let expr = &ast[0];
    let user_args = UserArgumentsContext::new();
    let cost_map = HashMap::new();

    let clarity_version = ClarityVersion::Clarity3;
    let epoch = StacksEpochId::Epoch32;
    let result = build_cost_analysis_tree(expr, &user_args, &cost_map, &clarity_version, epoch);

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

#[test]
fn test_let_cost() {
    let src = "(let ((a 1) (b 2)) (+ a b))";
    let src2 = "(let ((a 1) (b 2) (c 3)) (+ a b))"; // should compute for 3 bindings not 2

    let contract_id = QualifiedContractIdentifier::transient();
    let epoch = StacksEpochId::Epoch32;
    let ast = crate::vm::ast::build_ast(
        &QualifiedContractIdentifier::transient(),
        src,
        &mut (),
        ClarityVersion::Clarity3,
        epoch,
    )
    .unwrap();
    let function_map = static_cost_from_ast(&ast, &ClarityVersion::Clarity3, epoch).unwrap();
    let (let_cost, _) = function_map.get("let").unwrap();
    let (let2_cost, _) = function_map.get("let2").unwrap();
    assert_ne!(let2_cost.min.runtime, let_cost.min.runtime);
}


#[test]
fn test_dependent_function_calls() {
    let src = r#"(define-public (add-one (a uint))
  (begin
    (print "somefunc")
    (somefunc a)
  )
)
(define-private (somefunc (a uint))
  (ok (+ a 1))
)"#;

    let contract_id = QualifiedContractIdentifier::transient();
    let epoch = StacksEpochId::Epoch32;
    let ast = crate::vm::ast::build_ast(
        &QualifiedContractIdentifier::transient(),
        src,
        &mut (),
        ClarityVersion::Clarity3,
        epoch,
    )
    .unwrap();
    let function_map = static_cost_from_ast(&ast, &ClarityVersion::Clarity3, epoch).unwrap();

    let (add_one_cost, _) = function_map.get("add-one").unwrap();
    let (somefunc_cost, _) = function_map.get("somefunc").unwrap();

    println!("add_one_cost: {:?}", add_one_cost);
    println!("add_one_cost: {:?}", somefunc_cost);
    assert!(add_one_cost.min.runtime >= somefunc_cost.min.runtime);
    assert!(add_one_cost.max.runtime >= somefunc_cost.max.runtime);
}

#[test]
fn test_get_trait_count_direct() {
    let src = r#"(define-trait trait-name (
    (send (uint principal) (response uint uint))
))
(define-public (something (trait <trait-name>) (addresses (list 10 principal)))
    (map (send u500 trait) addresses)
)
(define-private (send (trait <trait-name>) (addr principal)) (trait addr))
"#;

    let contract_id = QualifiedContractIdentifier::transient();
    let ast = crate::vm::ast::build_ast(
        &contract_id,
        src,
        &mut (),
        ClarityVersion::Clarity3,
        StacksEpochId::Epoch32,
    )
    .unwrap();

    let costs =
        static_cost_tree_from_ast(&ast, &ClarityVersion::Clarity3, StacksEpochId::Epoch32).unwrap();

    // Extract trait_count from the result (all entries have the same trait_count)
    let trait_count = costs
        .values()
        .next()
        .and_then(|(_, trait_count)| trait_count.clone());

    let expected = {
        let mut map = HashMap::new();
        map.insert("something".to_string(), (0, 10));
        map.insert("send".to_string(), (1, 1));
        Some(map)
    };

    assert_eq!(trait_count, expected);
}

#[rstest]
fn test_trait_counting() {
    // map, fold, filter over traits counting
    let src = r#"(define-trait trait-name (
    (send (uint principal) (response uint uint))
))
(define-public (something (trait <trait-name>) (addresses (list 10 principal)))
    (map (send u500 trait) addresses)
)
(define-private (send (trait <trait-name>) (addr principal)) (trait addr))
"#;
    let contract_id = QualifiedContractIdentifier::local("trait-counting").unwrap();
    let epoch = StacksEpochId::Epoch32;
    let ast =
        crate::vm::ast::build_ast(&contract_id, src, &mut (), ClarityVersion::Clarity3, epoch)
            .unwrap();
    let static_cost = static_cost_from_ast(&ast, &ClarityVersion::Clarity3, epoch)
        .unwrap()
        .clone();
    let send_trait_count_map = static_cost.get("send").unwrap().1.clone().unwrap();
    let send_trait_count = send_trait_count_map.get("send").unwrap();
    assert_eq!(send_trait_count.0, 1);
    assert_eq!(send_trait_count.1, 1);

    let something_trait_count_map = static_cost.get("something").unwrap().1.clone().unwrap();
    let something_trait_count = something_trait_count_map.get("something").unwrap();
    assert_eq!(something_trait_count.0, 0);
    assert_eq!(something_trait_count.1, 10);
}

/// Helper function to execute a contract function and return the execution cost
fn execute_contract_function_and_get_cost(
    env: &mut OwnedEnvironment,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[u64],
    version: ClarityVersion,
) -> ExecutionCost {
    let initial_cost = env.get_cost_total();

    let sender = PrincipalData::parse_qualified_contract_principal(
        "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sender",
    )
    .unwrap();

    let arg_str = args
        .iter()
        .map(|a| format!("u{}", a))
        .collect::<Vec<_>>()
        .join(" ");
    let function_call = format!("({} {})", function_name, arg_str);

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

    let final_cost = env.get_cost_total();

    ExecutionCost {
        write_length: final_cost.write_length - initial_cost.write_length,
        write_count: final_cost.write_count - initial_cost.write_count,
        read_length: final_cost.read_length - initial_cost.read_length,
        read_count: final_cost.read_count - initial_cost.read_count,
        runtime: final_cost.runtime - initial_cost.runtime,
    }
}

#[test]
fn test_pox_4_costs() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let pox_4_path = workspace_root
        .join("contrib")
        .join("boot-contracts-unit-tests")
        .join("boot_contracts")
        .join("pox-4.clar");
    let contract_source = std::fs::read_to_string(&pox_4_path)
        .unwrap_or_else(|e| panic!("Failed to read pox-4.clar file at {:?}: {}", pox_4_path, e));

    let contract_id = QualifiedContractIdentifier::transient();
    let epoch = StacksEpochId::Epoch32;
    let clarity_version = ClarityVersion::Clarity3;

    let ast = crate::vm::ast::build_ast(
        &contract_id,
        &contract_source,
        &mut (),
        clarity_version,
        epoch,
    )
    .expect("Failed to build AST from pox-4.clar");

    let cost_map = static_cost_from_ast(&ast, &clarity_version, epoch)
        .expect("Failed to get static cost analysis for pox-4.clar");

    // Check some functions in the cost map
    let key_functions = vec![
        "stack-stx",
        "delegate-stx",
        "get-stacker-info",
        "current-pox-reward-cycle",
        "stack-aggregation-commit",
        "stack-increase",
        "stack-extend",
    ];

    for function_name in key_functions {
        assert!(
            cost_map.contains_key(function_name),
            "Expected function '{}' to be present in cost map",
            function_name
        );

        let (_cost, _trait_count) = cost_map.get(function_name).expect(&format!(
            "Failed to get cost for function '{}'",
            function_name
        ));
    }
}
