// TODO: This needs work to get the dynamic vs static testing working
use std::collections::HashMap;

use rstest::rstest;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::analysis::{
    build_cost_analysis_tree, get_trait_count, static_cost_from_ast, static_cost_tree_from_ast,
    UserArgumentsContext,
};
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
    let simple_impl = r#"(impl-trait .mytrait.mytrait)
        (define-public (somefunc (a uint) (b uint))
          (ok (+ a b))
        )"#;

    let mut owned_env = tl_env_factory.get_env(epoch);

    let epoch = StacksEpochId::Epoch21;
    let ast = crate::vm::ast::build_ast(
        &QualifiedContractIdentifier::transient(),
        simple_impl,
        &mut (),
        version,
        epoch,
    )
    .unwrap();
    let static_cost = static_cost_from_ast(&ast, &version).unwrap();
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
    let (cost, _trait_count) = static_cost.get(key).unwrap();
    assert!(dynamic_cost.runtime >= cost.min.runtime);
    assert!(dynamic_cost.runtime <= cost.max.runtime);
}

#[rstest]
#[case::clarity2(ClarityVersion::Clarity2, StacksEpochId::Epoch21)]
fn test_complex_trait_implementation_costs(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
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

    let epoch = StacksEpochId::Epoch21;
    let ast = crate::vm::ast::build_ast(
        &QualifiedContractIdentifier::transient(),
        complex_impl,
        &mut (),
        version,
        epoch,
    )
    .unwrap();
    let static_cost_result = static_cost_from_ast(&ast, &version);
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
            let (cost, _trait_count) = static_cost.get(key).unwrap();
            println!("dynamic_cost: {:?}", dynamic_cost);
            println!("cost: {:?}", cost);
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
    let function_map = static_cost_from_ast(&ast, &ClarityVersion::Clarity3).unwrap();

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

    let costs = static_cost_tree_from_ast(&ast, &ClarityVersion::Clarity3).unwrap();

    let trait_count = get_trait_count(&costs);

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
    let ast = crate::vm::ast::build_ast(
        &contract_id,
        src,
        &mut (),
        ClarityVersion::Clarity3,
        StacksEpochId::Epoch32,
    )
    .unwrap();
    let static_cost = static_cost_from_ast(&ast, &ClarityVersion::Clarity3)
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
