// TODO: This needs work to get the dynamic vs static testing working
use std::collections::HashMap;
use std::path::Path;

#[cfg(test)]
use rstest::rstest;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::analysis::{
    build_cost_analysis_tree, static_cost_from_ast, static_cost_tree_from_ast, UserArgumentsContext,
    CostAnalysisNode, CostExprNode,
};
use crate::vm::costs::ExecutionCost;
use crate::vm::database::MemoryBackingStore;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ast, ClarityVersion};
use crate::boot_util::boot_code_id;

#[cfg(test)]
use stackslib::chainstate::stacks::boot::{
    BOOT_CODE_COSTS, BOOT_CODE_COSTS_3, BOOT_CODE_COST_VOTING_TESTNET,
};

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

/// Helper function to pretty print the cost tree with accumulated costs
fn print_cost_tree(node: &CostAnalysisNode, depth: usize) {
    let indent = "  ".repeat(depth);
    let node_name = match &node.expr {
        CostExprNode::NativeFunction(nf) => format!("NativeFunction({:?})", nf),
        CostExprNode::UserFunction(name) => format!("UserFunction({})", name),
        CostExprNode::UserArgument(name, _) => format!("UserArgument({})", name),
        CostExprNode::AtomValue(val) => format!("AtomValue({:?})", val),
        CostExprNode::Atom(name) => format!("Atom({})", name),
        CostExprNode::FieldIdentifier(fid) => format!("FieldIdentifier({:?})", fid),
        CostExprNode::TraitReference(name) => format!("TraitReference({})", name),
    };

    // Calculate accumulated cost including children
    let mut child_total = 0u64;
    for child in &node.children {
        child_total += child.cost.min.runtime;
        for grandchild in &child.children {
            child_total += grandchild.cost.min.runtime;
        }
    }
    let total_with_children = node.cost.min.runtime + child_total;

    println!(
        "{}{} -> node_cost: {}, children_sum: {}, total: {}",
        indent, node_name, node.cost.min.runtime, child_total, total_with_children
    );
    for child in &node.children {
        print_cost_tree(child, depth + 1);
    }
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
    eprintln!("[EXECUTE_FUNCTION] Initial cost: {:?}", initial_cost);

    let sender = PrincipalData::parse_qualified_contract_principal(
        "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sender",
    )
    .unwrap();

    // Convert u64 arguments to Value::UInt, then to SymbolicExpression::atom_value
    use crate::vm::types::Value;
    use crate::vm::representations::SymbolicExpression;
    let arg_values: Vec<Value> = args.iter().map(|&a| Value::UInt(a as u128)).collect();
    let arg_exprs: Vec<SymbolicExpression> = arg_values.iter()
        .map(|v| SymbolicExpression::atom_value(v.clone()))
        .collect();

    eprintln!("[EXECUTE_FUNCTION] Executing function call: {} with {} args", function_name, arg_exprs.len());
    let _result = env.execute_transaction(
        sender,
        None,
        contract_id.clone(),
        function_name,
        &arg_exprs,
    );
    #[cfg(test)]
    match &_result {
        Ok((value, _, _)) => eprintln!("[EXECUTE_FUNCTION] Function returned successfully: {:?}", value),
        Err(e) => eprintln!("[EXECUTE_FUNCTION] Function returned error: {:?}", e),
    }

    let final_cost = env.get_cost_total();
    eprintln!("[EXECUTE_FUNCTION] Final cost: {:?}", final_cost);
    eprintln!("[EXECUTE_FUNCTION] Cost delta: runtime={}", final_cost.runtime - initial_cost.runtime);

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

#[test]
fn test_contract_call_cost_32() {
    let src = r#"(define-public (somefunc (a uint))
  (contract-call? .tokens my-get-token-balance tx-sender))
"#;
    let contract_id = QualifiedContractIdentifier::transient();
    let epoch = StacksEpochId::Epoch32;
    let clarity_version = ClarityVersion::Clarity3;
    let ast = crate::vm::ast::build_ast(
        &contract_id,
        &src,
        &mut (),
        clarity_version,
        epoch,
    )
    .expect("Failed to build AST from contract call test");
    let cost_map = static_cost_from_ast(&ast, &clarity_version, epoch)
        .expect("Failed to get static cost analysis for contract call test");
    let (somefunc_cost, _) = cost_map.get("somefunc").unwrap();
    assert_eq!(somefunc_cost.min.runtime, 134);
    assert_eq!(somefunc_cost.max.runtime, 134);
}

#[test]
fn test_contract_call_cost_33() {
    let src = r#"(define-public (somefunc (a uint))
  (contract-call? .tokens my-get-token-balance tx-sender))
"#;
    let contract_id = QualifiedContractIdentifier::transient();
    let epoch = StacksEpochId::Epoch33;
    let clarity_version = ClarityVersion::Clarity4;
    let ast = crate::vm::ast::build_ast(
        &contract_id,
        &src,
        &mut (),
        clarity_version,
        epoch,
    )
    .expect("Failed to build AST from contract call test");
    let cost_map = static_cost_from_ast(&ast, &clarity_version, epoch)
        .expect("Failed to get static cost analysis for contract call test");
    let (somefunc_cost, _) = cost_map.get("somefunc").unwrap();
    assert_eq!(somefunc_cost.min.runtime, 134);
    assert_eq!(somefunc_cost.max.runtime, 134);
}

// Helper function to run static and dynamic cost analysis on a contract function
// Returns Ok(()) if costs are within expected range, Err with message otherwise
#[cfg(test)]
fn run_cost_analysis_test(
    src: &str,
    function_name: &str,
    args: &[u64],
    epoch: StacksEpochId,
    clarity_version: ClarityVersion,
) -> Result<(), String> {
    let contract_id = QualifiedContractIdentifier::local("test-contract").unwrap();

    // Build AST for static cost analysis
    let ast = ast::build_ast(
        &contract_id,
        src,
        &mut (),
        clarity_version,
        epoch,
    )
    .expect("Failed to build AST");

    // Run static cost analysis
    let static_cost_map = static_cost_from_ast(&ast, &clarity_version, epoch)
        .expect("Failed to get static cost analysis");

    let (static_cost, _) = static_cost_map.get(function_name)
        .expect(&format!("Function '{}' not found in static cost map", function_name));

    // Set up environment for dynamic cost analysis
    let mut memory_store = MemoryBackingStore::new();
    let mut db = memory_store.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(epoch).unwrap();
    db.commit().unwrap();
    if epoch.clarity_uses_tip_burn_block() {
        db.begin();
        db.set_tenure_height(1).unwrap();
        db.commit().unwrap();
    }
    if epoch.uses_marfed_block_time() {
        db.begin();
        db.setup_block_metadata(Some(1)).unwrap();
        db.commit().unwrap();
    }

    // Initialize the costs and cost-voting contracts so we can use cost tracking
    // The cost tracker needs both contracts to be initialized
    // For epoch 32, we need costs-3 (not just costs)
    let costs_contract_id = boot_code_id("costs", false);
    let costs_3_contract_id = boot_code_id("costs-3", false);
    let cost_voting_contract_id = boot_code_id("cost-voting", false);
    {
        // Use a temporary free environment to initialize the contracts
        let mut temp_env = OwnedEnvironment::new(db, epoch);

        // Initialize costs contract (costs-1, needed as base)
        temp_env
            .initialize_versioned_contract(
                costs_contract_id.clone(),
                clarity_version,
                BOOT_CODE_COSTS,
                None,
            )
            .expect("Failed to initialize costs contract");

        // Initialize costs-3 contract (required for epoch 32)
        temp_env
            .initialize_versioned_contract(
                costs_3_contract_id.clone(),
                clarity_version,
                BOOT_CODE_COSTS_3,
                None,
            )
            .expect("Failed to initialize costs-3 contract");

        // Initialize cost-voting contract (required for cost tracker to read confirmed-proposal-count)
        temp_env
            .initialize_versioned_contract(
                cost_voting_contract_id.clone(),
                clarity_version,
                &BOOT_CODE_COST_VOTING_TESTNET.to_string(),
                None,
            )
            .expect("Failed to initialize cost-voting contract");

        // Extract the database from the environment
        let (extracted_db, _cost_tracker) = temp_env.destruct()
            .expect("Failed to extract database from environment");
        db = extracted_db;
    }

    // Now create environment with cost tracking enabled
    let mut owned_env = OwnedEnvironment::new_max_limit(db, epoch, false);

    // Deploy the contract
    owned_env
        .initialize_versioned_contract(contract_id.clone(), clarity_version, src, None)
        .expect("Failed to initialize contract");

    // Run dynamic cost analysis
    let dynamic_cost = execute_contract_function_and_get_cost(
        &mut owned_env,
        &contract_id,
        function_name,
        args,
        clarity_version,
    );

    println!("\n=== Cost Analysis for {} ===", function_name);
    println!("static cost: {:?}", static_cost);
    println!("dynamic cost: {:?}", dynamic_cost);

    // Get the cost tree to debug and print it with values
    let cost_trees_with_traits = crate::vm::costs::analysis::static_cost_tree_from_ast(&ast, &clarity_version, epoch)
        .expect("Failed to get static cost tree");
    if let Some((cost_tree, _)) = cost_trees_with_traits.get(function_name) {
        println!("\n=== Cost Tree for {} ===", function_name);
        print_cost_tree(cost_tree, 0);
    }

    // Verify that dynamic cost runtime is between static cost min and max
    if static_cost.min.runtime > static_cost.max.runtime {
        return Err(format!(
            "Static cost min {} should be <= max {}",
            static_cost.min.runtime,
            static_cost.max.runtime
        ));
    }

    if dynamic_cost.runtime < static_cost.min.runtime {
        return Err(format!(
            "Dynamic cost runtime {} is LESS than static min runtime {}",
            dynamic_cost.runtime,
            static_cost.min.runtime
        ));
    }

    if dynamic_cost.runtime > static_cost.max.runtime {
        return Err(format!(
            "Dynamic cost runtime {} is MORE than static max runtime {}",
            dynamic_cost.runtime,
            static_cost.max.runtime
        ));
    }

    Ok(())
}

// given a contract source, run dynamic cost analysis on pre-determined input
// arguments, followed by static cost analysis on the same source and confirm
// that the dynamic cost is between the min/max static cost
#[test]
fn test_against_dynamic_cost_analysis() {
    let epoch = StacksEpochId::Epoch32;
    let clarity_version = ClarityVersion::Clarity3;

    // Define test cases as (source, function_name, args)
    let test_cases: Vec<(&str, &str, &[u64])> = vec![
        (
            r#"(define-public (somefunc (a uint))
    (let ((b 1))
        (ok (+ a b))
))
"#,
            "somefunc",
            &[1],
        ),
        (
            r#"(define-public (simple-ok)
    (ok true)
)
"#,
            "simple-ok",
            &[],
        ),
    ];

    let mut failures = Vec::new();
    for (src, function_name, args) in test_cases {
        println!("\n\n=== Running test case: {} ===", function_name);
        match run_cost_analysis_test(src, function_name, args, epoch, clarity_version) {
            Ok(()) => println!("✓ Test case {} passed", function_name),
            Err(e) => {
                eprintln!("✗ Test case {} failed: {}", function_name, e);
                failures.push((function_name, e));
            }
        }
    }

    if !failures.is_empty() {
        let error_msg = failures.iter()
            .map(|(name, err)| format!("{}: {}", name, err))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("{} test case(s) failed:\n{}", failures.len(), error_msg);
    }
}
