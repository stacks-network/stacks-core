use crate::clarity_vm::{clarity::ClarityInstance, database::marf::MarfedKV};
use clarity::vm::ast::build_ast_with_rules;
use clarity::vm::test_util::{TEST_BURN_STATE_DB, TEST_HEADER_DB};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ClarityVersion;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::vm::ast::ASTRules;

fn dependency_edge_counting_runtime(iters: usize) -> u64 {
    let mut progn = "(define-private (a0) 1)".to_string();
    for i in 1..iters {
        progn.push_str(&format!("\n(define-private (a{}) (begin", i));
        for x in 0..i {
            progn.push_str(&format!(" (a{}) ", x));
        }
        progn.push_str("))");
    }

    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    let mut cost_track = clarity_instance
        .begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    let version = ClarityVersion::Clarity2;
    let epoch = StacksEpochId::Epoch21;
    build_ast_with_rules(
        &QualifiedContractIdentifier::transient(),
        &progn,
        &mut cost_track,
        version,
        epoch,
        ASTRules::PrecheckSize,
    )
    .unwrap();

    cost_track.get_total().runtime
}

#[test]
fn test_edge_counting_runtime() {
    let ratio_4_8 = dependency_edge_counting_runtime(8) / dependency_edge_counting_runtime(4);
    let ratio_8_16 = dependency_edge_counting_runtime(16) / dependency_edge_counting_runtime(8);

    // this really is just testing for the non-linearity
    //   in the runtime cost assessment (because the edge count in the dependency graph is going up O(n^2)).
    assert!(ratio_8_16 > ratio_4_8);
}
