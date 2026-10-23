// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::assert_matches;

use itertools::Itertools;
#[cfg(test)]
use rstest::rstest;
#[cfg(test)]
use rstest_reuse::{self, *};
use stacks_common::types::StacksEpochId;

use crate::vm::ClarityVersion;
use crate::vm::analysis::mem_type_check as run_analysis_helper;
use crate::vm::ast::definition_sorter::DefinitionSorter;
use crate::vm::ast::errors::{ParseErrorKind, ParseResult};
use crate::vm::ast::expression_identifier::ExpressionIdentifier;
use crate::vm::ast::stack_depth_checker::StackDepthLimits;
use crate::vm::ast::types::ContractAST;
use crate::vm::ast::{build_ast, parser};
use crate::vm::tests::test_clarity_versions;
use crate::vm::types::QualifiedContractIdentifier;

/// Takes a clarity contract and returns every possible ordering
/// of the top level expressions. It simply counts parentheses,
/// so it won't work if you have parens in comments or strings.
/// It's just for simple test cases.
pub fn reorderings(contract: &str) -> Vec<String> {
    let mut top_level_expressions = Vec::new();
    let mut open_parens: Option<u64> = None;
    let mut current = String::new();
    for c in contract.chars() {
        if c == '(' {
            open_parens = Some(open_parens.unwrap_or(0) + 1);
        }
        if open_parens.is_some() {
            current.push(c);
        }

        if c == ')' {
            let Some(open) = open_parens else {
                panic!("unbalanced parentheses");
            };
            if open == 1 {
                // closing the last one
                top_level_expressions.push(current);
                current = String::new();
                open_parens = None;
            } else {
                assert!(open > 1);
                open_parens = Some(open - 1);
            }
        }
    }
    assert!(open_parens.is_none(), "unbalanced parentheses");
    top_level_expressions
        .iter()
        .permutations(top_level_expressions.len())
        .map(|p| p.into_iter().join("\n"))
        .collect()
}

/// Asserts that no matter how the top-level expressions in the given
/// contract are ordered, the behavior is the same. If `maybe_err_substr`
/// is Some(), then contract analysis should fail with an error whose
/// `.to_string()` contains that substring. If `maybe_err_substr` is None,
/// then analysis should succeed.
///
/// The caveats from [`reorderings`] apply.
pub fn same_behavior_regardless_of_order(contract: &str, maybe_err_substr: Option<&str>) {
    for reordered in reorderings(contract) {
        let result =
            run_analysis_helper(contract, ClarityVersion::latest(), StacksEpochId::latest())
                .map_err(|e| e.to_string());

        if let Some(expected_err) = maybe_err_substr {
            let err = result.expect_err("expected analysis to error");

            assert!(
                err.contains(expected_err),
                "Expected error to contain \"{expected_err}\" but got \"{err}\" when analyzing \"{reordered}\""
            );
        } else {
            result.unwrap_or_else(|_| panic!("Expected analysis to succeed on \"{reordered}\""));
        }
    }
}

fn run_scoped_parsing_helper(
    contract: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> ParseResult<ContractAST> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let pre_expressions = parser::v1::parse(contract, StackDepthLimits::for_epoch(epoch))?;
    let mut contract_ast = ContractAST::new(contract_identifier, pre_expressions);
    ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast, version)?;
    DefinitionSorter::run_pass(&mut contract_ast, &mut (), version, epoch)?;
    Ok(contract_ast)
}

#[apply(test_clarity_versions)]
fn should_succeed_sorting_contract_call(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = "(define-read-only (foo-function (a int))
           (contract-call? .contract-b foo-function a))";
    run_scoped_parsing_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_fix_2123(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract = "(define-fungible-token limited-supply-stacks (supply))
    (define-read-only (supply) u100)";
    run_analysis_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_succeed_sorting_contract_case_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (wrapped-kv-del (key int))
            (kv-del key))
        (define-private (kv-del (key int))
            (begin
                (map-delete kv-store { key: key })
                key))
        (define-map kv-store { key: int } { value: int })
    "#;
    run_scoped_parsing_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_succeed_sorting_contract_case_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (+ x c))
        (define-constant c 1)
        (define-private (d (x int)) (h x))
        (define-constant e 1)
        (define-private (f (x int)) (+ e x))
        (define-constant g 1)
        (define-private (h (x int)) (a x))
        (+ (a 1) (b 1) c (d 1) e (f 1) g (h 1))
    "#;
    run_scoped_parsing_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (c x))
        (define-private (c (x int)) (a x))
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (a (x int)) (b x))
        (define-private (b (x int)) (c x))
        (define-private (c (x int)) (a x))
        (a 0)
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_raise_dependency_cycle_case_let_before_clarity_7(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (let ((foo 1)) (+ 1 x)))
    "#;

    let result = run_scoped_parsing_helper(contract, version, epoch);
    if version.definition_sorter_probes_binding_names() {
        assert_matches!(*result.unwrap_err().err, ParseErrorKind::NameAlreadyUsed(_));
    } else {
        result.unwrap();
        run_analysis_helper(contract, version, epoch).unwrap();
    }
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_let(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (let ((baz (foo 1))) (+ 1 x)))
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_raise_dependency_cycle_case_get(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (get foo (tuple (foo 1) (bar 2))))
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
    run_analysis_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_get(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (let ((res (foo 1))) (+ 1 x)))
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_raise_dependency_cycle_case_fetch_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-get? kv-store { foo: 1 }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
    run_analysis_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_fetch_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-get? kv-store { foo: (foo 1) }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_raise_dependency_cycle_case_delete_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-delete kv-store (tuple (foo 1))))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
    run_analysis_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_delete_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-delete kv-store (tuple (foo (foo 1)))))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_raise_dependency_cycle_case_set_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-set kv-store { foo: 1 } { bar: 3 }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
    run_analysis_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_set_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-set kv-store { foo: 1 } { bar: (foo 1) }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_raise_dependency_cycle_case_insert_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (begin (bar 1) 1))
        (define-private (bar (x int)) (map-insert kv-store { foo: 1 } { bar: 3 }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
    run_analysis_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_insert_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-insert kv-store { foo: (foo 1) } { bar: 3 }))
        (define-map kv-store { foo: int } { bar: int })
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_raise_dependency_cycle_case_fetch_contract_entry(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (foo (x int)) (+ (bar x) x))
        (define-private (bar (x int)) (map-get? kv-store { foo: (foo 1) }))
    "#;

    let err = run_scoped_parsing_helper(contract, version, epoch).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

#[apply(test_clarity_versions)]
fn should_not_build_cycle_within_defined_args_types(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-private (function-1 (function-2 int)) (+ 1 2))
        (define-private (function-2 (function-1 int)) (+ 1 2))
    "#;

    let result = run_scoped_parsing_helper(contract, version, epoch);
    if version.definition_sorter_probes_binding_names() {
        assert!(matches!(
            *result.unwrap_err().err,
            ParseErrorKind::NameAlreadyUsed(_)
        ));
    } else {
        result.unwrap();
    }
}

#[apply(test_clarity_versions)]
fn should_reorder_traits_references(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract = r#"
        (define-private (foo (function-2 <trait-a>)) (+ 1 2))
        (define-trait trait-a ((get-a () (response uint uint))))
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
}

#[apply(test_clarity_versions)]
fn should_not_conflict_with_atoms_from_trait_definitions(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract = r#"
        (define-trait foo ((bar (int) (int))))
        (define-trait bar ((foo (int) (int))))
    "#;

    run_scoped_parsing_helper(contract, version, epoch).unwrap();
}

/// Full AST pipeline, including the sorter.
fn build_ast_at(
    contract: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> ParseResult<ContractAST> {
    build_ast(
        &QualifiedContractIdentifier::transient(),
        contract,
        &mut (),
        version,
        epoch,
    )
}

/// Calling the native inside the same-named implementation is not a cycle.
#[test]
fn epoch41_native_application_in_same_named_function_is_not_a_cycle() {
    let contract = "(define-read-only (slice? (a int) (b int))
                        (len (unwrap-panic (slice? (list a b) u0 u1))))";
    build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap();
    // The gate is the epoch, not the version (a pinned Clarity 6 cannot deploy
    // at Epoch 4.1 on chain, but tooling may still parse one).
    build_ast_at(contract, ClarityVersion::Clarity6, StacksEpochId::Epoch41).unwrap();

    // Before Epoch 4.1 behavior is unchanged, whatever the version (such
    // contracts fail at initialization anyway).
    let err = build_ast_at(contract, ClarityVersion::Clarity6, StacksEpochId::Epoch40).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
    let err = build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch40).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

/// Same for reading a keyword inside the same-named implementation.
#[test]
fn epoch41_native_keyword_in_same_named_function_is_not_a_cycle() {
    let contract = "(define-read-only (stacks-block-height) (ok stacks-block-height))";
    build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap();

    let err = build_ast_at(contract, ClarityVersion::Clarity6, StacksEpochId::Epoch40).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

/// Only native names are affected: user-definition cycles are still detected.
#[test]
fn epoch41_user_function_cycle_is_still_detected() {
    let contract = "(define-private (a (x int)) (b x))
                    (define-private (b (x int)) (a x))";
    let err = build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));

    // A user function called from a native application is still a dependency.
    let contract = "(define-read-only (b) (a 1))
                    (define-read-only (a (x int)) (len (unwrap-panic (slice? (list (b)) u0 u1))))";
    let err = build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap_err();
    assert!(matches!(*err.err, ParseErrorKind::CircularReference(_)));
}

/// The names of the top-level definitions of `ast`, in sorted order.
fn sorted_definition_names(ast: &ContractAST) -> Vec<String> {
    ast.expressions
        .iter()
        .filter_map(|expr| {
            let define = expr.match_list()?;
            let signature = define.get(1)?;
            let name = signature
                .match_atom()
                .or_else(|| signature.match_list()?.first()?.match_atom())?;
            Some(name.to_string())
        })
        .collect()
}

/// Applying a keyword-named user function, directly or as a `map`/`fold`/
/// `filter` callback, makes the caller depend on it. One contract per case:
/// in a shared one the direct-call edge alone would satisfy the assertion.
#[rstest]
#[case::direct_call("(stacks-block-height u1)")]
#[case::map("(map stacks-block-height (list u1 u2))")]
#[case::fold("(fold stacks-block-height (list u1 u2) u0)")]
#[case::filter("(filter stacks-block-height (list u1 u2))")]
fn epoch41_keyword_named_function_is_a_dependency_in_function_position(#[case] call: &str) {
    let contract = format!(
        "(define-read-only (caller) {call})
         (define-read-only (stacks-block-height (x uint)) (ok x))"
    );
    let ast = build_ast_at(&contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap();
    let names = sorted_definition_names(&ast);
    assert_eq!(
        names,
        ["stacks-block-height", "caller"],
        "sorted: {names:?}"
    );
}

/// The remaining `fold` arguments are still probed: the seed is a dependency.
#[test]
fn epoch41_fold_seed_is_still_a_dependency() {
    let contract = "(define-read-only (fold-seed) (fold + (list u1 u2) seed))
                    (define-constant seed u0)";
    let ast = build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap();
    let names = sorted_definition_names(&ast);
    assert_eq!(names, ["seed", "fold-seed"], "sorted: {names:?}");
}

/// A native function name used as a callback still means the native.
#[test]
fn epoch41_native_function_name_in_function_position_is_not_a_dependency() {
    let contract =
        "(define-read-only (use-native) (map slice? (list (list 1 2)) (list u0) (list u1)))
                    (define-read-only (slice? (a int) (b int)) (ok (+ a b)))";
    let ast = build_ast_at(contract, ClarityVersion::Clarity7, StacksEpochId::Epoch41).unwrap();
    let names = sorted_definition_names(&ast);
    assert_eq!(names, ["use-native", "slice?"], "sorted: {names:?}");
}

#[test]
fn test_reordering_does_not_change_result() {
    same_behavior_regardless_of_order(
        "(define-read-only (g (c uint)) c)
         (define-constant c u42)",
        Some("NameAlreadyUsed(\\\"c\\\")"),
    );

    same_behavior_regardless_of_order(
        "(define-read-only (g) (let ((c u7)) u1))
         (define-constant c u42)
         (define-constant d (g))",
        Some("NameAlreadyUsed(\\\"c\\\")"),
    );

    same_behavior_regardless_of_order(
        "(define-read-only (a) (b))
         (define-read-only (b) (c))
         (define-read-only (c) (a))",
        Some("CircularReference([\\\"a\\\", \\\"b\\\", \\\"c\\\"])"),
    );

    same_behavior_regardless_of_order(
        "(define-trait my-trait ((some-name (uint) (response uint uint))))
         (define-read-only (foo) (let ((some-name \"abc\")) { some-name: some-name }))
         (define-read-only (bar (some-name int)) { some-name: some-name })
         (define-public (dispatch (some-name <my-trait>)) (contract-call? some-name some-name u99))
         ",
        None,
    );

    same_behavior_regardless_of_order(
        "(define-constant dupe u7)
         (define-trait my-trait ((dupe (uint) (response uint uint))))
         (define-read-only (foo) { dupe: dupe })
         (define-public (dispatch (target <my-trait>)) (contract-call? target dupe dupe))
         ",
        None,
    );
}
