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

mod bounded_message;

use std::time::Duration;

use stacks_common::types::StacksEpochId;

use crate::vm::ClarityVersion;
use crate::vm::analysis::read_only_checker::ReadOnlyChecker;
use crate::vm::analysis::type_checker::v2_1::TypeChecker as TypeChecker2_1;
use crate::vm::analysis::type_checker::v2_1::tests::mem_type_check;
use crate::vm::analysis::type_checker::v2_05::TypeChecker as TypeChecker2_05;
use crate::vm::analysis::{
    ContractAnalysis, StaticCheckError, StaticCheckErrorKind, mem_type_check as mem_run_analysis,
    run_analysis,
};
use crate::vm::ast::build_ast;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::MemoryBackingStore;
use crate::vm::resource_limiter::{ResourceBudget, ResourceLimiter};
use crate::vm::types::QualifiedContractIdentifier;

pub mod utils {
    use super::*;
    use crate::vm::analysis::AnalysisPass;

    /// Run the full analysis pipeline on `snippet` at the latest epoch / Clarity
    /// version with the given `resource_limiter`, returning the analysis error (if any).
    pub fn run_analysis_with_resource_limiter(
        snippet: &str,
        resource_limiter: ResourceLimiter,
    ) -> Result<ContractAnalysis, StaticCheckError> {
        let contract_id = QualifiedContractIdentifier::transient();
        let version = ClarityVersion::latest();
        let epoch = StacksEpochId::latest();

        let exprs = build_ast(&contract_id, snippet, &mut (), version, epoch)
            .expect("test contract should parse")
            .expressions;

        let mut marf = MemoryBackingStore::new();
        let mut analysis_db = marf.as_analysis_db();

        run_analysis(
            &contract_id,
            &exprs,
            &mut analysis_db,
            false, // save_contract
            LimitedCostTracker::new_free(),
            epoch,
            version,
            false, // build_type_map
            resource_limiter,
        )
        .map_err(|e| e.0)
    }

    pub enum SingleAnalysisPass {
        ReadOnlyChecker,
        TypeChecker2_05,
        TypeChecker2_1,
    }

    /// Given a Clarity snippet (which is assumed to be syntactically correct), parse it and
    /// hand it to the given analysis pass.
    pub fn run_single_analysis_pass(
        pass: SingleAnalysisPass,
        snippet: &str,
        version: ClarityVersion,
        epoch: StacksEpochId,
    ) -> Result<ContractAnalysis, StaticCheckError> {
        let contract_identifier = QualifiedContractIdentifier::transient();
        let contract = build_ast(&contract_identifier, snippet, &mut (), version, epoch)
            .unwrap()
            .expressions;

        let mut marf = MemoryBackingStore::new();
        let mut analysis_db = marf.as_analysis_db();
        let cost_tracker = LimitedCostTracker::new_free();
        let mut contract_analysis = ContractAnalysis::new(
            contract_identifier.clone(),
            contract,
            cost_tracker,
            epoch,
            version,
        );
        let result = analysis_db.execute(|db| match pass {
            SingleAnalysisPass::ReadOnlyChecker => ReadOnlyChecker::run_pass(
                &epoch,
                &mut contract_analysis,
                db,
                ResourceLimiter::unlimited(),
            ),
            SingleAnalysisPass::TypeChecker2_1 => TypeChecker2_1::run_pass(
                &epoch,
                &mut contract_analysis,
                db,
                true,
                ResourceLimiter::unlimited(),
            ),
            SingleAnalysisPass::TypeChecker2_05 => {
                TypeChecker2_05::run_pass(&epoch, &mut contract_analysis, db, true)
            }
        });
        result.map(|_| contract_analysis)
    }
}

#[test]
fn test_list_types_must_match() {
    let snippet = "(list 1 true)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'int', found 'bool'")
    );
}

#[test]
fn test_type_error() {
    let snippet = "(+ true 1)";
    let err = mem_type_check(snippet).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(
        format!("{}", err.diagnostic)
            .contains("expecting expression of type 'int' or 'uint', found 'bool'")
    );

    let snippet = "(+ 1 true)";
    let err = mem_type_check(snippet).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'int', found 'bool'")
    );
}

#[test]
fn test_union_type_error() {
    let snippet = "(hash160 true)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains(
            "expecting expression of type '(buff 1048576)', 'uint' or 'int', found 'bool'"
        )
    );
}

#[test]
fn test_expected_optional_type() {
    let snippet = "(is-none 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("expecting expression of type 'optional', found 'int'")
    );
}

#[test]
fn test_expected_response_type() {
    let snippet = "(is-ok 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("expecting expression of type 'response', found 'int'")
    );
}

#[test]
fn test_could_not_determine_response_ok_type() {
    let snippet = "(unwrap! (err \"error\") 0)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains(
            "attempted to obtain 'ok' value from response, but 'ok' type is indeterminate"
        )
    );
}

#[test]
fn test_could_not_determine_response_err_type() {
    let snippet = "(unwrap-err! (ok 1) 0)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains(
        "attempted to obtain 'err' value from response, but 'err' type is indeterminate"
    ));
}

#[test]
fn test_bad_tuple_field_name() {
    let snippet = "(get 1 (tuple (value 100)))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid tuple field name"));
}

#[test]
fn test_bad_function_name_2() {
    // outside of the legal "implicit" tuple structures,
    //    things that look like ((value 100)) are evaluated as
    //    _function applications_, so this should error, since (value 100) isn't a function.
    let snippet = "(ok ((value 100)))";
    let err = mem_type_check(snippet).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(format!("{}", err.diagnostic).contains("expecting expression of type function"));
}

#[test]
fn test_expected_tuple() {
    let snippet = "(get value 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expecting tuple, found 'int'"));
}

#[test]
fn test_no_such_tuple_field() {
    let snippet = "(get val (tuple (value 100)))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("cannot find field 'val' in tuple '(tuple (value int))'")
    );
}

#[test]
fn test_bad_tuple_construction() {
    let snippet = "(tuple (key 1) (key 2))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("invalid tuple syntax: defining 'key' conflicts with previous value.")
    );
}

#[test]
fn test_tuple_expects_pairs() {
    let snippet = "(tuple (key 1) (key-with-missing-value))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains(
            "invalid syntax binding: Tuple constructor item #2 is not a two-element list."
        )
    );
}

#[test]
fn test_no_such_variable() {
    let snippet = "(var-get unicorn)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("use of unresolved persisted variable 'unicorn'")
    );
}

#[test]
fn test_bad_map_name() {
    let snippet = "(define-map 1 { key: int } { value: int })";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expected a name argument"));
}

#[test]
fn test_no_such_map() {
    let snippet = "(map-get? unicorn { key: 1 })";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("use of unresolved map 'unicorn'"));
}

#[test]
fn test_define_function_bad_signature() {
    let snippet = "(define-public test (ok 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid function definition"));
}

#[test]
fn test_bad_function_name() {
    let snippet = "(define-public (1) (ok 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid function name"));
}

#[test]
fn test_public_function_must_return_response() {
    let snippet = "(define-public (fn) 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("public functions must return an expression of type 'response', found 'int'")
    );
}

#[test]
fn test_define_variable_bad_signature() {
    let snippet = "(define-data-var 1 int 0)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expected a name argument"));
}

#[test]
fn test_return_types_must_match() {
    let snippet = "(define-private (mismatched) (begin (unwrap! (ok 1) false) 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("detected two execution paths, returning two different expression types")
    );
}

#[test]
fn test_contract_call_expect_name() {
    let snippet = "(contract-call? 1 fn)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("missing contract name for call"));
}

#[test]
fn test_no_such_block_info_property() {
    let snippet = "(get-block-info? unicorn 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity2, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("use of block unknown property 'unicorn'"));
}

#[test]
fn test_no_such_stacks_block_info_property() {
    let snippet = "(get-stacks-block-info? unicorn 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("use of unknown stacks block property 'unicorn'")
    );
}

#[test]
fn test_no_such_tenure_info_property() {
    let snippet = "(get-tenure-info? unicorn 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("use of unknown tenure property 'unicorn'"));
}

#[test]
fn test_get_block_info_expect_property_name() {
    let snippet = "(get-block-info? 0 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity2, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("missing property name for block info introspection")
    );
}

#[test]
fn test_get_stacks_block_info_expect_property_name() {
    let snippet = "(get-stacks-block-info? 0 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("missing property name for stacks block info introspection")
    );
}

#[test]
fn test_get_tenure_info_expect_property_name() {
    let snippet = "(get-tenure-info? 0 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("missing property name for tenure info introspection")
    );
}

#[test]
fn test_no_such_block_info_height() {
    let snippet = "(get-block-info? time 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity2, StacksEpochId::latest()).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'uint', found 'int'")
    );
}

#[test]
fn test_no_such_stacks_block_info_height() {
    let snippet = "(get-stacks-block-info? time 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'uint', found 'int'")
    );
}

#[test]
fn test_no_such_tenure_info_height() {
    let snippet = "(get-tenure-info? time 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'uint', found 'int'")
    );
}

#[test]
fn test_name_already_used() {
    let snippet = "(define-constant var1 true) (define-constant var1 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("'var1' conflicts with previous value"));
}

#[test]
fn test_non_function_application() {
    let snippet = "(filter 1 (1 2 3 4))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expecting expression of type function"));
}

#[test]
fn test_expected_list_or_buff() {
    let snippet = "(filter not 4)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains(
            "expecting expression of type 'list', 'buff', 'string-ascii' or 'string-utf8'"
        )
    );
}

#[test]
fn test_bad_let_syntax() {
    let snippet = "(let 1 (true))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid syntax of 'let'"));
}

#[test]
fn test_bad_syntax_binding() {
    let snippet = "(let (t ((0))) t)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid syntax binding"));
}

#[test]
fn test_unbound_variable() {
    let snippet = "(+ 1 unicorn)";
    let err = mem_type_check(snippet).unwrap_err();
    eprintln!("{}", err.diagnostic);
    assert!(format!("{}", err.diagnostic).contains("use of unresolved variable 'unicorn'"));
}

#[test]
fn test_variadic_needs_one_argument() {
    let snippet = "(begin)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains(""));
}

#[test]
fn test_incorrect_argument_count() {
    let snippet = "(define-map my-map { val: int })";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expecting 3 arguments, got 2"));
}

#[test]
fn test_if_arms_must_match() {
    let snippet = "(if true true 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains(
        "expression types returned by the arms of 'if' must match (got 'bool' and 'int')"
    ));
}

#[test]
fn test_default_types_must_match() {
    let snippet = "(default-to 1 (some true))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("expression types passed in 'default-to' must match (got 'int' and 'bool')")
    );
}

#[test]
fn test_write_attempt_in_readonly() {
    let snippet = "(define-data-var x int 0) (define-read-only (fn) (var-set x 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic)
            .contains("expecting read-only statements, detected a writing operation")
    );
}

/// An already-elapsed deadline trips the per-node analysis check on the
/// very first `type_check` node, so even a trivial contract is rejected with
/// [`StaticCheckErrorKind::AnalysisResourceBudgetExceeded`].
#[test]
fn test_run_analysis_aborts_when_deadline_already_elapsed() {
    let err = utils::run_analysis_with_resource_limiter(
        "(define-read-only (foo) (+ 1 1))",
        ResourceBudget::new()
            .with_max_duration(Some(Duration::ZERO))
            .start_tracking(),
    )
    .expect_err("a zero-duration analysis deadline must abort");

    assert!(
        matches!(
            *err.err,
            StaticCheckErrorKind::AnalysisResourceBudgetExceeded(_)
        ),
        "expected AnalysisResourceBudgetExceeded, got {:?}",
        err.err
    );
}

/// An unlimited [`ResourceLimiter`] (the deterministic replay/commit path) imposes no
/// analysis deadline, so a valid contract type-checks successfully.
#[test]
fn test_run_analysis_no_tracking_is_not_time_limited() {
    let result = utils::run_analysis_with_resource_limiter(
        "(define-read-only (foo) (+ 1 1))",
        ResourceLimiter::unlimited(),
    );
    assert!(
        result.is_ok(),
        "NoTracking analysis should succeed, got {:?}",
        result.map(|_| ())
    );
}

/// A generous deadline is not hit by a trivial contract, so analysis succeeds. This
/// guards against the per-node check firing spuriously when a deadline is configured.
#[test]
fn test_run_analysis_generous_deadline_succeeds() {
    let result = utils::run_analysis_with_resource_limiter(
        "(define-read-only (foo) (+ 1 1))",
        ResourceBudget::new()
            .with_max_duration(Some(Duration::from_secs(300)))
            .start_tracking(),
    );
    assert!(
        result.is_ok(),
        "analysis deadline should not trip on a trivial contract, got {:?}",
        result.map(|_| ())
    );
}

/// Test that up to epoch 4.0, the read-only checker runs first during contract
/// analysis, then the type checker, and in epoch 4.1 and later, the order is
/// reversed.
#[test]
fn test_order_of_readonly_check_and_type_check() {
    // This contract contains a read-only error (can't use `stx-transfer?` inside a
    // read-only function) and a type error (can't use the special function `stx-transfer?`
    // as the mapping function).
    // Which of the two errors is returned by the analysis depends on which of the
    // two checks run first.
    let snippet = r#"
            (define-read-only (do-illegal-stuff)
                (map stx-transfer? (list u100) (list tx-sender) (list 'S12XR70XVZ0ZXQ35GKDH2VJ3ZDJJGNMW8XCQRYE6F))
            )
        "#;

    let expected_read_only_error = "WriteAttemptedInReadOnly";
    let expected_type_error = "IllegalOrUnknownFunctionApplication";

    let last_epoch_with_read_only_checker_first = StacksEpochId::Epoch40;
    let first_epoch_with_type_checker_first = StacksEpochId::Epoch41;

    // In epoch 4.0, the read-only checker runs first, and thus its error should
    // be the result that we get.
    let err = mem_run_analysis(
        snippet,
        ClarityVersion::latest(),
        last_epoch_with_read_only_checker_first,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains(expected_read_only_error),
        "expected error to contain \"{expected_read_only_error}\" but got {}",
        err
    );

    // Starting in epoch 4.1, the type checker runs first, and we should get
    // a different error.

    let err = mem_run_analysis(
        snippet,
        ClarityVersion::latest(),
        first_epoch_with_type_checker_first,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains(expected_type_error),
        "expected error to contain \"{expected_type_error}\" but got {}",
        err
    );
}

/// Checks that the analysis succeeds in 4.0 but fails in 4.1 with an error that
/// contains the given substring. Helper for [`test_definition_sorting_of_contract_call`]`.
fn assert_contract_starts_failing_in_epoch_41(snippet: &str, expected_error_41: &str) {
    let result = mem_run_analysis(snippet, ClarityVersion::latest(), StacksEpochId::Epoch40);
    assert!(
        result.is_ok(),
        "expected to pass in Epoch 4.0 but got {}; contract: {snippet}",
        result.unwrap_err()
    );

    let result = mem_run_analysis(snippet, ClarityVersion::latest(), StacksEpochId::Epoch41);
    match result {
        Err(e) => assert!(
            e.to_string().contains(expected_error_41),
            "expected error to contain \"{expected_error_41}\" in Epoch 4.1 but got {e}; contract: {snippet}"
        ),
        Ok(_) => panic!("should not succeed in Epoch 4.1"),
    };
}

/// Checks that the analysis fails in both 4.0 and 4.1 with an error that
/// contains the given substring. Helper for [`test_definition_sorting_of_contract_call`]`.
fn assert_contract_fails_even_before_epoch_41(snippet: &str, expected_error: &str) {
    let result = mem_run_analysis(snippet, ClarityVersion::latest(), StacksEpochId::Epoch40);
    match result {
        Err(e) => assert!(
            e.to_string().contains(expected_error),
            "expected error to contain \"{expected_error}\" in Epoch 4.0 but got {e}; contract: {snippet}"
        ),
        Ok(_) => panic!("should not succeed in Epoch 4.0"),
    };

    let result = mem_run_analysis(snippet, ClarityVersion::latest(), StacksEpochId::Epoch41);
    match result {
        Err(e) => assert!(
            e.to_string().contains(expected_error),
            "expected error to contain \"{expected_error}\" Epoch 4.1 but got {e}; contract: {snippet}"
        ),
        Ok(_) => panic!("should not succeed in Epoch 4.1"),
    };
}

#[test]
/// Until Epoch 4.0, the definition sorter ignored the first argument to `contract-call?`,
/// which means it didn't prevent a local binding (e.g. function parameter) and a global
/// object (e.g. a data-var) from having the same name, if the global was defined after
/// the function. This is inconsistent (this shouldn't depend on the order), and it can
/// cause cryptic failures at runtime, and was therefore fixed in Epoch 4.1.
/// Even for non-broken contracts, this fix can change cost, which is why we
/// have to preserve the legacy behavior for all earlier epochs. That is what this test
/// ensures: Until 4.0, such contracts pass analysis, but from 4.1 on, they fail. It also
/// ensures that the cases that have previously been rejected still are.
fn test_definition_sorting_of_contract_call() {
    // Function name matches parameter name. Even though that works as expected by
    // accident, it is invalid.
    assert_contract_starts_failing_in_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-public (stuff (stuff <my-trait>)) (contract-call? stuff trait-func))",
        "CircularReference",
    );

    // These contracts define a global `thing` *after* a function with a parameter
    // called `thing` that was passed to `contract-call?`. This passed analysis until
    // epoch 4.0, but should be rejected starting in 4.1

    assert_contract_starts_failing_in_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-public (stuff (thing <my-trait>)) (contract-call? thing trait-func))
         (define-constant thing (unwrap-panic (as-contract? () tx-sender)))",
        "NameAlreadyUsed",
    );

    assert_contract_starts_failing_in_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-public (stuff (thing <my-trait>)) (contract-call? thing trait-func))
         (define-data-var thing principal (unwrap-panic (as-contract? () tx-sender)))",
        "NameAlreadyUsed",
    );

    assert_contract_starts_failing_in_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-public (stuff (thing <my-trait>)) (contract-call? thing trait-func))
         (define-private (thing) 42)",
        "NameAlreadyUsed",
    );

    // same as above, except that the function parameter is fine -- it's the
    // `let` binding that uses the duplicate name
    assert_contract_starts_failing_in_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-public (stuff (target <my-trait>)) (let ((thing target)) (contract-call? thing trait-func)))
         (define-private (thing) 42)",
        "NameAlreadyUsed",
    );

    // These contracts are identical to the previous four, except that the global
    // `thing` is defined *before* the function. This was always prevented.

    assert_contract_fails_even_before_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-constant thing (unwrap-panic (as-contract? () tx-sender)))
         (define-public (stuff (thing <my-trait>)) (contract-call? thing trait-func))",
        "NameAlreadyUsed",
    );

    assert_contract_fails_even_before_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-data-var thing principal (unwrap-panic (as-contract? () tx-sender)))
         (define-public (stuff (thing <my-trait>)) (contract-call? thing trait-func))",
        "NameAlreadyUsed",
    );

    assert_contract_fails_even_before_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
        (define-private (thing) 42)
         (define-public (stuff (thing <my-trait>)) (contract-call? thing trait-func))",
        "NameAlreadyUsed",
    );

    assert_contract_fails_even_before_epoch_41(
        "(define-trait my-trait ((trait-func () (response uint uint))))
         (define-private (thing) 42)
         (define-public (stuff (target <my-trait>)) (let ((thing target)) (contract-call? thing trait-func)))",
        "NameAlreadyUsed",
    );
}
