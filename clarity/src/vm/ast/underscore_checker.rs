// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

//! AST pass that rejects identifiers beginning with `_` for pre-`Clarity6`
//! contracts.
//!
//! The wire-level `ClarityName` regex and the v2 lexer accept underscore-led
//! names unconditionally so that the parser can produce a well-formed AST and
//! report a precise, version-aware diagnostic here rather than a generic
//! "illegal name" lexer error. Clarity 6 permits the relaxation only from
//! `ClarityVersion::Clarity6` onwards.

use clarity_types::representations::ClarityName;
use stacks_common::types::StacksEpochId;

use crate::vm::ClarityVersion;
use crate::vm::ast::errors::{ParseError, ParseErrorKind, ParseResult};
use crate::vm::ast::types::{BuildASTPass, ContractAST};
use crate::vm::representations::{PreSymbolicExpression, PreSymbolicExpressionType};

pub struct UnderscoreIdentifierChecker;

impl BuildASTPass for UnderscoreIdentifierChecker {
    fn run_pass(
        contract_ast: &mut ContractAST,
        version: ClarityVersion,
        _epoch: StacksEpochId,
    ) -> ParseResult<()> {
        if version.allows_underscore_prefix() {
            return Ok(());
        }
        check(&contract_ast.pre_expressions)
    }
}

fn check(exprs: &[PreSymbolicExpression]) -> ParseResult<()> {
    for expr in exprs {
        check_one(expr)?;
    }
    Ok(())
}

fn check_one(expr: &PreSymbolicExpression) -> ParseResult<()> {
    match &expr.pre_expr {
        PreSymbolicExpressionType::Atom(name) => reject_if_underscore(name, expr),
        PreSymbolicExpressionType::TraitReference(name) => reject_if_underscore(name, expr),
        PreSymbolicExpressionType::SugaredFieldIdentifier(_, trait_name) => {
            reject_if_underscore(trait_name, expr)
        }
        PreSymbolicExpressionType::FieldIdentifier(trait_id) => {
            reject_if_underscore(&trait_id.name, expr)
        }
        PreSymbolicExpressionType::List(inner) | PreSymbolicExpressionType::Tuple(inner) => {
            check(inner)
        }
        PreSymbolicExpressionType::AtomValue(_)
        | PreSymbolicExpressionType::SugaredContractIdentifier(_)
        | PreSymbolicExpressionType::Comment(_)
        | PreSymbolicExpressionType::Placeholder(_) => Ok(()),
    }
}

fn reject_if_underscore(name: &ClarityName, expr: &PreSymbolicExpression) -> ParseResult<()> {
    if !name.starts_with('_') {
        return Ok(());
    }
    let mut err = ParseError::new(ParseErrorKind::UnderscoreIdentifierNotAllowed(
        name.to_string(),
    ));
    err.diagnostic.spans = vec![expr.span().clone()];
    Err(err)
}

#[cfg(test)]
mod tests {
    use clarity_types::representations::MAX_STRING_LEN;
    use clarity_types::types::QualifiedContractIdentifier;
    use pinny::tag;
    use proptest::prelude::*;
    use proptest::string::string_regex;

    use super::*;
    use crate::vm::ast::{build_ast, build_ast_with_diagnostics};
    use crate::vm::costs::LimitedCostTracker;

    fn parses(source: &str, version: ClarityVersion) -> bool {
        let contract_id = QualifiedContractIdentifier::transient();
        let (_ast, _diag, success) = build_ast_with_diagnostics(
            &contract_id,
            source,
            &mut LimitedCostTracker::new_free(),
            version,
            StacksEpochId::latest(),
        );
        success
    }

    /// Like `parses(...)` but with error-early enabled, so callers can match
    /// on the specific `ParseErrorKind` returned for a pre-Clarity-6 contract.
    fn parse_err(source: &str, version: ClarityVersion) -> ParseErrorKind {
        let contract_id = QualifiedContractIdentifier::transient();
        let err = build_ast(
            &contract_id,
            source,
            &mut LimitedCostTracker::new_free(),
            version,
            StacksEpochId::latest(),
        )
        .expect_err("expected parse error");
        *err.err
    }

    #[test]
    fn underscore_prefix_rejected_pre_clarity6() {
        assert!(!parses(
            "(define-constant _admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_prefix_accepted_in_clarity6() {
        assert!(parses(
            "(define-constant _admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity6,
        ));
    }

    #[test]
    fn underscore_prefix_in_let_binding_pre_clarity6_rejected() {
        assert!(!parses("(let ((_x 1)) (+ _x 1))", ClarityVersion::Clarity5,));
    }

    #[test]
    fn bare_underscore_rejected_pre_clarity6() {
        assert!(!parses("(let ((_ 1)) 0)", ClarityVersion::Clarity5));
    }

    #[test]
    fn bare_underscore_accepted_in_clarity6() {
        assert!(parses("(let ((_ 1)) 0)", ClarityVersion::Clarity6));
    }

    #[test]
    fn underscore_in_function_arg_rejected_pre_clarity6() {
        assert!(!parses(
            "(define-public (foo (_addr principal)) (ok _addr))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn nested_underscore_atom_rejected_pre_clarity6() {
        // The check must descend into nested lists.
        assert!(!parses(
            "(define-public (foo) (ok (let ((y 1)) _bad)))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn non_underscore_names_still_accepted_pre_clarity6() {
        // Regression guard: legacy identifiers must still parse.
        assert!(parses(
            "(define-constant admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
             (define-public (foo (addr principal)) (ok addr))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn interior_underscore_still_accepted_pre_clarity6() {
        // Underscores inside an identifier remain legal pre-Clarity-6;
        // only the leading position is gated.
        assert!(parses(
            "(define-constant my_admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_trait_reference_rejected_pre_clarity6() {
        assert!(!parses(
            "(define-trait t ((bar (<_foo>) (response uint uint))))",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_trait_reference_accepted_in_clarity6() {
        // Defines `_foo` so the later `TraitsResolver` pass doesn't fail with
        // `TraitReferenceUnknown` — pre-Clarity-6 short-circuits before that.
        assert!(parses(
            "(define-trait _foo ((m (uint) (response uint uint))))
             (define-trait t ((bar (<_foo>) (response uint uint))))",
            ClarityVersion::Clarity6,
        ));
    }

    #[test]
    fn underscore_in_let_binding_accepted_in_clarity6() {
        assert!(parses("(let ((_x 1)) (+ _x 1))", ClarityVersion::Clarity6));
    }

    #[test]
    fn underscore_in_function_arg_accepted_in_clarity6() {
        assert!(parses(
            "(define-public (foo (_addr principal)) (ok _addr))",
            ClarityVersion::Clarity6,
        ));
    }

    #[test]
    fn underscore_in_tuple_key_rejected_pre_clarity6() {
        // The pass descends into `Tuple` nodes — exercise that match arm via a
        // tuple-literal whose key is underscore-prefixed.
        assert!(!parses(
            "(define-constant x { _k: 1 })",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_in_tuple_key_accepted_in_clarity6() {
        assert!(parses(
            "(define-constant x { _k: 1 })",
            ClarityVersion::Clarity6,
        ));
    }

    #[test]
    fn underscore_in_sugared_field_identifier_rejected_pre_clarity6() {
        // `.contract.trait` desugars to `SugaredFieldIdentifier`. The trait
        // name `_t` should trigger the leading-`_` check via that arm.
        assert!(!parses(
            "(use-trait t .my-contract._t)",
            ClarityVersion::Clarity5,
        ));
    }

    #[test]
    fn underscore_in_fully_qualified_field_identifier_rejected_pre_clarity6() {
        // The fully-qualified `'<addr>.<contract>.<trait>` form yields a
        // `FieldIdentifier(TraitIdentifier { name, ... })`; exercise that
        // distinct match arm.
        assert!(!parses(
            "(use-trait t 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7.my-contract._t)",
            ClarityVersion::Clarity5,
        ));
    }

    /// Regression guard: the gate must emit `UnderscoreIdentifierNotAllowed`,
    /// not (say) a generic `IllegalClarityName`. The boolean-only tests
    /// above would not catch such a drift.
    #[test]
    fn rejection_emits_underscore_identifier_not_allowed_kind() {
        let err = parse_err(
            "(define-constant _admin 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)",
            ClarityVersion::Clarity5,
        );
        let ParseErrorKind::UnderscoreIdentifierNotAllowed(name) = err else {
            panic!("expected UnderscoreIdentifierNotAllowed, got {err:?}");
        };
        assert_eq!(name, "_admin");
    }

    /// Regression guard: operator names like `+`, `<=`, `*` never start with
    /// `_` and must pass the pass cleanly under any Clarity version.
    #[test]
    fn leading_operator_names_unaffected_pre_clarity6() {
        assert!(parses(
            "(define-private (foo) (+ 1 2)) (define-private (bar) (<= 1 2))",
            ClarityVersion::Clarity5,
        ));
    }

    /// Bare `_` is reserved as a discard pattern; outside `let`/`match`
    /// bindings it is rejected at the analyzer/runtime layer (see
    /// `check_name_used` / `check_legal_define`). The AST pass itself
    /// happily lets `_` through in Clarity 6+ — the rejection lives one
    /// layer up so let/match discards can use the same character.
    #[test]
    fn bare_underscore_passes_ast_pass_in_clarity6() {
        // AST pass alone accepts bare `_` as a define name; the analyzer
        // will reject it. The full-pipeline rejection is covered by
        // `test_bare_underscore_as_define_name_rejected_in_clarity6` in
        // `vm::tests::simple_apply_eval`.
        assert!(parses("(define-constant _ 1)", ClarityVersion::Clarity6));
    }

    #[test]
    fn bare_underscore_as_define_name_rejected_pre_clarity6() {
        assert!(!parses("(define-constant _ 1)", ClarityVersion::Clarity5));
    }

    /// Generates valid `_`-led `ClarityName` strings (including bare `_`),
    /// bounded by `MAX_STRING_LEN`.
    fn any_underscore_led_clarity_name() -> impl Strategy<Value = String> {
        string_regex(&format!(
            "_[a-zA-Z0-9_!?+<>=/*-]{{0,{}}}",
            (MAX_STRING_LEN as usize).saturating_sub(1)
        ))
        .unwrap()
    }

    /// For every valid `_`-led `ClarityName`, pre-Clarity-6 must reject with
    /// `UnderscoreIdentifierNotAllowed(name)` and Clarity 6 must accept.
    /// Covers bare `_`, `_>=` / `_+!` shapes, and names at the
    /// `MAX_STRING_LEN` boundary.
    #[tag(t_prop)]
    #[test]
    fn prop_underscore_led_names_gated_by_clarity_version() {
        proptest!(|(name in any_underscore_led_clarity_name())| {
            let src = format!("(define-constant {name} 1)");

            let err = parse_err(&src, ClarityVersion::Clarity5);
            prop_assert!(
                matches!(&err, ParseErrorKind::UnderscoreIdentifierNotAllowed(n) if n == &name),
                "expected UnderscoreIdentifierNotAllowed({name:?}), got {err:?}"
            );

            prop_assert!(
                parses(&src, ClarityVersion::Clarity6),
                "expected `_`-led name {name:?} to parse in Clarity 6"
            );
        });
    }
}
