// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! From Epoch 4.1, runtime cost and memory charges count the traits that
//! callable types hold. Each case checks one charge site on a list of trait
//! values against a `uint` twin, so a site that falls back to legacy sizes
//! fails its own case.
//!
//! Trait values only come from trait-typed arguments: a contract principal
//! literal evaluates to a plain principal. Storage types cannot hold traits,
//! so charges on the declared types of data vars, maps and NFTs never see a
//! callable type.

use rstest::rstest;
use stacks_common::types::StacksEpochId;

use super::TopLevelMemoryEnvironmentGenerator;
use crate::vm::ClarityVersion;
use crate::vm::contexts::{ExecutionState, InvocationContext, LocalContext, OwnedEnvironment};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{ExecutionCost, LimitedCostTracker, runtime_cost};
use crate::vm::database::MemoryBackingStore;
use crate::vm::hooks::EvalHook;
use crate::vm::representations::SymbolicExpression;
use crate::vm::tests::symbols_from_values;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value};

const VERSION: ClarityVersion = ClarityVersion::Clarity2;

const TRAITS: &str = "(define-trait trait-a ((f () (response bool uint))))";

const IMPL: &str = "(define-public (f) (ok true))";

/// Records the most memory held when the `marker` constant is evaluated.
#[derive(Default)]
struct MarkerMemory(u64);

impl EvalHook for MarkerMemory {
    fn will_begin_eval(
        &mut self,
        env: &mut ExecutionState,
        _invoke_ctx: &InvocationContext,
        _context: &LocalContext,
        expr: &SymbolicExpression,
    ) {
        if expr
            .match_atom()
            .is_some_and(|name| name.as_str() == "marker")
        {
            self.0 = self.0.max(env.global_context.cost_track.get_memory());
        }
    }
}

#[derive(Clone, Copy)]
enum Element {
    Trait,
    Uint,
}

impl Element {
    fn type_repr(self) -> &'static str {
        match self {
            Element::Trait => "<trait-a>",
            Element::Uint => "uint",
        }
    }

    fn value(self) -> Value {
        match self {
            Element::Trait => Value::from(PrincipalData::Contract(
                QualifiedContractIdentifier::local("impl").unwrap(),
            )),
            Element::Uint => Value::UInt(1),
        }
    }

    /// `xs`, a list of two one-element lists, and `y`, a one-element list.
    fn args(self) -> Vec<Value> {
        let y = Value::cons_list_unsanitized(vec![self.value()]).unwrap();
        let xs = Value::cons_list_unsanitized(vec![y.clone(), y.clone()]).unwrap();
        vec![xs, y]
    }
}

/// Deploys `TRAITS`, `IMPL` and a caller with public functions `op` and `base`
/// taking `xs` and `y` typed by `element`, under a free tracker.
fn deploy_caller(env: &mut OwnedEnvironment, element: Element, op: &str, base: &str) {
    let ty = element.type_repr();
    let caller = format!(
        "(use-trait trait-a .traits.trait-a)
         (define-constant marker true)
         (define-private (take (ys (list 2 (list 1 {ty})))) u0)
         (define-private (hold (ys (list 2 (list 1 {ty})))) marker)
         (define-public (op (xs (list 2 (list 1 {ty}))) (y (list 1 {ty}))) {op})
         (define-public (base (xs (list 2 (list 1 {ty}))) (y (list 1 {ty}))) {base})"
    );
    for (name, source) in [("traits", TRAITS), ("impl", IMPL), ("caller", &caller)] {
        env.initialize_versioned_contract(
            QualifiedContractIdentifier::local(name).unwrap(),
            VERSION,
            source,
            None,
        )
        .unwrap();
    }
}

/// Runtime cost of calling `function` and the memory held at `marker`.
struct Charges {
    runtime: u64,
    marker_memory: u64,
}

/// Calls `function` on a caller deployed at `epoch`, charging only the call.
fn call(epoch: StacksEpochId, element: Element, op: &str, base: &str, function: &str) -> Charges {
    let mut marker = MarkerMemory::default();
    let runtime = {
        let mut generator = TopLevelMemoryEnvironmentGenerator(MemoryBackingStore::new());
        let mut env = generator.get_env(epoch);
        env.add_eval_hook(&mut marker);
        deploy_caller(&mut env, element, op, base);
        *env.mut_cost_tracker() =
            LimitedCostTracker::new_with_limit(epoch, ExecutionCost::max_value());
        let (result, ..) = env
            .execute_transaction(
                StandardPrincipalData::transient().into(),
                None,
                QualifiedContractIdentifier::local("caller").unwrap(),
                function,
                &symbols_from_values(element.args()),
            )
            .unwrap();
        assert!(
            matches!(result, Value::Response(ref r) if r.committed),
            "{result}"
        );
        env.get_cost_total().runtime
    };
    Charges {
        runtime,
        marker_memory: marker.0,
    }
}

/// Each `op` charges `cost_function` once more than `base`, which reads the
/// same variables, so the difference between the epochs is that one charge.
/// `xs`, two one-element trait lists, is 2 * (276 + 6) + 11 = 575 bytes
/// before 4.1; from 4.1 each list type also holds the trait, for
/// 2 * (276 + 6 + 276) + 11 + 276 = 1403. One entry, like `y`, is 282 and 558.
#[rstest]
#[case::native_argument_clone(
    "(ok (len xs))",
    "(ok u0)",
    ClarityCostFunction::LookupVariableSize,
    575,
    1403
)]
#[case::print(
    "(begin (print xs) (ok u0))",
    "(begin xs (ok u0))",
    ClarityCostFunction::Print,
    575,
    1403
)]
#[case::list_cons(
    "(ok (len (list xs xs)))",
    "(ok (+ (len xs) (len xs)))",
    ClarityCostFunction::ListCons,
    2 * 575,
    2 * 1403
)]
#[case::function_argument(
    "(ok (take xs))",
    "(ok (len xs))",
    ClarityCostFunction::InnerTypeCheckCost,
    575,
    1403
)]
#[case::slice(
    "(ok (len (unwrap-panic (slice? xs u0 u1))))",
    "(ok (len xs))",
    ClarityCostFunction::Slice,
    282,
    558
)]
#[case::append(
    "(ok (len (append xs y)))",
    "(ok (+ (len xs) (len y)))",
    ClarityCostFunction::Append,
    282,
    558
)]
#[case::replace_at(
    "(ok (len (unwrap-panic (replace-at? xs u0 y))))",
    "(ok (+ (len xs) (len y)))",
    ClarityCostFunction::ReplaceAt,
    575,
    1403
)]
fn test_runtime_charge_counts_traits_from_epoch41(
    #[case] op: &str,
    #[case] base: &str,
    #[case] cost_function: ClarityCostFunction,
    #[case] legacy_size: u64,
    #[case] charged_size: u64,
) {
    let charge = |element: Element, epoch: StacksEpochId| {
        let op_cost = call(epoch, element, op, base, "op").runtime;
        let base_cost = call(epoch, element, op, base, "base").runtime;
        i128::from(op_cost) - i128::from(base_cost)
    };
    let cost = |size: u64| {
        let mut tracker =
            LimitedCostTracker::new_with_limit(StacksEpochId::Epoch41, ExecutionCost::max_value());
        runtime_cost(cost_function.clone(), &mut tracker, size).unwrap();
        i128::from(tracker.get_total().runtime)
    };

    assert_eq!(
        charge(Element::Trait, StacksEpochId::Epoch41)
            - charge(Element::Trait, StacksEpochId::Epoch40),
        cost(charged_size) - cost(legacy_size)
    );
    assert_eq!(
        charge(Element::Uint, StacksEpochId::Epoch41),
        charge(Element::Uint, StacksEpochId::Epoch40)
    );
}

/// Each body holds `xs`, or one of its entries, while `marker` is evaluated.
#[rstest]
#[case::let_binding("(let ((ys xs)) (ok marker))")]
#[case::match_binding("(match (some xs) ys (ok marker) (ok false))")]
#[case::function_argument("(ok (hold xs))")]
fn test_binding_memory_counts_traits_from_epoch41(#[case] body: &str) {
    let memory = |element: Element, epoch: StacksEpochId| {
        call(epoch, element, body, "(ok true)", "op").marker_memory
    };

    let trait_40 = memory(Element::Trait, StacksEpochId::Epoch40);
    assert!(trait_40 > 0, "marker not reached");
    assert!(memory(Element::Trait, StacksEpochId::Epoch41) > trait_40);
    assert_eq!(
        memory(Element::Uint, StacksEpochId::Epoch41),
        memory(Element::Uint, StacksEpochId::Epoch40)
    );
}

/// A constant built from trait values is charged for them while the rest of
/// the contract deploys.
#[test]
fn test_constant_memory_counts_traits_from_epoch41() {
    let memory = |element: Element, epoch: StacksEpochId| {
        let (ty, arg) = match element {
            Element::Trait => ("<trait-a>", ".impl"),
            Element::Uint => ("uint", "u1"),
        };
        let contract = format!(
            "(use-trait trait-a .traits.trait-a)
             (define-constant marker true)
             (define-private (wrap (t {ty})) (list (list t) (list t)))
             (define-constant held (wrap {arg}))
             (define-constant probe marker)"
        );
        let mut marker = MarkerMemory::default();
        {
            let mut generator = TopLevelMemoryEnvironmentGenerator(MemoryBackingStore::new());
            let mut env = generator.get_env(epoch);
            env.add_eval_hook(&mut marker);
            for (name, source) in [("traits", TRAITS), ("impl", IMPL)] {
                env.initialize_versioned_contract(
                    QualifiedContractIdentifier::local(name).unwrap(),
                    VERSION,
                    source,
                    None,
                )
                .unwrap();
            }
            *env.mut_cost_tracker() =
                LimitedCostTracker::new_with_limit(epoch, ExecutionCost::max_value());
            env.initialize_versioned_contract(
                QualifiedContractIdentifier::local("constant").unwrap(),
                VERSION,
                &contract,
                None,
            )
            .unwrap();
        }
        marker.0
    };

    let trait_40 = memory(Element::Trait, StacksEpochId::Epoch40);
    assert!(trait_40 > 0, "marker not reached");
    assert!(memory(Element::Trait, StacksEpochId::Epoch41) > trait_40);
    assert_eq!(
        memory(Element::Uint, StacksEpochId::Epoch41),
        memory(Element::Uint, StacksEpochId::Epoch40)
    );
}
