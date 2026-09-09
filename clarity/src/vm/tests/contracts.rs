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
#[cfg(any(test, feature = "testing"))]
use rstest::rstest;
#[cfg(test)]
use stacks_common::consts::CHAIN_ID_TESTNET;
#[cfg(test)]
use stacks_common::types::{StacksEpochId, chainstate::BlockHeaderHash};
#[cfg(test)]
use stacks_common::util::hash::Sha512Trunc256Sum;

#[cfg(test)]
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::contexts::{ExecutionState, InvocationContext};
#[cfg(test)]
use crate::vm::costs::{ExecutionCost, LimitedCostTracker};
#[cfg(test)]
use crate::vm::database::MemoryBackingStore;
use crate::vm::tests::{test_clarity_versions, test_epochs};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value};
#[cfg(test)]
use crate::vm::{
    ast::errors::ParseErrorKind,
    errors::{ClarityEvalError, RuntimeCheckErrorKind, RuntimeError, VmExecutionError},
    tests::{
        MemoryEnvironmentGenerator, TopLevelMemoryEnvironmentGenerator, env_factory, execute,
        is_committed, is_err_code_i128 as is_err_code, symbols_from_values, tl_env_factory,
    },
    types::{OptionalData, ResponseData, TypeSignature},
    {ClarityVersion, ContractContext, execute as vm_execute, max_call_stack_depth_for_epoch},
};

const FACTORIAL_CONTRACT: &str = "(define-map factorials { id: int } { current: int, index: int })
         (define-private (init-factorial (id int) (factorial int))
           (print (map-insert factorials (tuple (id id)) (tuple (current 1) (index factorial)))))
         (define-public (compute (id int))
           (let ((entry (unwrap! (map-get? factorials (tuple (id id)))
                                 (err false))))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             (ok true)
                             (begin
                               (map-set factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               (ok false))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5))";

const SIMPLE_TOKENS: &str = "(define-map tokens { account: principal } { balance: uint })
         (define-read-only (my-get-token-balance (account principal))
            (default-to u0 (get balance (map-get? tokens (tuple (account account))))))
         (define-read-only (explode (account principal))
             (map-delete tokens (tuple (account account))))
         (define-private (token-credit! (account principal) (amount uint))
            (if (<= amount u0)
                (err \"must be positive\")
                (let ((current-amount (my-get-token-balance account)))
                  (begin
                    (map-set tokens (tuple (account account))
                                       (tuple (balance (+ amount current-amount))))
                    (ok 0)))))
         (define-public (token-transfer (to principal) (amount uint))
          (let ((balance (my-get-token-balance tx-sender)))
             (if (or (> amount balance) (<= amount u0))
                 (err \"not enough balance\")
                 (begin
                   (map-set tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (print (token-transfer (print original-sender) u1)))))
         (define-public (mint-after (block-to-release uint))
           (if (>= block-height block-to-release)
               (faucet)
               (err \"must be in the future\")))
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR u10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G u200)
                (token-credit! .tokens u4))";

fn get_principal() -> Value {
    StandardPrincipalData::transient().into()
}

fn get_principal_as_principal_data() -> PrincipalData {
    StandardPrincipalData::transient().into()
}

#[apply(test_epochs)]
fn test_get_block_info_eval(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let contracts = [
        "(define-private (test-func) (get-block-info? time u1))",
        "(define-private (test-func) (get-block-info? time block-height))",
        "(define-private (test-func) (get-block-info? time u100000))",
        "(define-private (test-func) (get-block-info? time (- 1)))",
        "(define-private (test-func) (get-block-info? time true))",
        "(define-private (test-func) (get-block-info? header-hash u1))",
        "(define-private (test-func) (get-block-info? burnchain-header-hash u1))",
        "(define-private (test-func) (get-block-info? vrf-seed u1))",
    ];

    let expected = [
        Ok(Value::none()),
        Ok(Value::none()),
        Ok(Value::none()),
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::UIntType),
            Value::Int(-1).to_error_string(),
        )
        .into()),
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::UIntType),
            Value::Bool(true).to_error_string(),
        )
        .into()),
        Ok(Value::none()),
        Ok(Value::none()),
        Ok(Value::none()),
    ];

    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    let mut owned_env = tl_env_factory.get_env(epoch);
    for i in 0..contracts.len() {
        let contract_identifier =
            QualifiedContractIdentifier::local(&format!("test-contract-{i}")).unwrap();
        owned_env
            .initialize_versioned_contract(
                contract_identifier.clone(),
                ClarityVersion::Clarity2,
                contracts[i],
                None,
            )
            .unwrap();

        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        eprintln!("{}", contracts[i]);
        let eval_result =
            exec_state.eval_read_only(&invoke_ctx, &contract_identifier, "(test-func)");
        match expected[i] {
            // any (some UINT) is okay for checking get-block-info? time
            Ok(Value::UInt(0)) => {
                assert!(
                    if let Ok(Value::Optional(OptionalData { data: Some(x) })) = eval_result {
                        matches!(*x, Value::UInt(_))
                    } else {
                        false
                    }
                );
            }
            _ => assert_eq!(expected[i], eval_result),
        }
    }
}

#[apply(test_epochs)]
fn test_contract_caller(epoch: StacksEpochId, mut env_factory: MemoryEnvironmentGenerator) {
    let mut owned_env = env_factory.get_env(epoch);
    let contract_a = "(define-read-only (get-caller)
           (list contract-caller tx-sender))";
    let contract_b = "(define-read-only (get-caller)
           (list contract-caller tx-sender))
         (define-read-only (as-contract-get-caller)
           (as-contract (get-caller)))
         (define-read-only (cc-get-caller)
           (contract-call? .contract-a get-caller))
         (define-read-only (as-contract-cc-get-caller)
           (as-contract (contract-call? .contract-a get-caller)))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_state
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_state
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    {
        let c_b = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
        ));
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal().unwrap()),
            None,
            &placeholder_context,
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-a").unwrap(),
                    "get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![p1.clone(), p1.clone()]).unwrap()
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-b").unwrap(),
                    "as-contract-get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![c_b.clone(), c_b.clone()]).unwrap()
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-b").unwrap(),
                    "cc-get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![c_b.clone(), p1]).unwrap()
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-b").unwrap(),
                    "as-contract-cc-get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![c_b.clone(), c_b]).unwrap()
        );
    }
}

fn tx_sponsor_contract_asserts(
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    sponsor: Option<PrincipalData>,
) {
    let sponsor = match sponsor {
        None => Value::none(),
        Some(p) => Value::some(Value::Principal(p)).unwrap(),
    };
    assert_eq!(
        exec_state
            .execute_contract(
                invoke_ctx,
                &QualifiedContractIdentifier::local("contract-a").unwrap(),
                "get-sponsor",
                &[],
                false
            )
            .unwrap(),
        Value::cons_list_unsanitized(vec![sponsor.clone()]).unwrap()
    );
    assert_eq!(
        exec_state
            .execute_contract(
                invoke_ctx,
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "as-contract-get-sponsor",
                &[],
                false
            )
            .unwrap(),
        Value::cons_list_unsanitized(vec![sponsor.clone()]).unwrap()
    );
    assert_eq!(
        exec_state
            .execute_contract(
                invoke_ctx,
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "cc-get-sponsor",
                &[],
                false
            )
            .unwrap(),
        Value::cons_list_unsanitized(vec![sponsor.clone()]).unwrap()
    );
    assert_eq!(
        exec_state
            .execute_contract(
                invoke_ctx,
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "as-contract-cc-get-sponsor",
                &[],
                false
            )
            .unwrap(),
        Value::cons_list_unsanitized(vec![sponsor]).unwrap()
    );
}

#[apply(test_epochs)]
fn test_tx_sponsor(epoch: StacksEpochId, mut env_factory: MemoryEnvironmentGenerator) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-read-only (get-sponsor)
           (list tx-sponsor?))
           (asserts! (is-eq tx-sponsor? (some 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)) (err 1))";
    let contract_b = "(define-read-only (get-sponsor)
           (list tx-sponsor?))
         (define-read-only (as-contract-get-sponsor)
           (as-contract (get-sponsor)))
         (define-read-only (cc-get-sponsor)
           (contract-call? .contract-a get-sponsor))
         (define-read-only (as-contract-cc-get-sponsor)
           (as-contract (contract-call? .contract-a get-sponsor)))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
        .expect_principal()
        .unwrap();
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    let sponsor = if let Value::Principal(p) = p2 {
        Some(p)
    } else {
        panic!("p2 is not a principal value");
    };

    {
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(Some(p1.clone()), sponsor.clone(), &placeholder_context);
        exec_state
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_state
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    // Sponsor is equal to some(principal) in this code block.
    {
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(Some(p1.clone()), sponsor.clone(), &placeholder_context);
        tx_sponsor_contract_asserts(&mut exec_state, &invoke_ctx, sponsor);
    }

    // Sponsor is none in this code block.
    {
        let sponsor = None;
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(Some(p1), sponsor.clone(), &placeholder_context);
        tx_sponsor_contract_asserts(&mut exec_state, &invoke_ctx, sponsor);
    }
}

#[apply(test_epochs)]
fn test_fully_qualified_contract_call(
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-read-only (get-caller)
           (list contract-caller tx-sender))";
    let contract_b = "(define-read-only (get-caller)
           (list contract-caller tx-sender))
         (define-read-only (as-contract-get-caller)
           (as-contract (get-caller)))
         (define-read-only (cc-get-caller)
           (contract-call? 'S1G2081040G2081040G2081040G208105NK8PE5.contract-a get-caller))
         (define-read-only (as-contract-cc-get-caller)
           (as-contract (contract-call? .contract-a get-caller)))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_state
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_state
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    {
        let c_b = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
        ));
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal().unwrap()),
            None,
            &placeholder_context,
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-a").unwrap(),
                    "get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![p1.clone(), p1.clone()]).unwrap()
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-b").unwrap(),
                    "as-contract-get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![c_b.clone(), c_b.clone()]).unwrap()
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-b").unwrap(),
                    "cc-get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![c_b.clone(), p1]).unwrap()
        );
        assert_eq!(
            exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("contract-b").unwrap(),
                    "as-contract-cc-get-caller",
                    &[],
                    false
                )
                .unwrap(),
            Value::cons_list_unsanitized(vec![c_b.clone(), c_b]).unwrap()
        );
    }
}

#[apply(test_epochs)]
fn test_simple_naming_system(epoch: StacksEpochId, mut env_factory: MemoryEnvironmentGenerator) {
    let mut owned_env = env_factory.get_env(epoch);

    let tokens_contract = SIMPLE_TOKENS;

    let names_contract = "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-private (price-function (name int))
           (if (< name 100000) u1000 u100))

         (define-map name-map
           { name: int } { owner: principal })
         (define-map preorder-map
           { name-hash: (buff 20) }
           { buyer: principal, paid: uint })

         (define-public (preorder
                        (name-hash (buff 20))
                        (name-price uint))
           (let ((xfer-result (contract-call? .tokens token-transfer
                                  burn-address name-price)))
            (if (is-ok xfer-result)
               (if
                 (map-insert preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (if (is-eq (unwrap-err! xfer-result (err (- 1)))
                        \"not enough balance\")
                   (err 1) (err 3)))))

         (define-public (register
                        (recipient-principal principal)
                        (name int)
                        (salt int))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (unwrap! (map-get? preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 5)))
                 (name-entry
                   (map-get? name-map (tuple (name name)))))
             (if (and
                  (is-none name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name)
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (is-eq tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (map-insert name-map
                      (tuple (name name))
                      (tuple (owner recipient-principal)))
                    (map-delete preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");

    let name_hash_expensive_0 = execute("(hash160 1)");
    let name_hash_expensive_1 = execute("(hash160 2)");
    let name_hash_cheap_0 = execute("(hash160 100001)");
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    {
        let (mut exec_state, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);

        let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();
        exec_state
            .initialize_contract(&invoke_ctx, contract_identifier, tokens_contract)
            .unwrap();

        let contract_identifier = QualifiedContractIdentifier::local("names").unwrap();
        exec_state
            .initialize_contract(&invoke_ctx, contract_identifier, names_contract)
            .unwrap();
    }

    {
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p2.clone().expect_principal().unwrap()),
            None,
            &placeholder_context,
        );

        assert!(is_err_code(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "preorder",
                    &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::UInt(1000)]),
                    false
                )
                .unwrap(),
            1
        ));
    }

    {
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p1.clone().expect_principal().unwrap()),
            None,
            &placeholder_context,
        );
        assert!(is_committed(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "preorder",
                    &symbols_from_values(vec![name_hash_expensive_0.clone(), Value::UInt(1000)]),
                    false
                )
                .unwrap()
        ));
        assert!(is_err_code(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "preorder",
                    &symbols_from_values(vec![name_hash_expensive_0, Value::UInt(1000)]),
                    false
                )
                .unwrap(),
            2
        ));
    }

    {
        // shouldn't be able to register a name you didn't preorder!
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p2.clone().expect_principal().unwrap()),
            None,
            &placeholder_context,
        );
        assert!(is_err_code(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "register",
                    &symbols_from_values(vec![p2.clone(), Value::Int(1), Value::Int(0)]),
                    false
                )
                .unwrap(),
            4
        ));
    }

    {
        // should work!
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p1.expect_principal().unwrap()),
            None,
            &placeholder_context,
        );
        assert!(is_committed(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "register",
                    &symbols_from_values(vec![p2.clone(), Value::Int(1), Value::Int(0)]),
                    false
                )
                .unwrap()
        ));
    }

    {
        // try to underpay!
        let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
            Some(p2.clone().expect_principal().unwrap()),
            None,
            &placeholder_context,
        );
        assert!(is_committed(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "preorder",
                    &symbols_from_values(vec![name_hash_expensive_1, Value::UInt(100)]),
                    false
                )
                .unwrap()
        ));
        assert!(is_err_code(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "register",
                    &symbols_from_values(vec![p2.clone(), Value::Int(2), Value::Int(0)]),
                    false
                )
                .unwrap(),
            4
        ));

        // register a cheap name!
        assert!(is_committed(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "preorder",
                    &symbols_from_values(vec![name_hash_cheap_0, Value::UInt(100)]),
                    false
                )
                .unwrap()
        ));
        assert!(is_committed(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "register",
                    &symbols_from_values(vec![p2.clone(), Value::Int(100001), Value::Int(0)]),
                    false
                )
                .unwrap()
        ));

        // preorder must exist!
        assert!(is_err_code(
            &exec_state
                .execute_contract(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("names").unwrap(),
                    "register",
                    &symbols_from_values(vec![p2, Value::Int(100001), Value::Int(0)]),
                    false
                )
                .unwrap(),
            5
        ));
    }
}

#[apply(test_epochs)]
fn test_simple_contract_call(epoch: StacksEpochId, mut env_factory: MemoryEnvironmentGenerator) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_1 = FACTORIAL_CONTRACT;
    let contract_2 = "(define-public (proxy-compute)
            (contract-call? .factorial-contract compute 8008))
        ";

    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
        Some(get_principal().expect_principal().unwrap()),
        None,
        &placeholder_context,
    );

    let contract_identifier = QualifiedContractIdentifier::local("factorial-contract").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, contract_1)
        .unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("proxy-compute").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, contract_2)
        .unwrap();

    let args = symbols_from_values(vec![]);

    let expected = [
        Value::Int(5),
        Value::Int(20),
        Value::Int(60),
        Value::Int(120),
        Value::Int(120),
        Value::Int(120),
    ];
    for expected_result in &expected {
        exec_state
            .execute_contract(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("proxy-compute").unwrap(),
                "proxy-compute",
                &args,
                false,
            )
            .unwrap();
        assert_eq!(
            exec_state
                .eval_read_only(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("factorial-contract").unwrap(),
                    "(get current (unwrap! (map-get? factorials {id: 8008}) false))"
                )
                .unwrap(),
            *expected_result
        );
    }
}

#[apply(test_epochs)]
fn test_aborts(epoch: StacksEpochId, mut env_factory: MemoryEnvironmentGenerator) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_1 = "
(define-map data { id: int } { value: int })

;; this will return false if id != value,
;;   which _aborts_ any data that is modified during
;;   the routine.
(define-public (modify-data
                 (id int)
                 (value int))
   (begin
     (map-set data (tuple (id id))
                      (tuple (value value)))
     (if (is-eq id value)
         (ok 1)
         (err 1))))


(define-private (get-data (id int))
  (default-to 0
    (get value
     (map-get? data (tuple (id id))))))
";

    let contract_2 = "
(define-public (fail-in-other)
  (begin
    (contract-call? .contract-1 modify-data 100 101)
    (ok 1)))

(define-public (fail-in-self)
  (begin
    (contract-call? .contract-1 modify-data 105 105)
    (err 1)))
";
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    let (mut exec_state, mut invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    let contract_identifier = QualifiedContractIdentifier::local("contract-1").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, contract_1)
        .unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("contract-2").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, contract_2)
        .unwrap();

    invoke_ctx.sender = Some(get_principal_as_principal_data());

    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-1").unwrap(),
                "modify-data",
                &symbols_from_values(vec![Value::Int(10), Value::Int(10)]),
                false
            )
            .unwrap(),
        Value::Response(ResponseData {
            committed: true,
            data: Box::new(Value::Int(1))
        })
    );

    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-1").unwrap(),
                "modify-data",
                &symbols_from_values(vec![Value::Int(20), Value::Int(10)]),
                false
            )
            .unwrap(),
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::Int(1))
        })
    );

    assert_eq!(
        exec_state
            .eval_read_only(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-1").unwrap(),
                "(get-data 20)"
            )
            .unwrap(),
        Value::Int(0)
    );

    assert_eq!(
        exec_state
            .eval_read_only(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-1").unwrap(),
                "(get-data 10)"
            )
            .unwrap(),
        Value::Int(10)
    );

    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-2").unwrap(),
                "fail-in-other",
                &symbols_from_values(vec![]),
                false
            )
            .unwrap(),
        Value::Response(ResponseData {
            committed: true,
            data: Box::new(Value::Int(1))
        })
    );

    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-2").unwrap(),
                "fail-in-self",
                &symbols_from_values(vec![]),
                false
            )
            .unwrap(),
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::Int(1))
        })
    );

    assert_eq!(
        exec_state
            .eval_read_only(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-1").unwrap(),
                "(get-data 105)"
            )
            .unwrap(),
        Value::Int(0)
    );

    assert_eq!(
        exec_state
            .eval_read_only(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("contract-1").unwrap(),
                "(get-data 100)"
            )
            .unwrap(),
        Value::Int(0)
    );
}

#[apply(test_epochs)]
fn test_factorial_contract(epoch: StacksEpochId, mut env_factory: MemoryEnvironmentGenerator) {
    let mut owned_env = env_factory.get_env(epoch);

    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    let (mut exec_state, mut invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    let contract_identifier = QualifiedContractIdentifier::local("factorial").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, FACTORIAL_CONTRACT)
        .unwrap();

    let tx_name = "compute";
    let arguments_to_test = [
        symbols_from_values(vec![Value::Int(1337)]),
        symbols_from_values(vec![Value::Int(1337)]),
        symbols_from_values(vec![Value::Int(1337)]),
        symbols_from_values(vec![Value::Int(1337)]),
        symbols_from_values(vec![Value::Int(1337)]),
        symbols_from_values(vec![Value::Int(8008)]),
        symbols_from_values(vec![Value::Int(8008)]),
        symbols_from_values(vec![Value::Int(8008)]),
        symbols_from_values(vec![Value::Int(8008)]),
        symbols_from_values(vec![Value::Int(8008)]),
        symbols_from_values(vec![Value::Int(8008)]),
    ];

    let expected = vec![
        Value::Int(3),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(6),
        Value::Int(5),
        Value::Int(20),
        Value::Int(60),
        Value::Int(120),
        Value::Int(120),
        Value::Int(120),
    ];

    invoke_ctx.sender = Some(get_principal_as_principal_data());

    for (arguments, expectation) in arguments_to_test.iter().zip(expected.iter()) {
        exec_state
            .execute_contract(
                &invoke_ctx,
                &QualifiedContractIdentifier::local("factorial").unwrap(),
                tx_name,
                arguments,
                false,
            )
            .unwrap();

        assert_eq!(
            *expectation,
            exec_state
                .eval_read_only(
                    &invoke_ctx,
                    &QualifiedContractIdentifier::local("factorial").unwrap(),
                    &format!(
                        "(unwrap! (get current (map-get? factorials (tuple (id {})))) false)",
                        arguments[0]
                    )
                )
                .unwrap()
        );
    }

    let err_result = exec_state
        .execute_contract(
            &invoke_ctx,
            &QualifiedContractIdentifier::local("factorial").unwrap(),
            "init-factorial",
            &symbols_from_values(vec![Value::Int(9000), Value::Int(15)]),
            false,
        )
        .unwrap_err();
    assert!(matches!(
        err_result,
        VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::NoSuchPublicFunction(_, _))
    ));

    let err_result = exec_state
        .execute_contract(
            &invoke_ctx,
            &QualifiedContractIdentifier::local("factorial").unwrap(),
            "compute",
            &symbols_from_values(vec![Value::Bool(true)]),
            false,
        )
        .unwrap_err();
    assert!(matches!(
        err_result,
        VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::TypeValueError(_, _))
    ));
}

#[apply(test_epochs)]
fn test_at_unknown_block(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract = "(define-data-var foo int 3)
                        (at-block 0x0202020202020202020202020202020202020202020202020202020202020202
                          (+ 1 2))";
    let err = owned_env
        .initialize_contract(
            QualifiedContractIdentifier::local("contract").unwrap(),
            contract,
            None,
        )
        .unwrap_err();
    eprintln!("{err}");
    if epoch.supports_at_block() {
        match err {
            ClarityEvalError::Vm(VmExecutionError::Runtime(x, _)) => assert_eq!(
                x,
                RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash::from(
                    vec![2_u8; 32].as_slice()
                ))
            ),
            e => panic!("Unexpected error: {e}"),
        }
    } else {
        match err {
            ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(x)) => {
                assert_eq!(x, RuntimeCheckErrorKind::AtBlockUnavailable)
            }
            e => panic!("Unexpected error: {e}"),
        }
    }
}

#[apply(test_epochs)]
fn test_as_max_len(epoch: StacksEpochId, mut tl_env_factory: TopLevelMemoryEnvironmentGenerator) {
    let mut owned_env = tl_env_factory.get_env(epoch);
    let contract = "(define-data-var token-ids (list 10 uint) (list))
                        (var-set token-ids
                           (unwrap! (as-max-len? (append (var-get token-ids) u1) u10) (err 10)))";

    owned_env
        .initialize_contract(
            QualifiedContractIdentifier::local("contract").unwrap(),
            contract,
            None,
        )
        .unwrap();
}

#[test]
fn test_ast_stack_depth() {
    let program = "(+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       1 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)

                      ";
    assert_eq!(
        vm_execute(program).unwrap_err(),
        ClarityEvalError::Parse(
            ParseErrorKind::VaryExpressionStackDepthTooDeep {
                max_depth: max_call_stack_depth_for_epoch(StacksEpochId::Epoch20)
            }
            .into()
        )
    );
}

#[test]
fn test_arg_stack_depth() {
    let program = "(define-private (foo)
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       bar 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1))
                       (define-private (bar)
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       1 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1))
                       (foo)
                      ";
    assert_eq!(
        vm_execute(program).unwrap_err(),
        RuntimeError::MaxStackDepthReached.into()
    );
}

fn build_nested_plus(expr: &str, depth: usize) -> String {
    let mut nested = expr.to_string();
    for _ in 0..depth {
        nested = format!("(+ {nested} 1)");
    }
    nested
}

#[apply(test_clarity_versions)]
fn test_cc_stack_depth(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    // The `unwrap-panic` adds 1 stack frame, the `contract-call?` adds 2, and the `ok` adds one
    // more for a total of 4, so we use all but 3 to test just over the limit.
    let nested_plus = build_nested_plus("1", (max_call_stack_depth_for_epoch(epoch) - 3) as usize);
    let contract_one = format!(
        "(define-public (foo)
            (ok {nested_plus}))"
    );

    let contract_two = "(unwrap-panic (contract-call? .c-foo foo))";
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    let contract_identifier = QualifiedContractIdentifier::local("c-foo").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, &contract_one)
        .unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("c-bar").unwrap();
    assert_eq!(
        exec_state
            .initialize_contract(&invoke_ctx, contract_identifier, contract_two)
            .unwrap_err(),
        RuntimeError::MaxStackDepthReached.into()
    );
}

#[apply(test_clarity_versions)]
fn test_cc_trait_stack_depth(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    // The call to bar adds 1 stack frame, `unwrap-panic` adds another, the `contract-call?`
    // adds 2, and the `ok` adds one more for a total of 5, so we use all but 4 to test just over
    // the limit.
    let nested_plus = build_nested_plus("1", (max_call_stack_depth_for_epoch(epoch) - 4) as usize);
    let contract_one = format!(
        "(define-trait trait-1 (
        (foo () (response int int))))
        (define-public (foo)
            (ok {nested_plus}))"
    );

    let contract_two = "(use-trait trait-1 .c-foo.trait-1)
        (define-private (bar (F <trait-1>))
            (unwrap-panic (contract-call? F foo)))
        (bar .c-foo)
        ";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    let contract_identifier = QualifiedContractIdentifier::local("c-foo").unwrap();
    exec_state
        .initialize_contract(&invoke_ctx, contract_identifier, &contract_one)
        .unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("c-bar").unwrap();
    assert_eq!(
        exec_state
            .initialize_contract(&invoke_ctx, contract_identifier, contract_two)
            .unwrap_err(),
        RuntimeError::MaxStackDepthReached.into()
    );
}

#[apply(test_epochs)]
fn test_eval_with_non_existing_contract(
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    );

    let (mut exec_state, invoke_ctx) = owned_env.get_exec_environment(
        Some(get_principal().expect_principal().unwrap()),
        None,
        &placeholder_context,
    );

    let result = exec_state.eval_read_only(
        &invoke_ctx,
        &QualifiedContractIdentifier::local("absent").unwrap(),
        "(ok 0)",
    );
    assert_eq!(
        result.as_ref().unwrap_err(),
        &VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::NoSuchContract(
            QualifiedContractIdentifier::local("absent")
                .unwrap()
                .to_string()
        ))
        .into()
    );
    owned_env.commit().unwrap();
    assert!(owned_env.destruct().is_some());
}

#[apply(test_clarity_versions)]
fn test_contract_hash_success(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    // contract-hash? is not available before Clarity 4
    if version < ClarityVersion::Clarity4 {
        return;
    }

    let mut owned_env = env_factory.get_env(epoch);
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // Deploy a contract to hash
    let other_contract = QualifiedContractIdentifier::local("other-contract").unwrap();
    let contract_content = "(define-constant test-var 1)";
    let expected_hash = Sha512Trunc256Sum::from_data(contract_content.as_bytes());

    exec_state
        .initialize_contract(&invoke_ctx, other_contract.clone(), contract_content)
        .unwrap();

    // Test successful contract hash retrieval
    let test_contract = QualifiedContractIdentifier::local("test-contract").unwrap();
    let test_program =
        "(define-read-only (get-hash (contract principal)) (contract-hash? contract))";

    exec_state
        .initialize_contract(&invoke_ctx, test_contract.clone(), test_program)
        .unwrap();

    // Attempt to get the hash of the other contract and expect it to be
    // successful and for the returned hash to match the expected hash.
    let standard_principal = QualifiedContractIdentifier::local("standard-principal").unwrap();
    let result = exec_state
        .execute_contract(
            &invoke_ctx,
            &test_contract,
            "get-hash",
            &symbols_from_values(vec![Value::Principal(PrincipalData::Contract(
                other_contract.clone(),
            ))]),
            true,
        )
        .unwrap();

    let hash = result
        .expect_result_ok()
        .expect("expected ok")
        .expect_buff(32)
        .expect("expected 32-byte hash");
    assert_eq!(&hash, expected_hash.as_bytes(), "hash mismatch");
}

#[apply(test_clarity_versions)]
fn test_contract_hash_nonexistent_contract(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    // contract-hash? is not available before Clarity 4
    if version < ClarityVersion::Clarity4 {
        return;
    }

    let mut owned_env = env_factory.get_env(epoch);
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // Deploy a contract to hash
    let other_contract = QualifiedContractIdentifier::local("other-contract").unwrap();
    let contract_content = "(define-constant test-var 1)";
    let expected_hash = Sha512Trunc256Sum::from_data(contract_content.as_bytes());

    exec_state
        .initialize_contract(&invoke_ctx, other_contract.clone(), contract_content)
        .unwrap();

    // Test successful contract hash retrieval
    let test_contract = QualifiedContractIdentifier::local("test-contract").unwrap();
    let test_program =
        "(define-read-only (get-hash (contract principal)) (contract-hash? contract))";

    exec_state
        .initialize_contract(&invoke_ctx, test_contract.clone(), test_program)
        .unwrap();

    // Attempt to get the hash of a non-existent contract, expecting an `(err u2)`
    let non_existent_contract = QualifiedContractIdentifier::local("nonexistent-contract").unwrap();
    let result = exec_state
        .execute_contract(
            &invoke_ctx,
            &test_contract,
            "get-hash",
            &symbols_from_values(vec![Value::Principal(PrincipalData::Contract(
                non_existent_contract.clone(),
            ))]),
            true,
        )
        .unwrap();

    assert_eq!(result, Value::err_uint(2));
}

#[apply(test_clarity_versions)]
fn test_contract_hash_standard_principal(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    // contract-hash? is not available before Clarity 4
    if version < ClarityVersion::Clarity4 {
        return;
    }

    let mut owned_env = env_factory.get_env(epoch);
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // Deploy a contract to hash
    let other_contract = QualifiedContractIdentifier::local("other-contract").unwrap();
    let contract_content = "(define-constant test-var 1)";
    let expected_hash = Sha512Trunc256Sum::from_data(contract_content.as_bytes());

    exec_state
        .initialize_contract(&invoke_ctx, other_contract.clone(), contract_content)
        .unwrap();

    // Test successful contract hash retrieval
    let test_contract = QualifiedContractIdentifier::local("test-contract").unwrap();
    let test_program =
        "(define-read-only (get-hash (contract principal)) (contract-hash? contract))";

    exec_state
        .initialize_contract(&invoke_ctx, test_contract.clone(), test_program)
        .unwrap();

    // Attempt to get the hash of a standard principal, expecting an `(err u1)`
    let result = exec_state
        .execute_contract(
            &invoke_ctx,
            &test_contract,
            "get-hash",
            &symbols_from_values(vec![Value::Principal(PrincipalData::Standard(
                StandardPrincipalData::transient(),
            ))]),
            true,
        )
        .unwrap();

    assert_eq!(result, Value::err_uint(1));
}

#[apply(test_clarity_versions)]
fn test_contract_hash_type_check(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    // contract-hash? is not available before Clarity 4
    if version < ClarityVersion::Clarity4 {
        return;
    }

    let mut owned_env = env_factory.get_env(epoch);
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // Deploy a contract with a type-check error in the `contract-hash?` expression
    // Note that this would usually fail in analysis, but we've skipped it here.
    let test_contract = QualifiedContractIdentifier::local("test-contract").unwrap();
    let test_program = "(define-read-only (get-hash) (contract-hash? u123))";

    exec_state
        .initialize_contract(&invoke_ctx, test_contract.clone(), test_program)
        .unwrap();

    // Attempt to execute the contract, expecting a type-check error
    let err = exec_state
        .execute_contract(&invoke_ctx, &test_contract, "get-hash", &[], true)
        .unwrap_err();
    assert_eq!(
        err,
        VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::ExpectedContractPrincipalValue(
            Value::UInt(123).to_error_string()
        ))
    );
}

#[apply(test_clarity_versions)]
fn test_contract_hash_pre_clarity4(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    // contract-hash? is available in Clarity 4
    if version >= ClarityVersion::Clarity4 {
        return;
    }

    let mut owned_env = env_factory.get_env(epoch);
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // Deploy a contract to hash
    let other_contract = QualifiedContractIdentifier::local("other-contract").unwrap();
    let contract_content = "(define-constant test-var 1)";
    let expected_hash = Sha512Trunc256Sum::from_data(contract_content.as_bytes());

    exec_state
        .initialize_contract(&invoke_ctx, other_contract.clone(), contract_content)
        .unwrap();

    // Test successful contract hash retrieval
    let test_contract = QualifiedContractIdentifier::local("test-contract").unwrap();
    let test_program =
        "(define-read-only (get-hash (contract principal)) (contract-hash? contract))";

    exec_state
        .initialize_contract(&invoke_ctx, test_contract.clone(), test_program)
        .unwrap();

    // Attempt to get the hash of the other contract and expect it to be
    // successful and for the returned hash to match the expected hash.
    let standard_principal = QualifiedContractIdentifier::local("standard-principal").unwrap();
    let err = exec_state
        .execute_contract(
            &invoke_ctx,
            &test_contract,
            "get-hash",
            &symbols_from_values(vec![Value::Principal(PrincipalData::Contract(
                other_contract.clone(),
            ))]),
            true,
        )
        .unwrap_err();

    assert_eq!(
        err,
        VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::UndefinedFunction(
            "contract-hash?".to_string()
        ))
    );
}

#[apply(test_clarity_versions)]
fn test_contract_call_with_constant(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-public (foo) (ok true))";
    let contract_b = "(define-constant MY_CONTRACT .contract-a)
        (define-public (call-foo)
            (contract-call? MY_CONTRACT foo)
        )
        ";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let (mut exec_env, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    let (mut exec_env, invoke_ctx) = owned_env.get_exec_environment(
        Some(p1.clone().expect_principal().unwrap()),
        None,
        &placeholder_context,
    );
    let call_result = exec_env.execute_contract(
        &invoke_ctx,
        &QualifiedContractIdentifier::local("contract-b").unwrap(),
        "call-foo",
        &[],
        false,
    );

    if epoch.supports_call_with_constant() && version.supports_callables() {
        assert_eq!(call_result.unwrap(), Value::okay_true());
    } else {
        assert_eq!(
            call_result.unwrap_err(),
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::ContractCallExpectName)
        );
    }
}

/// Calling from a deploying contract into a contract via define-constant
///  should not be allowed in any epochs
#[apply(test_clarity_versions)]
fn test_contract_call_with_constant_at_deploy(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-public (foo) (ok true))";
    let contract_b = "(define-constant MY_CONTRACT .contract-a)
        (define-public (call-foo)
            (contract-call? MY_CONTRACT foo)
        )
        (call-foo)
        ";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let (mut exec_env, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);
    exec_env
        .initialize_contract(
            &invoke_ctx,
            QualifiedContractIdentifier::local("contract-a").unwrap(),
            contract_a,
        )
        .unwrap();
    let call_result = exec_env.initialize_contract(
        &invoke_ctx,
        QualifiedContractIdentifier::local("contract-b").unwrap(),
        contract_b,
    );

    assert_eq!(
        call_result.unwrap_err(),
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::ContractCallExpectName
        )),
    );
}

/// Calling from a deploying contract into a contract which uses contract-calls via define-constant
///  should be allowed in appropriate epochs
#[apply(test_clarity_versions)]
fn test_nested_cc_with_constant_at_deploy(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-public (foo) (ok true))";
    let contract_b = "(define-constant MY_CONTRACT .contract-a)
        (define-public (call-foo)
            (contract-call? MY_CONTRACT foo)
        )
        ";
    let contract_c = "
        (define-public (call-call-foo)
            (contract-call? .contract-b call-foo))
        (call-call-foo)
        ";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    let (mut exec_env, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);
    exec_env
        .initialize_contract(
            &invoke_ctx,
            QualifiedContractIdentifier::local("contract-a").unwrap(),
            contract_a,
        )
        .unwrap();
    exec_env
        .initialize_contract(
            &invoke_ctx,
            QualifiedContractIdentifier::local("contract-b").unwrap(),
            contract_b,
        )
        .unwrap();
    let call_result = exec_env.initialize_contract(
        &invoke_ctx,
        QualifiedContractIdentifier::local("contract-c").unwrap(),
        contract_c,
    );

    if epoch.supports_call_with_constant() && version.supports_callables() {
        call_result.unwrap();
    } else {
        assert_eq!(
            call_result.unwrap_err(),
            ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
                RuntimeCheckErrorKind::ContractCallExpectName
            )),
        );
    }
}

#[apply(test_clarity_versions)]
fn test_constant_to_trait(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-public (foo) (ok true))";
    let contract_b = "(define-constant MY_CONTRACT .contract-a)
        (define-trait my-trait (
            (foo () (response bool bool))
        ))
        (define-private (inner-call-foo (contract <my-trait>))
            (contract-call? contract foo))
        (define-public (call-foo)
            (inner-call-foo MY_CONTRACT))
        ";

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let (mut exec_env, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    let (mut exec_env, invoke_ctx) = owned_env.get_exec_environment(
        Some(p1.clone().expect_principal().unwrap()),
        None,
        &placeholder_context,
    );
    let call_result = exec_env.execute_contract(
        &invoke_ctx,
        &QualifiedContractIdentifier::local("contract-b").unwrap(),
        "call-foo",
        &[],
        false,
    );

    assert_eq!(call_result.unwrap(), Value::okay_true());
}

/// Contract principal constants must work with principal-inspecting functions
/// (`is-standard`, `principal-destruct?`, `to-ascii?`). These functions
/// pattern-match on `Value::Principal` and previously failed when constants were
/// rewritten to `Value::CallableContract`.
///
/// Skips Clarity1 because `is-standard` and `principal-destruct?` are not
/// available. Runs in all epochs for Clarity2+ because `define-constant`
/// with a contract principal literal always stores a `Value::Principal`.
#[apply(test_clarity_versions)]
fn test_constant_contract_principal_in_principal_functions(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    if version < ClarityVersion::Clarity2 {
        // Clarity1 does not have is-standard or principal-destruct?
        return;
    }

    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "(define-public (ping) (ok true))";
    let has_to_ascii = version >= ClarityVersion::Clarity4;
    let contract_b = if has_to_ascii {
        "
        (define-constant TARGET .contract-a)
        (define-read-only (check-standard)
            (is-standard TARGET))
        (define-read-only (check-destruct)
            (principal-destruct? TARGET))
        (define-read-only (check-to-ascii)
            (to-ascii? TARGET))
        "
    } else {
        "
        (define-constant TARGET .contract-a)
        (define-read-only (check-standard)
            (is-standard TARGET))
        (define-read-only (check-destruct)
            (principal-destruct? TARGET))
        "
    };

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let (mut exec_env, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let (mut exec_env, invoke_ctx) = owned_env.get_exec_environment(
        Some(p1.expect_principal().unwrap()),
        None,
        &placeholder_context,
    );

    let contract_b_id = QualifiedContractIdentifier::local("contract-b").unwrap();

    // is-standard returns false because the local test principal uses a
    // non-standard version byte (0x01).
    let result = exec_env
        .execute_contract(&invoke_ctx, &contract_b_id, "check-standard", &[], false)
        .unwrap();
    assert_eq!(result, Value::Bool(false));

    // principal-destruct? returns (err ...) because version byte 0x01 is not
    // a recognized network version. The tuple still contains the decomposed
    // principal fields.
    let result = exec_env
        .execute_contract(&invoke_ctx, &contract_b_id, "check-destruct", &[], false)
        .unwrap();
    assert_eq!(
        result,
        execute(
            "(err { version: 0x01, hash-bytes: 0x0101010101010101010101010101010101010101, name: (some \"contract-a\") })"
        )
    );

    // to-ascii? returns (ok <string>) with the full principal representation.
    if has_to_ascii {
        let result = exec_env
            .execute_contract(&invoke_ctx, &contract_b_id, "check-to-ascii", &[], false)
            .unwrap();
        assert_eq!(
            result,
            execute("(ok \"S1G2081040G2081040G2081040G208105NK8PE5.contract-a\")")
        );
    }
}

/// A constant contract principal can be used as BOTH a contract-call? target
/// AND a principal argument to native functions within the same contract.
///
/// In unsupported epochs, `contract-call?` via a constant fails with
/// `ContractCallExpectName`, but the principal-accepting functions
/// (`stx-get-balance`, `is-standard`) still work because the constant
/// evaluates to `Value::Principal`.
///
/// Skips Clarity1 because `is-standard` is not available.
#[apply(test_clarity_versions)]
fn test_constant_contract_principal_dual_use(
    version: ClarityVersion,
    epoch: StacksEpochId,
    mut env_factory: MemoryEnvironmentGenerator,
) {
    if version < ClarityVersion::Clarity2 {
        // Clarity1 does not have is-standard
        return;
    }
    let mut owned_env = env_factory.get_env(epoch);

    let contract_a = "
        (define-public (foo) (ok true))
    ";
    let contract_b = "
        (define-constant TARGET .contract-a)
        (define-public (call-it)
            (contract-call? TARGET foo))
        (define-read-only (get-bal)
            (stx-get-balance TARGET))
        (define-read-only (check-standard)
            (is-standard TARGET))
    ";

    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    {
        let (mut exec_env, invoke_ctx) =
            owned_env.get_exec_environment(None, None, &placeholder_context);
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-a").unwrap(),
                contract_a,
            )
            .unwrap();
        exec_env
            .initialize_contract(
                &invoke_ctx,
                QualifiedContractIdentifier::local("contract-b").unwrap(),
                contract_b,
            )
            .unwrap();
    }

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR");
    let (mut exec_env, invoke_ctx) = owned_env.get_exec_environment(
        Some(p1.expect_principal().unwrap()),
        None,
        &placeholder_context,
    );
    let contract_b_id = QualifiedContractIdentifier::local("contract-b").unwrap();

    // contract-call? via constant requires epoch + version support
    let call_result = exec_env.execute_contract(&invoke_ctx, &contract_b_id, "call-it", &[], false);
    if epoch.supports_call_with_constant() && version.supports_callables() {
        assert_eq!(call_result.unwrap(), Value::okay_true());
    } else {
        assert_eq!(
            call_result.unwrap_err(),
            VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::ContractCallExpectName)
        );
    }

    // stx-get-balance and is-standard work in all epochs because the
    // constant is always `Value::Principal`.
    let result = exec_env
        .execute_contract(&invoke_ctx, &contract_b_id, "get-bal", &[], false)
        .unwrap();
    assert_eq!(result, Value::UInt(0));

    // is-standard returns false because the local test principal uses a
    // non-standard version byte (0x01).
    let result = exec_env
        .execute_contract(&invoke_ctx, &contract_b_id, "check-standard", &[], false)
        .unwrap();
    assert_eq!(result, Value::Bool(false));
}

/// Deploys `contracts` (name, version, source) into a fresh Epoch 4.1
/// environment and opens the transaction `execute_contract` needs.
#[cfg(test)]
fn make_epoch41_env<'a>(
    tl_env_factory: &'a mut TopLevelMemoryEnvironmentGenerator,
    contracts: &[(&str, ClarityVersion, &str)],
) -> OwnedEnvironment<'a, 'a> {
    let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
    for &(name, version, source) in contracts {
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local(name).unwrap(),
                version,
                source,
                None,
            )
            .unwrap();
    }
    owned_env.begin();
    owned_env
}

// Clarity 7 reserved-name defines: the rule these tests pin is documented on
// `is_shadowable_reserved`.

/// A transient Clarity 7 contract context for `get_exec_environment`.
#[cfg(test)]
fn make_c7_placeholder() -> ContractContext {
    ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity7,
    )
}

/// Pins `is_shadowable_reserved` to an explicit list, so adding or removing a
/// native forces a conscious update here.
#[test]
fn shadowable_reserved_names_at_clarity7() {
    use crate::vm::functions::NativeFunctions;
    use crate::vm::is_shadowable_reserved;
    use crate::vm::variables::NativeVariables;

    let mut shadowable: Vec<&str> = NativeFunctions::ALL_NAMES
        .iter()
        .chain(NativeVariables::ALL_NAMES.iter())
        .copied()
        .filter(|name| is_shadowable_reserved(name, &ClarityVersion::Clarity7))
        .collect();
    shadowable.sort_unstable();

    let expected = [
        "as-contract?",
        "bit-and",
        "bit-not",
        "bit-or",
        "bit-shift-left",
        "bit-shift-right",
        "bit-xor",
        "buff-to-int-be",
        "buff-to-int-le",
        "buff-to-uint-be",
        "buff-to-uint-le",
        "chain-id",
        "contract-hash?",
        "current-contract",
        "ed25519-verify",
        "element-at?",
        "from-consensus-buff?",
        "get-bitcoin-tx-output?",
        "get-burn-block-info?",
        "get-stacks-block-info?",
        "get-tenure-info?",
        "index-of?",
        "int-to-ascii",
        "int-to-utf8",
        "is-in-mainnet",
        "is-standard",
        "principal-construct?",
        "principal-destruct?",
        "replace-at?",
        "restrict-assets?",
        "secp256k1-decompress?",
        "secp256r1-verify",
        "slice?",
        "stacks-block-height",
        "stacks-block-time",
        "string-to-int?",
        "string-to-uint?",
        "stx-account",
        "stx-transfer-memo?",
        "tenure-height",
        "to-ascii?",
        "to-consensus-buff?",
        "tx-sponsor?",
        "verify-merkle-proof",
        "with-all-assets-unsafe",
        "with-ft",
        "with-nft",
        "with-pox",
        "with-staking",
        "with-stx",
    ];
    assert_eq!(expected.as_slice(), shadowable.as_slice());

    // Reserved since Clarity 1: never shadowable.
    for name in ["map", "+", "tx-sender", "let", "true"] {
        assert!(!is_shadowable_reserved(name, &ClarityVersion::Clarity7));
    }
    // Removed natives are plain free names, not shadowable.
    for name in [
        "block-height",
        "get-block-info?",
        "as-contract",
        "at-block",
        "with-stacking",
    ] {
        assert!(!is_shadowable_reserved(name, &ClarityVersion::Clarity7));
    }
}

/// The implementing function is reachable from outside by its literal name,
/// while a bare reference inside the contract still resolves to the native.
#[test]
fn clarity7_external_call_reaches_shadowed_function_and_native_is_kept() {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = make_epoch41_env(
        &mut tl_env_factory,
        &[
            // A Clarity 1 trait whose method name later became a native.
            (
                "ops-def",
                ClarityVersion::Clarity1,
                "(define-trait ops ((slice? (int int) (response int int))))",
            ),
            // Implements `slice?` and also uses the native `slice?`.
            (
                "c7-shadow",
                ClarityVersion::Clarity7,
                "(impl-trait .ops-def.ops)
                 (define-public (slice? (a int) (b int)) (ok (+ a b)))
                 (define-read-only (use-native) (slice? (list 10 20 30) u0 u2))",
            ),
        ],
    );
    let contract_id = QualifiedContractIdentifier::local("c7-shadow").unwrap();
    let placeholder_context = make_c7_placeholder();
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // An external call by literal name reaches the user-defined `slice?`.
    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &contract_id,
                "slice?",
                &symbols_from_values(vec![Value::Int(4), Value::Int(5)]),
                false
            )
            .unwrap(),
        Value::okay(Value::Int(9)).unwrap()
    );

    // A bare `slice?` inside the contract still means the NATIVE.
    assert_eq!(
        Ok(Value::some(Value::list_from(vec![Value::Int(10), Value::Int(20)]).unwrap()).unwrap()),
        exec_state.eval_read_only(&invoke_ctx, &contract_id, "(use-native)")
    );
}

#[rstest]
// No `impl-trait`: illegal, as in every earlier version.
#[case(None, "(define-public (slice? (a int) (b int)) (ok (+ a b)))")]
// The implemented trait lacks the name.
#[case(
    Some(("other-def", "(define-trait other ((foo (int) (response int int))))", ClarityVersion::Clarity1)),
    "(impl-trait .other-def.other)
     (define-public (foo (x int)) (ok x))
     (define-public (slice? (a int) (b int)) (ok (+ a b)))"
)]
// The trait's own version already reserved the name; only traits that predate
// the reservation unlock it (pre-7 traits could declare any name).
#[case(
    Some(("bad-def", "(define-trait bad ((slice? (int int) (response int int))))", ClarityVersion::Clarity5)),
    "(impl-trait .bad-def.bad)
     (define-public (slice? (a int) (b int)) (ok (+ a b)))"
)]
fn clarity7_shadowable_define_requires_legacy_trait_method(
    #[case] trait_setup: Option<(&str, &str, ClarityVersion)>,
    #[case] contract: &str,
) {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
    if let Some((name, code, version)) = trait_setup {
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local(name).unwrap(),
                version,
                code,
                None,
            )
            .unwrap();
    }
    let contract_id = QualifiedContractIdentifier::local("subject").unwrap();
    let err = owned_env
        .initialize_versioned_contract(contract_id, ClarityVersion::Clarity7, contract, None)
        .unwrap_err();
    assert_eq!(
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::NameAlreadyUsed("slice?".to_string())
        )),
        err
    );
}

/// The reported unmatched name is the lexicographically first, not the first
/// defined: nodes must agree on the error.
#[test]
fn clarity7_multiple_unmatched_names_report_deterministically() {
    let mut tl_env_factory = tl_env_factory();
    // `slice?` is defined first, but the error names `element-at?`.
    let contract = "(define-public (slice? (a int) (b int)) (ok (+ a b)))
                    (define-public (element-at? (a int)) (ok a))";
    let contract_id = QualifiedContractIdentifier::local("c7-multi").unwrap();
    let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
    let err = owned_env
        .initialize_versioned_contract(contract_id, ClarityVersion::Clarity7, contract, None)
        .unwrap_err();
    assert_eq!(
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::NameAlreadyUsed("element-at?".to_string())
        )),
        err
    );
}

/// Read-only functions qualify too.
#[test]
fn clarity7_read_only_implementation_of_legacy_trait_method() {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = make_epoch41_env(
        &mut tl_env_factory,
        &[
            (
                "ops-def",
                ClarityVersion::Clarity1,
                "(define-trait ops ((slice? (int int) (response int int))))",
            ),
            (
                "c7-ro-impl",
                ClarityVersion::Clarity7,
                "(impl-trait .ops-def.ops)
                 (define-read-only (slice? (a int) (b int)) (ok (+ a b)))",
            ),
        ],
    );
    let contract_id = QualifiedContractIdentifier::local("c7-ro-impl").unwrap();
    let placeholder_context = make_c7_placeholder();
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);
    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &contract_id,
                "slice?",
                &symbols_from_values(vec![Value::Int(4), Value::Int(5)]),
                false
            )
            .unwrap(),
        Value::okay(Value::Int(9)).unwrap()
    );
}

/// A keyword-named implementation splits by position: head position calls it
/// (no native function has that name); the bare atom reads the keyword.
#[test]
fn clarity7_keyword_name_implementation_splits_by_position() {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = make_epoch41_env(
        &mut tl_env_factory,
        &[
            // The method name became a native keyword in Clarity 3.
            (
                "ops-def",
                ClarityVersion::Clarity1,
                "(define-trait ops ((stacks-block-height () (response uint uint))))",
            ),
            (
                "c7-keyword",
                ClarityVersion::Clarity7,
                "(impl-trait .ops-def.ops)
                 (define-read-only (stacks-block-height) (ok u12345))
                 (define-read-only (call-mine) (stacks-block-height))
                 (define-read-only (read-keyword) stacks-block-height)",
            ),
        ],
    );
    let contract_id = QualifiedContractIdentifier::local("c7-keyword").unwrap();
    let placeholder_context = make_c7_placeholder();
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    // Head position: the implementing function.
    assert_eq!(
        Ok(Value::okay(Value::UInt(12345)).unwrap()),
        exec_state.eval_read_only(&invoke_ctx, &contract_id, "(call-mine)")
    );
    // Bare atom: the keyword (the env's height, u1).
    assert_eq!(
        Ok(Value::UInt(1)),
        exec_state.eval_read_only(&invoke_ctx, &contract_id, "(read-keyword)")
    );
    // Literal-name lookup from outside.
    assert_eq!(
        exec_state
            .execute_contract(&invoke_ctx, &contract_id, "stacks-block-height", &[], false)
            .unwrap(),
        Value::okay(Value::UInt(12345)).unwrap()
    );
}

#[test]
fn clarity7_duplicate_shadowable_define_rejected() {
    let mut tl_env_factory = tl_env_factory();
    let trait_def = "(define-trait ops ((slice? (int int) (response int int))))";
    // A second definition is a plain collision, trait or not.
    let contract = "(impl-trait .ops-def.ops)
                    (define-public (slice? (a int) (b int)) (ok (+ a b)))
                    (define-public (slice? (a int) (b int)) (ok (- a b)))";
    let trait_id = QualifiedContractIdentifier::local("ops-def").unwrap();
    let contract_id = QualifiedContractIdentifier::local("c7-dup").unwrap();
    let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
    owned_env
        .initialize_versioned_contract(trait_id, ClarityVersion::Clarity1, trait_def, None)
        .unwrap();
    let err = owned_env
        .initialize_versioned_contract(contract_id, ClarityVersion::Clarity7, contract, None)
        .unwrap_err();
    assert_eq!(
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::NameAlreadyUsed("slice?".to_string())
        )),
        err
    );
}

/// VM-only edges of `impl-trait` references (on-chain, analysis rejects both
/// with `TraitReferenceUnknown`): a missing contract errors; an existing
/// contract without the trait contributes nothing.
#[test]
fn clarity7_reserved_name_validation_impl_trait_edges() {
    // Missing contract.
    {
        let mut tl_env_factory = tl_env_factory();
        let contract = "(impl-trait .missing.t)
                        (define-public (slice? (a int) (b int)) (ok (+ a b)))";
        let contract_id = QualifiedContractIdentifier::local("c7-missing").unwrap();
        let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
        let err = owned_env
            .initialize_versioned_contract(contract_id, ClarityVersion::Clarity7, contract, None)
            .unwrap_err();
        match &err {
            ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
                RuntimeCheckErrorKind::NoSuchContract(contract),
            )) if contract.ends_with(".missing") => {}
            e => panic!("expected NoSuchContract for .missing, got {e:?}"),
        }
    }

    // Existing contract without the trait: skipped; another trait matches.
    {
        let mut tl_env_factory = tl_env_factory();
        let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("plain").unwrap(),
                ClarityVersion::Clarity1,
                "(define-public (foo) (ok 1))",
                None,
            )
            .unwrap();
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("ops-def").unwrap(),
                ClarityVersion::Clarity1,
                "(define-trait ops ((slice? (int int) (response int int))))",
                None,
            )
            .unwrap();
        let contract = "(impl-trait .plain.nonexistent)
                        (impl-trait .ops-def.ops)
                        (define-public (slice? (a int) (b int)) (ok (+ a b)))";
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("c7-skip").unwrap(),
                ClarityVersion::Clarity7,
                contract,
                None,
            )
            .unwrap();
    }
}

/// Loading stops once every name is matched, so a broken reference sorted
/// after the matching trait is never loaded. On-chain, analysis rejects broken
/// references first; the early stop only changes what is charged.
#[test]
fn clarity7_trait_loading_stops_once_all_names_are_matched() {
    let ops_def = "(define-trait ops ((slice? (int int) (response int int))))";

    // `ops` sorts first: matched before the broken reference is loaded.
    {
        let mut tl_env_factory = tl_env_factory();
        let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("ops-def").unwrap(),
                ClarityVersion::Clarity1,
                ops_def,
                None,
            )
            .unwrap();
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("c7-skips-broken").unwrap(),
                ClarityVersion::Clarity7,
                "(impl-trait .ops-def.ops)
                 (impl-trait .missing.zzz-trait)
                 (define-public (slice? (a int) (b int)) (ok (+ a b)))",
                None,
            )
            .unwrap();
    }

    // `aaa-trait` sorts first: the broken reference is loaded and fails.
    {
        let mut tl_env_factory = tl_env_factory();
        let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
        owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("ops-def").unwrap(),
                ClarityVersion::Clarity1,
                ops_def,
                None,
            )
            .unwrap();
        let err = owned_env
            .initialize_versioned_contract(
                QualifiedContractIdentifier::local("c7-hits-broken").unwrap(),
                ClarityVersion::Clarity7,
                "(impl-trait .ops-def.ops)
                 (impl-trait .missing.aaa-trait)
                 (define-public (slice? (a int) (b int)) (ok (+ a b)))",
                None,
            )
            .unwrap_err();
        match &err {
            ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
                RuntimeCheckErrorKind::NoSuchContract(contract),
            )) if contract.ends_with(".missing") => {}
            e => panic!("expected NoSuchContract for .missing, got {e:?}"),
        }
    }
}

/// The contract's own traits are skipped: they cannot declare reserved names
/// and are not stored yet.
#[test]
fn clarity7_own_trait_cannot_match_reserved_name() {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
    let contract = "(define-trait self-ops ((foo (int) (response int int))))
                    (impl-trait .subject.self-ops)
                    (define-public (foo (x int)) (ok x))
                    (define-public (slice? (a int) (b int)) (ok (+ a b)))";
    let err = owned_env
        .initialize_versioned_contract(
            QualifiedContractIdentifier::local("subject").unwrap(),
            ClarityVersion::Clarity7,
            contract,
            None,
        )
        .unwrap_err();
    assert_eq!(
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::NameAlreadyUsed("slice?".to_string())
        )),
        err
    );
}

#[test]
fn clarity7_trait_cannot_declare_reserved_method_name() {
    let trait_def = "(define-trait t ((slice? (int int) (response int int))))";

    // Unchecked before Clarity 7 (definable, though unimplementable).
    {
        let mut tl_env_factory = tl_env_factory();
        let trait_id = QualifiedContractIdentifier::local("t-c5").unwrap();
        let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch34);
        owned_env
            .initialize_versioned_contract(trait_id, ClarityVersion::Clarity5, trait_def, None)
            .unwrap();
    }

    // From Clarity 7, a trait may not declare a currently-reserved method name.
    {
        let mut tl_env_factory = tl_env_factory();
        let trait_id = QualifiedContractIdentifier::local("t-c7").unwrap();
        let mut owned_env = tl_env_factory.get_env(StacksEpochId::Epoch41);
        let err = owned_env
            .initialize_versioned_contract(trait_id, ClarityVersion::Clarity7, trait_def, None)
            .unwrap_err();
        assert_eq!(
            ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
                RuntimeCheckErrorKind::NameAlreadyUsed("slice?".to_string())
            )),
            err
        );
    }
}

/// Defines that stay illegal: reserved names before Clarity 7; private
/// functions (never trait methods); and names reserved since Clarity 1, for
/// every define form.
#[rstest]
#[case::later_native_at_c5(
    StacksEpochId::Epoch34,
    ClarityVersion::Clarity5,
    "(define-read-only (slice? (a int) (b int)) (+ a b))",
    "slice?"
)]
#[case::later_native_at_c6(
    StacksEpochId::Epoch40,
    ClarityVersion::Clarity6,
    "(define-read-only (slice? (a int) (b int)) (+ a b))",
    "slice?"
)]
#[case::private_at_c7(
    StacksEpochId::Epoch41,
    ClarityVersion::Clarity7,
    "(define-private (slice? (a int) (b int)) (+ a b))",
    "slice?"
)]
#[case::hard_reserved_public_at_c7(
    StacksEpochId::Epoch41,
    ClarityVersion::Clarity7,
    "(define-public (map (x int)) (ok x))",
    "map"
)]
#[case::hard_reserved_read_only_at_c7(
    StacksEpochId::Epoch41,
    ClarityVersion::Clarity7,
    "(define-read-only (map (x int)) x)",
    "map"
)]
#[case::hard_reserved_private_at_c7(
    StacksEpochId::Epoch41,
    ClarityVersion::Clarity7,
    "(define-private (map (x int)) x)",
    "map"
)]
fn reserved_define_rejected(
    #[case] epoch: StacksEpochId,
    #[case] version: ClarityVersion,
    #[case] contract: &str,
    #[case] name: &str,
) {
    let mut tl_env_factory = tl_env_factory();
    let contract_id = QualifiedContractIdentifier::local("subject").unwrap();
    let mut owned_env = tl_env_factory.get_env(epoch);
    let err = owned_env
        .initialize_versioned_contract(contract_id, version, contract, None)
        .unwrap_err();
    assert_eq!(
        ClarityEvalError::Vm(VmExecutionError::RuntimeCheck(
            RuntimeCheckErrorKind::NameAlreadyUsed(name.to_string())
        )),
        err
    );
}

/// A legacy dispatcher dynamically dispatches its trait into a Clarity 7
/// implementation whose method name is now reserved.
#[test]
fn clarity7_implements_legacy_trait_with_reserved_method_name() {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = make_epoch41_env(
        &mut tl_env_factory,
        &[
            // A Clarity 1 trait with a method named `slice?` (free then), and a
            // dispatcher over it.
            (
                "legacy",
                ClarityVersion::Clarity1,
                "(define-trait ops ((slice? (int int) (response int int))))
                 (define-public (call-slice (impl-c <ops>))
                     (contract-call? impl-c slice? 4 5))",
            ),
            // A Clarity 7 contract can still implement that trait.
            (
                "impl-c7",
                ClarityVersion::Clarity7,
                "(impl-trait .legacy.ops)
                 (define-public (slice? (a int) (b int)) (ok (+ a b)))",
            ),
        ],
    );
    let legacy_id = QualifiedContractIdentifier::local("legacy").unwrap();
    let impl_id = QualifiedContractIdentifier::local("impl-c7").unwrap();
    let placeholder_context = make_c7_placeholder();
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);

    assert_eq!(
        exec_state
            .execute_contract(
                &invoke_ctx,
                &legacy_id,
                "call-slice",
                &symbols_from_values(vec![Value::from(PrincipalData::Contract(impl_id))]),
                false
            )
            .unwrap(),
        Value::okay(Value::Int(9)).unwrap()
    );
}

/// A static `contract-call?` from another contract reaches the shadowed
/// function by its literal name.
#[test]
fn clarity7_cross_contract_call_resolves_shadowed_function() {
    let mut tl_env_factory = tl_env_factory();
    let mut owned_env = make_epoch41_env(
        &mut tl_env_factory,
        &[
            (
                "ops-def",
                ClarityVersion::Clarity1,
                "(define-trait ops ((slice? (int int) (response int int))))",
            ),
            (
                "contract-a",
                ClarityVersion::Clarity7,
                "(impl-trait .ops-def.ops)
                 (define-public (slice? (a int) (b int)) (ok (+ a b)))",
            ),
            (
                "contract-b",
                ClarityVersion::Clarity7,
                "(define-public (call-a) (contract-call? .contract-a slice? 4 5))",
            ),
        ],
    );
    let id_b = QualifiedContractIdentifier::local("contract-b").unwrap();
    let placeholder_context = make_c7_placeholder();
    let (mut exec_state, invoke_ctx) =
        owned_env.get_exec_environment(None, None, &placeholder_context);
    assert_eq!(
        exec_state
            .execute_contract(&invoke_ctx, &id_b, "call-a", &[], false)
            .unwrap(),
        Value::okay(Value::Int(9)).unwrap()
    );
}

/// Epoch 4.1 environment with a memory-accounting cost tracker (the shared test
/// environments are free), capped at `memory_limit`.
#[cfg(test)]
fn make_memory_tracked_epoch41_env(
    marf: &mut MemoryBackingStore,
    memory_limit: u64,
) -> OwnedEnvironment<'_, '_> {
    let epoch = StacksEpochId::Epoch41;
    let mut db = marf.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(epoch).unwrap();
    db.commit().unwrap();
    db.begin();
    db.set_tenure_height(1).unwrap();
    db.commit().unwrap();
    db.begin();
    db.setup_block_metadata(Some(1)).unwrap();
    db.commit().unwrap();
    let mut cost_track = LimitedCostTracker::new_with_limit(epoch, ExecutionCost::max_value());
    cost_track.set_memory_limit(memory_limit);
    OwnedEnvironment::new_cost_limited(false, CHAIN_ID_TESTNET, db, cost_track, epoch)
}

/// Trait-contract loads during the reserved-name validation hold memory per
/// load, like contract calls, so many `impl-trait`s do not add up.
#[test]
fn clarity7_reserved_name_validation_accounts_memory_per_trait_load() {
    // Non-matching legacy traits, padded to dwarf other memory in flight; they
    // sort before the matching `zzz`, so all of them are loaded.
    let filler_count = 5;
    let pad = "00".repeat(1024);
    let mut marf = MemoryBackingStore::new();
    let mut owned_env = make_memory_tracked_epoch41_env(&mut marf, u64::MAX);
    let mut trait_contract_ids = Vec::new();
    for i in 0..filler_count {
        let id = QualifiedContractIdentifier::local(&format!("filler-{i}")).unwrap();
        owned_env
            .initialize_versioned_contract(
                id.clone(),
                ClarityVersion::Clarity1,
                &format!(
                    "(define-constant pad 0x{pad})
                     (define-trait aaa-{i} ((foo (int) (response int int))))"
                ),
                None,
            )
            .unwrap();
        trait_contract_ids.push(id);
    }
    let zzz_id = QualifiedContractIdentifier::local("zzz-def").unwrap();
    owned_env
        .initialize_versioned_contract(
            zzz_id.clone(),
            ClarityVersion::Clarity1,
            "(define-trait zzz ((slice? (int int) (response int int))))",
            None,
        )
        .unwrap();
    trait_contract_ids.push(zzz_id);

    // Between the largest single load and the sum of all loads: cumulative
    // accounting would exceed it.
    owned_env.context.database.begin();
    let sizes: Vec<u64> = trait_contract_ids
        .iter()
        .map(|id| owned_env.context.database.get_contract_size(id).unwrap())
        .collect();
    owned_env.context.database.roll_back().unwrap();
    let largest = *sizes.iter().max().unwrap();
    let total: u64 = sizes.iter().sum();
    let memory_before = owned_env.context.cost_track.get_memory();
    let memory_limit = memory_before + largest + (total - largest) / 2;
    assert!(
        memory_before + total > memory_limit,
        "the limit must be reachable by cumulative accounting"
    );
    owned_env.context.cost_track.set_memory_limit(memory_limit);

    let impl_traits: String = (0..filler_count)
        .map(|i| format!("(impl-trait .filler-{i}.aaa-{i}) "))
        .collect();
    let contract = format!(
        "{impl_traits}
         (impl-trait .zzz-def.zzz)
         (define-public (foo (x int)) (ok x))
         (define-public (slice? (a int) (b int)) (ok (+ a b)))"
    );
    owned_env
        .initialize_versioned_contract(
            QualifiedContractIdentifier::local("c7-many-traits").unwrap(),
            ClarityVersion::Clarity7,
            &contract,
            None,
        )
        .unwrap();
    // All held memory was released.
    assert_eq!(memory_before, owned_env.context.cost_track.get_memory());

    // And each load is charged: a limit below one load fails.
    let memory_before = owned_env.context.cost_track.get_memory();
    owned_env
        .context
        .cost_track
        .set_memory_limit(memory_before + largest - 1);
    let err = owned_env
        .initialize_versioned_contract(
            QualifiedContractIdentifier::local("c7-too-tight").unwrap(),
            ClarityVersion::Clarity7,
            &contract,
            None,
        )
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("MemoryBalanceExceeded"),
        "expected a memory error, got {err:?}"
    );
}
