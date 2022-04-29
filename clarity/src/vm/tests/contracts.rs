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

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::StacksBlockId;

#[cfg(any(test, feature = "testing"))]
use rstest::rstest;
#[cfg(any(test, feature = "testing"))]
use rstest_reuse::{self, *};

use crate::vm::ast;
use crate::vm::ast::errors::ParseErrors;
use crate::vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use crate::vm::contracts::Contract;
use crate::vm::costs::ExecutionCost;
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::{CheckErrors, Error, RuntimeErrorType};
use crate::vm::execute as vm_execute;
use crate::vm::representations::SymbolicExpression;
use crate::vm::tests::{
    execute, is_committed, is_err_code_i128 as is_err_code, symbols_from_values,
    with_memory_environment, BurnStateDB, TEST_BURN_STATE_DB, TEST_HEADER_DB,
};
use crate::vm::types::{
    OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
    TypeSignature, Value,
};
use crate::vm::ClarityVersion;
use stacks_common::types::chainstate::{ConsensusHash, SortitionId};
use stacks_common::util::hash::hex_bytes;

use crate::vm::types::serialization::TypePrefix::Buffer;
use crate::vm::types::BuffData;
use crate::vm::Value::Sequence;

use crate::vm::database::MemoryBackingStore;

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

fn get_principal() -> Value {
    StandardPrincipalData::transient().into()
}

fn get_principal_as_principal_data() -> PrincipalData {
    StandardPrincipalData::transient().into()
}

#[test]
fn test_get_block_info_eval() {
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
        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, Value::Int(-1)).into()),
        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, Value::Bool(true)).into()),
        Ok(Value::none()),
        Ok(Value::none()),
        Ok(Value::none()),
    ];

    for i in 0..contracts.len() {
        let mut marf = MemoryBackingStore::new();
        let mut owned_env = OwnedEnvironment::new(marf.as_clarity_db());
        let contract_identifier = QualifiedContractIdentifier::local("test-contract").unwrap();
        owned_env
            .initialize_contract(contract_identifier.clone(), contracts[i], None)
            .unwrap();

        let mut env = owned_env.get_exec_environment(None, None);

        let eval_result = env.eval_read_only(&contract_identifier, "(test-func)");
        match expected[i] {
            // any (some UINT) is okay for checking get-block-info? time
            Ok(Value::UInt(0)) => {
                assert!(
                    if let Ok(Value::Optional(OptionalData { data: Some(x) })) = eval_result {
                        if let Value::UInt(_) = *x {
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                );
            }
            _ => assert_eq!(expected[i], eval_result),
        }
    }
}

fn test_block_headers(n: u8) -> StacksBlockId {
    StacksBlockId([n as u8; 32])
}

fn test_contract_caller(owned_env: &mut OwnedEnvironment) {
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

    {
        let mut env = owned_env.get_exec_environment(None, None);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-a").unwrap(),
            contract_a,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
            contract_b,
        )
        .unwrap();
    }

    {
        let c_b = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(Some(p1.clone().expect_principal()), None);
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-a").unwrap(),
                "get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![p1.clone(), p1.clone()]).unwrap()
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "as-contract-get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap()
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "cc-get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![c_b.clone(), p1.clone()]).unwrap()
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "as-contract-cc-get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap()
        );
    }
}

fn tx_sponsor_contract_asserts(env: &mut Environment, sponsor: Option<PrincipalData>) {
    let sponsor = match sponsor {
        None => Value::none(),
        Some(p) => Value::some(Value::Principal(p)).unwrap(),
    };
    assert_eq!(
        env.execute_contract(
            &QualifiedContractIdentifier::local("contract-a").unwrap(),
            "get-sponsor",
            &vec![],
            false
        )
        .unwrap(),
        Value::list_from(vec![sponsor.clone()]).unwrap()
    );
    assert_eq!(
        env.execute_contract(
            &QualifiedContractIdentifier::local("contract-b").unwrap(),
            "as-contract-get-sponsor",
            &vec![],
            false
        )
        .unwrap(),
        Value::list_from(vec![sponsor.clone()]).unwrap()
    );
    assert_eq!(
        env.execute_contract(
            &QualifiedContractIdentifier::local("contract-b").unwrap(),
            "cc-get-sponsor",
            &vec![],
            false
        )
        .unwrap(),
        Value::list_from(vec![sponsor.clone()]).unwrap()
    );
    assert_eq!(
        env.execute_contract(
            &QualifiedContractIdentifier::local("contract-b").unwrap(),
            "as-contract-cc-get-sponsor",
            &vec![],
            false
        )
        .unwrap(),
        Value::list_from(vec![sponsor.clone()]).unwrap()
    );
}

fn test_tx_sponsor(owned_env: &mut OwnedEnvironment) {
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

    let p1 = execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR").expect_principal();
    let p2 = execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G");
    let sponsor = if let Value::Principal(p) = p2 {
        Some(p)
    } else {
        panic!("p2 is not a principal value");
    };

    {
        let mut env = owned_env.get_exec_environment(Some(p1.clone()), sponsor.clone());
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-a").unwrap(),
            contract_a,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
            contract_b,
        )
        .unwrap();
    }

    // Sponsor is equal to some(principal) in this code block.
    {
        let mut env = owned_env.get_exec_environment(Some(p1.clone()), sponsor.clone());
        tx_sponsor_contract_asserts(&mut env, sponsor.clone());
    }

    // Sponsor is none in this code block.
    {
        let sponsor = None;
        let mut env = owned_env.get_exec_environment(Some(p1.clone()), sponsor.clone());
        tx_sponsor_contract_asserts(&mut env, sponsor.clone());
    }
}

fn test_fully_qualified_contract_call(owned_env: &mut OwnedEnvironment) {
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

    {
        let mut env = owned_env.get_exec_environment(None, None);
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-a").unwrap(),
            contract_a,
        )
        .unwrap();
        env.initialize_contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
            contract_b,
        )
        .unwrap();
    }

    {
        let c_b = Value::from(PrincipalData::Contract(
            QualifiedContractIdentifier::local("contract-b").unwrap(),
        ));
        let mut env = owned_env.get_exec_environment(Some(p1.clone().expect_principal()), None);
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-a").unwrap(),
                "get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![p1.clone(), p1.clone()]).unwrap()
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "as-contract-get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap()
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "cc-get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![c_b.clone(), p1.clone()]).unwrap()
        );
        assert_eq!(
            env.execute_contract(
                &QualifiedContractIdentifier::local("contract-b").unwrap(),
                "as-contract-cc-get-caller",
                &vec![],
                false
            )
            .unwrap(),
            Value::list_from(vec![c_b.clone(), c_b.clone()]).unwrap()
        );
    }
}

fn test_simple_contract_call(owned_env: &mut OwnedEnvironment) {
    let contract_1 = FACTORIAL_CONTRACT;
    let contract_2 = "(define-public (proxy-compute)
            (contract-call? .factorial-contract compute 8008))
        ";

    let mut env = owned_env.get_exec_environment(Some(get_principal().expect_principal()), None);

    let contract_identifier = QualifiedContractIdentifier::local("factorial-contract").unwrap();
    env.initialize_contract(contract_identifier, contract_1)
        .unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("proxy-compute").unwrap();
    env.initialize_contract(contract_identifier, contract_2)
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
        env.execute_contract(
            &QualifiedContractIdentifier::local("proxy-compute").unwrap(),
            "proxy-compute",
            &args,
            false,
        )
        .unwrap();
        assert_eq!(
            env.eval_read_only(
                &QualifiedContractIdentifier::local("factorial-contract").unwrap(),
                "(get current (unwrap! (map-get? factorials {id: 8008}) false))"
            )
            .unwrap(),
            *expected_result
        );
    }
}

fn test_aborts(owned_env: &mut OwnedEnvironment) {
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
    let mut env = owned_env.get_exec_environment(None, None);

    let contract_identifier = QualifiedContractIdentifier::local("contract-1").unwrap();
    env.initialize_contract(contract_identifier, contract_1)
        .unwrap();

    let contract_identifier = QualifiedContractIdentifier::local("contract-2").unwrap();
    env.initialize_contract(contract_identifier, contract_2)
        .unwrap();

    env.sender = Some(get_principal_as_principal_data());

    assert_eq!(
        env.execute_contract(
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
        env.execute_contract(
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
        env.eval_read_only(
            &QualifiedContractIdentifier::local("contract-1").unwrap(),
            "(get-data 20)"
        )
        .unwrap(),
        Value::Int(0)
    );

    assert_eq!(
        env.eval_read_only(
            &QualifiedContractIdentifier::local("contract-1").unwrap(),
            "(get-data 10)"
        )
        .unwrap(),
        Value::Int(10)
    );

    assert_eq!(
        env.execute_contract(
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
        env.execute_contract(
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
        env.eval_read_only(
            &QualifiedContractIdentifier::local("contract-1").unwrap(),
            "(get-data 105)"
        )
        .unwrap(),
        Value::Int(0)
    );

    assert_eq!(
        env.eval_read_only(
            &QualifiedContractIdentifier::local("contract-1").unwrap(),
            "(get-data 100)"
        )
        .unwrap(),
        Value::Int(0)
    );
}

fn test_factorial_contract(owned_env: &mut OwnedEnvironment) {
    let mut env = owned_env.get_exec_environment(None, None);

    let contract_identifier = QualifiedContractIdentifier::local("factorial").unwrap();
    env.initialize_contract(contract_identifier, FACTORIAL_CONTRACT)
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

    env.sender = Some(get_principal_as_principal_data());

    for (arguments, expectation) in arguments_to_test.iter().zip(expected.iter()) {
        env.execute_contract(
            &QualifiedContractIdentifier::local("factorial").unwrap(),
            &tx_name,
            arguments,
            false,
        )
        .unwrap();

        assert_eq!(
            *expectation,
            env.eval_read_only(
                &QualifiedContractIdentifier::local("factorial").unwrap(),
                &format!(
                    "(unwrap! (get current (map-get? factorials (tuple (id {})))) false)",
                    arguments[0]
                )
            )
            .unwrap()
        );
    }

    let err_result = env
        .execute_contract(
            &QualifiedContractIdentifier::local("factorial").unwrap(),
            "init-factorial",
            &symbols_from_values(vec![Value::Int(9000), Value::Int(15)]),
            false,
        )
        .unwrap_err();
    match err_result {
        Error::Unchecked(CheckErrors::NoSuchPublicFunction(_, _)) => {}
        _ => {
            println!("{:?}", err_result);
            panic!("Attempt to call init-factorial should fail!")
        }
    }

    let err_result = env
        .execute_contract(
            &QualifiedContractIdentifier::local("factorial").unwrap(),
            "compute",
            &symbols_from_values(vec![Value::Bool(true)]),
            false,
        )
        .unwrap_err();
    match err_result {
        Error::Unchecked(CheckErrors::TypeValueError(_, _)) => {}
        _ => {
            println!("{:?}", err_result);
            assert!(false, "Attempt to call compute with void type should fail!")
        }
    }
}

#[test]
fn test_at_unknown_block() {
    fn test(owned_env: &mut OwnedEnvironment) {
        let contract = "(define-data-var foo int 3)
                        (at-block 0x0202020202020202020202020202020202020202020202020202020202020202
                          (+ 1 2))";
        let err = owned_env
            .initialize_contract(
                QualifiedContractIdentifier::local("contract").unwrap(),
                &contract,
                None,
            )
            .unwrap_err();
        eprintln!("{}", err);
        match err {
            Error::Runtime(x, _) => assert_eq!(
                x,
                RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash::from(
                    vec![2 as u8; 32].as_slice()
                ))
            ),
            _ => panic!("Unexpected error"),
        }
    }

    with_memory_environment(test, true);
}

#[test]
fn test_as_max_len() {
    fn test(owned_env: &mut OwnedEnvironment) {
        let contract = "(define-data-var token-ids (list 10 uint) (list))
                        (var-set token-ids 
                           (unwrap! (as-max-len? (append (var-get token-ids) u1) u10) (err 10)))";

        owned_env
            .initialize_contract(
                QualifiedContractIdentifier::local("contract").unwrap(),
                &contract,
                None,
            )
            .unwrap();
    }

    with_memory_environment(test, true);
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
        RuntimeErrorType::ASTError(ParseErrors::ExpressionStackDepthTooDeep.into()).into()
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
        RuntimeErrorType::MaxStackDepthReached.into()
    );
}

#[test]
fn test_cc_stack_depth() {
    let contract_one = "(define-public (foo) 
                        (ok (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ 
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ 
                       1 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)))";
    let contract_two =
                      "(define-private (bar) 
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ 
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ 
                        (unwrap-panic (contract-call? .c-foo foo ) )
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1))
                       (bar)
                      ";

    with_memory_environment(
        |owned_env| {
            let mut env = owned_env.get_exec_environment(None, None);

            let contract_identifier = QualifiedContractIdentifier::local("c-foo").unwrap();
            env.initialize_contract(contract_identifier, contract_one)
                .unwrap();

            let contract_identifier = QualifiedContractIdentifier::local("c-bar").unwrap();
            assert_eq!(
                env.initialize_contract(contract_identifier, contract_two)
                    .unwrap_err(),
                RuntimeErrorType::MaxStackDepthReached.into()
            );
        },
        false,
    );
}

#[test]
fn test_cc_trait_stack_depth() {
    let contract_one = "(define-public (foo)
                        (ok (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                       1 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)))";
    let contract_two =
                      "(define-trait trait-1 (
                        (foo () (response int int))))
                       (define-private (bar (F <trait-1>))
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                        (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+ (+
                        (unwrap-panic (contract-call? F foo))
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1)
                         1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1) 1))
                       (bar .c-foo)
                      ";

    with_memory_environment(
        |owned_env| {
            let mut env = owned_env.get_exec_environment(None, None);

            let contract_identifier = QualifiedContractIdentifier::local("c-foo").unwrap();
            env.initialize_contract(contract_identifier, contract_one)
                .unwrap();

            let contract_identifier = QualifiedContractIdentifier::local("c-bar").unwrap();
            assert_eq!(
                env.initialize_contract(contract_identifier, contract_two)
                    .unwrap_err(),
                RuntimeErrorType::MaxStackDepthReached.into()
            );
        },
        false,
    );
}

#[test]
fn test_all() {
    let to_test = [
        test_factorial_contract,
        test_aborts,
        test_contract_caller,
        test_tx_sponsor,
        test_fully_qualified_contract_call,
        test_simple_contract_call,
    ];
    for test in to_test.iter() {
        eprintln!("..");
        with_memory_environment(test, false);
    }
}
