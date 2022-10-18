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

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::{ClarityInstance, Error as ClarityError};
use crate::core::StacksEpochId;
use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::StacksBlockId;
use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::ast::{self, ASTRules};
use clarity::vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use clarity::vm::contracts::Contract;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::errors::Error as InterpreterError;
use clarity::vm::errors::{CheckErrors, Error, RuntimeErrorType};
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::test_util::*;
use clarity::vm::types::{
    OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
    TypeSignature, Value,
};
use clarity::vm::MAX_CALL_STACK_DEPTH;
use stacks_common::util::hash::hex_bytes;

use crate::clarity_vm::database::marf::MarfedKV;
use clarity::vm::clarity::TransactionConnection;

fn test_block_headers(n: u8) -> StacksBlockId {
    StacksBlockId([n as u8; 32])
}

pub const TEST_BURN_STATE_DB_AST_PRECHECK: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: StacksEpochId::Epoch20,
    ast_rules: ast::ASTRules::PrecheckSize,
};

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

#[test]
fn test_deep_tuples() {
    let mut clarity = ClarityInstance::new(false, MarfedKV::temporary());
    let p1 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            .unwrap(),
    );
    let p2 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            .unwrap(),
    );
    let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();

    {
        let mut block = clarity.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &test_block_headers(0),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let stack_limit =
            (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;
        let exceeds_stack_depth_tuple = format!(
            "{}u1 {}",
            "{ a : ".repeat(stack_limit + 5),
            "} ".repeat(stack_limit + 5)
        );

        let error = block.as_transaction(|tx| {
            //  basically, without the new stack depth checks in the lexer/parser,
            //    and without the VaryStackDepthChecker, this next call will return a checkerror
            let analysis_resp = tx.analyze_smart_contract(
                &contract_identifier,
                &exceeds_stack_depth_tuple,
                ASTRules::PrecheckSize,
            );
            analysis_resp.unwrap_err()
        });

        match error {
            ClarityError::Interpreter(InterpreterError::Runtime(r_e, _)) => {
                eprintln!("Runtime error: {:?}", r_e);
            }
            other => {
                eprintln!("Other error: {:?}", other);
            }
        }
    }
}

#[test]
fn test_deep_tuples_ast_precheck() {
    let mut clarity = ClarityInstance::new(false, MarfedKV::temporary());
    let p1 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            .unwrap(),
    );
    let p2 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            .unwrap(),
    );
    let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();

    {
        let mut block = clarity.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &test_block_headers(0),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB_AST_PRECHECK,
        );

        let stack_limit =
            (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;

        // absurdly deep tuple depth
        let exceeds_stack_depth_tuple = format!(
            "{}u1 {}",
            "{ a : ".repeat(stack_limit + 1024 * 128),
            "} ".repeat(stack_limit + 1024 * 128)
        );

        let error = block.as_transaction(|tx| {
            //  basically, without the new stack depth checks in the lexer/parser,
            //    and without the VaryStackDepthChecker, this next call will return a checkerror
            let analysis_resp = tx.analyze_smart_contract(
                &contract_identifier,
                &exceeds_stack_depth_tuple,
                ASTRules::PrecheckSize,
            );
            analysis_resp.unwrap_err()
        });

        match error {
            ClarityError::Interpreter(InterpreterError::Runtime(r_e, _)) => {
                eprintln!("Runtime error: {:?}", r_e);
            }
            other => {
                eprintln!("Other error: {:?}", other);
            }
        }
    }
}

#[test]
fn test_deep_type_nesting() {
    let mut clarity = ClarityInstance::new(false, MarfedKV::temporary());
    let p1 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            .unwrap(),
    );
    let p2 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            .unwrap(),
    );
    let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();

    {
        let mut block = clarity.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &test_block_headers(0),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let stack_limit =
            (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;
        let mut parts = vec!["(a0 { a0 : u1 })".to_string()];
        for i in 1..1024 {
            parts.push(format!("(a{} {{ a{} : (print a{}) }})", i, i, i - 1));
        }

        let exceeds_type_depth = format!(
            "(let (
                {}
            )
                (print a31)
            )",
            &parts.join("\n")
        );

        let error = block.as_transaction(|tx| {
            //  basically, without the new stack depth checks in the lexer/parser,
            //    and without the VaryStackDepthChecker, this next call will return a checkerror
            let analysis_resp = tx.analyze_smart_contract(
                &contract_identifier,
                &exceeds_type_depth,
                ASTRules::PrecheckSize,
            );
            analysis_resp.unwrap_err()
        });

        match error {
            ClarityError::Interpreter(InterpreterError::Runtime(r_e, _)) => {
                eprintln!("Runtime error: {:?}", r_e);
            }
            other => {
                eprintln!("Other error: {:?}", other);
            }
        }
    }
}

#[test]
fn test_simple_token_system() {
    let mut clarity = ClarityInstance::new(false, MarfedKV::temporary());
    let p1 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            .unwrap(),
    );
    let p2 = PrincipalData::from(
        PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            .unwrap(),
    );
    let contract_identifier = QualifiedContractIdentifier::local("tokens").unwrap();

    {
        let mut block = clarity.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &test_block_headers(0),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let tokens_contract = SIMPLE_TOKENS;

        let contract_ast = ast::build_ast(&contract_identifier, tokens_contract, &mut ()).unwrap();

        block.as_transaction(|tx| {
            tx.initialize_smart_contract(
                &contract_identifier,
                &contract_ast,
                tokens_contract,
                |_, _| false,
            )
            .unwrap()
        });

        assert!(!is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p2,
                    &contract_identifier,
                    "token-transfer",
                    &[p1.clone().into(), Value::UInt(210)],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));
        assert!(is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "token-transfer",
                    &[p2.clone().into(), Value::UInt(9000)],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));

        assert!(!is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "token-transfer",
                    &[p2.clone().into(), Value::UInt(1001)],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));
        assert!(is_committed(
            & // send to self!
            block.as_transaction(|tx| tx.run_contract_call(&p1, &contract_identifier, "token-transfer",
                                    &[p1.clone().into(), Value::UInt(1000)], |_, _| false)).unwrap().0
        ));

        assert_eq!(
            block
                .as_transaction(|tx| tx.eval_read_only(
                    &contract_identifier,
                    "(my-get-token-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"
                ))
                .unwrap(),
            Value::UInt(1000)
        );
        assert_eq!(
            block
                .as_transaction(|tx| tx.eval_read_only(
                    &contract_identifier,
                    "(my-get-token-balance 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)"
                ))
                .unwrap(),
            Value::UInt(9200)
        );

        assert!(is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "faucet",
                    &[],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));

        assert!(is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "faucet",
                    &[],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));

        assert!(is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "faucet",
                    &[],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));

        assert_eq!(
            block
                .as_transaction(|tx| tx.eval_read_only(
                    &contract_identifier,
                    "(my-get-token-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"
                ))
                .unwrap(),
            Value::UInt(1003)
        );

        assert!(!is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "mint-after",
                    &[Value::UInt(25)],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));
        block.commit_block();
    }

    for i in 0..25 {
        {
            let block = clarity.begin_block(
                &test_block_headers(i),
                &test_block_headers(i + 1),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            );
            block.commit_block();
        }
    }

    {
        let mut block = clarity.begin_block(
            &test_block_headers(25),
            &test_block_headers(26),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );
        assert!(is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "mint-after",
                    &[Value::UInt(25)],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));

        assert!(!is_committed(
            &block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "faucet",
                    &[],
                    |_, _| false
                ))
                .unwrap()
                .0
        ));

        assert_eq!(
            block
                .as_transaction(|tx| tx.eval_read_only(
                    &contract_identifier,
                    "(my-get-token-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"
                ))
                .unwrap(),
            Value::UInt(1004)
        );
        assert_eq!(
            block
                .as_transaction(|tx| tx.run_contract_call(
                    &p1,
                    &contract_identifier,
                    "my-get-token-balance",
                    &[p1.clone().into()],
                    |_, _| false
                ))
                .unwrap()
                .0,
            Value::UInt(1004)
        );
    }
}

/*
 * This test exhibits memory inflation --
 *   `(define-data-var var-x ...)` uses more than 1048576 bytes of memory.
 *      this is mainly due to using hex encoding in the sqlite storage.
 */
#[test]
#[ignore]
pub fn rollback_log_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();
    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let define_data_var = "(define-data-var XZ (buff 1048576) 0x00)";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            let cur_size = format!("{}", 2u32.pow(i));
            contract.push_str("\n");
            contract.push_str(&format!(
                "(var-set XZ (concat (unwrap-panic (as-max-len? (var-get XZ) u{}))
                                             (unwrap-panic (as-max-len? (var-get XZ) u{}))))",
                cur_size, cur_size
            ));
        }
        for i in 0..EXPLODE_N {
            let exploder = format!("(define-data-var var-{} (buff 1048576) (var-get XZ))", i);
            contract.push_str("\n");
            contract.push_str(&exploder);
        }

        conn.as_transaction(|conn| {
            let (ct_ast, _ct_analysis) = conn
                .analyze_smart_contract(&contract_identifier, &contract, ASTRules::PrecheckSize)
                .unwrap();
            assert!(format!(
                "{:?}",
                conn.initialize_smart_contract(&contract_identifier, &ct_ast, &contract, |_, _| {
                    false
                })
                .unwrap_err()
            )
            .contains("MemoryBalanceExceeded"));
        });
    }
}

/*
 */
#[test]
pub fn let_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let define_data_var = "(define-constant buff-0 0x00)";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            contract.push_str("\n");
            contract.push_str(&format!(
                "(define-constant buff-{} (concat buff-{} buff-{}))",
                i + 1,
                i,
                i
            ));
        }

        contract.push_str("\n");
        contract.push_str("(let (");

        for i in 0..EXPLODE_N {
            let exploder = format!("(var-{} buff-20) ", i);
            contract.push_str(&exploder);
        }

        contract.push_str(") 1)");

        conn.as_transaction(|conn| {
            let (ct_ast, _ct_analysis) = conn
                .analyze_smart_contract(&contract_identifier, &contract, ASTRules::PrecheckSize)
                .unwrap();
            assert!(format!(
                "{:?}",
                conn.initialize_smart_contract(&contract_identifier, &ct_ast, &contract, |_, _| {
                    false
                })
                .unwrap_err()
            )
            .contains("MemoryBalanceExceeded"));
        });
    }
}

#[test]
pub fn argument_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let define_data_var = "(define-constant buff-0 0x00)";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            contract.push_str("\n");
            contract.push_str(&format!(
                "(define-constant buff-{} (concat buff-{} buff-{}))",
                i + 1,
                i,
                i
            ));
        }

        contract.push_str("\n");
        contract.push_str("(is-eq ");

        for _i in 0..EXPLODE_N {
            let exploder = "buff-20 ";
            contract.push_str(exploder);
        }

        contract.push_str(")");

        conn.as_transaction(|conn| {
            let (ct_ast, _ct_analysis) = conn
                .analyze_smart_contract(&contract_identifier, &contract, ASTRules::PrecheckSize)
                .unwrap();
            assert!(format!(
                "{:?}",
                conn.initialize_smart_contract(&contract_identifier, &ct_ast, &contract, |_, _| {
                    false
                })
                .unwrap_err()
            )
            .contains("MemoryBalanceExceeded"));
        });
    }
}

#[test]
pub fn fcall_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let COUNT_PER_FUNC = 10;
    let FUNCS = 10;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let define_data_var = "(define-constant buff-0 0x00)";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            contract.push_str("\n");
            contract.push_str(&format!(
                "(define-constant buff-{} (concat buff-{} buff-{}))",
                i + 1,
                i,
                i
            ));
        }

        contract.push_str("\n");

        for i in 0..FUNCS {
            contract.push_str(&format!("(define-private (call-{})\n", i));

            contract.push_str("(let (");

            for j in 0..COUNT_PER_FUNC {
                let exploder = format!("(var-{} buff-20) ", j);
                contract.push_str(&exploder);
            }

            if i == 0 {
                contract.push_str(") 1) )\n");
            } else {
                contract.push_str(&format!(") (call-{})) )\n", i - 1));
            }
        }

        let mut contract_ok = contract.clone();
        let mut contract_err = contract.clone();

        contract_ok.push_str("(call-0)");
        contract_err.push_str("(call-9)");

        eprintln!("{}", contract_ok);
        eprintln!("{}", contract_err);

        conn.as_transaction(|conn| {
            let (ct_ast, _ct_analysis) = conn
                .analyze_smart_contract(&contract_identifier, &contract_ok, ASTRules::PrecheckSize)
                .unwrap();
            assert!(match conn
                .initialize_smart_contract(
                    // initialize the ok contract without errs, but still abort.
                    &contract_identifier,
                    &ct_ast,
                    &contract_ok,
                    |_, _| true
                )
                .unwrap_err()
            {
                ClarityError::AbortedByCallback(..) => true,
                _ => false,
            });
        });

        conn.as_transaction(|conn| {
            let (ct_ast, _ct_analysis) = conn
                .analyze_smart_contract(&contract_identifier, &contract_err, ASTRules::PrecheckSize)
                .unwrap();
            assert!(format!(
                "{:?}",
                conn.initialize_smart_contract(
                    &contract_identifier,
                    &ct_ast,
                    &contract_err,
                    |_, _| false
                )
                .unwrap_err()
            )
            .contains("MemoryBalanceExceeded"));
        });
    }
}

#[test]
#[ignore]
pub fn ccall_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let COUNT_PER_CONTRACT = 20;
    let CONTRACTS = 5;

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        let define_data_var = "(define-constant buff-0 0x00)\n";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            contract.push_str(&format!(
                "(define-constant buff-{} (concat buff-{} buff-{}))\n",
                i + 1,
                i,
                i
            ));
        }

        for i in 0..COUNT_PER_CONTRACT {
            contract.push_str(&format!("(define-constant var-{} buff-20)\n", i));
        }

        contract.push_str("(define-public (call)\n");

        let mut contracts = vec![];

        for i in 0..CONTRACTS {
            let mut my_contract = contract.clone();
            if i == 0 {
                my_contract.push_str("(ok 1))\n");
            } else {
                my_contract.push_str(&format!("(contract-call? .contract-{} call))\n", i - 1));
            }
            my_contract.push_str("(call)\n");
            contracts.push(my_contract);
        }

        for (i, contract) in contracts.into_iter().enumerate() {
            let contract_name = format!("contract-{}", i);
            let contract_identifier = QualifiedContractIdentifier::local(&contract_name).unwrap();

            if i < (CONTRACTS - 1) {
                conn.as_transaction(|conn| {
                    let (ct_ast, ct_analysis) = conn
                        .analyze_smart_contract(
                            &contract_identifier,
                            &contract,
                            ASTRules::PrecheckSize,
                        )
                        .unwrap();
                    conn.initialize_smart_contract(
                        &contract_identifier,
                        &ct_ast,
                        &contract,
                        |_, _| false,
                    )
                    .unwrap();
                    conn.save_analysis(&contract_identifier, &ct_analysis)
                        .unwrap();
                });
            } else {
                conn.as_transaction(|conn| {
                    let (ct_ast, _ct_analysis) = conn
                        .analyze_smart_contract(
                            &contract_identifier,
                            &contract,
                            ASTRules::PrecheckSize,
                        )
                        .unwrap();
                    assert!(format!(
                        "{:?}",
                        conn.initialize_smart_contract(
                            &contract_identifier,
                            &ct_ast,
                            &contract,
                            |_, _| false
                        )
                        .unwrap_err()
                    )
                    .contains("MemoryBalanceExceeded"));
                });
            }
        }
    }
}
