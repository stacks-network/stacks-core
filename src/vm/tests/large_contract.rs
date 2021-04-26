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
use crate::types::proof::ClarityMarfTrieId;
use chainstate::stacks::index::storage::TrieFileStorage;
use clarity_vm::clarity::{ClarityInstance, Error as ClarityError};
use util::hash::hex_bytes;
use vm::ast;
use vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use vm::contracts::Contract;
use vm::costs::ExecutionCost;
use vm::database::{ClarityDatabase, NULL_BURN_STATE_DB, NULL_HEADER_DB};
use vm::errors::{CheckErrors, Error, RuntimeErrorType};
use vm::execute as vm_execute;
use vm::representations::SymbolicExpression;
use vm::tests::{execute, symbols_from_values, with_marfed_environment, with_memory_environment};
use vm::types::{
    OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
    TypeSignature, Value,
};

use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::MemoryBackingStore;

/*
 * This test exhibits memory inflation --
 *   `(define-data-var var-x ...)` uses more than 1048576 bytes of memory.
 *      this is mainly due to using hex encoding in the sqlite storage.
 */
#[test]
#[ignore]
pub fn rollback_log_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf, ExecutionCost::max_value());
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();
    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
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
                .analyze_smart_contract(&contract_identifier, &contract)
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
    let mut clarity_instance = ClarityInstance::new(false, marf, ExecutionCost::max_value());
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
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
                .analyze_smart_contract(&contract_identifier, &contract)
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
    let mut clarity_instance = ClarityInstance::new(false, marf, ExecutionCost::max_value());
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
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
                .analyze_smart_contract(&contract_identifier, &contract)
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
    let mut clarity_instance = ClarityInstance::new(false, marf, ExecutionCost::max_value());
    let COUNT_PER_FUNC = 10;
    let FUNCS = 10;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
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
                .analyze_smart_contract(&contract_identifier, &contract_ok)
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
                .analyze_smart_contract(&contract_identifier, &contract_err)
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
    let mut clarity_instance = ClarityInstance::new(false, marf, ExecutionCost::max_value());
    let COUNT_PER_CONTRACT = 20;
    let CONTRACTS = 5;

    clarity_instance
        .begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId([0 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        )
        .commit_block();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
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
                        .analyze_smart_contract(&contract_identifier, &contract)
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
                        .analyze_smart_contract(&contract_identifier, &contract)
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
