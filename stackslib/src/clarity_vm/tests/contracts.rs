// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use clarity::types::chainstate::StacksAddress;
use clarity::vm::ast;
use clarity::vm::ast::errors::ParseErrors;
use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::Error as ClarityError;
use clarity::vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use clarity::vm::contracts::Contract;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::errors::{CheckErrors, Error, RuntimeErrorType};
use clarity::vm::execute as vm_execute;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::tests::{
    execute, is_committed, is_err_code_i128 as is_err_code, symbols_from_values, BurnStateDB,
    TEST_BURN_STATE_DB, TEST_HEADER_DB,
};
use clarity::vm::types::BuffData;
use clarity::vm::types::SequenceData::Buffer;
use clarity::vm::types::{
    OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
    TypeSignature, Value,
};
use clarity::vm::ClarityVersion;
use clarity::vm::Value::Sequence;
#[cfg(any(test, feature = "testing"))]
use rstest::rstest;
#[cfg(any(test, feature = "testing"))]
use rstest_reuse::{self, *};
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::{ConsensusHash, SortitionId};
use stacks_common::types::StacksEpoch;
use stacks_common::util::hash::hex_bytes;

use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::stacks::boot::contract_tests::{test_sim_height_to_hash, ClarityTestSim};
use crate::clarity::vm::clarity::ClarityConnection;
use crate::clarity::vm::clarity::TransactionConnection;
use crate::clarity_vm::clarity::ClarityBlockConnection;

#[test]
// Here, we set up a basic test to see if we can recover a path from the ClarityTestSim.
fn test_get_burn_block_info_eval() {
    let mut sim = ClarityTestSim::new();
    sim.epoch_bounds = vec![0, 2, 4];

    // Advance at least one block because 'get-burn-block-info' only works after the first block.
    sim.execute_next_block(|_env| {});
    // Advance another block so we get to Stacks 2.05.
    sim.execute_next_block_as_conn(|conn| {
        let contract_identifier = QualifiedContractIdentifier::local("test-contract-1").unwrap();
        let contract =
            "(define-private (test-func (height uint)) (get-burn-block-info? header-hash height))";
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let res = clarity_db.analyze_smart_contract(
                &contract_identifier,
                clarity_version,
                contract,
                ASTRules::PrecheckSize,
            );
            if let Err(ClarityError::Analysis(check_error)) = res {
                if let CheckErrors::UnknownFunction(func_name) = check_error.err {
                    assert_eq!(func_name, "get-burn-block-info?");
                } else {
                    panic!("Bad analysis error: {:?}", &check_error);
                }
            } else {
                panic!("Bad analysis result: {:?}", &res);
            }
        });
    });
    // Advance another block so we get to Stacks 2.1. This is the last block in 2.05
    sim.execute_next_block_as_conn(|conn| {
        let contract_identifier = QualifiedContractIdentifier::local("test-contract-2").unwrap();
        let contract =
            "(define-private (test-func (height uint)) (get-burn-block-info? header-hash height))";
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let res = clarity_db.analyze_smart_contract(
                &contract_identifier,
                clarity_version,
                contract,
                ASTRules::PrecheckSize,
            );
            if let Err(ClarityError::Analysis(check_error)) = res {
                if let CheckErrors::UnknownFunction(func_name) = check_error.err {
                    assert_eq!(func_name, "get-burn-block-info?");
                } else {
                    panic!("Bad analysis error: {:?}", &check_error);
                }
            } else {
                panic!("Bad analysis result: {:?}", &res);
            }
        });
    });
    // now in Stacks 2.1, so this should work!
    sim.execute_next_block_as_conn(|conn| {
        let contract_identifier = QualifiedContractIdentifier::local("test-contract-3").unwrap();
        let contract =
            "(define-private (test-func (height uint)) (get-burn-block-info? header-hash height))";
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &contract_identifier,
                    clarity_version,
                    contract,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &contract_identifier,
                    clarity_version,
                    &ast,
                    contract,
                    None,
                    |_, _| false,
                )
                .unwrap();
        });
        // This relies on `TestSimBurnStateDB::get_burn_header_hash'
        // * burnchain is 100 blocks ahead of stacks
        // * sortition IDs, consensus hashes, and block hashes encode height and fork ID
        let mut tx = conn.start_transaction_processing();
        assert_eq!(
            Value::Optional(OptionalData {
                data: Some(Box::new(Sequence(Buffer(BuffData {
                    data: test_sim_height_to_hash(0, 0).to_vec()
                }))))
            }),
            tx.eval_read_only(&contract_identifier, "(test-func u0)")
                .unwrap()
        );
        assert_eq!(
            Value::Optional(OptionalData {
                data: Some(Box::new(Sequence(Buffer(BuffData {
                    data: test_sim_height_to_hash(1, 0).to_vec()
                }))))
            }),
            tx.eval_read_only(&contract_identifier, "(test-func u1)")
                .unwrap()
        );
        assert_eq!(
            Value::Optional(OptionalData {
                data: Some(Box::new(Sequence(Buffer(BuffData {
                    data: test_sim_height_to_hash(2, 0).to_vec()
                }))))
            }),
            tx.eval_read_only(&contract_identifier, "(test-func u2)")
                .unwrap()
        );
        // burnchain is 100 blocks ahead of stacks chain in this sim
        assert_eq!(
            Value::Optional(OptionalData { data: None }),
            tx.eval_read_only(&contract_identifier, "(test-func u103)")
                .unwrap()
        );
    });
}

#[test]
fn test_get_block_info_eval_v210() {
    let mut sim = ClarityTestSim::new();
    sim.epoch_bounds = vec![0, 3, 5];

    // Advance at least one block because 'get-block-info' only works after the first block.
    sim.execute_next_block(|_env| {});
    // Advance another block so we get to Stacks 2.05.
    sim.execute_next_block(|_env| {});
    sim.execute_next_block_as_conn(|conn| {
        let contract_identifier = QualifiedContractIdentifier::local("test-contract-1").unwrap();
        let contract =
            "(define-private (test-func (height uint)) (get-block-info? block-reward height))";
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let res = clarity_db.analyze_smart_contract(
                &contract_identifier,
                clarity_version,
                contract,
                ASTRules::PrecheckSize,
            );
            if let Err(ClarityError::Analysis(check_error)) = res {
                if let CheckErrors::NoSuchBlockInfoProperty(name) = check_error.err {
                    assert_eq!(name, "block-reward");
                } else {
                    panic!("Bad analysis error: {:?}", &check_error);
                }
            } else {
                panic!("Bad analysis result: {:?}", &res);
            }
        });
    });
    // Advance another block so we get to Stacks 2.1. This is the last block in 2.05
    sim.execute_next_block_as_conn(|conn| {
        let contract_identifier = QualifiedContractIdentifier::local("test-contract-2").unwrap();
        let contract =
            "(define-private (test-func (height uint)) (get-block-info? block-reward height))";
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let res = clarity_db.analyze_smart_contract(
                &contract_identifier,
                clarity_version,
                contract,
                ASTRules::PrecheckSize,
            );
            if let Err(ClarityError::Analysis(check_error)) = res {
                if let CheckErrors::NoSuchBlockInfoProperty(name) = check_error.err {
                    assert_eq!(name, "block-reward");
                } else {
                    panic!("Bad analysis error: {:?}", &check_error);
                }
            } else {
                panic!("Bad analysis result: {:?}", &res);
            }
        });
    });
    // now in Stacks 2.1, so this should work!
    sim.execute_next_block_as_conn(|conn| {
        let contract_identifier = QualifiedContractIdentifier::local("test-contract-3").unwrap();
        let contract =
            "(define-private (test-func-1 (height uint)) (get-block-info? block-reward height)) 
             (define-private (test-func-2 (height uint)) (get-block-info? miner-spend-winner height))
             (define-private (test-func-3 (height uint)) (get-block-info? miner-spend-total height))";
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(&contract_identifier, clarity_version, contract, ASTRules::PrecheckSize)
                .unwrap();
            clarity_db
                .initialize_smart_contract(&contract_identifier, clarity_version, &ast, contract, None, |_, _| false)
                .unwrap();
        });
        let mut tx = conn.start_transaction_processing();
        // no values for the genesis block
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-1 u0)")
                .unwrap()
        );
        assert_eq!(
            Value::some(Value::UInt(0)).unwrap(),
            tx.eval_read_only(&contract_identifier, "(test-func-2 u0)")
                .unwrap()
        );
        assert_eq!(
            Value::some(Value::UInt(0)).unwrap(),
            tx.eval_read_only(&contract_identifier, "(test-func-3 u0)")
                .unwrap()
        );
        // only works at the first block and later (not the 0th block) 
        assert_eq!(
            Value::some(Value::UInt(3000)).unwrap(),
            tx.eval_read_only(&contract_identifier, "(test-func-1 u1)")
                .unwrap()
        );
        assert_eq!(
            Value::some(Value::UInt(1000)).unwrap(),
            tx.eval_read_only(&contract_identifier, "(test-func-2 u1)")
                .unwrap()
        );
        assert_eq!(
            Value::some(Value::UInt(2000)).unwrap(),
            tx.eval_read_only(&contract_identifier, "(test-func-3 u1)")
                .unwrap()
        );
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-1 u103)")
                .unwrap()
        );
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-2 u103)")
                .unwrap()
        );
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-3 u103)")
                .unwrap()
        );
        // only works on ancestor blocks, not the current block
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-1 block-height)")
                .unwrap()
        );
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-2 block-height)")
                .unwrap()
        );
        assert_eq!(
            Value::none(),
            tx.eval_read_only(&contract_identifier, "(test-func-3 block-height)")
                .unwrap()
        );
    });
}

fn publish_contract(
    bc: &mut ClarityBlockConnection,
    contract_id: &QualifiedContractIdentifier,
    contract: &str,
    version: ClarityVersion,
) -> Result<(), clarity::vm::clarity::Error> {
    bc.as_transaction(|tx| {
        let (ast, analysis) =
            tx.analyze_smart_contract(contract_id, version, contract, ASTRules::PrecheckSize)?;
        tx.initialize_smart_contract(contract_id, version, &ast, contract, None, |_, _| false)?;
        tx.save_analysis(contract_id, &analysis)?;
        Ok(())
    })
}

/// Test that you cannot invoke a 2.05 contract
///  with a trait parameter using a stored principal.
#[test]
fn trait_invocation_205_with_stored_principal() {
    let mut sim = ClarityTestSim::new();
    sim.epoch_bounds = vec![0, 3, 5];

    // Advance two blocks so we get to Stacks 2.05.
    sim.execute_next_block(|_env| {});
    sim.execute_next_block(|_env| {});

    let trait_contract = "(define-trait simple-method ((foo (uint) (response uint uint)) ))";
    let impl_contract =
        "(impl-trait .simple-trait.simple-method) (define-read-only (foo (x uint)) (ok x))";
    let use_contract = "(use-trait simple .simple-trait.simple-method)
                        (define-public (call-simple (s <simple>)) (contract-call? s foo u0))";
    let invoke_contract = "
        (use-trait simple .simple-trait.simple-method)
        (define-data-var callee-contract principal .impl-simple)
        (define-public (invocation-1)
          (contract-call? .use-simple call-simple (var-get callee-contract)))
    ";

    let trait_contract_id = QualifiedContractIdentifier::local("simple-trait").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("impl-simple").unwrap();
    let use_contract_id = QualifiedContractIdentifier::local("use-simple").unwrap();
    let invoke_contract_id = QualifiedContractIdentifier::local("invoke-simple").unwrap();

    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        let clarity_version = ClarityVersion::default_for_epoch(epoch);
        publish_contract(conn, &trait_contract_id, trait_contract, clarity_version).unwrap();
        publish_contract(conn, &impl_contract_id, impl_contract, clarity_version).unwrap();
        publish_contract(conn, &use_contract_id, use_contract, clarity_version).unwrap();
    });
    // Advance another block so we get to Stacks 2.1. This is the last block in 2.05
    sim.execute_next_block(|_| {});
    // now in Stacks 2.1
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        let clarity_version = ClarityVersion::default_for_epoch(epoch);
        assert_eq!(clarity_version, ClarityVersion::Clarity2);
        let error = publish_contract(conn, &invoke_contract_id, invoke_contract, clarity_version)
            .unwrap_err();
        match error {
            ClarityError::Analysis(ref e) => match e.err {
                CheckErrors::TypeError(..) => (),
                _ => panic!("Unexpected error: {:?}", error),
            },
            _ => panic!("Unexpected error: {:?}", error),
        };
    });
}

/// Publish a trait in epoch 2.05 and then invoke it in epoch 2.1.
/// Test the behaviors in 2.2 and 2.3 as well.
#[test]
fn trait_invocation_cross_epoch() {
    let mut sim = ClarityTestSim::new();
    sim.epoch_bounds = vec![0, 3, 5, 7, 9];

    // Advance two blocks so we get to Stacks 2.05.
    sim.execute_next_block(|_env| {});
    sim.execute_next_block(|_env| {});

    let trait_contract = "(define-trait simple-method ((foo (uint) (response uint uint)) ))";
    let impl_contract =
        "(impl-trait .simple-trait.simple-method) (define-read-only (foo (x uint)) (ok x))";
    let use_contract = "(use-trait simple .simple-trait.simple-method)
                        (define-public (call-simple (s <simple>)) (contract-call? s foo u0))";
    let invoke_contract = "
        (use-trait simple .simple-trait.simple-method)
        (define-public (invocation-1)
          (contract-call? .use-simple call-simple .impl-simple))
        (define-public (invocation-2 (st <simple>))
          (contract-call? .use-simple call-simple st))
    ";

    let trait_contract_id = QualifiedContractIdentifier::local("simple-trait").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("impl-simple").unwrap();
    let use_contract_id = QualifiedContractIdentifier::local("use-simple").unwrap();
    let invoke_contract_id = QualifiedContractIdentifier::local("invoke-simple").unwrap();

    let sender = StacksAddress::burn_address(false).into();

    info!("Sim height = {}", sim.height);
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        let clarity_version = ClarityVersion::default_for_epoch(epoch);
        publish_contract(conn, &trait_contract_id, trait_contract, clarity_version).unwrap();
        publish_contract(conn, &impl_contract_id, impl_contract, clarity_version).unwrap();
        publish_contract(conn, &use_contract_id, use_contract, clarity_version).unwrap();
    });
    // Advance another block so we get to Stacks 2.1. This is the last block in 2.05
    info!("Sim height = {}", sim.height);
    sim.execute_next_block(|_| {});
    // now in Stacks 2.1
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        let clarity_version = ClarityVersion::default_for_epoch(epoch);
        assert_eq!(clarity_version, ClarityVersion::Clarity2);
        publish_contract(conn, &invoke_contract_id, invoke_contract, clarity_version).unwrap();
    });

    info!("Sim height = {}", sim.height);
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &invoke_contract_id,
                    "invocation-1",
                    &[],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    info!("Sim height = {}", sim.height);
    // now in Stacks 2.2
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let error = clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &invoke_contract_id,
                    "invocation-1",
                    &[],
                    |_, _| false,
                )
                .unwrap_err();

            if let ClarityError::Interpreter(Error::Unchecked(CheckErrors::TypeValueError(TypeSignature::TraitReferenceType(_), value))) = error {
                // pass
            } else {
                panic!("Expected an Interpreter(UncheckedError(TypeValue(TraitReferenceType, Principal))) during Epoch-2.2");
            };
        });
    });

    info!("Sim height = {}", sim.height);
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let error = clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &invoke_contract_id,
                    "invocation-2",
                    &[Value::Principal(impl_contract_id.clone().into())],
                    |_, _| false,
                )
                .unwrap_err();

            if let ClarityError::Interpreter(Error::Unchecked(CheckErrors::TypeValueError(TypeSignature::TraitReferenceType(_), value))) = error {
                // pass
            } else {
                panic!("Expected an Interpreter(UncheckedError(TypeValue(TraitReferenceType, Principal))) during Epoch-2.2");
            };
        });
    });

    // should now be in Stacks 2.3, so the invocation should work again!
    info!("Sim height = {}", sim.height);
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &invoke_contract_id,
                    "invocation-1",
                    &[],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    info!("Sim height = {}", sim.height);
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &invoke_contract_id,
                    "invocation-2",
                    &[Value::Principal(impl_contract_id.clone().into())],
                    |_, _| false,
                )
                .unwrap();
        });
    });
}

/// Publish a trait that includes another trait in one of its functions in
/// epoch 2.05 and then invoke it in epoch 2.1. Test variations of epoch and
/// Clarity versions for the contract that uses the trait.
#[test]
fn trait_with_trait_invocation_cross_epoch() {
    let mut sim = ClarityTestSim::new();
    sim.epoch_bounds = vec![0, 3, 5];

    // Advance two blocks so we get to Stacks 2.05.
    sim.execute_next_block(|_env| {});
    sim.execute_next_block(|_env| {});

    let math_trait = "
        (define-trait math (
            (add (uint uint) (response uint uint))
            (sub (uint uint) (response uint uint))
        ))
    ";
    let compute_trait = "
        (use-trait math-trait .math-trait.math)
        (define-trait compute-trait (
            (compute (<math-trait> uint) (response uint uint))
        ))
    ";
    let impl_compute = "
        (impl-trait .compute.compute-trait)
        (use-trait math-trait .math-trait.math)
        (define-public (compute (m <math-trait>) (arg uint))
            (contract-call? m add arg u1)
        )
    ";
    let impl_math = "
    (impl-trait .math-trait.math)
    (define-read-only (add (x uint) (y uint)) (ok (+ x y)) )
    (define-read-only (sub (x uint) (y uint)) (ok (- x y)) )
    ";
    let use_compute = "
        (use-trait compute-trait .compute.compute-trait)
        (use-trait math-trait .math-trait.math)
        (define-public (do-it-static)
            (contract-call? .impl-compute compute .impl-math-trait u3)
        )
        (define-public (do-it-dyn (computer <compute-trait>) (math-contract <math-trait>) (x uint))
            (contract-call? computer compute math-contract x)
        )
    ";

    let math_contract_id = QualifiedContractIdentifier::local("math-trait").unwrap();
    let compute_contract_id = QualifiedContractIdentifier::local("compute").unwrap();
    let impl_math_id = QualifiedContractIdentifier::local("impl-math-trait").unwrap();
    let impl_compute_id = QualifiedContractIdentifier::local("impl-compute").unwrap();
    let use_compute_20_id = QualifiedContractIdentifier::local("use-compute-2-0").unwrap();
    let use_compute_21_c1_id = QualifiedContractIdentifier::local("use-compute-2-1-c1").unwrap();
    let use_compute_21_c2_id = QualifiedContractIdentifier::local("use-compute-2-1-c2").unwrap();

    let sender = StacksAddress::burn_address(false).into();

    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &math_contract_id,
                    clarity_version,
                    math_trait,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &math_contract_id,
                    clarity_version,
                    &ast,
                    math_trait,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&math_contract_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &compute_contract_id,
                    clarity_version,
                    compute_trait,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &compute_contract_id,
                    clarity_version,
                    &ast,
                    compute_trait,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&compute_contract_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &impl_compute_id,
                    clarity_version,
                    impl_compute,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &impl_compute_id,
                    clarity_version,
                    &ast,
                    impl_compute,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&impl_compute_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &impl_math_id,
                    clarity_version,
                    impl_math,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &impl_math_id,
                    clarity_version,
                    &ast,
                    impl_math,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&impl_math_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::default_for_epoch(epoch);
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &use_compute_20_id,
                    clarity_version,
                    use_compute,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &use_compute_20_id,
                    clarity_version,
                    &ast,
                    use_compute,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&use_compute_20_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
    });
    // Advance another block so we get to Stacks 2.1. This is the last block in 2.05
    sim.execute_next_block(|_| {});
    // now in Stacks 2.1
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        // Publish the contract that uses the trait in both Clarity 1 and Clarity 2
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::Clarity1;
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &use_compute_21_c1_id,
                    clarity_version,
                    use_compute,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &use_compute_21_c1_id,
                    clarity_version,
                    &ast,
                    use_compute,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&use_compute_21_c1_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
        conn.as_transaction(|clarity_db| {
            let clarity_version = ClarityVersion::Clarity2;
            let (ast, analysis) = clarity_db
                .analyze_smart_contract(
                    &use_compute_21_c2_id,
                    clarity_version,
                    use_compute,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            clarity_db
                .initialize_smart_contract(
                    &use_compute_21_c2_id,
                    clarity_version,
                    &ast,
                    use_compute,
                    None,
                    |_, _| false,
                )
                .unwrap();
            clarity_db
                .save_analysis(&use_compute_21_c2_id, &analysis)
                .expect("FATAL: failed to store contract analysis");
        });
    });

    // Call both functions in the 2.05 version
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &use_compute_20_id,
                    "do-it-static",
                    &[],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &use_compute_20_id,
                    "do-it-dyn",
                    &[
                        Value::Principal(impl_compute_id.clone().into()),
                        Value::Principal(impl_math_id.clone().into()),
                        Value::UInt(1),
                    ],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    // Call both functions in the 2.1 Clarity 1 version
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &use_compute_21_c1_id,
                    "do-it-static",
                    &[],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &use_compute_21_c1_id,
                    "do-it-dyn",
                    &[
                        Value::Principal(impl_compute_id.clone().into()),
                        Value::Principal(impl_math_id.clone().into()),
                        Value::UInt(1),
                    ],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    // Call both functions in the 2.1 Clarity 2 version
    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &use_compute_21_c2_id,
                    "do-it-static",
                    &[],
                    |_, _| false,
                )
                .unwrap();
        });
    });

    sim.execute_next_block_as_conn(|conn| {
        let epoch = conn.get_epoch();
        conn.as_transaction(|clarity_db| {
            clarity_db
                .run_contract_call(
                    &sender,
                    None,
                    &use_compute_21_c2_id,
                    "do-it-dyn",
                    &[
                        Value::Principal(impl_compute_id.into()),
                        Value::Principal(impl_math_id.into()),
                        Value::UInt(1),
                    ],
                    |_, _| false,
                )
                .unwrap();
        });
    });
}
