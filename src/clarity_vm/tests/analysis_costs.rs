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

use crate::chainstate::stacks::index::storage::TrieFileStorage;
use crate::clarity_vm::clarity::ClarityInstance;
use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::TransactionConnection;
use clarity::vm::contexts::Environment;
use clarity::vm::contexts::{AssetMap, AssetMapEntry, GlobalContext, OwnedEnvironment};
use clarity::vm::contracts::Contract;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::errors::{CheckErrors, Error, RuntimeErrorType};
use clarity::vm::execute as vm_execute;
use clarity::vm::functions::NativeFunctions;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::test_util::{TEST_BURN_STATE_DB, TEST_HEADER_DB};
use clarity::vm::types::{
    AssetIdentifier, PrincipalData, QualifiedContractIdentifier, ResponseData, Value,
};
use stacks_common::util::hash::hex_bytes;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::ClarityConnection;
use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::tests::costs::get_simple_test;
use crate::types::chainstate::{BlockHeaderHash, StacksBlockId};
use crate::types::StacksEpochId;
use clarity::vm::ClarityVersion;

pub fn test_tracked_costs(prog: &str, use_mainnet: bool, epoch: StacksEpochId) -> ExecutionCost {
    let version = ClarityVersion::Clarity2;
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(use_mainnet, marf);

    let p1 = vm_execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
        .unwrap()
        .unwrap();

    let p1_principal = match p1 {
        Value::Principal(PrincipalData::Standard(ref data)) => data.clone(),
        _ => panic!(),
    };

    let contract_trait = "(define-trait trait-1 (
                            (foo-exec (int) (response int int))
                          ))";
    let contract_other = "(impl-trait .contract-trait.trait-1)
                          (define-map map-foo { a: int } { b: int })
                          (define-public (foo-exec (a int)) (ok 1))";

    let contract_self = format!(
        "(define-map map-foo {{ a: int }} {{ b: int }})
        (define-non-fungible-token nft-foo int)
        (define-fungible-token ft-foo)
        (define-data-var var-foo int 0)
        (define-constant tuple-foo (tuple (a 1)))
        (define-constant list-foo (list true))
        (define-constant list-bar (list 1))
        (use-trait trait-1 .contract-trait.trait-1)
        (define-public (execute (contract <trait-1>)) (ok {}))",
        prog
    );

    let self_contract_id = QualifiedContractIdentifier::new(p1_principal.clone(), "self".into());
    let other_contract_id =
        QualifiedContractIdentifier::new(p1_principal.clone(), "contract-other".into());
    let trait_contract_id =
        QualifiedContractIdentifier::new(p1_principal.clone(), "contract-trait".into());

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

        if epoch == StacksEpochId::Epoch2_05 {
            conn.initialize_epoch_2_05().unwrap();
        }

        conn.commit_block();
    }

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([1 as u8; 32]),
            &StacksBlockId([2 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        assert_eq!(
            conn.with_clarity_db_readonly(|db| db.get_clarity_epoch_version()),
            epoch
        );

        conn.as_transaction(|conn| {
            let (ct_ast, ct_analysis) = conn
                .analyze_smart_contract(
                    &trait_contract_id,
                    version,
                    contract_trait,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            conn.initialize_smart_contract(
                &trait_contract_id,
                version,
                &ct_ast,
                contract_trait,
                None,
                |_, _| false,
            )
            .unwrap();
            conn.save_analysis(&trait_contract_id, &ct_analysis)
                .unwrap();
        });

        conn.commit_block();
    }

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([2 as u8; 32]),
            &StacksBlockId([3 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );
        conn.as_transaction(|conn| {
            let (ct_ast, ct_analysis) = conn
                .analyze_smart_contract(
                    &other_contract_id,
                    version,
                    contract_other,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            conn.initialize_smart_contract(
                &other_contract_id,
                version,
                &ct_ast,
                contract_other,
                None,
                |_, _| false,
            )
            .unwrap();
            conn.save_analysis(&other_contract_id, &ct_analysis)
                .unwrap();
        });

        conn.commit_block();
    }

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId([3 as u8; 32]),
            &StacksBlockId([4 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        conn.as_transaction(|conn| {
            let (ct_ast, ct_analysis) = conn
                .analyze_smart_contract(
                    &self_contract_id,
                    version,
                    &contract_self,
                    ASTRules::PrecheckSize,
                )
                .unwrap();
            conn.initialize_smart_contract(
                &self_contract_id,
                version,
                &ct_ast,
                &contract_self,
                None,
                |_, _| false,
            )
            .unwrap();
            conn.save_analysis(&self_contract_id, &ct_analysis).unwrap();
        });

        conn.commit_block().get_total()
    }
}

fn test_all(use_mainnet: bool) {
    let baseline = test_tracked_costs("1", use_mainnet, StacksEpochId::Epoch20);

    for f in NativeFunctions::ALL.iter() {
        let test = get_simple_test(f);
        let cost = test_tracked_costs(test, use_mainnet, StacksEpochId::Epoch20);
        assert!(cost.exceeds(&baseline));
    }
}

#[test]
fn test_all_mainnet() {
    test_all(true)
}

#[test]
fn test_all_testnet() {
    test_all(false)
}

fn epoch_205_test_all(use_mainnet: bool) {
    let baseline = test_tracked_costs("1", use_mainnet, StacksEpochId::Epoch2_05);

    for f in NativeFunctions::ALL.iter() {
        let test = get_simple_test(f);
        let cost = test_tracked_costs(test, use_mainnet, StacksEpochId::Epoch2_05);
        assert!(cost.exceeds(&baseline));
    }
}

#[test]
fn epoch_205_test_all_mainnet() {
    epoch_205_test_all(true)
}

#[test]
fn epoch_205_test_all_testnet() {
    epoch_205_test_all(false)
}
