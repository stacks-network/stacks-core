// Copyright (C) 2022-2026 Stacks Open Internet Foundation
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
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::errors::{ClarityEvalError, RuntimeError, VmExecutionError};
use clarity::vm::test_util::{TEST_BURN_STATE_DB, TEST_HEADER_DB};
use clarity::vm::types::QualifiedContractIdentifier;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::{ClarityMarfStore, ClarityMarfStoreTransaction};
use crate::clarity_vm::database::marf::MarfedKV;

pub fn with_marfed_environment<F>(f: F, top_level: bool)
where
    F: FnOnce(&mut OwnedEnvironment),
{
    let mut marf_kv = MarfedKV::temporary();

    {
        let mut store = marf_kv.begin(
            &StacksBlockId::sentinel(),
            &StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH),
        );

        store
            .as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB)
            .initialize();
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(
            &StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH),
            &StacksBlockId([1; 32]),
        );

        let mut owned_env = OwnedEnvironment::new(
            store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
            StacksEpochId::latest(),
        );
        // start an initial transaction.
        if !top_level {
            owned_env.begin();
        }

        f(&mut owned_env)
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
                contract,
                None,
            )
            .unwrap_err();
        eprintln!("{err}");
        match err {
            ClarityEvalError::Vm(VmExecutionError::Runtime(x, _)) => assert_eq!(
                x,
                RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash::from(vec![2; 32].as_slice()))
            ),
            _ => panic!("Unexpected error"),
        }
    }

    with_marfed_environment(test, true);
}
