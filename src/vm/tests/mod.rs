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

use chainstate::stacks::index::storage::TrieFileStorage;
use core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use util::hash::hex_bytes;
use vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use vm::contracts::Contract;
use vm::database::{ClarityDatabase, NULL_BURN_STATE_DB, NULL_HEADER_DB};
use vm::errors::Error;
use vm::execute as vm_execute;
use vm::representations::SymbolicExpression;
use vm::types::{PrincipalData, ResponseData, Value};

use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::MemoryBackingStore;
use crate::types::chainstate::{StacksBlockHeader, StacksBlockId};
use crate::types::proof::ClarityMarfTrieId;

mod assets;
mod contracts;
pub mod costs;
mod datamaps;
mod defines;
mod events;
mod forking;
mod large_contract;
mod sequences;
mod simple_apply_eval;
mod traits;

pub fn with_memory_environment<F>(f: F, top_level: bool)
where
    F: FnOnce(&mut OwnedEnvironment) -> (),
{
    let mut marf_kv = MemoryBackingStore::new();

    let mut owned_env = OwnedEnvironment::new(marf_kv.as_clarity_db());
    // start an initial transaction.
    if !top_level {
        owned_env.begin();
    }

    f(&mut owned_env)
}

pub fn with_marfed_environment<F>(f: F, top_level: bool)
where
    F: FnOnce(&mut OwnedEnvironment) -> (),
{
    let mut marf_kv = MarfedKV::temporary();

    {
        let mut store = marf_kv.begin(
            &StacksBlockId::sentinel(),
            &StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            ),
        );

        store
            .as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB)
            .initialize();
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(
            &StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            ),
            &StacksBlockId([1 as u8; 32]),
        );

        let mut owned_env =
            OwnedEnvironment::new(store.as_clarity_db(&NULL_HEADER_DB, &NULL_BURN_STATE_DB));
        // start an initial transaction.
        if !top_level {
            owned_env.begin();
        }

        f(&mut owned_env)
    }
}

pub fn execute(s: &str) -> Value {
    vm_execute(s).unwrap().unwrap()
}

pub fn symbols_from_values(vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.into_iter()
        .map(|value| SymbolicExpression::atom_value(value))
        .collect()
}

pub fn is_committed(v: &Value) -> bool {
    eprintln!("is_committed?: {}", v);

    match v {
        Value::Response(ref data) => data.committed,
        _ => false,
    }
}

pub fn is_err_code(v: &Value, e: u128) -> bool {
    eprintln!("is_err_code?: {}", v);
    match v {
        Value::Response(ref data) => !data.committed && *data.data == Value::UInt(e),
        _ => false,
    }
}
