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
use vm::database::ClarityDatabase;
use vm::errors::Error;
use vm::execute as vm_execute;
use vm::representations::SymbolicExpression;
use vm::types::{PrincipalData, ResponseData, Value};

use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::MemoryBackingStore;
use crate::core::{
    StacksEpoch, StacksEpochId, BITCOIN_REGTEST_FIRST_BLOCK_HASH,
    BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT, BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP,
};
use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, StacksBlockHeader,
    StacksBlockId, VRFSeed,
};
use crate::types::proof::ClarityMarfTrieId;

use super::costs::ExecutionCost;
use super::database::{BurnStateDB, HeadersDB};

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

pub struct UnitTestBurnStateDB {}
pub struct UnitTestHeaderDB {}

pub const TEST_HEADER_DB: UnitTestHeaderDB = UnitTestHeaderDB {};
pub const TEST_BURN_STATE_DB: UnitTestBurnStateDB = UnitTestBurnStateDB {};

impl HeadersDB for UnitTestHeaderDB {
    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        if *id_bhh
            == StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        {
            let first_block_hash =
                BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
            Some(first_block_hash)
        } else {
            None
        }
    }
    fn get_vrf_seed_for_block(&self, _bhh: &StacksBlockId) -> Option<VRFSeed> {
        None
    }
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        if *id_bhh
            == StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        {
            Some(FIRST_STACKS_BLOCK_HASH)
        } else {
            None
        }
    }
    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        if *id_bhh
            == StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP as u64)
        } else {
            None
        }
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        if *id_bhh
            == StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT as u32)
        } else {
            Some(1 + id_bhh.as_bytes()[0] as u32)
        }
    }
    fn get_miner_address(&self, _id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        None
    }
}

impl BurnStateDB for UnitTestBurnStateDB {
    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        None
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        None
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
        })
    }

    fn get_stacks_epoch_by_epoch_id(&self, _epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        self.get_stacks_epoch(0)
    }
}

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
            .as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB)
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
            OwnedEnvironment::new(store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB));
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
