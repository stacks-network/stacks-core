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

use util::hash::hex_bytes;
use vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use vm::contracts::Contract;
use vm::database::ClarityDatabase;
use vm::database::MemoryBackingStore;
use vm::errors::Error;
use vm::representations::SymbolicExpression;
use vm::types::{PrincipalData, ResponseData, Value};
use vm::StacksEpoch;

use stacks_common::consts::{
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::{StacksEpochId, PEER_VERSION_EPOCH_2_0};

use vm::{
    analysis::AnalysisDatabase,
    clarity::{ClarityConnection, TransactionConnection},
    contexts::AssetMap,
    costs::{ExecutionCost, LimitedCostTracker},
    database::{BurnStateDB, HeadersDB},
};

use super::events::StacksTransactionEvent;
pub use super::test_util::*;

mod assets;
mod contracts;
mod datamaps;
mod defines;
mod events;
mod sequences;
mod simple_apply_eval;
mod traits;

// pub struct TestBlockConnection {
//     store: MemoryBackingStore,
//     epoch: StacksEpochId,
// }

// pub struct TestTxConnection<'a> {
//     store: &'a mut MemoryBackingStore,
//     epoch: StacksEpochId,
// }

// impl TestBlockConnection {
//     pub fn new(epoch: StacksEpochId) -> TestBlockConnection {
//         TestBlockConnection {
//             store: MemoryBackingStore::new(),
//             epoch
//         }
//     }

//     pub fn start_transaction_processing<'a>(&'a mut self) -> TestTxConnection<'a> {
//         TestTxConnection {
//             store: &mut self.store,
//             epoch: self.epoch
//         }
//     }

//     pub fn as_transaction<F, R>(&mut self, todo: F) -> R
//     where
//         F: FnOnce(&mut TestTxConnection) -> R,
//     {
//         let mut tx = self.start_transaction_processing();
//         let r = todo(&mut tx);
//         tx.commit();
//         r
//     }
// }

// impl <'a> ClarityConnection for TestTxConnection <'a> {
//     fn with_clarity_db_readonly_owned<F, R>(&mut self, to_do: F) -> R
//     where
//         F: FnOnce(ClarityDatabase) -> (R, ClarityDatabase) {
//         let db = self.store.as_clarity_db();
//         let (result, _) = to_do(db);
//         result
//     }

//     fn with_analysis_db_readonly<F, R>(&mut self, to_do: F) -> R
//     where
//         F: FnOnce(&mut AnalysisDatabase) -> R {
//         let mut db = self.store.as_analysis_db();
//         to_do(&mut db)
//     }

//     fn get_epoch(&self) -> StacksEpochId {
//         self.epoch
//     }
// }

// impl <'a> TransactionConnection for TestTxConnection <'a> {
//     fn with_abort_callback<F, A, R, E>(
//         &mut self,
//         to_do: F,
//         abort_call_back: A,
//     ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>, bool), E>
//     where
//         A: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool,
//         F: FnOnce(
//             &mut OwnedEnvironment,
//         ) -> Result<(R, AssetMap, Vec<StacksTransactionEvent>), E>
//     {
//         let mut db = self.store.as_clarity_db();
//         db.begin();
//         let mut owned_env = OwnedEnvironment::new(db);
//         let result = to_do(&mut owned_env);
//         let (mut db, cost_track) = owned_env.destruct().unwrap();
//         match result {
//             Ok((value, asset_map, events)) => {
//                 let aborted = abort_call_back(&asset_map, &mut db);
//                 if aborted {
//                     db.roll_back();
//                 } else {
//                     db.commit();
//                 }
//                 Ok((value, asset_map, events, aborted))
//             }
//             Err(e) => {
//                 db.roll_back();
//                 Err(e)
//             }
//         }
//     }

//     fn with_analysis_db<F, R>(&mut self, to_do: F) -> R
//     where
//         F: FnOnce(&mut AnalysisDatabase, LimitedCostTracker) -> (LimitedCostTracker, R) {

//         let cost_tracker = LimitedCostTracker::new_free();
//         let (_cost_tracker, result) = to_do(&mut self.store.as_analysis_db(), cost_tracker);
//         result
//     }
// }

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
    //     let mut marf_kv = MarfedKV::temporary();

    //     {
    //         let mut store = marf_kv.begin(
    //             &StacksBlockId::sentinel(),
    //             &StacksBlockId::new(
    //                 &FIRST_BURNCHAIN_CONSENSUS_HASH,
    //                 &FIRST_STACKS_BLOCK_HASH,
    //             ),
    //         );

    //         store
    //             .as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB)
    //             .initialize();
    //         store.test_commit();
    //     }

    //     {
    //         let mut store = marf_kv.begin(
    //             &StacksBlockId::new(
    //                 &FIRST_BURNCHAIN_CONSENSUS_HASH,
    //                 &FIRST_STACKS_BLOCK_HASH,
    //             ),
    //             &StacksBlockId([1 as u8; 32]),
    //         );

    //         let mut owned_env =
    //             OwnedEnvironment::new(store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB));
    //         // start an initial transaction.
    //         if !top_level {
    //             owned_env.begin();
    //         }

    //         f(&mut owned_env)
    //     }
}
