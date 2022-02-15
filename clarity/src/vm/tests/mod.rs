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
