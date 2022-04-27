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

use crate::vm::contexts::{Environment, GlobalContext, OwnedEnvironment};
use crate::vm::contracts::Contract;
use crate::vm::database::ClarityDatabase;
use crate::vm::database::MemoryBackingStore;
use crate::vm::errors::Error;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{PrincipalData, ResponseData, Value};
use crate::vm::StacksEpoch;
use stacks_common::util::hash::hex_bytes;

use stacks_common::consts::{
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::{StacksEpochId, PEER_VERSION_EPOCH_2_0};

use crate::vm::{
    analysis::AnalysisDatabase,
    clarity::{ClarityConnection, TransactionConnection},
    contexts::AssetMap,
    costs::{ExecutionCost, LimitedCostTracker},
    database::{BurnStateDB, HeadersDB},
};

use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};

use super::events::StacksTransactionEvent;
pub use super::test_util::*;

mod assets;
mod contracts;
mod datamaps;
mod defines;
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

/// Determine whether or not to use the testnet or mainnet chain ID, given whether or not the
/// caller expects to use mainnet or testnet.
///
/// WARNING TO THE READER:  This is *test-only* code.  The existence of this method does *not*
/// imply that there is a canonical, supported way to convert a `bool` into a chain ID.  The fact
/// that Stacks has a separate chain ID for its testnet (0x80000000) is an accident.  In general, a
/// Stacks blockchain instance only needs _one_ chain ID, and can use the mainnet/testnet field in
/// its transactions to determine whether or not a transaction should be mined in a given chain.
/// Going forward, you should *never* use a different chain ID for your testnet.
///
/// So, do *not* refactor this code to use this conversion in production.
pub fn test_only_mainnet_to_chain_id(mainnet: bool) {
    // seriously -- don't even think about it.
    if mainnet {
        CHAIN_ID_MAINNET
    } else {
        CHAIN_ID_TESTNET
    }
}
