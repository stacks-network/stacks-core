// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::collections::{HashMap, HashSet};
use std::fmt;

use clarity::vm::types::StacksAddressExtensions;
use madhouse::State;
use stacks_common::types::StacksEpochId;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::tests::consensus::{ConsensusChain, FAUCET_PRIV_KEY};
use crate::core::test_util::to_addr;

/// Model + real chain state for the Epoch34 madhouse scenario. Created fresh
/// per proptest case via `Default`. Commands update both the model fields and
/// the real `ConsensusChain`, then assert they agree.
pub struct Epoch33ToEpoch34TestState {
    /// Real chain, initially booted to Epoch33. `'static` because
    /// `ConsensusChain::new` passes `observer: None`.
    pub chain: ConsensusChain<'static>,
    /// Model: which epoch we believe we are in.
    pub current_epoch: StacksEpochId,
    /// Model: next nonce for the faucet account.
    pub next_nonce: u64,
    /// Model: set of deployed contract names.
    pub deployed: HashSet<String>,
    /// Model: STX balance of the with-stx contract. Updated on deploy (funded)
    /// and on successful as-contract? calls (drained).
    pub contract_stx_balance: u64,
}

impl fmt::Debug for Epoch33ToEpoch34TestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch33ToEpoch34TestState")
            .field("chain", &"...")
            .field("current_epoch", &self.current_epoch)
            .field("nonce", &self.next_nonce)
            .field("deployed", &self.deployed)
            .field("contract_stx_balance", &self.contract_stx_balance)
            .finish()
    }
}

/// Initial STX balance for the faucet account.
const INITIAL_BALANCE: u64 = 1_000_000_000;

impl Default for Epoch33ToEpoch34TestState {
    fn default() -> Self {
        let faucet_addr = to_addr(&FAUCET_PRIV_KEY).to_account_principal();
        let initial_balances = vec![(faucet_addr, INITIAL_BALANCE)];

        let mut num_blocks_per_epoch = HashMap::new();
        // Short epochs to speed up tests

        num_blocks_per_epoch.insert(StacksEpochId::Epoch33, 10);
        num_blocks_per_epoch.insert(StacksEpochId::Epoch34, 20);

        let mut chain =
            ConsensusChain::new("madhouse-epoch34", initial_balances, num_blocks_per_epoch);

        // Advance into Epoch33 using the miner key to avoid polluting the
        // faucet nonce.
        let miner_key = chain.test_chainstate.miner.nakamoto_miner_key();
        chain
            .test_chainstate
            .advance_into_epoch(&miner_key, StacksEpochId::Epoch33);

        Self {
            chain,
            current_epoch: StacksEpochId::Epoch33,
            next_nonce: 0,
            deployed: HashSet::new(),
            contract_stx_balance: 0,
        }
    }
}

impl Epoch33ToEpoch34TestState {
    /// Whether the model believes we are in Epoch34 or later.
    pub fn is_epoch34(&self) -> bool {
        self.current_epoch >= StacksEpochId::Epoch34
    }

    /// Query the chain's current epoch from the sortition DB. Used to verify
    /// the model agrees with the chain before branching on epoch-dependent
    /// behavior.
    pub fn chain_epoch(&mut self) -> StacksEpochId {
        let sortdb = self.chain.test_chainstate.sortdb.take().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("failed to get canonical burn tip");
        let epoch = SortitionDB::get_stacks_epoch(sortdb.conn(), tip.block_height)
            .expect("failed to query epoch")
            .expect("no epoch for current burn tip");
        self.chain.test_chainstate.sortdb = Some(sortdb);
        epoch.epoch_id
    }
}

impl State for Epoch33ToEpoch34TestState {}
