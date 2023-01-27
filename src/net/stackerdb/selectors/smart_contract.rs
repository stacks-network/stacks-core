// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use crate::net::stackerdb::{SmartContractSelector, StackerDBConfig, StackerDBSelector};

use crate::net::Error as net_error;

use crate::chainstate::stacks::boot::{RawRewardSetEntry, RewardSet};

use crate::clarity_vm::clarity::ClarityReadOnlyConnection;

use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksAddress;

impl StackerDBSelector for SmartContractSelector {
    /// Load up the config from this smart contract
    fn load_config(
        &self,
        _clarity_conn: &ClarityReadOnlyConnection,
        _rc_consensus_hash: &ConsensusHash,
    ) -> Result<StackerDBConfig, net_error> {
        unimplemented!()
    }

    /// Given a reward set, figure out the list of principals who must sign off on each
    /// blob.
    fn find_slots(
        &self,
        _clarity_conn: &ClarityReadOnlyConnection,
        _rc_consensus_hash: &ConsensusHash,
        _reward_set: &RewardSet,
        mut _registered_addrs: Vec<RawRewardSetEntry>,
    ) -> Result<Vec<(StacksAddress, u64)>, net_error> {
        unimplemented!()
    }
}
