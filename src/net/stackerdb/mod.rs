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

#[cfg(test)]
pub mod tests;

use std::collections::HashSet;

use crate::net::ContractId;
use crate::net::NeighborKey;
use crate::net::StackerDBChunkData;

/// maximum chunk inventory size
pub const STACKERDB_INV_MAX: u32 = 4096;

/// Final result of synchronizing state with a remote set of DB replicas
pub struct StackerDBSyncResult {
    /// which contract this is a replica for
    pub contract_id: ContractId,
    /// list of data to store
    pub chunks_to_store: Vec<StackerDBChunkData>,
    /// dead neighbors we can disconnect from
    pub dead: HashSet<NeighborKey>,
}
