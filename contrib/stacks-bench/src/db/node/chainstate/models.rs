// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use anyhow::{Result, bail};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Text};
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockId};

use crate::Network;

#[derive(Queryable, Debug)]
#[diesel(table_name = db_config)]
pub struct DbConfig {
    pub version: i32,
    pub mainnet: bool,
    pub chain_id: i32,
}

impl DbConfig {
    /// Asserts that this database configuration is compatible with the target network.
    pub fn assert_matches_network(&self, network: Network) -> Result<()> {
        let expected_mainnet = network.is_mainnet();
        let expected_chain_id = network.to_chain_id();

        if self.mainnet != expected_mainnet {
            bail!(
                "Network mismatch: CLI specified {}, but DB is configured for {}",
                network,
                if self.mainnet {
                    "mainnet"
                } else {
                    "testnet/regtest"
                }
            );
        }

        // Cast i32 from DB to u32 for comparison
        let db_chain_id = self.chain_id as u32;
        if db_chain_id != expected_chain_id {
            bail!(
                "Chain ID mismatch: CLI expects {} (0x{:x}), but DB has {} (0x{:x})",
                expected_chain_id,
                expected_chain_id,
                db_chain_id,
                db_chain_id
            );
        }

        Ok(())
    }

    pub fn is_mainnet(&self) -> bool {
        self.mainnet
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id as u32
    }
}

#[derive(Queryable, QueryableByName, Debug, Clone)]
pub struct BlockHeader {
    #[diesel(sql_type = Text)]
    pub index_block_hash: String,
    #[diesel(sql_type = Text)]
    pub block_hash: String,
    #[diesel(sql_type = Text)]
    pub parent_block_id: String,
    #[diesel(sql_type = BigInt)]
    pub block_height: i64,
    #[diesel(sql_type = Text)]
    pub consensus_hash: String,
    #[diesel(sql_type = Text)]
    pub burn_header_hash: String,
    #[diesel(sql_type = BigInt)]
    pub burn_header_height: i64,
}

impl TryInto<crate::StacksBlockHeader> for BlockHeader {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<crate::StacksBlockHeader> {
        Ok(crate::StacksBlockHeader {
            id: StacksBlockId::from_hex(&self.index_block_hash)?,
            hash: BlockHeaderHash::from_hex(&self.block_hash)?,
            parent_id: StacksBlockId::from_hex(&self.parent_block_id)?,
            height: self.block_height.try_into()?,
            burn_block_hash: BurnchainHeaderHash::from_hex(&self.burn_header_hash)?,
            burn_block_height: self.burn_header_height.try_into()?,
        })
    }
}
