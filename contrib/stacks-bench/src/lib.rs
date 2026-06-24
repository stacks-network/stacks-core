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

use std::fmt::Display;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::db::StacksChainState;
use clarity::codec::StacksMessageCodec;
use clarity::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use clarity::types::StacksEpochId;
use clarity::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};
use serde::{Deserialize, Serialize};
use stacks_common::types::chainstate::StacksBlockId;

use crate::db::ReadOnly;
use crate::db::node::NakamotoDb;

pub mod baseline;
pub mod bench_events;
pub mod blocks;
pub mod context;
pub mod db;
pub mod filter;
pub mod indexer;
pub mod metrics;
pub mod paths;
pub mod provenance;
pub mod replay;
pub mod shadow;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StacksEpoch {
    epoch_id: StacksEpochId,
    network_epoch_id: u32,
    start_block_height: u64,
    end_block_height: u64,
    write_length_budget: u64,
    write_count_budget: u64,
    read_length_budget: u64,
    read_count_budget: u64,
    runtime_budget: u64,
}

impl Display for StacksEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Epoch {}", self.epoch_id)
    }
}

impl StacksEpoch {
    pub fn epoch_id_le_bytes(&self) -> [u8; 4] {
        (self.epoch_id as u32).to_le_bytes()
    }
    pub fn epoch_id(&self) -> StacksEpochId {
        self.epoch_id
    }

    pub fn start_block_height(&self) -> u64 {
        self.start_block_height
    }

    pub fn end_block_height(&self) -> u64 {
        self.end_block_height
    }
}

impl From<&StacksEpoch> for stacks_common::types::StacksEpoch<clarity::vm::costs::ExecutionCost> {
    fn from(e: &StacksEpoch) -> Self {
        Self {
            epoch_id: e.epoch_id,
            start_height: e.start_block_height,
            end_height: e.end_block_height,
            block_limit: clarity::vm::costs::ExecutionCost {
                write_length: e.write_length_budget,
                write_count: e.write_count_budget,
                read_length: e.read_length_budget,
                read_count: e.read_count_budget,
                runtime: e.runtime_budget,
            },
            network_epoch: StacksEpochId::network_epoch(e.epoch_id),
        }
    }
}

pub trait ResolveEpochFromHeight {
    fn resolve_stacks_epoch(&self, height: u64) -> Option<StacksEpochId>;
}

impl ResolveEpochFromHeight for [StacksEpoch] {
    fn resolve_stacks_epoch(&self, height: u64) -> Option<StacksEpochId> {
        for epoch in self {
            // Use half-open interval [start, end) to handle overlapping boundaries
            // where the end of one epoch is the start (activation) of the next.
            if height >= epoch.start_block_height && height < epoch.end_block_height {
                return Some(epoch.epoch_id);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StacksBlockRef {
    Hash(BlockHeaderHash),
    Height(u64),
}

impl FromStr for StacksBlockRef {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(height) = s.parse::<u64>() {
            Ok(Self::Height(height))
        } else if let Ok(hash) = BlockHeaderHash::from_hex(s) {
            Ok(Self::Hash(hash))
        } else {
            bail!(
                "invalid block identifier: {s} \
                 (expected u64 height, hex index_block_hash, or hex block_hash)"
            )
        }
    }
}

impl std::fmt::Display for StacksBlockRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StacksBlockRef::Hash(hash) => write!(f, "{hash}"),
            StacksBlockRef::Height(h) => write!(f, "{h}"),
        }
    }
}

/// The Stacks network from which the node data is sourced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    pub fn is_mainnet(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    pub fn to_chain_id(&self) -> u32 {
        match self {
            Self::Mainnet => CHAIN_ID_MAINNET,
            Self::Testnet | Self::Regtest => CHAIN_ID_TESTNET,
        }
    }

    /// Validates that the provided database configuration matches this network.
    pub fn validate_chainstate(&self, db_mainnet: bool, db_chain_id: u32) -> Result<(), String> {
        let expected_mainnet = self.is_mainnet();
        let expected_chain_id = self.to_chain_id();

        if db_mainnet != expected_mainnet {
            return Err(format!(
                "Network mismatch: CLI specified {self}, but DB is configured for {}",
                if db_mainnet {
                    "mainnet"
                } else {
                    "testnet/regtest"
                }
            ));
        }

        if db_chain_id != expected_chain_id {
            return Err(format!(
                "Chain ID mismatch: CLI expects {expected_chain_id} (0x{expected_chain_id:x}), \
                but DB has {db_chain_id} (0x{db_chain_id:x})",
            ));
        }

        Ok(())
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest => write!(f, "regtest"),
        }
    }
}

impl FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(anyhow!("invalid network: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BlockEra {
    PreNakamoto,
    Nakamoto,
}

#[derive(Debug, Clone)]
pub struct StacksBlockHeader {
    pub id: StacksBlockId,
    pub hash: BlockHeaderHash,
    pub height: u64,
    pub parent_id: StacksBlockId,
    pub burn_block_height: u32,
    pub burn_block_hash: BurnchainHeaderHash,
}

pub enum BlockSource<'a, P: AsRef<Path>> {
    Disk(P),
    NakamotoDb(&'a mut NakamotoDb<ReadOnly>),
}

pub struct StacksBlockLoader<'a> {
    blocks_dir: PathBuf,
    naka_db: &'a mut NakamotoDb<ReadOnly>,
    naka_db_cutoff_height: u64,
}

impl<'a> StacksBlockLoader<'a> {
    pub fn new<P: AsRef<Path>>(
        blocks_dir: P,
        naka_db: &'a mut NakamotoDb<ReadOnly>,
        naka_db_cutoff_height: u64,
    ) -> Self {
        Self {
            blocks_dir: blocks_dir.as_ref().to_path_buf(),
            naka_db,
            naka_db_cutoff_height,
        }
    }

    pub fn get_block_source(&mut self, block_height: u64) -> BlockSource<'_, impl AsRef<Path>> {
        if block_height >= self.naka_db_cutoff_height {
            return BlockSource::NakamotoDb(self.naka_db);
        }
        BlockSource::Disk(self.blocks_dir.clone())
    }

    async fn load_pre_nakamoto_block(
        &self,
        block_id: &StacksBlockId,
    ) -> Result<blockstack_lib::chainstate::stacks::StacksBlock> {
        let blocks_dir_str = self.blocks_dir.to_string_lossy();
        let block_path = StacksChainState::get_index_block_path(&blocks_dir_str, block_id)
            .context("Failed to resolve block path")?;

        let stacks_block = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut file = std::fs::File::open(&block_path)
                .with_context(|| format!("Failed to open block file: {:?}", block_path))?;

            blockstack_lib::chainstate::stacks::StacksBlock::consensus_deserialize(&mut file)
                .with_context(|| {
                    format!(
                        "Failed to deserialize StacksBlock from file: {:?}",
                        block_path
                    )
                })
        })
        .await
        .context("Failed to join blocking task")??;

        Ok(stacks_block)
    }

    async fn load_nakamoto_block(
        &mut self,
        block_id: &StacksBlockId,
    ) -> Result<blockstack_lib::chainstate::nakamoto::NakamotoBlock> {
        let naka_block_bytes = self
            .naka_db
            .get_nakamoto_block(block_id)
            .await
            .with_context(|| format!("Failed to load Nakamoto block {block_id} from DB"))?
            .ok_or_else(|| anyhow!("Nakamoto block not found: {block_id}"))?
            .data;

        let mut cursor = Cursor::new(naka_block_bytes);
        NakamotoBlock::consensus_deserialize(&mut cursor)
            .with_context(|| format!("Failed to deserialize Nakamoto block {block_id}"))
    }

    pub async fn load_block(&mut self, block: &StacksBlockHeader) -> Result<StacksBlock> {
        let block_id = &block.id;

        if block.height >= self.naka_db_cutoff_height {
            let naka_block = self
                .load_nakamoto_block(block_id)
                .await
                .with_context(|| format!("Failed to load Nakamoto block {block_id}"))?;
            Ok(StacksBlock::Nakamoto(naka_block))
        } else {
            let stacks_block = self
                .load_pre_nakamoto_block(block_id)
                .await
                .with_context(|| format!("Failed to load StacksBlock {block_id} from disk"))?;
            Ok(StacksBlock::PreNakamoto(stacks_block))
        }
    }
}

#[derive(Debug, Clone)]
pub enum StacksBlock {
    PreNakamoto(blockstack_lib::chainstate::stacks::StacksBlock),
    Nakamoto(blockstack_lib::chainstate::nakamoto::NakamotoBlock),
}

impl AsRef<[StacksTransaction]> for StacksBlock {
    fn as_ref(&self) -> &[StacksTransaction] {
        match self {
            StacksBlock::PreNakamoto(block) => &block.txs,
            StacksBlock::Nakamoto(block) => &block.txs,
        }
    }
}

impl StacksBlock {
    pub fn transactions(&self) -> &[StacksTransaction] {
        match self {
            StacksBlock::PreNakamoto(block) => &block.txs,
            StacksBlock::Nakamoto(block) => &block.txs,
        }
    }

    pub fn into_transactions_vec(self) -> Vec<StacksTransaction> {
        match self {
            StacksBlock::PreNakamoto(block) => block.txs,
            StacksBlock::Nakamoto(block) => block.txs,
        }
    }
}
