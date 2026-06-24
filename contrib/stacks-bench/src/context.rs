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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow};
use blockstack_lib::burnchains::Burnchain;
use blockstack_lib::chainstate::burn::db::sortdb::SortitionDB;
use blockstack_lib::chainstate::stacks::db::StacksChainState;
use blockstack_lib::chainstate::stacks::index::marf::MARFOpenOpts;
use blockstack_lib::chainstate::stacks::index::storage::TrieHashCalculationMode;
use blockstack_lib::core::{STACKS_EPOCHS_MAINNET, STACKS_EPOCHS_REGTEST, STACKS_EPOCHS_TESTNET};
use clarity::vm::costs::ExecutionCost;
use futures::{Stream, StreamExt};
use stacks_common::types::StacksEpochId;

use crate::blocks::{BackwardsBlockStream, BlockRef};
use crate::db::node::sortition::SortitionDb;
use crate::db::node::{ChainStateDb, NakamotoDb};
use crate::db::{DbOpenForRead, ReadOnly};
use crate::paths::{BurnChainDir, ChainStateDir};
use crate::{
    BlockEra, Network, ResolveEpochFromHeight, StacksBlockHeader, StacksBlockRef, StacksEpoch,
};

const BURNCHAIN_NAME: &str = "bitcoin";

/// Returns an epoch list suitable for opening stackslib against a copied DB.
fn normalize_sortdb_open_epochs(
    network: Network,
    archive_epochs: &[StacksEpoch],
) -> Vec<StacksEpoch> {
    let builtin_epochs = match network {
        Network::Mainnet => Some(STACKS_EPOCHS_MAINNET.as_ref()),
        Network::Testnet => Some(STACKS_EPOCHS_TESTNET.as_ref()),
        Network::Regtest => Some(STACKS_EPOCHS_REGTEST.as_ref()),
    };

    let Some(builtin_epochs) = builtin_epochs else {
        return archive_epochs.to_vec();
    };

    let builtin_epochs: Vec<StacksEpoch> = builtin_epochs.iter().map(epoch_from_core).collect();
    if source_epochs_are_compatible_prefix(archive_epochs, &builtin_epochs) {
        builtin_epochs
    } else {
        archive_epochs.to_vec()
    }
}

/// Converts stackslib's epoch representation into the local app model.
fn epoch_from_core(epoch: &stacks_common::types::StacksEpoch<ExecutionCost>) -> StacksEpoch {
    StacksEpoch {
        epoch_id: epoch.epoch_id,
        network_epoch_id: epoch.network_epoch.into(),
        start_block_height: epoch.start_height,
        end_block_height: epoch.end_height,
        write_length_budget: epoch.block_limit.write_length,
        write_count_budget: epoch.block_limit.write_count,
        read_length_budget: epoch.block_limit.read_length,
        read_count_budget: epoch.block_limit.read_count,
        runtime_budget: epoch.block_limit.runtime,
    }
}

/// Checks whether source epochs are an older prefix of the built-in schedule.
fn source_epochs_are_compatible_prefix(
    source_epochs: &[StacksEpoch],
    builtin_epochs: &[StacksEpoch],
) -> bool {
    if source_epochs.is_empty() || source_epochs.len() > builtin_epochs.len() {
        return false;
    }

    source_epochs.iter().enumerate().all(|(idx, source_epoch)| {
        let Some(builtin_epoch) = builtin_epochs.get(idx) else {
            return false;
        };

        if idx + 1 == source_epochs.len() && source_epochs.len() < builtin_epochs.len() {
            epochs_match_except_end_height(source_epoch, builtin_epoch)
        } else {
            source_epoch == builtin_epoch
        }
    })
}

/// Compares epoch identity and limits while allowing an older open-ended tail.
fn epochs_match_except_end_height(left: &StacksEpoch, right: &StacksEpoch) -> bool {
    left.epoch_id == right.epoch_id
        && left.network_epoch_id == right.network_epoch_id
        && left.start_block_height == right.start_block_height
        && left.write_length_budget == right.write_length_budget
        && left.write_count_budget == right.write_count_budget
        && left.read_length_budget == right.read_length_budget
        && left.read_count_budget == right.read_count_budget
        && left.runtime_budget == right.runtime_budget
}

pub struct BenchEnvOpts {
    /// The Stacks network to target for the benchmark. Typically determined
    /// based on the source chainstate, but may be overridden.
    network: Network,
    /// The Stacks chain ID to target for the benchmark. Typically determined
    /// based on the source chainstate, but may be overridden.
    chain_id: u32,
    /// Optional start block for the benchmark. If not provided, defaults to the
    /// genesis block.
    start_at: Option<StacksBlockRef>,
    /// Optional end block for the benchmark.
    ///
    /// If provided it must be a descendent of the determined starting block; if
    /// not provided, it defaults to the current tip.
    end_at: Option<StacksBlockRef>,
    /// Optional block count to determine the end block based on the start block.
    block_count: Option<u32>,
    /// The chain tip to be used by the context.
    tip: Option<StacksBlockRef>,
    /// The epochs which are applicable for the context.
    epochs: Vec<StacksEpoch>,
    /// Epochs supplied to stackslib when opening the shadow sortition DB.
    ///
    /// This can differ from `epochs` for historical chainstates. `epochs` is also
    /// used by the current replay planner with Stacks block heights, so keep it
    /// faithful to the archive. Opening stackslib, however, needs the current
    /// network epoch schedule so runtime epoch validation accepts old DBs.
    sortdb_open_epochs: Vec<StacksEpoch>,
}

impl BenchEnvOpts {
    pub fn new<I>(network: Network, chain_id: u32, epochs: I) -> Result<Self>
    where
        I: IntoIterator<Item = StacksEpoch>,
    {
        let epochs: Vec<StacksEpoch> = epochs.into_iter().collect();
        let sortdb_open_epochs = normalize_sortdb_open_epochs(network, &epochs);

        Ok(Self {
            network,
            chain_id,
            start_at: None,
            end_at: None,
            block_count: None,
            tip: None,
            epochs,
            sortdb_open_epochs,
        })
    }

    pub fn with_start_block<T: Into<Option<StacksBlockRef>>>(mut self, start: T) -> Self {
        self.start_at = start.into();
        self
    }

    pub fn with_end_block<T: Into<Option<StacksBlockRef>>>(mut self, end: T) -> Self {
        self.end_at = end.into();
        self
    }

    pub fn with_tip<T: Into<Option<StacksBlockRef>>>(mut self, tip: T) -> Self {
        self.tip = tip.into();
        self
    }

    pub fn with_block_count<T: Into<Option<u32>>>(mut self, count: T) -> Self {
        self.block_count = count.into();
        self
    }
}

pub struct BenchEnv {
    pub is_mainnet: bool,
    pub working_dir: PathBuf,
    pub chainstate_dir: ChainStateDir,
    pub burnchain_dir: BurnChainDir,
    pub epochs: Arc<Vec<StacksEpoch>>,
    pub sortdb_open_epochs: Arc<Vec<StacksEpoch>>,
    pub network: Network,
    pub chain_id: u32,
}

impl BenchEnv {
    pub async fn initialize<P: AsRef<Path>>(
        working_dir: P,
        opts: BenchEnvOpts,
    ) -> Result<(Self, BlockRef)> {
        let burnchain_dir = BurnChainDir::from_node_root(working_dir.as_ref());
        let chainstate_dir = ChainStateDir::from_node_root(working_dir.as_ref());

        let is_mainnet = opts.network.is_mainnet();

        // Canonical node tip (id + height) is obtained from sortition db without any Stacks header walking
        let mut sortition_db =
            SortitionDb::open_for_read(burnchain_dir.sortition_db_path()).await?;
        let (node_tip_id, node_tip_height) = sortition_db.get_canonical_stacks_tip().await?;

        let env = Self {
            is_mainnet,
            working_dir: working_dir.as_ref().to_path_buf(),
            chainstate_dir,
            burnchain_dir,
            epochs: Arc::new(opts.epochs),
            sortdb_open_epochs: Arc::new(opts.sortdb_open_epochs),
            network: opts.network,
            chain_id: opts.chain_id,
        };

        Ok((
            env,
            BlockRef {
                id: node_tip_id,
                height: node_tip_height,
            },
        ))
    }

    pub async fn open_chainstate_db_for_read(&self) -> Result<ChainStateDb<ReadOnly>> {
        ChainStateDb::<ReadOnly>::open_for_read(self.chainstate_dir.index_db_path()).await
    }

    pub async fn open_nakamoto_db_for_read(&self) -> Result<NakamotoDb<ReadOnly>> {
        NakamotoDb::<ReadOnly>::open_for_read(self.chainstate_dir.nakamoto_db_path()).await
    }

    pub async fn open_sortition_db_for_read(&self) -> Result<SortitionDb<ReadOnly>> {
        SortitionDb::<ReadOnly>::open_for_read(self.burnchain_dir.sortition_db_path()).await
    }
}

pub struct BenchContext<'a> {
    env: &'a BenchEnv,
    start_block: BlockRef,
    end_block: BlockRef,
    chain_tip: BlockRef,
}

impl<'a> BenchContext<'a> {
    pub fn from_env(
        env: &'a BenchEnv,
        chain_tip: BlockRef,
        start_block: BlockRef,
        end_block: BlockRef,
    ) -> Self {
        Self {
            env,
            chain_tip,
            start_block,
            end_block,
        }
    }

    pub fn env(&self) -> &'a BenchEnv {
        self.env
    }

    /// Returns the Stacks chain tip as a `(StacksBlockId, u64)`] tuple.
    pub fn chain_tip(&self) -> &BlockRef {
        &self.chain_tip
    }

    pub fn resolve_block_era(&self, epoch: StacksEpochId) -> BlockEra {
        if epoch >= StacksEpochId::Epoch30 {
            BlockEra::Nakamoto
        } else {
            BlockEra::PreNakamoto
        }
    }

    /// Returns the target block range as `(start_height, end_height)`.
    pub fn block_height_range(&self) -> Result<(u64, u64)> {
        Ok((self.start_block.height, self.end_block.height))
    }

    pub fn start_block(&self) -> &BlockRef {
        &self.start_block
    }

    pub fn end_block(&self) -> &BlockRef {
        &self.end_block
    }

    /// Opens the heavy `StacksChainState` and `Burnchain` databases on demand.
    /// Use this only when you need to execute blocks or access deep chain state.
    pub fn open_stacks_chainstate(&self) -> Result<(StacksChainState, Burnchain)> {
        let network_name = self.env.network.to_string();

        let burnchain = Burnchain::new(
            self.env.burnchain_dir.as_str()?,
            BURNCHAIN_NAME,
            &network_name,
            None,
        )?;

        // Apply sortition DB migrations on the shadow copy if needed.
        let sortdb_epochs: Vec<stacks_common::types::StacksEpoch<ExecutionCost>> =
            self.env.sortdb_open_epochs.iter().map(Into::into).collect();
        let sort_db_path = burnchain.get_db_path();
        drop(SortitionDB::connect(
            &sort_db_path,
            burnchain.first_block_height,
            &burnchain.first_block_hash,
            burnchain.first_block_timestamp.into(),
            &sortdb_epochs,
            burnchain.pox_constants.clone(),
            None,
            true,
            burnchain.marf_opts.clone(),
        )?);

        let marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true);

        let (chainstate, _) = StacksChainState::open(
            self.env.is_mainnet,
            self.env.chain_id,
            self.env.chainstate_dir.as_str()?,
            Some(marf_opts),
        )?;

        Ok((chainstate, burnchain))
    }

    /// Opens the Nakamoto blocks database in read-only mode using our internal,
    /// lightweight [`NakamotoDb`].
    pub async fn open_nakamoto_db_for_read(&self) -> Result<NakamotoDb<ReadOnly>> {
        let nakamoto_db_path = self.env.chainstate_dir.nakamoto_db_path();
        NakamotoDb::<ReadOnly>::open_for_read(nakamoto_db_path)
            .await
            .with_context(|| "Failed to open nakamoto DB for read")
    }

    /// Opens the Stacks chainstate index database in read-only mode using our
    /// internal, lightweight [`ChainStateDb`].
    pub async fn open_chainstate_db_for_read(&self) -> Result<ChainStateDb<ReadOnly>> {
        let index_db_path = self.env.chainstate_dir.index_db_path();
        ChainStateDb::<ReadOnly>::open_for_read(index_db_path)
            .await
            .with_context(|| "Failed to open chainstate index DB for read")
    }

    /// Opens the sortition database in read-only mode using our internal,
    /// lightweight [`SortitionDb`].
    pub async fn open_sortition_db_for_read(&self) -> Result<SortitionDb<ReadOnly>> {
        let sortition_db_path = self.env.burnchain_dir.sortition_db_path();
        SortitionDb::<ReadOnly>::open_for_read(sortition_db_path)
            .await
            .with_context(|| "Failed to open sortition DB for read")
    }

    /// Stream canonical blocks from `end_height` down to `start_height`.
    pub async fn canonical_block_stream(
        &mut self,
        start_height: u32,
        end_height: u32,
    ) -> impl Stream<Item = Result<StacksBlockHeader>> + '_ {
        let start_height = start_height as u64;
        let end_height = end_height as u64;

        let current_id = self.end_block.id.clone();

        // Open a local handle to the ChainStateDb.
        // We expect this to succeed since the node is running/initialized.
        let chainstate_db_res =
            ChainStateDb::open_for_read(self.env.chainstate_dir.index_db_path()).await;

        match chainstate_db_res {
            Ok(chainstate_db) => {
                let stream = BackwardsBlockStream::new(chainstate_db, current_id);
                futures::stream::unfold(stream, move |mut bs| async move {
                    loop {
                        match bs.next_block().await {
                            Ok(Some(header)) => {
                                if header.height < start_height {
                                    return None;
                                }
                                if header.height <= end_height {
                                    return Some((Ok(header), bs));
                                }
                                // If not yielding (because we are above end_height), loop continues to walk back
                            }
                            Ok(None) => return Some((Err(anyhow!("Missing header")), bs)),
                            Err(e) => return Some((Err(e), bs)),
                        }
                    }
                })
                .boxed()
            }
            Err(e) => {
                futures::stream::once(
                    async move { Err(anyhow!("Failed to open chainstate DB: {e}")) },
                )
                .boxed()
            }
        }
    }
}

impl ResolveEpochFromHeight for BenchContext<'_> {
    fn resolve_stacks_epoch(&self, height: u64) -> Option<StacksEpochId> {
        self.env.epochs.as_slice().resolve_stacks_epoch(height)
    }
}
