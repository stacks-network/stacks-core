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

use std::path::Path;

use anyhow::{Result, anyhow};
use stacks_bench::context::{BenchEnv, BenchEnvOpts};
use stacks_bench::db::node::sortition::SortitionDb;
use stacks_bench::db::node::{ChainStateDb, NakamotoDb};
use stacks_bench::db::{DbOpenForRead, ReadOnly};
use stacks_bench::indexer::ChainIndexPlan;
use stacks_bench::paths::{BurnChainDir, ChainStateDir};
use stacks_bench::shadow::{ShadowDir, ShadowDirBuilder};
use stacks_bench::{Network, StacksBlockHeader, StacksBlockRef, StacksEpoch};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};

use super::args::IndexerArgs;

#[derive(Debug, Clone)]
pub struct ResolvedStacksBlockRef {
    pub height: u64,
    pub expected_ids: Vec<StacksBlockId>,
}

pub fn get_git_hash() -> Option<Vec<u8>> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let s = String::from_utf8_lossy(&output.stdout);
            hex::decode(s.trim()).ok()
        })
}

pub fn create_shadow_dir<P: AsRef<Path>>(
    source_dir: P,
    with_pre_nakamoto_blocks: bool,
    shadow_dir_root: Option<&Path>,
) -> Result<ShadowDir> {
    let mut builder = ShadowDirBuilder::new(source_dir.as_ref())
        .glob("burnchain/**")
        .glob("chainstate/vm/**");

    if with_pre_nakamoto_blocks {
        builder = builder.glob("chainstate/blocks/**");
    } else {
        builder = builder
            .glob("chainstate/blocks/nakamoto.sqlite")
            .glob("chainstate/blocks/nakamoto.sqlite-wal");
    }

    builder = builder
        .watch("chainstate/vm/clarity/marf.sqlite")
        .watch("chainstate/vm/clarity/marf.sqlite.blobs")
        .watch("chainstate/vm/clarity/marf.sqlite-wal")
        .watch("chainstate/vm/index.sqlite")
        .watch("chainstate/vm/index.sqlite.blobs")
        .watch("chainstate/vm/index.sqlite-wal");

    if let Some(root) = shadow_dir_root {
        builder = builder.parent_dir(root);
    }

    let shadow_dir = builder.copy()?;
    Ok(shadow_dir)
}

/// Initializes a [`BenchEnv`] from a working directory with network, chain_id,
/// and epoch resolution. Returns the env and the resolved anchor tip.
///
/// When `tip_override` is `Some`, the tip is resolved from the override;
/// otherwise the canonical node tip is used.
pub async fn setup_bench_env<P: AsRef<Path>>(
    working_dir: P,
    network_override: Option<Network>,
    tip_override: Option<&StacksBlockRef>,
) -> Result<(BenchEnv, stacks_bench::blocks::BlockRef)> {
    let chainstate_path = ChainStateDir::from_node_root(&working_dir);
    let burnchain_path = BurnChainDir::from_node_root(&working_dir);

    // Resolve network and chain ID
    let (network, chain_id) = {
        let chainstate_db = ChainStateDb::open_for_read(chainstate_path.index_db_path()).await?;
        let db_config = chainstate_db.read_db_config().await?;

        let network = if let Some(n) = network_override {
            db_config.assert_matches_network(n)?;
            n
        } else if db_config.is_mainnet() {
            Network::Mainnet
        } else {
            Network::Testnet
        };
        (network, db_config.chain_id())
    };

    // Load epochs (node sortition epochs -> StacksEpoch)
    let epochs: Vec<StacksEpoch> = {
        SortitionDb::open_for_read(burnchain_path.sortition_db_path())
            .await?
            .get_epochs()
            .await?
            .iter()
            .map(StacksEpoch::try_from)
            .collect::<Result<Vec<_>>>()?
    };

    let context_opts =
        BenchEnvOpts::new(network, chain_id, epochs)?.with_tip(tip_override.cloned());

    let (env, node_tip) = BenchEnv::initialize(working_dir, context_opts).await?;

    let chainstate_db = ChainStateDb::open_for_read(chainstate_path.index_db_path()).await?;
    let nakamoto_db = open_optional_nakamoto_db(&chainstate_path).await?;

    // Anchor tip: indexing-first mode needs a fork-unique id up front. Hex tip
    // refs resolve through the chainstate header table. Tip-by-height still
    // requires a potentially long chain walk, so reject it explicitly.
    let anchor_tip = match tip_override {
        None => node_tip,
        Some(r @ StacksBlockRef::Hash(_)) => {
            let resolved = resolve_ref(&chainstate_db, nakamoto_db.as_ref(), r, "tip").await?;
            let [tip_id] = resolved.expected_ids.as_slice() else {
                anyhow::bail!(
                    "tip hash {r} resolved to {} candidate block ids; pass the fork-unique \
                     index_block_hash instead",
                    resolved.expected_ids.len()
                );
            };
            stacks_bench::blocks::BlockRef {
                id: tip_id.clone(),
                height: resolved.height,
            }
        }
        Some(StacksBlockRef::Height(h)) => {
            anyhow::bail!(
                "--tip by height ({h}) requires a chain-walk to resolve the canonical tip id; \
                for indexing-first mode, pass --tip as an index_block_hash or block_hash instead"
            );
        }
    };

    Ok((env, anchor_tip))
}

pub async fn setup_bench_env_and_plan<'a, A: IndexerArgs, P: AsRef<Path> + 'a>(
    working_dir: P,
    args: &'_ A,
) -> Result<(BenchEnv, ChainIndexPlan)> {
    let (env, anchor_tip) = setup_bench_env(&working_dir, args.network(), args.tip()).await?;

    let chainstate_path = ChainStateDir::from_node_root(&working_dir);
    let chainstate_db = ChainStateDb::open_for_read(chainstate_path.index_db_path()).await?;
    let nakamoto_db = open_optional_nakamoto_db(&chainstate_path).await?;

    // start_height
    let start = match args.start_at() {
        Some(r) => resolve_ref(&chainstate_db, nakamoto_db.as_ref(), r, "start").await?,
        None => ResolvedStacksBlockRef {
            height: 1,
            expected_ids: Vec::new(),
        },
    };
    let start_height = start.height;

    if start_height == 0 {
        anyhow::bail!("start height cannot be 0 (genesis). Use height >= 1.");
    }
    if start_height > anchor_tip.height {
        anyhow::bail!(
            "start height {start_height} is beyond anchor tip height {}",
            anchor_tip.height
        );
    }

    // end_height (from count, end_at, or default to anchor tip)
    let (end_height, expected_end_ids) = if let Some(count) = args.block_count() {
        if count == 0 {
            anyhow::bail!("block count must be > 0");
        }
        let count_u64 = count as u64;
        let end_height = start_height
            .checked_add(count_u64 - 1)
            .ok_or_else(|| anyhow!("end height overflow computing start+count-1"))?;
        (end_height, Vec::new())
    } else if let Some(r) = args.end_at() {
        let end = resolve_ref(&chainstate_db, nakamoto_db.as_ref(), r, "end").await?;
        (end.height, end.expected_ids)
    } else {
        (anchor_tip.height, Vec::new())
    };

    if end_height < start_height {
        anyhow::bail!("end height {end_height} is before start height {start_height}");
    }
    if end_height > anchor_tip.height {
        anyhow::bail!(
            "end height {end_height} is beyond anchor tip height {}",
            anchor_tip.height
        );
    }

    let plan = ChainIndexPlan {
        anchor_tip,
        start_height,
        end_height,
        expected_start_ids: start.expected_ids,
        expected_end_ids,
    };

    Ok((env, plan))
}

pub async fn resolve_ref(
    chainstate_db: &ChainStateDb<ReadOnly>,
    nakamoto_db: Option<&NakamotoDb<ReadOnly>>,
    r: &StacksBlockRef,
    label: &'static str,
) -> Result<ResolvedStacksBlockRef> {
    match r {
        StacksBlockRef::Height(h) => {
            if *h == 0 {
                anyhow::bail!("{label} height cannot be 0 (genesis). Use height >= 1.");
            }
            Ok(ResolvedStacksBlockRef {
                height: *h,
                expected_ids: Vec::new(),
            })
        }
        StacksBlockRef::Hash(hash) => {
            let id = StacksBlockId::from_hex(&hash.to_hex())?;
            if let Some(hdr) = chainstate_db.get_block_header(&id).await? {
                let hdr: StacksBlockHeader = hdr.try_into()?;
                if hdr.height == 0 {
                    anyhow::bail!(
                        "{label} block {hash} has invalid height {} in DB",
                        hdr.height
                    );
                }
                return Ok(ResolvedStacksBlockRef {
                    height: hdr.height,
                    expected_ids: vec![hdr.id],
                });
            }

            resolve_block_hash_ref(chainstate_db, nakamoto_db, hash, label).await
        }
    }
}

async fn resolve_block_hash_ref(
    chainstate_db: &ChainStateDb<ReadOnly>,
    nakamoto_db: Option<&NakamotoDb<ReadOnly>>,
    block_hash: &BlockHeaderHash,
    label: &'static str,
) -> Result<ResolvedStacksBlockRef> {
    let mut candidates = Vec::new();

    for hdr in chainstate_db.get_block_headers_by_hash(block_hash).await? {
        if hdr.block_height > 0 {
            candidates.push((
                hdr.block_height as u64,
                StacksBlockId::from_hex(&hdr.index_block_hash)?,
            ));
        }
    }

    if let Some(nakamoto_db) = nakamoto_db {
        for block in nakamoto_db.get_nakamoto_blocks_by_hash(block_hash).await? {
            if block.height > 0 {
                candidates.push((
                    block.height as u64,
                    StacksBlockId::from_hex(&block.index_block_hash)?,
                ));
            }
        }
    }

    candidates.sort_by(|(left_height, left_id), (right_height, right_id)| {
        left_height
            .cmp(right_height)
            .then_with(|| left_id.cmp(right_id))
    });
    candidates.dedup();

    if candidates.is_empty() {
        anyhow::bail!(
            "{label} block hash {block_hash} not found in chainstate DB or Nakamoto block DB"
        );
    }

    let mut heights: Vec<u64> = candidates.iter().map(|(height, _)| *height).collect();
    heights.sort_unstable();
    heights.dedup();
    let [height] = heights.as_slice() else {
        anyhow::bail!(
            "{label} block hash {block_hash} matched candidates at multiple heights {:?}; \
             pass the fork-unique index_block_hash instead",
            heights
        );
    };

    let expected_ids = candidates.into_iter().map(|(_, id)| id).collect::<Vec<_>>();

    Ok(ResolvedStacksBlockRef {
        height: *height,
        expected_ids,
    })
}

async fn open_optional_nakamoto_db(
    chainstate_path: &ChainStateDir,
) -> Result<Option<NakamotoDb<ReadOnly>>> {
    let path = chainstate_path.nakamoto_db_path();
    if path.exists() {
        Ok(Some(NakamotoDb::open_for_read(path).await?))
    } else {
        Ok(None)
    }
}
