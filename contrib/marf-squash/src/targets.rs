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

//! Resolution of the canonical Stacks + sortition boundaries that a squash must
//! anchor on.

use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, SortitionId, StacksBlockId,
};
use stackslib::burnchains::PoxConstants;
use stackslib::chainstate::burn::BlockSnapshot;
use stackslib::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn};
use stackslib::chainstate::nakamoto::NakamotoChainState;
use stackslib::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};

/// Mainnet only: the squash boundary must sit at least this many Bitcoin blocks
/// behind the canonical burn tip, so the squashed tenure is final and cannot be
/// reorged out from under a booted node. 6 is the standard Bitcoin finality depth.
const MAINNET_MIN_BURN_CONFIRMATIONS: u64 = 6;

/// Canonical Stacks and sortition MARF boundaries that must be squashed together.
#[derive(Debug, Clone)]
pub struct CanonicalSquashTargets {
    /// Tenure-start Stacks block height that Clarity and Index squash to.
    pub stacks_height: u32,
    /// Tenure-start Stacks tip that Clarity and Index squash to.
    pub stacks_tip: StacksBlockId,
    /// Consensus hash of the tenure-start tip.
    pub stacks_tip_consensus_hash: ConsensusHash,
    /// Burn view of the tenure-start block - the sortition boundary.
    pub stacks_tip_burn_view_consensus_hash: ConsensusHash,
    /// Block hash of the tenure-start tip.
    pub stacks_tip_block_hash: BlockHeaderHash,
    /// Bitcoin height of the squash boundary (the tenure-start block's `burn_view`).
    pub squash_bitcoin_height: u32,
    /// Sortition MARF height for `squash_bitcoin_height`.
    pub sortition_marf_height: u32,
    /// Source canonical burn tip - the fork selector for `MARF::squash_to_path`.
    pub sortition_canonical_tip: SortitionId,
    /// Squash boundary sortition (at `squash_bitcoin_height`) that the squashed output holds.
    pub sortition_boundary_tip: SortitionId,
    /// Sortition DB's first Bitcoin block height (used to derive MARF heights).
    pub first_bitcoin_height: u32,
}

/// Build the error for a `--tenure-start-bitcoin-height` that did not start a
/// Nakamoto tenure, listing nearby tenure starts to help the caller pick one.
fn format_no_tenure_start_error(
    sortition_db: &SortitionDB,
    canonical_sortition_id: &SortitionId,
    start_height: u64,
) -> String {
    let ic = sortition_db.index_handle_at_tip();
    // Find nearby tenure starts for a helpful error message.
    let mut nearby = Vec::new();
    let search_radius = 10u64;
    let search_start = start_height.saturating_sub(search_radius);
    let search_end = start_height.saturating_add(search_radius);
    for h in search_start..=search_end {
        if h == start_height {
            continue;
        }
        if let Ok(Some(s)) = SortitionDB::get_ancestor_snapshot(&ic, h, canonical_sortition_id)
            && s.sortition
        {
            nearby.push(h);
        }
    }
    let nearby_str = if nearby.is_empty() {
        String::new()
    } else {
        format!(
            "\n  Nearby tenure starts: {}",
            nearby
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "Bitcoin height {start_height} did not start a Nakamoto tenure \
         (sortition=false).{nearby_str}"
    )
}

/// Inputs to [`resolve_canonical_squash_targets`]: the source DB locations, the
/// network identity, the tenure-start Bitcoin height, and the PoX constants.
pub struct SquashTargetQuery<'a> {
    pub chainstate_root: &'a str,
    pub sortition_db_dir: &'a str,
    pub tenure_start_bitcoin_height: u32,
    pub mainnet: bool,
    pub chain_id: u32,
    pub pox_constants: PoxConstants,
}

/// The sortition read context shared by the boundary-resolution steps: the open
/// sortition DB, an index handle at its tip, and the canonical burn-chain tip
/// that ancestor lookups are anchored on.
struct SortitionReadCtx<'a> {
    sortition_db: &'a SortitionDB,
    ic: &'a SortitionHandleConn<'a>,
    canonical_tip: &'a BlockSnapshot,
}

/// Open the source chainstate and sortition DBs, and read the sortition DB's
/// `first_block_height` (as u32) and canonical burn-chain tip. Returns
/// `(chainstate, sortition_db, first_bitcoin_height, canonical_tip)`.
fn open_squash_dbs(
    query: &SquashTargetQuery,
) -> Result<(StacksChainState, SortitionDB, u32, BlockSnapshot), String> {
    let (chainstate, _) =
        StacksChainState::open(query.mainnet, query.chain_id, query.chainstate_root, None)
            .map_err(|e| {
                format!(
                    "Failed to open chainstate at '{}': {e}",
                    query.chainstate_root
                )
            })?;

    let sortition_db = SortitionDB::open(
        query.sortition_db_dir,
        false,
        query.pox_constants.clone(),
        None,
    )
    .map_err(|e| {
        format!(
            "Failed to open sortition DB at '{}': {e}",
            query.sortition_db_dir
        )
    })?;

    let first_bitcoin_height: u32 = sortition_db.first_block_height.try_into().map_err(|_| {
        format!(
            "Sortition first_block_height {} does not fit in u32",
            sortition_db.first_block_height
        )
    })?;

    let canonical_tip = SortitionDB::get_canonical_burn_chain_tip(sortition_db.conn())
        .map_err(|e| format!("Failed to get canonical burn tip: {e}"))?;

    Ok((
        chainstate,
        sortition_db,
        first_bitcoin_height,
        canonical_tip,
    ))
}

/// Resolve the tenure-start sortition snapshot at `start_height`, requiring it to
/// have started a Nakamoto tenure (`sortition=true`).
fn resolve_tenure_start_snapshot(
    ctx: &SortitionReadCtx,
    start_height: u64,
) -> Result<BlockSnapshot, String> {
    let start_snapshot =
        SortitionDB::get_ancestor_snapshot(ctx.ic, start_height, &ctx.canonical_tip.sortition_id)
            .map_err(|e| {
                format!("Failed to get ancestor snapshot at Bitcoin height {start_height}: {e}")
            })?
            .ok_or_else(|| format!("No canonical sortition at Bitcoin height {start_height}"))?;

    if !start_snapshot.sortition {
        return Err(format_no_tenure_start_error(
            ctx.sortition_db,
            &ctx.canonical_tip.sortition_id,
            start_height,
        ));
    }
    Ok(start_snapshot)
}

/// Load the tenure-start block's `burn_view` sortition snapshot, confirm it sits
/// on the canonical burn-chain fork, and resolve the squash Bitcoin height. Under
/// first-block anchoring the tenure-start block's `burn_view` IS the tenure-start
/// sortition, so the resolved height must equal `tenure_start_bitcoin_height`; a
/// mismatch means the anchor is not the tenure's first block. Returns
/// `(burn_view_snapshot, squash_bitcoin_height)`.
fn resolve_squash_burn_view_snapshot(
    ctx: &SortitionReadCtx,
    header_burn_view: &ConsensusHash,
    tenure_start_bitcoin_height: u32,
    first_bitcoin_height: u32,
) -> Result<(BlockSnapshot, u32), String> {
    let burn_view_snapshot =
        SortitionDB::get_block_snapshot_consensus(ctx.sortition_db.conn(), header_burn_view)
            .map_err(|e| format!("Failed to load snapshot for burn_view {header_burn_view}: {e}"))?
            .ok_or_else(|| {
                format!("No snapshot found for tenure start's burn_view {header_burn_view}")
            })?;

    let canonical_at_height = SortitionDB::get_ancestor_snapshot(
        ctx.ic,
        burn_view_snapshot.block_height,
        &ctx.canonical_tip.sortition_id,
    )
    .map_err(|e| {
        format!(
            "Failed to get canonical ancestor at Bitcoin height {}: {e}",
            burn_view_snapshot.block_height
        )
    })?
    .ok_or_else(|| {
        format!(
            "No canonical sortition at Bitcoin height {} (burn_view {header_burn_view})",
            burn_view_snapshot.block_height
        )
    })?;

    if canonical_at_height.sortition_id != burn_view_snapshot.sortition_id {
        return Err(format!(
            "Tenure start's burn_view {header_burn_view} points at sortition_id \
             {} (Bitcoin height {}), which is not on the canonical burn-chain \
             fork. Cowardly refusing to squash a tenure that landed on an \
             orphan burn fork.",
            burn_view_snapshot.sortition_id, burn_view_snapshot.block_height
        ));
    }

    let squash_bitcoin_height: u32 = burn_view_snapshot.block_height.try_into().map_err(|_| {
        format!(
            "Tenure burn-view Bitcoin height {} does not fit in u32",
            burn_view_snapshot.block_height
        )
    })?;
    if squash_bitcoin_height != tenure_start_bitcoin_height {
        return Err(format!(
            "Tenure-start block's burn-view Bitcoin height {squash_bitcoin_height} does not \
             equal the requested tenure-start Bitcoin height {tenure_start_bitcoin_height}. \
             Under first-block anchoring the tenure-start block's burn_view is the tenure-start \
             sortition, so these must match; a mismatch means the resolved anchor is not the \
             tenure's first block. Refusing to squash."
        ));
    }
    if squash_bitcoin_height < first_bitcoin_height {
        return Err(format!(
            "Tenure burn-view Bitcoin height {squash_bitcoin_height} is below the \
             sortition DB's first_bitcoin_height {first_bitcoin_height}"
        ));
    }

    Ok((burn_view_snapshot, squash_bitcoin_height))
}

/// Resolve the tenure's FIRST Nakamoto block (the BlockFound block) canonically:
/// walk the Stacks index from the canonical Stacks tip back to the tenure start for
/// `tenure_ch`. For a tenure-extend, the later intra-tenure and extend blocks share
/// `tenure_ch` but are not the tenure start, so they fall above the boundary and are
/// re-synced from peers on boot.
fn resolve_tenure_start_anchor(
    chainstate: &StacksChainState,
    sortition_db: &SortitionDB,
    tenure_ch: &ConsensusHash,
    start_height: u64,
) -> Result<StacksHeaderInfo, String> {
    let (canonical_ch, canonical_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(sortition_db.conn())
            .map_err(|e| format!("Failed to read canonical Stacks chain tip: {e}"))?;
    let canonical_stacks_tip = StacksBlockId::new(&canonical_ch, &canonical_bhh);
    NakamotoChainState::get_nakamoto_tenure_start_block_header(
        &mut chainstate.index_conn(),
        &canonical_stacks_tip,
        tenure_ch,
    )
    .map_err(|e| format!("Failed to resolve tenure-start block for {tenure_ch}: {e}"))?
    .ok_or_else(|| {
        format!(
            "Tenure {tenure_ch} (Bitcoin height {start_height}) has no canonical Nakamoto \
             tenure-start block. Either the elected tenure produced no canonical blocks, or \
             this predates Nakamoto activation."
        )
    })
}

/// Resolve the canonical Stacks and sortition boundaries to squash to from the
/// tenure starting at `query.tenure_start_bitcoin_height`.
///
/// Clarity and Index anchor at the tenure's FIRST Nakamoto block (the BlockFound
/// block). For a tenure-extend tenure (one spanning several burn blocks), the
/// later intra-tenure blocks are dropped from the artifact and re-synced from
/// peers on boot; the sortition boundary is the tenure-start sortition (the first
/// block's `burn_view`).
///
/// Validates that the tenure exists and that the boundary burn_view is on the
/// canonical burn fork.
pub fn resolve_canonical_squash_targets(
    query: SquashTargetQuery,
) -> Result<CanonicalSquashTargets, String> {
    let tenure_start_bitcoin_height = query.tenure_start_bitcoin_height;
    let start_height = u64::from(tenure_start_bitcoin_height);

    let (chainstate, sortition_db, first_bitcoin_height, canonical_tip) = open_squash_dbs(&query)?;

    let ic = sortition_db.index_handle_at_tip();
    let ctx = SortitionReadCtx {
        sortition_db: &sortition_db,
        ic: &ic,
        canonical_tip: &canonical_tip,
    };

    // Rule: a tenure must exist at the requested Bitcoin height.
    let start_snapshot = resolve_tenure_start_snapshot(&ctx, start_height)?;
    let tenure_ch = start_snapshot.consensus_hash.clone();

    // Anchor at the tenure's FIRST Nakamoto block (the BlockFound block).
    let start_header =
        resolve_tenure_start_anchor(&chainstate, &sortition_db, &tenure_ch, start_height)?;

    let stacks_height: u32 = start_header.stacks_block_height.try_into().map_err(|_| {
        format!(
            "Tenure start Stacks height {} does not fit in u32",
            start_header.stacks_block_height
        )
    })?;
    let stacks_tip = start_header.index_block_hash();
    let stacks_tip_consensus_hash = start_header.consensus_hash.clone();
    let stacks_tip_block_hash = start_header.anchored_header.block_hash();

    let header_burn_view = start_header.burn_view.clone().ok_or_else(|| {
        format!(
            "Nakamoto tenure start {stacks_tip} (height {stacks_height}) has no \
             burn_view set. Squash requires a Nakamoto block header with a \
             burn_view."
        )
    })?;

    let (burn_view_snapshot, squash_bitcoin_height) = resolve_squash_burn_view_snapshot(
        &ctx,
        &header_burn_view,
        tenure_start_bitcoin_height,
        first_bitcoin_height,
    )?;

    // Mainnet fork-safety: only squash finalized tenures. If the boundary burn
    // block is too close to the canonical burn tip it could still be reorged,
    // leaving a node booted from the snapshot stranded on a dead fork.
    if query.mainnet {
        let tip_height = canonical_tip.block_height;
        let boundary = u64::from(squash_bitcoin_height);
        if boundary + MAINNET_MIN_BURN_CONFIRMATIONS > tip_height {
            return Err(format!(
                "Refusing to squash: boundary Bitcoin height {boundary} is only {} burn block(s) \
                 behind the canonical burn tip {tip_height}. Mainnet requires at least \
                 {MAINNET_MIN_BURN_CONFIRMATIONS} for finality.",
                tip_height.saturating_sub(boundary)
            ));
        }
    }

    let sortition_marf_height = squash_bitcoin_height - first_bitcoin_height;
    let sortition_canonical_tip = canonical_tip.sortition_id.clone();
    let sortition_boundary_tip = burn_view_snapshot.sortition_id.clone();

    Ok(CanonicalSquashTargets {
        stacks_height,
        stacks_tip,
        stacks_tip_consensus_hash,
        stacks_tip_burn_view_consensus_hash: header_burn_view,
        stacks_tip_block_hash,
        squash_bitcoin_height,
        sortition_marf_height,
        sortition_canonical_tip,
        sortition_boundary_tip,
        first_bitcoin_height,
    })
}
