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

use diesel::prelude::*;

table! {
    epochs (start_block_height, epoch_id) {
        start_block_height -> BigInt,
        end_block_height -> BigInt,
        epoch_id -> Integer,
        block_limit -> Text,
        network_epoch -> Integer
    }
}

table! {
    snapshots (sortition_id) {
        sortition_id -> Text,
        block_height -> BigInt,
        burn_header_hash -> Text,
        parent_sortition_id -> Text,
        canonical_stacks_tip_hash -> Text,
        canonical_stacks_tip_consensus_hash -> Text,
        canonical_stacks_tip_height -> BigInt,
        pox_valid -> Integer,
    }
}

table! {
    stacks_chain_tips (sortition_id) {
        sortition_id -> Text,
        consensus_hash -> Text,
        block_hash -> Text,
        block_height -> BigInt,
    }
}

// Post-Nakamoto canonical Stacks tip storage. Introduced by stacks-core
// commit 5aa6af4e96 ("fix: track and report both tenure and burn view
// consensus hash for stacks tips"). The legacy `stacks_chain_tips` is
// only populated by the schema-8 one-shot backfill of pre-Nakamoto
// snapshot rows; for epoch ≥ 3.0 the canonical tip is here.
table! {
    stacks_chain_tips_by_burn_view (sortition_id, burn_view_consensus_hash) {
        sortition_id -> Text,
        consensus_hash -> Text,
        burn_view_consensus_hash -> Text,
        block_hash -> Text,
        block_height -> BigInt,
    }
}
