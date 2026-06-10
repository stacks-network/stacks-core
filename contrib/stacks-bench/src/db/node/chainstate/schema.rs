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
    db_config (version) {
        version -> Integer,
        mainnet -> Bool,
        chain_id -> Integer
    }
}

table! {
    block_headers (consensus_hash, block_hash) {
        consensus_hash -> Text,
        block_hash -> Text,
        index_block_hash -> Text,
        parent_block_id -> Text,
        block_height -> BigInt,
        burn_header_hash -> Text,
        burn_header_height -> BigInt,
    }
}

table! {
    nakamoto_block_headers (consensus_hash, block_hash) {
        consensus_hash -> Text,
        block_hash -> Text,
        index_block_hash -> Text,
        parent_block_id -> Text,
        block_height -> BigInt,
        burn_header_hash -> Text,
        burn_header_height -> BigInt,
        header_type -> Text,
    }
}
