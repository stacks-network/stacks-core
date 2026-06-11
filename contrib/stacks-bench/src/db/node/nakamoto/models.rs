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

use super::schema::nakamoto_staging_blocks;

#[derive(Queryable, Selectable, Identifiable, Debug, Clone)]
#[diesel(table_name = nakamoto_staging_blocks)]
#[diesel(primary_key(block_hash, consensus_hash))]
pub struct NakamotoStagingBlock {
    pub block_hash: String,
    pub consensus_hash: String,
    pub parent_block_id: String,
    pub height: i32,
    pub index_block_hash: String,
    pub data: Vec<u8>,
}
