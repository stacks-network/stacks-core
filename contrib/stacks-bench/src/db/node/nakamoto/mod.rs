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

use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use anyhow::{Context, Result};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::db::{DbOpen, SqliteDbHandle};

pub mod models;
pub mod schema;

#[derive(Clone)]
pub struct NakamotoDb<Mode> {
    handle: SqliteDbHandle<Mode>,
}

impl<Mode> Deref for NakamotoDb<Mode> {
    type Target = SqliteDbHandle<Mode>;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<Mode> DerefMut for NakamotoDb<Mode> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

// Generic implementation: If SqliteDbHandle can be opened in Mode,
// then NakamotoDb can also be opened in Mode.
impl<Mode> DbOpen<Mode> for NakamotoDb<Mode>
where
    SqliteDbHandle<Mode>: DbOpen<Mode>,
    Mode: Send,
{
    async fn open<P: AsRef<Path> + Debug + Send>(path: P) -> Result<Self> {
        Ok(Self {
            handle: SqliteDbHandle::<Mode>::open(path).await?,
        })
    }
}

impl<Mode> NakamotoDb<Mode> {
    pub async fn get_nakamoto_block(
        &self,
        id: &stacks_common::types::chainstate::StacksBlockId,
    ) -> Result<Option<models::NakamotoStagingBlock>> {
        use self::schema::nakamoto_staging_blocks;

        let id_str = id.to_string();
        let mut conn = self.handle.get_conn().await?;

        nakamoto_staging_blocks::table
            .filter(nakamoto_staging_blocks::index_block_hash.eq(id_str))
            .first(&mut conn)
            .await
            .optional()
            .with_context(|| format!("Failed to query nakamoto_staging_blocks for id {id}"))
    }

    pub async fn get_nakamoto_blocks_by_hash(
        &self,
        hash: &BlockHeaderHash,
    ) -> Result<Vec<models::NakamotoStagingBlock>> {
        use self::schema::nakamoto_staging_blocks;

        let hash_str = hash.to_string();
        let mut conn = self.handle.get_conn().await?;

        nakamoto_staging_blocks::table
            .filter(nakamoto_staging_blocks::block_hash.eq(&hash_str))
            .load(&mut conn)
            .await
            .with_context(|| {
                format!("Failed to query nakamoto_staging_blocks for block hash {hash}")
            })
    }

    pub async fn get_min_block_height(&self) -> Result<Option<u64>> {
        use self::schema::nakamoto_staging_blocks::dsl::*;

        let mut conn = self.handle.get_conn().await?;

        nakamoto_staging_blocks
            .select(diesel::dsl::min(height))
            .first::<Option<i32>>(&mut conn)
            .await
            .map(|opt| opt.map(|h| h as u64))
            .context("Failed to get min block height from nakamoto db")
    }
}
