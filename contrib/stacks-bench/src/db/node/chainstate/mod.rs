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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow};
use clarity::types::chainstate::{BlockHeaderHash, StacksBlockId};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use futures::Stream;

use crate::StacksBlockHeader;
use crate::blocks::{BackwardsBlockStream, BlockHeaderProvider};
use crate::db::{DbOpen, SqliteDbHandle};

pub mod models;
pub mod schema;

#[derive(Clone)]
pub struct ChainStateDb<Mode> {
    handle: SqliteDbHandle<Mode>,
}

impl<Mode> Deref for ChainStateDb<Mode> {
    type Target = SqliteDbHandle<Mode>;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<Mode> DerefMut for ChainStateDb<Mode> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

// Generic implementation: If SqliteDbHandle can be opened in Mode,
// then ChainStateDb can also be opened in Mode.
impl<Mode> DbOpen<Mode> for ChainStateDb<Mode>
where
    SqliteDbHandle<Mode>: DbOpen<Mode>,
{
    async fn open<P: AsRef<Path> + Debug + Send>(path: P) -> Result<Self> {
        Ok(Self {
            handle: SqliteDbHandle::<Mode>::open(path).await?,
        })
    }
}

impl<Mode: Send + Sync + 'static> ChainStateDb<Mode> {
    pub async fn read_db_config(&self) -> Result<models::DbConfig> {
        use schema::db_config::dsl::db_config;
        let mut conn = self.handle.get_conn().await?;
        db_config
            .first::<models::DbConfig>(&mut conn)
            .await
            .with_context(|| "Failed to query chainstate 'db_config' table")
    }

    /// Tries to find a block header in either `nakamoto_block_headers` or `block_headers`.
    pub async fn get_block_header(
        &self,
        block_id: &StacksBlockId,
    ) -> Result<Option<models::BlockHeader>> {
        use self::schema::{block_headers, nakamoto_block_headers};
        let index_hash_hex = block_id.to_hex();
        let mut conn = self.handle.get_conn().await?;

        let q1 = nakamoto_block_headers::table
            .select((
                nakamoto_block_headers::index_block_hash,
                nakamoto_block_headers::block_hash,
                nakamoto_block_headers::parent_block_id,
                nakamoto_block_headers::block_height,
                nakamoto_block_headers::consensus_hash,
                nakamoto_block_headers::burn_header_hash,
                nakamoto_block_headers::burn_header_height,
            ))
            .filter(nakamoto_block_headers::index_block_hash.eq(&index_hash_hex));

        let q2 = block_headers::table
            .select((
                block_headers::index_block_hash,
                block_headers::block_hash,
                block_headers::parent_block_id,
                block_headers::block_height,
                block_headers::consensus_hash,
                block_headers::burn_header_hash,
                block_headers::burn_header_height,
            ))
            .filter(block_headers::index_block_hash.eq(&index_hash_hex));

        // UNION ALL with LIMIT 1 is efficient: SQLite checks the first query,
        // and if it finds a match, it stops immediately without checking the second.
        q1.union_all(q2)
            .first::<models::BlockHeader>(&mut conn)
            .await
            .optional()
            .with_context(|| {
                format!("Failed to query block header for block with index hash '{index_hash_hex}'")
            })
    }

    /// Finds pre-Nakamoto block headers by their Stacks block hash.
    pub async fn get_block_headers_by_hash(
        &self,
        block_hash: &BlockHeaderHash,
    ) -> Result<Vec<models::BlockHeader>> {
        use self::schema::block_headers;
        let block_hash_hex = block_hash.to_hex();
        let mut conn = self.handle.get_conn().await?;

        block_headers::table
            .select((
                block_headers::index_block_hash,
                block_headers::block_hash,
                block_headers::parent_block_id,
                block_headers::block_height,
                block_headers::consensus_hash,
                block_headers::burn_header_hash,
                block_headers::burn_header_height,
            ))
            .filter(block_headers::block_hash.eq(&block_hash_hex))
            .load::<models::BlockHeader>(&mut conn)
            .await
            .with_context(|| {
                format!("Failed to query block header for block hash '{block_hash_hex}'")
            })
    }

    /// Stream canonical headers by walking parent links from `tip_id`,
    /// yielding headers whose height is in [start_height, end_height] (descending).
    ///
    /// When `walk_progress` is provided, the tracker is updated with the current
    /// height as the stream walks backwards through blocks above `end_height`.
    /// This allows callers to monitor progress during the pre-range walk phase.
    pub fn canonical_block_stream_from_tip(
        &self,
        tip_id: StacksBlockId,
        start_height: u64,
        end_height: u64,
        walk_progress: Option<Arc<AtomicU64>>,
    ) -> impl Stream<Item = Result<StacksBlockHeader>> {
        let stream = BackwardsBlockStream::new(self, tip_id);

        Box::pin(futures::stream::unfold(stream, move |mut bs| {
            let walk_progress = walk_progress.clone();
            async move {
                loop {
                    match bs.next_block().await {
                        Ok(Some(header)) => {
                            if header.height < start_height {
                                return None;
                            }
                            if header.height <= end_height {
                                return Some((Ok(header), bs));
                            }
                            // above end_height: keep walking, update tracker
                            if let Some(ref tracker) = walk_progress {
                                tracker.store(header.height, Ordering::Relaxed);
                            }
                        }
                        Ok(None) => return Some((Err(anyhow!("Missing header")), bs)),
                        Err(e) => return Some((Err(e), bs)),
                    }
                }
            }
        }))
    }
}

impl<Mode: Send + Sync + 'static> BlockHeaderProvider for ChainStateDb<Mode> {
    async fn get_header(&self, id: &StacksBlockId) -> Result<Option<crate::StacksBlockHeader>> {
        let header = self.get_block_header(id).await?;
        match header {
            Some(h) => Ok(Some(h.try_into()?)),
            None => Ok(None),
        }
    }
}

impl<Mode: Send + Sync + 'static> BlockHeaderProvider for &ChainStateDb<Mode> {
    async fn get_header(&self, id: &StacksBlockId) -> Result<Option<crate::StacksBlockHeader>> {
        let header = self.get_block_header(id).await?;
        match header {
            Some(h) => Ok(Some(h.try_into()?)),
            None => Ok(None),
        }
    }
}
