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

use anyhow::{Result, anyhow, bail};
use stacks_common::types::chainstate::StacksBlockId;

use crate::StacksBlockHeader;

#[derive(Clone, Debug)]
pub struct BlockRef {
    pub id: StacksBlockId,
    pub height: u64,
}

impl Display for BlockRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.height)
    }
}

/// Trait for caching and retrieving block ancestors to speed up chain walking.
pub trait ChainCache {
    /// Finds the closest known ancestor of `tip` that has a height >= `target_height`.
    /// Returns `Some((block_id, height))` if found.
    fn find_closest_ancestor(
        &self,
        tip: &StacksBlockId,
        target_height: u64,
    ) -> impl Future<Output = Result<Option<(StacksBlockId, u64)>>>;

    /// Caches a known ancestor for a given tip.
    fn cache_ancestor(
        &mut self,
        tip: &StacksBlockId,
        height: u64,
        block: &StacksBlockId,
    ) -> impl Future<Output = Result<()>>;
}

pub struct NoopChainCache;
impl ChainCache for NoopChainCache {
    async fn find_closest_ancestor(
        &self,
        _tip: &StacksBlockId,
        _target_height: u64,
    ) -> Result<Option<(StacksBlockId, u64)>> {
        Ok(None)
    }

    async fn cache_ancestor(
        &mut self,
        _tip: &StacksBlockId,
        _height: u64,
        _block: &StacksBlockId,
    ) -> Result<()> {
        Ok(())
    }
}

/// Implement ChainCache for mutable references so we can pass `&mut AppDb`
impl<T: ChainCache + ?Sized> ChainCache for &mut T {
    fn find_closest_ancestor(
        &self,
        tip: &StacksBlockId,
        target_height: u64,
    ) -> impl Future<Output = Result<Option<(StacksBlockId, u64)>>> {
        (**self).find_closest_ancestor(tip, target_height)
    }

    fn cache_ancestor(
        &mut self,
        tip: &StacksBlockId,
        height: u64,
        block: &StacksBlockId,
    ) -> impl Future<Output = Result<()>> {
        (**self).cache_ancestor(tip, height, block)
    }
}

pub trait BlockHeaderProvider: Send {
    fn get_header(
        &self,
        id: &StacksBlockId,
    ) -> impl Future<Output = Result<Option<StacksBlockHeader>>>;
}

pub struct BackwardsBlockStream<P, C = NoopChainCache> {
    provider: P,
    current_id: StacksBlockId,
    cache: C,
}

impl<P, C> BackwardsBlockStream<P, C> {
    pub fn into_inner(self) -> P {
        self.provider
    }
}

impl<P: BlockHeaderProvider> BackwardsBlockStream<P, NoopChainCache> {
    pub fn new(provider: P, start_id: StacksBlockId) -> Self {
        Self {
            provider,
            current_id: start_id,
            cache: NoopChainCache,
        }
    }
}

impl<P: BlockHeaderProvider, C: ChainCache> BackwardsBlockStream<P, C> {
    /// Use a different cache provider.
    pub fn with_cache<NewC: ChainCache>(self, cache: NewC) -> BackwardsBlockStream<P, NewC> {
        BackwardsBlockStream {
            provider: self.provider,
            current_id: self.current_id,
            cache,
        }
    }

    pub async fn next_block(&mut self) -> Result<Option<StacksBlockHeader>> {
        let header_opt = self.provider.get_header(&self.current_id).await?;
        match header_opt {
            Some(header) => {
                self.current_id = header.parent_id.clone();

                if Self::should_cache_block(header.height) {
                    let _ = self
                        .cache
                        .cache_ancestor(&header.id, header.height, &self.current_id)
                        .await;
                }
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    pub async fn seek_to_height(
        &mut self,
        target_height: u64,
        anchor_tip: &StacksBlockId,
    ) -> Result<StacksBlockHeader> {
        let mut header = self
            .provider
            .get_header(&self.current_id)
            .await?
            .ok_or_else(|| anyhow!("Missing header for {}", self.current_id))?;

        let mut curr_h = header.height;

        if curr_h == target_height {
            return Ok(header);
        }

        if let Ok(Some((cached_id, cached_h))) = self
            .cache
            .find_closest_ancestor(anchor_tip, target_height)
            .await
            && cached_h < curr_h
            && cached_h >= target_height
        {
            self.current_id = cached_id;
            // Fetch header for new location
            header = self
                .provider
                .get_header(&self.current_id)
                .await?
                .ok_or_else(|| anyhow!("Missing header for {}", self.current_id))?;
            curr_h = header.height;
        }

        while curr_h > target_height {
            self.current_id = header.parent_id;
            let next_h = curr_h.saturating_sub(1);

            // Populate cache
            if Self::should_cache_block(next_h) {
                let _ = self
                    .cache
                    .cache_ancestor(anchor_tip, next_h, &self.current_id)
                    .await;
            }

            // Fetch next header
            header = self
                .provider
                .get_header(&self.current_id)
                .await?
                .ok_or_else(|| anyhow!("Missing header for {}", self.current_id))?;

            curr_h = header.height;
        }

        // Cache final result
        let _ = self
            .cache
            .cache_ancestor(anchor_tip, curr_h, &self.current_id)
            .await;

        if curr_h != target_height {
            bail!("Failed to seek to height {target_height}: ended at {curr_h}");
        }

        Ok(header)
    }

    fn should_cache_block(height: u64) -> bool {
        height.is_multiple_of(1_000)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use futures::StreamExt;
    use stacks_common::types::chainstate::StacksBlockId;

    use super::*;

    /// In-memory mock that holds a chain of headers linked by parent_id.
    struct MockHeaderProvider {
        headers: HashMap<StacksBlockId, StacksBlockHeader>,
    }

    impl BlockHeaderProvider for &MockHeaderProvider {
        async fn get_header(&self, id: &StacksBlockId) -> Result<Option<StacksBlockHeader>> {
            Ok(self.headers.get(id).cloned())
        }
    }

    fn make_block_id(height: u64) -> StacksBlockId {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_be_bytes());
        StacksBlockId(bytes)
    }

    /// Build a synthetic chain of headers: genesis(0) ← 1 ← 2 ← ... ← tip_height.
    fn build_mock_chain(tip_height: u64) -> (MockHeaderProvider, StacksBlockId) {
        use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};

        let mut headers = HashMap::new();

        for h in 0..=tip_height {
            let id = make_block_id(h);
            let parent_id = if h > 0 {
                make_block_id(h - 1)
            } else {
                StacksBlockId([0xff; 32]) // genesis parent
            };
            headers.insert(
                id.clone(),
                StacksBlockHeader {
                    id,
                    hash: BlockHeaderHash([0u8; 32]),
                    parent_id,
                    height: h,
                    burn_block_height: 0,
                    burn_block_hash: BurnchainHeaderHash([0u8; 32]),
                },
            );
        }

        let tip_id = make_block_id(tip_height);
        (MockHeaderProvider { headers }, tip_id)
    }

    /// Test that the walk_progress tracker is updated during the pre-range
    /// portion of the chain walk (heights above end_height).
    ///
    /// This replicates the exact unfold pattern from
    /// `ChainStateDb::canonical_block_stream_from_tip`.
    #[tokio::test]
    async fn walk_progress_tracker_updates() {
        let tip_height = 100u64;
        let end_height = 50u64;
        let start_height = 40u64;

        let (provider, tip_id) = build_mock_chain(tip_height);
        let walk_progress = Arc::new(AtomicU64::new(0));

        // Replicate the exact stream construction from canonical_block_stream_from_tip
        let stream = BackwardsBlockStream::new(&provider, tip_id);
        let wp = Some(walk_progress.clone());

        let mut stream = Box::pin(futures::stream::unfold(stream, move |mut bs| {
            let walk_progress = wp.clone();
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
        }));

        // Consume the stream and collect yielded headers
        let mut yielded_heights = Vec::new();
        while let Some(result) = stream.next().await {
            let header = result.expect("stream should not error");
            yielded_heights.push(header.height);
        }

        // (a) Walk tracker should have been updated with heights above end_height
        let final_walk_height = walk_progress.load(Ordering::Relaxed);
        // The last pre-range height walked is end_height + 1 = 51
        assert_eq!(final_walk_height, end_height + 1);

        // (b) Stream should yield exactly the 11 in-range headers (50 down to 40)
        assert_eq!(yielded_heights.len(), 11);
        assert_eq!(*yielded_heights.first().unwrap(), end_height);
        assert_eq!(*yielded_heights.last().unwrap(), start_height);

        // Verify descending order
        for i in 1..yielded_heights.len() {
            assert_eq!(yielded_heights[i], yielded_heights[i - 1] - 1);
        }
    }
}
