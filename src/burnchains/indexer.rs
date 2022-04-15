// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use burnchains::events::NewBlock;
use burnchains::BurnchainBlock;
use burnchains::Error as burnchain_error;
use burnchains::*;

use crate::types::chainstate::BurnchainHeaderHash;
use core::StacksEpoch;
use std::sync::Arc;

// IPC messages between threads
pub trait BurnHeaderIPC {
    type H: Send + Sync + Clone;

    fn height(&self) -> u64;
    fn header(&self) -> Self::H;
    fn header_hash(&self) -> [u8; 32];
    fn parent_header_hash(&self) -> [u8; 32];
    fn time_stamp(&self) -> u64;
}

pub trait BurnBlockIPC {
    type H: BurnHeaderIPC + Sync + Send + Clone;
    type B: Send + Sync + Clone;

    fn height(&self) -> u64;
    fn header(&self) -> Self::H;
    fn block(&self) -> Self::B;
}

pub trait BurnchainBlockDownloader {
    type B: BurnBlockIPC + Sync + Send + Clone;

    fn download(
        &mut self,
        header: &<Self::B as BurnBlockIPC>::H,
    ) -> Result<Self::B, burnchain_error>;
}

pub trait BurnchainBlockParser {
    type B: BurnBlockIPC + Sync + Send + Clone;

    fn parse(&mut self, block: &Self::B) -> Result<BurnchainBlock, burnchain_error>;
}

pub trait BurnchainChannel: Send + Sync {
    /// Push a block into the channel.
    fn push_block(&self, new_block: NewBlock) -> Result<(), burnchain_error>;
}

pub trait BurnchainIndexer {
    type B: BurnBlockIPC + Sync + Send + Clone;
    type P: BurnchainBlockParser<B = Self::B> + Send + Sync;
    type D: BurnchainBlockDownloader<B = Self::B> + Send + Sync;

    /// This call should be a no-op. TODO: Remove this.
    fn connect(&mut self, readwrite: bool) -> Result<(), burnchain_error>;

    /// Gets a channel to input blocks to this indexer.
    fn get_channel(&self) -> Arc<dyn BurnchainChannel>;

    /// Retrieve aspects of the "first block" that we are tracking.
    fn get_first_block_height(&self) -> u64;
    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, burnchain_error>;
    fn get_first_block_header_timestamp(&self) -> Result<u64, burnchain_error>;

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch>;

    /// Returns the path for the database underlying this.
    fn get_headers_path(&self) -> String;

    /// Returns the relative height (relative to the first block) of the highest header.
    fn get_highest_header_height(&self) -> Result<u64, burnchain_error>;

    /// Returns `get_highest_header_height() + 1.
    fn get_headers_height(&self) -> Result<u64, burnchain_error>;

    /// Returns true if there has been a reorg since the last time this function was called.
    fn find_chain_reorg(&mut self) -> Result<u64, burnchain_error>;

    /// This method will block until at least one header (the "first" tracked header) has been read.
    ///
    /// It will return the highest height known about.
    fn sync_headers(
        &mut self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> Result<u64, burnchain_error>;

    /// This is a no-op for hyper-chains. TODO: Remove this.
    fn drop_headers(&mut self, new_height: u64) -> Result<(), burnchain_error>;

    /// Reads in the headers from `start_block` to `end_block`.
    /// If the headers in this range do not exist, it is not an error, and a truncated vector
    /// is returned.
    fn read_headers(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<<Self::B as BurnBlockIPC>::H>, burnchain_error>;

    fn downloader(&self) -> Self::D;
    fn parser(&self) -> Self::P;
}
