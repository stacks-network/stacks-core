// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::io;
use std::io::{Read, Write};

use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::StacksBlockId;

use crate::burnchains::Txid;
use crate::chainstate::stacks::{StacksBlock, StacksBlockHeader, StacksMicroblock};

use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainstateError;

use crate::core::mempool::MemPoolDB;

use crate::net::MemPoolSyncData;

use rand::thread_rng;
use rand::Rng;

/// Interface for streaming data
pub trait Streamer {
    /// Return the offset into the stream at which this Streamer points.  This value is equivalent
    /// to returning the number of bytes streamed out so far.
    fn offset(&self) -> u64;
    /// Update the stream's offset pointer by `nw` bytes, so the implementation can keep track of
    /// how much data has been sent so far.
    fn add_bytes(&mut self, nw: u64);
}

/// Opaque structure for streaming block, microblock, and header data from disk
#[derive(Debug, PartialEq, Clone)]
pub enum StreamCursor {
    Block(BlockStreamData),
    Microblocks(MicroblockStreamData),
    Headers(HeaderStreamData),
    MempoolTxs(TxStreamData),
}

#[derive(Debug, PartialEq, Clone)]
pub struct BlockStreamData {
    /// index block hash of the block to download
    pub index_block_hash: StacksBlockId,
    /// offset into whatever is being read (the blob, or the file in the chunk store)
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,
}

#[derive(Debug, PartialEq, Clone)]
pub struct MicroblockStreamData {
    /// index block hash of the block to download
    pub index_block_hash: StacksBlockId,
    /// microblock blob row id
    pub rowid: Option<i64>,
    /// offset into whatever is being read (the blob, or the file in the chunk store)
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,

    /// length prefix
    pub num_items_buf: [u8; 4],
    pub num_items_ptr: usize,

    /// microblock pointer
    pub microblock_hash: BlockHeaderHash,
    pub parent_index_block_hash: StacksBlockId,

    /// unconfirmed state
    pub seq: u16,
    pub unconfirmed: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HeaderStreamData {
    /// index block hash of the block to download
    pub index_block_hash: StacksBlockId,
    /// offset into whatever is being read (the blob, or the file in the chunk store)
    pub offset: u64,
    /// total number of bytes read.
    pub total_bytes: u64,
    /// number of headers requested
    pub num_headers: u32,

    /// header buffer data
    pub header_bytes: Option<Vec<u8>>,
    pub end_of_stream: bool,
    pub corked: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TxStreamData {
    /// Mempool sync data requested
    pub tx_query: MemPoolSyncData,
    /// last txid loaded
    pub last_randomized_txid: Txid,
    /// serialized transaction buffer that's being sent
    pub tx_buf: Vec<u8>,
    pub tx_buf_ptr: usize,
    /// number of transactions visited in the DB so far
    pub num_txs: u64,
    /// maximum we can visit in the query
    pub max_txs: u64,
    /// height of the chain at time of query
    pub height: u64,
    /// Are we done sending transactions, and are now in the process of sending the trailing page
    /// ID?
    pub corked: bool,
}

impl MicroblockStreamData {
    /// Stream the number of microblocks, as a SIP-003-encoded 4-byte big-endian integer.
    /// Returns the number of bytes written to `fd` on success
    /// Returns chainstate errors otherwise.
    fn stream_count<W: Write>(&mut self, fd: &mut W, count: u64) -> Result<u64, ChainstateError> {
        let mut num_written = 0;
        while self.num_items_ptr < self.num_items_buf.len() && num_written < count {
            // stream length prefix
            test_debug!(
                "Length prefix: try to send {:?} (ptr={})",
                &self.num_items_buf[self.num_items_ptr..],
                self.num_items_ptr
            );
            let num_sent = match fd.write(&self.num_items_buf[self.num_items_ptr..]) {
                Ok(0) => {
                    // done (disconnected)
                    test_debug!("Length prefix: wrote 0 bytes",);
                    return Ok(num_written);
                }
                Ok(n) => {
                    self.num_items_ptr += n;
                    n as u64
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // EINTR; try again
                        continue;
                    } else if e.kind() == io::ErrorKind::WouldBlock
                        || (cfg!(windows) && e.kind() == io::ErrorKind::TimedOut)
                    {
                        // blocked
                        return Ok(num_written);
                    } else {
                        return Err(ChainstateError::WriteError(e));
                    }
                }
            };
            num_written += num_sent;
            test_debug!(
                "Length prefix: sent {} bytes ({} total)",
                num_sent,
                num_written
            );
        }
        Ok(num_written)
    }
}

impl StreamCursor {
    /// Create a new stream cursor for a Stacks block
    pub fn new_block(index_block_hash: StacksBlockId) -> StreamCursor {
        StreamCursor::Block(BlockStreamData {
            index_block_hash: index_block_hash,
            offset: 0,
            total_bytes: 0,
        })
    }

    /// Create a new stream cursor for a Stacks microblock stream that has been confirmed.
    /// Returns an error if the identified microblock stream does not exist.
    pub fn new_microblock_confirmed(
        chainstate: &StacksChainState,
        tail_index_microblock_hash: StacksBlockId,
    ) -> Result<StreamCursor, ChainstateError> {
        // look up parent
        let mblock_info = StacksChainState::load_staging_microblock_info_indexed(
            &chainstate.db(),
            &tail_index_microblock_hash,
        )?
        .ok_or(ChainstateError::NoSuchBlockError)?;

        let parent_index_block_hash = StacksBlockHeader::make_index_block_hash(
            &mblock_info.consensus_hash,
            &mblock_info.anchored_block_hash,
        );

        // need to send out the consensus_serialize()'ed array length before sending microblocks.
        // this is exactly what seq tells us, though.
        let num_items_buf = ((mblock_info.sequence as u32) + 1).to_be_bytes();

        Ok(StreamCursor::Microblocks(MicroblockStreamData {
            index_block_hash: StacksBlockId([0u8; 32]),
            rowid: None,
            offset: 0,
            total_bytes: 0,
            microblock_hash: mblock_info.microblock_hash,
            parent_index_block_hash: parent_index_block_hash,
            seq: mblock_info.sequence,
            unconfirmed: false,
            num_items_buf: num_items_buf,
            num_items_ptr: 0,
        }))
    }

    /// Create a new stream cursor for a Stacks microblock stream that is unconfirmed.
    /// Returns an error if the parent Stacks block does not exist, or if the sequence number is
    /// too far ahead of the unconfirmed stream's tail.
    pub fn new_microblock_unconfirmed(
        chainstate: &StacksChainState,
        anchored_index_block_hash: StacksBlockId,
        seq: u16,
    ) -> Result<StreamCursor, ChainstateError> {
        let mblock_info = StacksChainState::load_next_descendant_microblock(
            &chainstate.db(),
            &anchored_index_block_hash,
            seq,
        )?
        .ok_or(ChainstateError::NoSuchBlockError)?;

        Ok(StreamCursor::Microblocks(MicroblockStreamData {
            index_block_hash: anchored_index_block_hash.clone(),
            rowid: None,
            offset: 0,
            total_bytes: 0,
            microblock_hash: mblock_info.block_hash(),
            parent_index_block_hash: anchored_index_block_hash,
            seq: seq,
            unconfirmed: true,
            num_items_buf: [0u8; 4],
            num_items_ptr: 4, // stops us from trying to send a length prefix
        }))
    }

    pub fn new_headers(
        chainstate: &StacksChainState,
        tip: &StacksBlockId,
        num_headers_requested: u32,
    ) -> Result<StreamCursor, ChainstateError> {
        let header_info = StacksChainState::load_staging_block_info(chainstate.db(), tip)?
            .ok_or(ChainstateError::NoSuchBlockError)?;

        let num_headers = if header_info.height < (num_headers_requested as u64) {
            header_info.height as u32
        } else {
            num_headers_requested
        };

        test_debug!("Request for {} headers from {}", num_headers, tip);

        Ok(StreamCursor::Headers(HeaderStreamData {
            index_block_hash: tip.clone(),
            offset: 0,
            total_bytes: 0,
            num_headers: num_headers,
            header_bytes: None,
            end_of_stream: false,
            corked: false,
        }))
    }

    /// Create a new stream cursor for mempool transactions
    pub fn new_tx_stream(
        tx_query: MemPoolSyncData,
        max_txs: u64,
        height: u64,
        page_id_opt: Option<Txid>,
    ) -> StreamCursor {
        let last_randomized_txid = page_id_opt.unwrap_or_else(|| {
            let random_bytes = thread_rng().gen::<[u8; 32]>();
            Txid(random_bytes)
        });

        StreamCursor::MempoolTxs(TxStreamData {
            tx_query,
            last_randomized_txid: last_randomized_txid,
            tx_buf: vec![],
            tx_buf_ptr: 0,
            num_txs: 0,
            max_txs: max_txs,
            height: height,
            corked: false,
        })
    }

    /// Write a single byte to the given `fd`.
    /// Non-blocking -- masks EINTR by returning 0.
    fn stream_one_byte<W: Write>(fd: &mut W, b: u8) -> Result<u64, ChainstateError> {
        loop {
            match fd.write(&[b]) {
                Ok(0) => {
                    // done (disconnected)
                    return Ok(0);
                }
                Ok(n) => {
                    return Ok(n as u64);
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        // EINTR; try again
                        continue;
                    } else if e.kind() == io::ErrorKind::WouldBlock
                        || (cfg!(windows) && e.kind() == io::ErrorKind::TimedOut)
                    {
                        // blocked
                        return Ok(0);
                    } else {
                        return Err(ChainstateError::WriteError(e));
                    }
                }
            }
        }
    }

    /// Get the offset into the stream at which the cursor points
    pub fn get_offset(&self) -> u64 {
        match self {
            StreamCursor::Block(ref stream) => stream.offset(),
            StreamCursor::Microblocks(ref stream) => stream.offset(),
            StreamCursor::Headers(ref stream) => stream.offset(),
            // no-op for mempool txs
            StreamCursor::MempoolTxs(..) => 0,
        }
    }

    /// Update the cursor's offset by nw
    pub fn add_more_bytes(&mut self, nw: u64) {
        match self {
            StreamCursor::Block(ref mut stream) => stream.add_bytes(nw),
            StreamCursor::Microblocks(ref mut stream) => stream.add_bytes(nw),
            StreamCursor::Headers(ref mut stream) => stream.add_bytes(nw),
            // no-op fo mempool txs
            StreamCursor::MempoolTxs(..) => (),
        }
    }

    /// Stream chainstate data into the given `fd`.
    /// Depending on what StreamCursor variant we are, the data may come from the chainstate or
    /// mempool.
    /// Returns the number of bytes streamed on success.
    /// Return an error on I/O errors, or if this cursor does not represent chainstate data.
    pub fn stream_to<W: Write>(
        &mut self,
        mempool: &MemPoolDB,
        chainstate: &mut StacksChainState,
        fd: &mut W,
        count: u64,
    ) -> Result<u64, ChainstateError> {
        match self {
            StreamCursor::Microblocks(ref mut stream) => {
                let mut num_written = 0;
                if !stream.unconfirmed {
                    // Confirmed microblocks are represented as a consensus-encoded vector of
                    // microblocks, in reverse sequence order.
                    // Write 4-byte length prefix first
                    num_written += stream.stream_count(fd, count)?;
                    StacksChainState::stream_microblocks_confirmed(&chainstate, fd, stream, count)
                        .and_then(|bytes_sent| Ok(bytes_sent + num_written))
                } else {
                    StacksChainState::stream_microblocks_unconfirmed(&chainstate, fd, stream, count)
                        .and_then(|bytes_sent| Ok(bytes_sent + num_written))
                }
            }
            StreamCursor::MempoolTxs(ref mut tx_stream) => mempool.stream_txs(fd, tx_stream, count),
            StreamCursor::Headers(ref mut stream) => {
                // headers are a JSON array.  Start by writing '[', then write each header, and
                // then write ']'
                let mut num_written = 0;
                if stream.total_bytes == 0 {
                    test_debug!("Opening header stream");
                    let byte_written = StreamCursor::stream_one_byte(fd, '[' as u8)?;
                    num_written += byte_written;
                    stream.total_bytes += byte_written;
                }
                if stream.total_bytes > 0 {
                    let mut sent = chainstate.stream_headers(fd, stream, count)?;

                    if stream.end_of_stream && !stream.corked {
                        // end of stream; cork it
                        test_debug!("Corking header stream");
                        let byte_written = StreamCursor::stream_one_byte(fd, ']' as u8)?;
                        if byte_written > 0 {
                            sent += byte_written;
                            stream.total_bytes += byte_written;
                            stream.corked = true;
                        }
                    }
                    num_written += sent;
                }
                Ok(num_written)
            }
            StreamCursor::Block(ref mut stream) => chainstate.stream_block(fd, stream, count),
        }
    }
}

impl Streamer for StreamCursor {
    fn offset(&self) -> u64 {
        self.get_offset()
    }
    fn add_bytes(&mut self, nw: u64) {
        self.add_more_bytes(nw)
    }
}

impl Streamer for HeaderStreamData {
    fn offset(&self) -> u64 {
        self.offset
    }
    fn add_bytes(&mut self, nw: u64) {
        self.offset += nw;
        self.total_bytes += nw;
    }
}

impl Streamer for BlockStreamData {
    fn offset(&self) -> u64 {
        self.offset
    }
    fn add_bytes(&mut self, nw: u64) {
        self.offset += nw;
        self.total_bytes += nw;
    }
}

impl Streamer for MicroblockStreamData {
    fn offset(&self) -> u64 {
        self.offset
    }
    fn add_bytes(&mut self, nw: u64) {
        self.offset += nw;
        self.total_bytes += nw;
    }
}
