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

use rand::{thread_rng, Rng};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};
use stacks_common::util::chunked_encoding::{
    HttpChunkedTransferWriter, HttpChunkedTransferWriterState,
};
use stacks_common::util::pipe::PipeWrite;

use crate::burnchains::Txid;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock,
};
use crate::core::mempool::{MemPoolDB, MemPoolSyncData};
use crate::util_lib::db::Error as DBError;

pub trait HttpChunkGenerator: Send {
    fn generate_next_chunk(&mut self) -> Result<Vec<u8>, String>;
    fn hint_chunk_size(&self) -> usize;

    /// Stream one chunk to the pipe writer.  This never blocks.
    /// Returns Ok(num-bytes > 0) if there are more chunks (i.e. the caller should call this again)
    /// Returns Ok(0) if there are no more chunks (i.e. the caller should not call this again)
    /// Returns Err(..) on irrecoverable I/O error
    #[cfg_attr(test, mutants::skip)]
    fn stream_to(
        &mut self,
        encoder_state: &mut HttpChunkedTransferWriterState,
        fd: &mut PipeWrite,
    ) -> Result<u64, io::Error> {
        let chunk = self.generate_next_chunk().map_err(|e| {
            warn!("Chunk generator failed: {}", &e);
            io::ErrorKind::Other
        })?;

        let mut encoder = HttpChunkedTransferWriter::from_writer_state(fd, encoder_state);

        if chunk.is_empty() {
            // no more chunks, but be sure to cork the stream
            if !encoder.corked() {
                encoder.flush()?;
                encoder.cork();
            }
        } else {
            encoder.write_all(&chunk)?;
        }

        Ok(chunk.len() as u64)
    }
}

/// Interface for streaming data
pub trait Streamer {
    /// Return the offset into the stream at which this Streamer points.  This value is equivalent
    /// to returning the number of bytes streamed out so far.
    fn offset(&self) -> u64;
    /// Update the stream's offset pointer by `nw` bytes, so the implementation can keep track of
    /// how much data has been sent so far.
    fn add_bytes(&mut self, nw: u64);
}
