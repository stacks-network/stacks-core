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

pub mod blocks;
pub mod common;
pub mod index;
pub mod spv;

#[cfg(test)]
mod tests;

pub use blocks::{
    copy_confirmed_epoch2_microblocks, copy_epoch2_block_files, copy_nakamoto_staging_blocks,
    validate_epoch2_block_files, validate_microblock_streams, validate_nakamoto_staging_blocks,
    Epoch2BlockFileCopyStats, Epoch2BlockFileValidation, Epoch2MicroblockCopyStats,
    MicroblockValidation, NakamotoBlockCopyStats, NakamotoBlockValidation,
};
pub use index::{
    copy_index_side_tables, validate_index_side_tables, IndexSideTableStats,
    IndexSideTableValidation,
};
pub use spv::{copy_spv_headers, validate_spv_headers, SpvHeadersCopyStats, SpvHeadersValidation};
