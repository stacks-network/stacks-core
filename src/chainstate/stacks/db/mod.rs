/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

pub mod accounts;
pub mod contracts;

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;

use chainstate::stacks::*;
use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::hash::to_hex;

#[cfg(target_os = "unix")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "unix")]
use libc;

use net::Error as net_error;

#[derive(Debug, Clone, PartialEq)]
pub enum AccountField {
    Nonce,
    STXBalance
};

impl fmt::Display for AccountField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AccountField::Nonce => write!(f, "nonce"),
            AccountField::STXBalance => write!(f, "stx")
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StacksAccount {
    pub principal: PrincipalData,
    pub nonce: u64,
    pub stx_balance: u128
}

impl StacksChainState {
    fn mkdirs(path: &PathBuf) -> Result<String, Error> {
        match fs::metadata(path) {
            Ok(md) => {
                if !md.is_dir() {
                    error!("Not a directory: {}", path);
                    return Err(Error::DBError(db_error::ExistsError));
                }
            },
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::IOError(e)));
                }
                fs::create_dir_all(path).map_err(|e| Error::DBError(db_error::IOError(e)))?;
            }
        }

        let path_str = path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError)).to_string();
        Ok(path_str)
    }

    pub fn open(path_str: &str) -> Result<StacksChainState, Error> {
        let chain_storage = sqlite_marf(path_str, None).map_err(Error::ClarityError)?;

        let mut path = PathBuf::from(path_str);
        path.push("blocks");

        let blocks_path = StacksChainState::mkdirs(&path)?;
        
        Ok(StacksChainState {
            chain_storage: chain_storage,
            blocks_path: blocks_path
        })
    }

    pub fn get_block_path(&self, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let block_path = PathBuf::from(self.blocks_path);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));
        block_path.push(to_hex(block_hash_bytes));

        let blocks_path_str = blocks_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError)).to_string();
        Ok(blocks_path_str)
    }

    pub fn make_block_dir(&self, block_hash: &BlockHeaderHash) -> Result<String, Error> {
        let block_hash_bytes = block_hash.as_bytes();
        let block_path = PathBuf::from(self.blocks_path);

        block_path.push(to_hex(&block_hash_bytes[0..2]));
        block_path.push(to_hex(&block_hash_bytes[2..4]));

        let _ = StacksChainState::mkdirs(&block_path)?;

        block_path.push(to_hex(block_hash_bytes));
        let blocks_path_str = blocks_path.to_str().ok_or_else(|| Error::DBError(db_error::ParseError)).to_string();
        Ok(blocks_path_str)
    }

    pub fn atomic_file_write(path: &String, bytes: &Vec<u8>) -> Result<(), Error> {
        let path_tmp = format!("{}.tmp", path);
        let mut fd = fs::OpenOptions::new()
                    .read(false)
                    .write(true)
                    .truncate(true)
                    .open(&path_tmp)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", &block_path_tmp);
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        fd.write_all(bytes).map_err(|e| Error::DBError(db_error::IOError(e)))?;

        #[cfg(target_os = "unix")] {
            let fsync_ret = unsafe {
                libc::fsync(fd.as_raw_fd())
            };

            if fsync_ret != 0 {
                let last_errno = std::io::Error::last_os_error().raw_os_error();
                panic!("Failed to fsync() on file descriptor for {:?}: error {:?}", &path_tmp, last_errno);
            }
        }

        // TODO: I don't know if there's a way to do the above in Windows

        // atomically put this trie file in place
        trace!("Rename {:?} to {:?}", &path_tmp, &path);
        fs::rename(&path_tmp, &path).map_err(|e| Error::DBError(db_error::IOError(e)))?;

        Ok(())
    }

    pub fn file_load(path: &String) -> Result<Vec<u8>, Error> {
        let mut fd = fs::OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(path)
                    .map_err(|e| {
                        if e.kind() == io::ErrorKind::NotFound {
                            error!("File not found: {:?}", path);
                            Error::DBError(db_error::NotFoundError)
                        }
                        else {
                            Error::DBError(db_error::IOError(e))
                        }
                    })?;

        let sz = match fs::metadata(path) {
            Ok(md) => {
                md.len()
            },
            Err(e) => {
                return Error::DBError(db_error::IOError(e));
            }
        }

        if sz >= usize;:max_value() {
            return Error::DBError(db_error::Corruption);
        }

        let mut buf = Vec::with_capacity(sz as usize);
        fd.read_to_end(&mut buf).map_err(|e| Error::DBError(db_error::IOError(e)))?;
        Ok(buf)
    }

    /// Store a block, named by its hash
    pub fn store_block(&self, block: &StacksBlock) -> Result<(), Error> {
        let block_hash = block.block_hash();
        let block_path = StacksChainState::make_block_dir(&block_hash)?;

        let block_data = block.serialize();
        StacksChainState::atomic_file_write(&block_path, &block_data)
    }

    /// Load up a block
    pub fn load_block(&self, block_hash: &BlockHeaderHash) -> Result<StacksBlock, Error> {
        let block_path = self.get_block_path(block_hash);
        let block_bytes = StacksChainState::file_load(block_path)?;

        let mut index = 0;
        let block = StacksBlock::deserialize(&block_bytes, &mut index, block_bytes.len())?;
        if index != (block_bytes.len() as usize) {
            error!("Corrupt block {}: read {} out of {} bytes", block_hash.to_hex(), index, block_bytes.len());
            return Error::DBError(db_error::Corruption);
        }

        Ok(block)
    }
    
    /// Store a stream of microblocks, named by its tail block's hash
    pub fn store_microblock_stream(&self, microblocks: &Vec<StacksMicroblock>) -> Result<(), Error> {
        let block_hash = microblocks[microblocks.len() - 1].block_hash();
        let block_path = StacksChainState::make_block_dir(&block_hash)?;

        let mut buf = vec![];
        for mblock in microblocks {
            let mut mblock_buf = mblock.serialize();
            buf.append(&block_buf);
        }

        StacksChainState::atomic_file_write(&block_path, &buf)
    }

    /// Load a stream of microblocks, given its tail block's hash 
    pub fn load_microblock_stream(&self, microblock_tail_hash: &BlockHeaderHash) -> Result<Vec<StacksMicroblock>, Error> {
        let block_path = self.get_block_path(block_hash);
        let block_bytes = StacksChainState::file_load(block_path)?;

        let mut index = 0;
        let mut microblocks = vec![];
        while index < block_bytes.len() {
            let microblock = StacksMicroblock::deserialize(&block_bytes, &mut index, block_bytes.len())?;
            microblocks.push(microblock);
        }

        if index != (block_bytes.len() as usize) {
            error!("Corrupt microblock stream {}: read {} out of {} bytes", block_hash.to_hex(), index, block_bytes.len());
            return Error::DBError(db_error::Corruption);
        }

        Ok(microblocks)
    }

    /// Process a block

}
