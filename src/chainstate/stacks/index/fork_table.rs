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

/// This file provides the fork table, described in SIP 004

use std::fmt;
use std::error;
use std::io;
use std::io::{
    Read,
    Write,
    Seek,
    SeekFrom,
    Cursor
};

use hashbrown::HashMap;
use std::collections::VecDeque;

use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::index::node::{
    clear_backptr,
    TrieNode4,
    TrieNode16,
    TrieNode48,
    TrieNode256,
    TrieLeaf
};

use chainstate::stacks::index::storage::{
    read_all,
    write_all,
    fseek,
}; 

use chainstate::stacks::index::{
    TrieHash,
    TRIEHASH_ENCODED_SIZE,
    fast_extend_from_slice,
};

use chainstate::stacks::index::Error as Error;

use util::log;

#[derive(Debug, Clone, PartialEq)]
pub struct TrieForkPtr {
    fork_id: usize,
    index: usize,
    parent_fork_id: usize,
    parent_index: usize
}

impl TrieForkPtr {
    pub fn new(fork_id: usize, index: usize, parent_fork_id: usize, parent_index: usize) -> TrieForkPtr {
        TrieForkPtr {
            fork_id,
            index,
            parent_fork_id,
            parent_index
        }
    }
}

/// Fork table for encoding parent/child relationships in the blockchain and identifying chain
/// tips and block ancestors.
#[derive(Debug, Clone, PartialEq)]
pub struct TrieForkTable {
    // map fork columns (note that SIP 004 calls these "fork rows")
    pub fork_table: Vec<Vec<BlockHeaderHash>>,

    // map each block header hash to its fork ID, the length of the fork ID column at the time
    // of insertion (helps speed up walking backwards), and the parent fork ID
    pub fork_ids: HashMap<BlockHeaderHash, TrieForkPtr>
}

impl TrieForkTable {
    /// Instantiate a fork table, given the blockchain's first block hash (the root_hash) and a
    /// mapping between blocks and their descendents (of which there may be multiple).
    /// If the parent_children table is malformed (i.e. represents a non-contiguous blockchain), this method fails.
    pub fn new(root_hash: &BlockHeaderHash, parent_children: &HashMap<BlockHeaderHash, Vec<BlockHeaderHash>>) -> Result<TrieForkTable, Error> {
        // extend out to all children
        let mut fork_table = TrieForkTable {
            fork_table: vec![],
            fork_ids: HashMap::with_capacity(1000000)
        };

        let mut fork_queue = VecDeque::new();
        fork_queue.push_back(root_hash.clone());

        while fork_queue.len() > 0 {
            let next_hash = match fork_queue.pop_front() {
                Some(h) => {
                    h
                },
                None => {
                    break;
                }
            };

            match parent_children.get(&next_hash) {
                Some(children) => {
                    // ensure that fork table columns are all created in the same order
                    let mut sorted_children = children.clone();
                    sorted_children.sort();

                    for child in sorted_children.iter() {
                        fork_table.extend(&next_hash, child)?;
                        fork_queue.push_back(child.clone());
                    }
                },
                None => {}
            }
        }

        Ok(fork_table)
    }

    /// Extend this fork table by starting a new fork, or growing an existing fork.
    /// cur_block is the ancestor of the new fork, and next_block is the first block in the new
    /// fork.  cur_block must already be known in the fork table.
    pub fn extend(&mut self, cur_block: &BlockHeaderHash, next_block: &BlockHeaderHash) -> Result<(), Error> {
        if !self.fork_ids.contains_key(cur_block) {
            if self.fork_ids.len() == 0 && self.fork_table.len() == 0 {
                // first block ever! add cur_block as the parent of next_block as the first fork column
                self.fork_table.push(vec![cur_block.clone(), next_block.clone()]);

                let cur_fork_ptr = TrieForkPtr::new(0, 0, 0, 0);
                let next_fork_ptr = TrieForkPtr::new(0, 1, 0, 0);

                trace!("New fork table: cur = {:?}, next = {:?}", cur_block, next_block);
                self.fork_ids.insert(cur_block.clone(), cur_fork_ptr);
                self.fork_ids.insert(next_block.clone(), next_fork_ptr);
                return Ok(());
            }
            else {
                // cur_block isn't in the fork table
                trace!("No fork ID for {:?}", cur_block);
                return Err(Error::NotFoundError);
            }
        }

        let fork_id = match self.fork_ids.get(cur_block) {
            Some(ref fork_ptr) => {
                fork_ptr.fork_id
            },
            None => {
                // would have errored out earlier
                unreachable!();
            }
        };

        if self.fork_table[fork_id][self.fork_table[fork_id].len() - 1] == *cur_block {
            // appending to this fork
            self.fork_table[fork_id].push((*next_block).clone());

            let fork_ptr = TrieForkPtr::new(fork_id, self.fork_table[fork_id].len() - 1, fork_id, self.fork_table[fork_id].len() - 2);
            self.fork_ids.insert((*next_block).clone(), fork_ptr.clone());
            
            trace!("Append {:?} to fork {} off of {:?} at {:?}", next_block, fork_id, cur_block, &fork_ptr);
        }
        else {
            // starting a new fork column
            self.fork_table.push(vec![(*next_block).clone()]);
            
            // what's the index in cur_block's fork column of cur_block?
            let cur_block_fork_ptr = match self.fork_ids.get(cur_block) {
                Some(fork_ptr) => {
                    fork_ptr.clone()
                },
                None => {
                    return Err(Error::CorruptionError(format!("No fork ptr for {:?}", cur_block)));
                }
            };

            assert_eq!(cur_block_fork_ptr.fork_id, fork_id);

            let next_fork_id = self.fork_table.len() - 1;
            let fork_ptr = TrieForkPtr::new(next_fork_id, 0, fork_id, cur_block_fork_ptr.index);
            self.fork_ids.insert((*next_block).clone(), fork_ptr.clone());
            
            trace!("Start a new fork column for {:?} at fork column {}, off of {:?} in fork column {} index {}", next_block, next_fork_id, cur_block, fork_ptr.parent_fork_id, fork_ptr.parent_index);
        }

        Ok(())
    }

    /// Given a block, return its fork pointer data.
    /// Returns NotFoundError if the block isn't in the fork table.
    pub fn get_fork_ptr(&self, cur_block: &BlockHeaderHash) -> Result<TrieForkPtr, Error> {
        match self.fork_ids.get(cur_block) {
            Some(ref fork_ptr) => {
                Ok((*fork_ptr).clone())
            },
            None => {
                trace!("Not in fork table: {:?}", cur_block);
                Err(Error::NotFoundError)
            }
        }
    }

    /// Given a block in the fork table, walk back the given number of blocks to find its ancestor.
    /// Fails if cur_block isn't in the fork table, or if the number of blocks to walk back would
    /// put us behind the first-ever block in the blockchain.
    pub fn walk_back(&self, cur_block: &BlockHeaderHash, _back_block: u32) -> Result<BlockHeaderHash, Error> {
        if _back_block == 0 {
            return Ok(cur_block.clone());
        }

        let fork_ptr = self.get_fork_ptr(cur_block)?;
        self.walk_back_from(&fork_ptr, cur_block, _back_block)
    }

    /// Given a fork pointer and its block, and a block count, walk back.  This is a separate
    /// method from walk_back() as an optimization -- the caller may already have queried the fork
    /// pointer for cur_block.  In this case, the caller can avoid a (surprisingly expensive)
    /// lookup in the ancestor table (the fork_table member) if the target block is in the same
    /// fork column as the fork_ptr.
    ///
    /// NOTE: cur_block is only needed for debugging purposes
    pub fn walk_back_from(&self, fork_ptr: &TrieForkPtr, cur_block: &BlockHeaderHash, _back_block: u32) -> Result<BlockHeaderHash, Error> {
        let back_block = _back_block as usize;
        let mut cnt = 0;

        let (fork_id, index) = (fork_ptr.fork_id, fork_ptr.index);

        // are we staying within our own fork column?
        if back_block <= index {
            trace!("Found in our own fork column {}: at {} - {}", fork_id, index, back_block);
            return Ok(self.fork_table[fork_id][index - back_block].clone());
        }

        // target is in some other fork column.
        // walk from the end of this fork column.
        cnt += index + 1;
        let mut block_ptr = self.fork_table[fork_id][0].clone();

        trace!("Walk from {:?} to {:?} (not in fork column {}), {} of {}", cur_block, block_ptr, fork_id, cnt, back_block);
        
        while cnt <= back_block {
            let next_block_ptr = match self.fork_ids.get(&block_ptr) {
                Some(ref fork_ptr) => {
                    let parent_fork_id = fork_ptr.parent_fork_id;
                    let parent_index = fork_ptr.parent_index;
                    let fork_column = &self.fork_table[parent_fork_id];

                    if fork_ptr.fork_id == fork_ptr.parent_fork_id && fork_ptr.index == fork_ptr.parent_index {
                        // at root
                        break;
                    }

                    trace!("cnt = {}, back_block = {}, parent_fork_id = {}, parent_index = {}", cnt, back_block, parent_fork_id, parent_index);

                    // in the parent's fork column?
                    if back_block - cnt <= parent_index {
                        let idx = parent_index - (back_block - cnt);
                        trace!("Found: parent_fork_id = {}, index = {} = {} - ({} - {}), target = {:?}", parent_fork_id, idx, parent_index, back_block, cnt, &fork_column[idx]);
                        return Ok(fork_column[idx].clone());
                    }
                    
                    // skip the rest of the fork column
                    cnt += parent_index + 1;

                    trace!("Step from {:?} to {:?} ({} steps): {} of {}", block_ptr, &fork_column[0], parent_index, cnt, back_block);
                    fork_column[0].clone()
                },
                None => {
                    return Err(Error::CorruptionError(format!("No fork ID for {:?}", &block_ptr)));
                }
            };
            block_ptr = next_block_ptr;
            trace!("walk from {:?} to {:?}, {} of {}", block_ptr, next_block_ptr, cnt, back_block);
        }
        
        trace!("Not enough ancestors of {:?} (found only {})", cur_block, cnt);
        return Err(Error::NotFoundError);
    }

    /// Is this block in the blockchain?
    pub fn contains(&self, bhh: &BlockHeaderHash) -> bool {
        self.fork_ids.contains_key(bhh)
    }

    /// What's the immediate ancestor of this block?
    pub fn get_parent(&self, bhh: &BlockHeaderHash) -> Result<BlockHeaderHash, Error> {
        self.walk_back(bhh, 1)
    }

    /// What are the chain tips of the blockchain?
    pub fn chain_tips(&self) -> Vec<BlockHeaderHash> {
        let mut ret = Vec::with_capacity(self.fork_ids.len());
        for fork_id in 0..self.fork_table.len() {
            ret.push(self.fork_table[fork_id][self.fork_table[fork_id].len() - 1].clone());
        }
        ret
    }

    /// Blow away all state
    pub fn clear(&mut self) -> () {
        self.fork_ids.clear();
        self.fork_table.clear();
    }

    /// How many blocks do we know about, across all forks?
    pub fn size(&self) -> usize {
        self.fork_ids.len()
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_variables)]
    #![allow(unused_assignments)]
    
    use super::*;
    use std::io::{
        Cursor
    };
    use std::fs;

    use chainstate::burn::BlockHeaderHash;

    use chainstate::stacks::index::test::*;
    
    use chainstate::stacks::index::bits::*;
    use chainstate::stacks::index::fork_table::*;
    use chainstate::stacks::index::marf::*;
    use chainstate::stacks::index::node::*;
    use chainstate::stacks::index::proofs::*;
    use chainstate::stacks::index::storage::*;
    use chainstate::stacks::index::trie::*;

    #[test]
    fn triefilestorage_extend() {
        let path = "/tmp/rust_triefilestorage_extend".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        // build a 5-block fork
        for i in 0..5 {
            let bhh = BlockHeaderHash([i as u8; 32]);
            MARF::extend_trie(&mut f, &bhh).unwrap();
            f.flush().unwrap();

            // file must be created
            let block_path = TrieFileStorage::block_path(&f.dir_path, &bhh);
            match fs::metadata(&block_path) {
                Ok(md) => {
                },
                Err(_) => {
                    assert!(false);
                }
            }

            // file must have parent hash
            let parent_hash = TrieFileStorage::read_block_parent(&f.dir_path, &bhh).unwrap();
            if i == 0 {
                assert_eq!(parent_hash, TrieFileStorage::block_sentinel());
            }
            else {
                assert_eq!(parent_hash, BlockHeaderHash([(i - 1) as u8; 32]));
            }
        }

        for i in 0..5 {
            assert!(f.fork_table.contains(&BlockHeaderHash([i as u8; 32])));
        }
        
        for i in 0..5 {
            assert_eq!(f.fork_table.walk_back(&BlockHeaderHash([4u8; 32]), i).unwrap(), BlockHeaderHash([(4 - i) as u8; 32]));
        }

        assert_eq!(f.tell(), BlockHeaderHash([4u8; 32]));
        assert_eq!(f.fork_table.fork_table.len(), 1);

        let mut sorted_chain_tips = f.fork_table.fork_table[0].clone();
        sorted_chain_tips.sort();

        assert_eq!(sorted_chain_tips, vec![BlockHeaderHash([0u8; 32]), BlockHeaderHash([1u8; 32]), BlockHeaderHash([2u8; 32]), BlockHeaderHash([3u8; 32]), BlockHeaderHash([4u8; 32]), TrieFileStorage::block_sentinel()]);

        // re-instantiation will load the fork
        let f2 = TrieFileStorage::new(&path).unwrap();
        assert_eq!(f2.fork_table, f.fork_table);
        
        for i in 0..5 {
            assert!(f2.fork_table.contains(&BlockHeaderHash([i as u8; 32])));
        }
        
        for i in 0..5 {
            assert_eq!(f2.fork_table.walk_back(&BlockHeaderHash([4u8; 32]), i).unwrap(), BlockHeaderHash([(4 - i) as u8; 32]));
        }
    } 
    
    #[test]
    fn triefilestorage_extend_fork_sequence() {
        let path = "/tmp/rust_triefilestorage_extend_fork_sequence".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut main_fork = vec![TrieFileStorage::block_sentinel()];
        let mut expected_forks : Vec<Vec<BlockHeaderHash>> = vec![];
        let mut expected_chain_tips = vec![];

        for i in 0..5 {
            expected_forks.push(vec![TrieFileStorage::block_sentinel()]);
        }

        for i in 0..5 {
            let bhh = BlockHeaderHash([i as u8; 32]);
            let fork_bhh = BlockHeaderHash([(i + 128) as u8; 32]);

            MARF::extend_trie(&mut f, &bhh).unwrap();
            f.flush().unwrap();
            
            // file must be created
            let block_path = TrieFileStorage::block_path(&f.dir_path, &bhh);
            match fs::metadata(&block_path) {
                Ok(md) => {
                },
                Err(_) => {
                    assert!(false);
                }
            }

            // file must have parent hash
            let parent_hash = TrieFileStorage::read_block_parent(&f.dir_path, &bhh).unwrap();
            if i == 0 {
                assert_eq!(parent_hash, TrieFileStorage::block_sentinel());
            }
            else {
                assert_eq!(parent_hash, BlockHeaderHash([(i - 1) as u8; 32]));
            }

            // make a sibling 1-block fork
            if i > 0 {
                f.open(&parent_hash, true).unwrap();
                MARF::extend_trie(&mut f, &fork_bhh).unwrap();
                f.flush().unwrap();
            
                // file must be created
                let block_path = TrieFileStorage::block_path(&f.dir_path, &fork_bhh);
                match fs::metadata(&block_path) {
                    Ok(md) => {
                    },
                    Err(_) => {
                        assert!(false);
                    }
                }

                // file must have parent hash
                let parent_hash = TrieFileStorage::read_block_parent(&f.dir_path, &fork_bhh).unwrap();
                assert_eq!(parent_hash, BlockHeaderHash([(i - 1) as u8; 32]));

                expected_chain_tips.push(fork_bhh);
            }

            f.open(&bhh, true).unwrap();

            if i > 0 {
                expected_forks[i] = main_fork.clone();
                expected_forks[i].push(fork_bhh);
            }
            
            main_fork.push(bhh);
        }
        
        expected_forks[0] = main_fork.clone();

        expected_chain_tips.push(f.tell());

        trace!("fork table:\n{:#?}", &f.fork_table);

        let mut chain_tips = f.fork_table.chain_tips();

        expected_chain_tips.sort();
        chain_tips.sort();
        assert_eq!(expected_chain_tips, chain_tips);
        
        trace!("chain tips: {:?}", chain_tips);
        trace!("expected forks:\n{:#?}", &expected_forks);

        // all parent blocks are reachable from each non-root
        for expected_fork in expected_forks.iter() {
            for j in 0..expected_fork.len() {
                let chain_tip = expected_fork[expected_fork.len() - j - 1].clone();
                for i in 0..expected_fork.len()-j {
                    let k = expected_fork.len() - j - 1 - i;
                    trace!("Walk from {:?} back {} to {:?}", &chain_tip, k, &expected_fork[i]);
                    let parent_bhh = f.fork_table.walk_back(&chain_tip, k as u32).unwrap();
                    assert_eq!(parent_bhh, expected_fork[i]);
                }
            }
        }
        
        // re-instantiation will load the fork
        let f2 = TrieFileStorage::new(&path).unwrap();

        trace!("fork table 1:\n{:#?}", &f.fork_table);
        trace!("fork table 2:\n{:#?}", &f2.fork_table);

        assert_eq!(f2.fork_table, f.fork_table);
        
        // all parent blocks are reachable from each non-root
        for expected_fork in expected_forks.iter() {
            for j in 0..expected_fork.len() {
                let chain_tip = expected_fork[expected_fork.len() - j - 1].clone();
                for i in 0..expected_fork.len()-j {
                    let k = expected_fork.len() - j - 1 - i;
                    trace!("Walk from {:?} back {} to {:?}", &chain_tip, k, &expected_fork[i]);
                    let parent_bhh = f2.fork_table.walk_back(&chain_tip, k as u32).unwrap();
                    assert_eq!(parent_bhh, expected_fork[i]);
                }
            }
        }
    }

    #[test]
    fn triefilestorage_extend_fork_5_len_3() {
        let path = "/tmp/rust_triefilestorage_extend_fork_5_len_3".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();

        let mut expected_forks : Vec<Vec<BlockHeaderHash>> = vec![];
        let mut expected_root_fork = vec![];

        expected_root_fork.push(TrieFileStorage::block_sentinel());

        // build a 5-block fork...
        for i in 0..5 {
            let bhh = BlockHeaderHash([i as u8; 32]);
            expected_root_fork.push(bhh.clone());

            MARF::extend_trie(&mut f, &bhh).unwrap();
            f.flush().unwrap();

            // file must be created
            let block_path = TrieFileStorage::block_path(&f.dir_path, &bhh);
            match fs::metadata(&block_path) {
                Ok(md) => {
                },
                Err(_) => {
                    assert!(false);
                }
            }

            // file must have parent hash
            let parent_hash = TrieFileStorage::read_block_parent(&f.dir_path, &bhh).unwrap();
            if i == 0 {
                assert_eq!(parent_hash, TrieFileStorage::block_sentinel());
            }
            else {
                assert_eq!(parent_hash, BlockHeaderHash([(i - 1) as u8; 32]));
            }
        }

        for i in 0..5 {
            expected_forks.push(expected_root_fork.clone());
        }

        // build 5 additional 3-block forks off of it
        for i in 0..5 {
            f.open(&BlockHeaderHash([4u8; 32]), false).unwrap();

            for j in 0..3 {
                let bhh = BlockHeaderHash([(3*(i+5) + j) as u8; 32]);
                expected_forks[i].push(bhh);

                MARF::extend_trie(&mut f, &bhh).unwrap();
                f.flush().unwrap();

                // file must be created
                let block_path = TrieFileStorage::block_path(&f.dir_path, &bhh);
                match fs::metadata(&block_path) {
                    Ok(md) => {
                    },
                    Err(_) => {
                        assert!(false);
                    }
                }

                // file must have parent hash
                let parent_hash = TrieFileStorage::read_block_parent(&f.dir_path, &bhh).unwrap();
                if j == 0 {
                    // common ancestor of all 3 forks
                    assert_eq!(parent_hash, BlockHeaderHash([4u8; 32]));
                }
                else {
                    assert_eq!(parent_hash, BlockHeaderHash([(3*(i+5) + j - 1) as u8; 32]));
                }
            }
        }

        trace!("fork table = \n{:#?}", &f.fork_table);
        assert_eq!(f.fork_table.fork_table.len(), 5);
        let chain_tips = f.fork_table.chain_tips();
        assert_eq!(chain_tips.len(), 5);

        assert_eq!(chain_tips, vec![
                   BlockHeaderHash([17u8; 32]), 
                   BlockHeaderHash([20u8; 32]), 
                   BlockHeaderHash([23u8; 32]),
                   BlockHeaderHash([26u8; 32]),
                   BlockHeaderHash([29u8; 32])
                ]);

        for (j, chain_tip) in chain_tips.iter().enumerate() {
            // we can walk back all the way to the root from each chain tip
            for i in 0..9 {
                trace!("walk {:?} back {} to {:?}?", chain_tip, 8 - i, expected_forks[j][i as usize]);
                let bh = f.fork_table.walk_back(chain_tip, 8 - i).unwrap();
                assert_eq!(expected_forks[j][i as usize], bh);
            }
        }

        // re-instantiation will load the fork
        let f2 = TrieFileStorage::new(&path).unwrap();

        trace!("fork table 1:\n{:#?}", &f.fork_table);
        trace!("fork table 2:\n{:#?}", &f2.fork_table);

        assert_eq!(f2.fork_table, f.fork_table);

        for (j, chain_tip) in chain_tips.iter().enumerate() {
            // we can walk back all the way to the root from each chain tip in the loaded fork
            for i in 0..9 {
                trace!("walk {:?} back {} to {:?}?", chain_tip, 8 - i, expected_forks[j][i as usize]);
                let bh = f2.fork_table.walk_back(chain_tip, 8 - i).unwrap();
                assert_eq!(expected_forks[j][i as usize], bh);
            }
        }

        // all parent blocks are reachable from all non-root blocks
        for s in [f, f2].iter() {
            for expected_fork in expected_forks.iter() {
                for j in 0..expected_fork.len() {
                    let chain_tip = expected_fork[expected_fork.len() - j - 1].clone();
                    for i in 0..expected_fork.len()-j {
                        let k = expected_fork.len() - j - 1 - i;
                        trace!("Walk from {:?} back {} to {:?}", &chain_tip, k, &expected_fork[i]);
                        let parent_bhh = s.fork_table.walk_back(&chain_tip, k as u32).unwrap();
                        assert_eq!(parent_bhh, expected_fork[i]);
                    }
                }
            }
        }
    }

    #[test]
    fn triefilestorage_extend_fork_tree_256() {
        // make a 256-item binary tree of forks
        let path = "/tmp/rust_triefilestorage_extend_fork_tree_256".to_string();
        match fs::metadata(&path) {
            Ok(_) => {
                fs::remove_dir_all(&path).unwrap();
            },
            Err(_) => {}
        };
        let mut f = TrieFileStorage::new(&path).unwrap();
        let mut fork_headers = vec![];
        
        MARF::extend_trie(&mut f, &BlockHeaderHash([0u8; 32])).unwrap();

        let mut pattern = 0u8;
        for c in 0..8 {
            let mut next_fork_row = vec![];
            for i in 0..(1 << c) {
                next_fork_row.push(BlockHeaderHash([pattern; 32]));
                pattern += 1;
            }
            fork_headers.push(next_fork_row);
        }

        for i in 1..8 {
            let parent_row = &fork_headers[i-1];
            for j in 0..parent_row.len() {
                let parent_hash = &parent_row[j];
                for k in (2*j)..(2*j+2) {
                    let child_hash = &fork_headers[i][k];

                    test_debug!("Branch from {:?} to {:?}", parent_hash, child_hash);
                    
                    f.open(&parent_hash, true).unwrap();
                    MARF::extend_trie(&mut f, child_hash).unwrap();
                    f.flush().unwrap();
            
                    // file must be created
                    let block_path = TrieFileStorage::block_path(&f.dir_path, child_hash);
                    match fs::metadata(&block_path) {
                        Ok(md) => {
                        },
                        Err(_) => {
                            assert!(false);
                        }
                    }

                    // file must have parent hash
                    let parent_hash_read = TrieFileStorage::read_block_parent(&f.dir_path, child_hash).unwrap();
                    if i == 0 {
                        assert_eq!(parent_hash_read, TrieFileStorage::block_sentinel());
                    }
                    else {
                        assert_eq!(parent_hash_read, *parent_hash);
                    }
                }
            }
        }
        
        let mut expected_chain_tips = fork_headers[fork_headers.len() - 1].clone();
        expected_chain_tips.sort();

        let mut chain_tips = f.fork_table.chain_tips();
        chain_tips.sort();

        trace!("fork table = \n{:#?}", &f.fork_table);
        assert_eq!(chain_tips, expected_chain_tips);

        let f2 = TrieFileStorage::new(&path).unwrap();
        assert_eq!(f2.fork_table, f.fork_table);

        test_debug!("fork_headers = \n{:#?}", fork_headers);
        for i in 1..8 {
            let parent_row = &fork_headers[i-1];
            for j in 0..parent_row.len() {
                let parent_hash = &parent_row[j];
                for d in i..8 {
                    let depth = d - i + 1;
                    for k in ((1 << depth)*j)..((1 << depth)*(j+1)) {
                        test_debug!("Test walk back from [{}][{}] to [{}][{}]", i + depth - 1, k, i-1, j);

                        let child_hash = &fork_headers[i + depth - 1][k];
                        
                        test_debug!("Test walk back from [{}][{}] {:?} to [{}][{}] {:?} (back {})", i + depth - 1, k, child_hash, i-1, j, parent_hash, depth);
                        let ph = f.fork_table.walk_back(&child_hash, depth as u32).unwrap();
                        assert_eq!(*parent_hash, ph);
                    }
                }
            }
        }
    }
}


