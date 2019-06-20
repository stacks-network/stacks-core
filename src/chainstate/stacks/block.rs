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

use chainstate::stacks::TransactionAnchorMode;
use chainstate::stacks::TransactionPayloadID;
use chainstate::stacks::StacksBlockHeader;
use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksMicroblockHeader;
use chainstate::stacks::StacksMicroblock;
use chainstate::stacks::StacksTransaction;
use chainstate::stacks::MAX_BLOCK_SIZE;
use chainstate::stacks::MAX_MICROBLOCK_SIZE;

use chainstate::burn::BlockHeaderHash;

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use util::vrf::ECVRF_Proof;
use util::hash::MerkleTree;
use util::hash::Sha256Sum;
use util::hash::DoubleSha256;

impl StacksMessageCodec for ECVRF_Proof {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<ECVRF_Proof, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 80 {
            return Err(net_error::OverflowError);
        }
        if index + 80 < max_size {
            return Err(net_error::OverflowError);
        }

        if (buf.len() as u32) < index + 80 {
            return Err(net_error::UnderflowError);
        }
        let res = ECVRF_Proof::from_slice(&buf[(index as usize)..((index+80) as usize)])
            .map_err(|_e| net_error::DeserializeError)?;
            
        *index_ptr += 80;
        Ok(res)
    }
}
            

impl StacksMessageCodec for StacksBlockHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.version);
        write_next(&mut ret, &self.parent_block);
        write_next(&mut ret, &self.last_microblock);
        write_next(&mut ret, &self.proof);
        write_next(&mut ret, &self.merkle_root);
        write_next(&mut ret, &self.balance_root);
        write_next(&mut ret, &self.state_root);
        write_next(&mut ret, &self.principal);
        write_next(&mut ret, &self.reserved);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksBlockHeader, net_error> {
        let version: u8                         = read_next(&buf, index, max_size)?;
        let parent_block: BlockHeaderHash       = read_next(&buf, index, max_size)?;
        let last_microblock: BlockHeaderHash    = read_next(&buf, index, max_size)?;
        let proof : ECVRF_Proof                 = read_next(&buf, index, max_size)?;
        let merkle_root: DoubleSha256           = read_next(&buf, index, max_size)?;
        let balance_root: DoubleSha256          = read_next(&buf, index, max_size)?;
        let state_root: DoubleSha256            = read_next(&buf, index, max_size)?;
        let principal: StacksAddress            = read_next(&buf, index, max_size)?;
        let reserved: [u8; 32]                  = read_next(&buf, index, max_size)?;

        Ok(StacksBlockHeader {
            version,
            parent_block,
            last_microblock,
            proof,
            merkle_root,
            balance_root,
            state_root,
            principal,
            reserved
        })
    }
}

impl StacksMessageCodec for StacksBlock {
    /// NOTE: the merkle root will _not_ be checked against the transactions!
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.header);
        write_next(&mut ret, &self.txs);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksBlock, net_error> {
        // no matter what, do not allow us to parse a block bigger than 1MB
        let index = *index_ptr;
        if index > u32::max_value() - MAX_BLOCK_SIZE {
            return Err(net_error::OverflowError);
        }

        let size_clamp = index + MAX_BLOCK_SIZE;
        let header : StacksBlockHeader      = read_next(buf, index_ptr, size_clamp)?;
        let txs : Vec<StacksTransaction>    = read_next(buf, index_ptr, size_clamp)?;

        // all transactions must have anchor mode either OnChainOnly or Any
        // (no OffChainOnly allowed)
        for i in 0..txs.len() {
            match txs[i].anchor_mode {
                TransactionAnchorMode::OnChainOnly | TransactionAnchorMode::Any => {
                    continue;
                }
                _ => {
                    return Err(net_error::DeserializeError);
                }
            };
        }

        // header and transactions must be consistent
        let txid_vecs = txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<DoubleSha256>::new(&txid_vecs);
        let merkle_root = merkle_tree.root();
        
        if merkle_root != header.merkle_root {
            return Err(net_error::DeserializeError);
        }

        Ok(StacksBlock {
            header,
            txs
        })
    }
}

impl StacksMessageCodec for StacksMicroblockHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.version);
        write_next(&mut ret, &self.prev_block);
        write_next(&mut ret, &self.merkle_root);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMicroblockHeader, net_error> {
        let version : u8                    = read_next(buf, index_ptr, max_size)?;
        let prev_block : BlockHeaderHash    = read_next(buf, index_ptr, max_size)?;
        let merkle_root : DoubleSha256      = read_next(buf, index_ptr, max_size)?;
        Ok(StacksMicroblockHeader {
            version,
            prev_block,
            merkle_root
        })
    }
}

impl StacksMessageCodec for StacksMicroblock {
    /// NOTE: the merkle root will _not_ be checked against the transactions!
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.header);
        write_next(&mut ret, &self.txs);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMicroblock, net_error> {
        // no matter what, do not allow us to parse a block bigger than 1MB
        let index = *index_ptr;
        if index > u32::max_value() - MAX_MICROBLOCK_SIZE {
            return Err(net_error::OverflowError);
        }

        let size_clamp = index + MAX_MICROBLOCK_SIZE;
        let header : StacksMicroblockHeader = read_next(buf, index_ptr, size_clamp)?;
        let txs : Vec<StacksTransaction>    = read_next(buf, index_ptr, size_clamp)?;

        // all transactions must have anchor mode either OffChainOnly or Any
        // (no OnChainOnly allowed)
        for i in 0..txs.len() {
            match txs[i].anchor_mode {
                TransactionAnchorMode::OffChainOnly | TransactionAnchorMode::Any => {
                    continue;
                }
                _ => {
                    return Err(net_error::DeserializeError);
                }
            };
        }

        // header and transactions must be consistent
        let txid_vecs = txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<DoubleSha256>::new(&txid_vecs);
        let merkle_root = merkle_tree.root();
        
        if merkle_root != header.merkle_root {
            return Err(net_error::DeserializeError);
        }

        Ok(StacksMicroblock {
            header,
            txs
        })
    }
}
