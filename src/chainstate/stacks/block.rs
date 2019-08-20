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

use chainstate::stacks::*;
use chainstate::stacks::index::TrieHash;
use net::StacksPublicKeyBuffer;

use chainstate::burn::BlockHeaderHash;

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use util::vrf::{
    ECVRF_Proof,
    ECVRF_PROOF_ENCODED_SIZE
};

use util::hash::MerkleTree;
use util::hash::Sha512_256;
use util::secp256k1::MessageSignature;

impl StacksMessageCodec for ECVRF_Proof {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<ECVRF_Proof, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - ECVRF_PROOF_ENCODED_SIZE {
            return Err(net_error::OverflowError);
        }
        if index + ECVRF_PROOF_ENCODED_SIZE < max_size {
            return Err(net_error::OverflowError);
        }

        if (buf.len() as u32) < index + ECVRF_PROOF_ENCODED_SIZE {
            return Err(net_error::UnderflowError);
        }
        let res = ECVRF_Proof::from_slice(&buf[(index as usize)..((index+ECVRF_PROOF_ENCODED_SIZE) as usize)])
            .map_err(|_e| net_error::DeserializeError)?;
            
        *index_ptr += ECVRF_PROOF_ENCODED_SIZE;
        Ok(res)
    }
}

impl StacksMessageCodec for StacksWorkScore {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.burn);
        write_next(&mut ret, &self.work);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksWorkScore, net_error> {
        let burn = read_next(buf, index, max_size)?;
        let work = read_next(buf, index, max_size)?;
        Ok(StacksWorkScore {
            burn,
            work
        })
    }
}

impl StacksMessageCodec for StacksBlockHeader {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.version);
        write_next(&mut ret, &self.total_work);
        write_next(&mut ret, &self.proof);
        write_next(&mut ret, &self.parent_block);
        write_next(&mut ret, &self.parent_microblock);
        write_next(&mut ret, &self.tx_merkle_root);
        write_next(&mut ret, &self.state_index_root);
        write_next(&mut ret, &StacksPublicKeyBuffer::from_public_key(&self.microblock_pubkey));
        ret
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksBlockHeader, net_error> {
        let version: u8                         = read_next(buf, index, max_size)?;
        let total_work : StacksWorkScore        = read_next(buf, index, max_size)?;
        let proof : ECVRF_Proof                 = read_next(buf, index, max_size)?;
        let parent_block: BlockHeaderHash       = read_next(buf, index, max_size)?;
        let parent_microblock: BlockHeaderHash  = read_next(buf, index, max_size)?;
        let tx_merkle_root: Sha512_256          = read_next(buf, index, max_size)?;
        let state_index_root: TrieHash          = read_next(buf, index, max_size)?;
        let pubkey_buf : StacksPublicKeyBuffer  = read_next(buf, index, max_size)?;

        let microblock_pubkey = pubkey_buf.to_public_key()?;

        Ok(StacksBlockHeader {
            version,
            total_work,
            proof,
            parent_block,
            parent_microblock,
            tx_merkle_root,
            state_index_root,
            microblock_pubkey
        })
    }
}

impl StacksMessageCodec for StacksBlock {
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
                TransactionAnchorMode::OffChainOnly => {
                    return Err(net_error::DeserializeError);
                },
                _ => {}
            };
        }

        // header and transactions must be consistent
        let txid_vecs = txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512_256>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        
        if tx_merkle_root != header.tx_merkle_root {
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
        write_next(&mut ret, &self.sequence);
        write_next(&mut ret, &self.prev_block);
        write_next(&mut ret, &self.tx_merkle_root);
        write_next(&mut ret, &self.signature);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMicroblockHeader, net_error> {
        let version : u8                    = read_next(buf, index_ptr, max_size)?;
        let sequence : u32                  = read_next(buf, index_ptr, max_size)?;
        let prev_block : BlockHeaderHash    = read_next(buf, index_ptr, max_size)?;
        let tx_merkle_root : Sha512_256     = read_next(buf, index_ptr, max_size)?;
        let signature : MessageSignature    = read_next(buf, index_ptr, max_size)?;

        let _ = signature.to_secp256k1_recoverable()
            .ok_or(net_error::DeserializeError)?;
        
        Ok(StacksMicroblockHeader {
            version,
            sequence,
            prev_block,
            tx_merkle_root,
            signature
        })
    }
}


impl StacksMessageCodec for StacksMicroblock {
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

        let merkle_tree = MerkleTree::<Sha512_256>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        
        if tx_merkle_root != header.tx_merkle_root {
            return Err(net_error::DeserializeError);
        }

        Ok(StacksMicroblock {
            header,
            txs
        })
    }
}
