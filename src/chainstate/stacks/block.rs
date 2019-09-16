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

use chainstate::burn::BlockHeaderHash;

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use util::vrf::{
    VRFProof,
    VRF_PROOF_ENCODED_SIZE
};

use util::hash::MerkleTree;
use util::hash::Sha512_256;
use util::secp256k1::MessageSignature;

use sha2::Sha512Trunc256;
use sha2::Digest;

impl StacksMessageCodec for VRFProof {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<VRFProof, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - VRF_PROOF_ENCODED_SIZE {
            return Err(net_error::OverflowError);
        }
        if index + VRF_PROOF_ENCODED_SIZE < max_size {
            return Err(net_error::OverflowError);
        }

        if (buf.len() as u32) < index + VRF_PROOF_ENCODED_SIZE {
            return Err(net_error::UnderflowError);
        }
        let res = VRFProof::from_slice(&buf[(index as usize)..((index+VRF_PROOF_ENCODED_SIZE) as usize)])
            .map_err(|_e| net_error::DeserializeError)?;
            
        *index_ptr += VRF_PROOF_ENCODED_SIZE;
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

impl StacksWorkScore {
    pub fn initial() -> StacksWorkScore {
        StacksWorkScore {
            burn: 0,
            wrk: 0
        }
    }

    pub fn add(&self, work_delta: &StacksWorkScore) -> StacksWorkScore {
        let mut ret = self.clone();
        ret.burn = self.burn.checked_add(work_delta.burn).expect("FATAL: numeric overflow on calculating new total burn");
        ret.work = self.work.checked_add(work_delta.work).expect("FATAL: numeric overflow on calculating new total work");
        ret
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
        write_next(&mut ret, &self.parent_microblock_sequence);
        write_next(&mut ret, &self.tx_merkle_root);
        write_next(&mut ret, &self.state_index_root);
        write_next(&mut ret, &self.microblock_pubkey_hash);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksBlockHeader, net_error> {
        let version: u8                         = read_next(buf, index, max_size)?;
        let total_work : StacksWorkScore        = read_next(buf, index, max_size)?;
        let proof : VRFProof                    = read_next(buf, index, max_size)?;
        let parent_block: BlockHeaderHash       = read_next(buf, index, max_size)?;
        let parent_microblock: BlockHeaderHash  = read_next(buf, index, max_size)?;
        let parent_microblock_sequence: u8      = read_next(buf, index, max_size)?;
        let tx_merkle_root: Sha512_256          = read_next(buf, index, max_size)?;
        let state_index_root: TrieHash          = read_next(buf, index, max_size)?;
        let pubkey_hash_buf: Hash160            = read_next(buf, index, max_size)?;

        Ok(StacksBlockHeader {
            version,
            total_work,
            proof,
            parent_block,
            parent_microblock,
            parent_microblock_sequence,
            tx_merkle_root,
            state_index_root,
            microblock_pubkey_hash
        })
    }
}

impl StacksBlockHeader {
    pub fn pubkey_hash(pubk: &StacksPublicKey) -> Hash160 {
        let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubk);
        let bytes = pubkey_buf.serialize();
        Hash160::from_data(&bytes[..])
    }

    pub fn initial(tx_merkle_root: &Sha512_256, state_index_root: &TrieHash, microblock_pubkey_hash: &Hash160) -> StacksBlockHeader {
        StacksBlockHeader {
            version: STACKS_BLOCK_VERSION,
            total_work: StacksWorkScore::initial(),
            proof: VRFProof::empty(),
            parent_block: BlockHeaderHash([0u8; 32]),
            parent_microblock: BlockHeaderHash([0u8; 32]),
            parent_microblock_sequence: 0,
            tx_merkle_root: tx_merkle_root.clone(),
            state_index_root: state_index_root.clone(),
            microblock_pubkey_hash: microblock_pubkey_hash.clone(),
        }
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        let buf = self.serialize();
        BlockHeaderHash::from_serialized_header(&buf[..])
    }

    pub fn from_parent(parent_header: &StacksBlockHeader, parent_microblock_header: &StacksMicroblockHeader,  work_delta: &StacksWorkScore, proof: &VRFProof, tx_merkle_root: &Sha512_256, state_index_root: &TrieHash, microblock_pubkey_hash: &Hash160) -> StacksBlockHeader {
        StacksBlockHeader {
            version: STACKS_BLOCK_VERSION,
            total_work: parent_header.total_work.add(work_delta),
            proof: proof.clone(),
            parent_block: parent_header.block_hash(),
            parent_microblock: parent_microblock_header.block_hash(),
            parent_microblock_sequence: parent_microblock_header.sequence,
            tx_merkle_root: tx_merkle_root.clone(),
            state_index_root: state_index_root.clone(),
            microblock_pubkey_hash: microblock_pubkey_hash.clone(),
        }
    }

    /// Validate this block header against the burnchain.
    /// Used to determine whether or not we'll keep a block around (even if we don't yet have its parent).
    // TODO: consider putting the winning VRF key, winning seed, and parent seed into the snapshot
    pub fn validate_burnchain(&self, snapshot: &BlockSnapshot, leader_key: &LeaderKeyRegisterOp, block_commit: &LeaderBlockCommitOp, parent_snapshot: &BlockSnapshot, parent_block_commit: &LeaderBlockCommitOp) -> bool {
        if self.block_hash() != snapshot.winning_stacks_block_hash {
            test_debug!("Invalid Stacks block header {}: invalid commit: {} != {}", self.block_hash().to_hex(), self.block_hash.to_hex(), snapshot.winning_stacks_block_hash.to_hex());
            return false;
        }

        if self.parent_block != parent_snapshot.winning_stacks_block_hash {
            test_debug!("Invalid Stacks block header {}: invalid parent hash: {} != {}", self.block_hash.to_hex(), self.parent_block.to_hex(), parent_snapshot.winning_stacks_block_hash.to_hex());
            return false;
        }
        
        if !parent_block_commit.new_seed.is_from_proof(&self.proof) {
            test_debug!("Invalid Stacks block header {}: invalid VRF proof: hash({}) != {} (but {})", self.block_hash.to_hex(), self.proof.to_hex(), parent_block_commit.new_seed.to_hex(), VRFSeed::from_proof(&self.proof));
            return false;
        }

        if self.total_work.burns != parent_snapshot.total_burn {
            test_debug!("Invalid Stacks block header {}: invalid total burns: {} != {}", self.block_hash().to_hex(), self.total_work.burns, parent_snapshot.total_burn);
            return false;
        }

        // TODO: work score?

        if !VRF::verify(&leader_key.public_key, &self.proof, &parent_block_commit.new_seed.as_bytes().to_vec()) {
            test_debug!("Invalid Stacks block header {}: leader VRF key {} did not produce proof {}", self.block_hash.to_hex(), leader_key.public_key.to_hex(), self.proof.to_hex());
            return false;
        }

        // not verified by this method:
        // * parent_microblock and parent_microblock_sequence
        // * tx_merkle_root
        // * state_index_root
        true
    }

    /// Validate this block header against its parent block header.
    /// Call after validate_burnchain()
    pub fn validate_parent(&self, parent: &StacksBlockHeader, microblock_parent_opt: Option<&StacksMicroblockHeader>) -> bool {
        if parent.block_hash() != self.parent_block_hash {
            test_debug!("Invalid Stacks block header {}: parent {} != {}", self.block_hash().to_hex(), parent.block_hash().to_hex(), self.parent_block_hash.to_hex());
            return false;
        }

        if let Some(ref microblock_parent) = microblock_parent_opt {
            if self.parent_microblock_sequence == 0 {
                // we have no parent microblock 
                test_debug!("Invalid Stacks block header {}: no parent microblock (sequence 0), but expected {}", self.block_hash().to_hex(), microblock_parent.sequence);
                return false;
            }

            if microblock_parent.block_hash() != self.parent_microblock_hash {
                test_debug!("Invalid Stacks block header {}: parent microblock {} != {}", self.block_hash().to_hex(), microblock_parent.block_hash().to_hex(), self.parent_microblock_hash.to_hex());
                return false;
            }

            if microblock_parent.sequence != self.parent_microblock_sequence {
                test_debug!("Invalid Stacks block header {}: parent microblock sequence {} != {}", self.block_hash().to_hex(), microblock_parent.sequence, self.parent_microblock_sequence);
                return false;
            }
        }
        else {
            // no parent microblock, so these fields must be 0'ed
            if self.parent_microblock_sequence != 0 {
                test_debug!("Invalid Stacks block header {}: sequence is not 0 (but is {})", self.block_hash().to_hex(), self.parent_microblock_sequence);
                return false;
            }

            if self.parent_microblock_hash != BlockHeaderHash([0u8; 32]) {
                test_debug!("Invalid Stacks block header {}: parent microblock {} != {}", self.block_hash().to_hex(), microblock_parent.block_hash, BlockHeaderHash([0u8; 32]).to_hex());
                return false;
            }
        }

        return true;
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

impl StacksBlock {
    pub fn initial(txs: Vec<StacksTransaction>, state_index_root: &TrieHash, microblock_pubkey_hash: &Hash160) -> StacksBlock {
        let txids = txs.iter().map(|ref tx| tx.txid()).collect();
        let merkle_tree = MerkleTree::<Sha512_256>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header = StacksBlockHeader::initial(&tx_merkle_root, state_index_root, microblock_pubkey_hash);
        StacksBlock {
            header,
            txs
        }
    }

    pub fn from_parent(parent_header: &StacksBlockHeader, parent_microblock_header: &StacksMicroblockHeader, txs: Vec<StacksTransaction>, work_delta: &StacksWorkScore, proof: &VRFProof, state_index_root: &TrieHash, microblock_pubkey_hash: &Hash160) -> StacksBlock {
        let txids = txs.iter().map(|ref tx| tx.txid()).collect();
        let merkle_tree = MerkleTree::<Sha512_256>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header = StacksBlockHeader(parent_header, parent_microblock_header, proof, &tx_merkle_root, state_index_root, microblock_pubkey_hash);
        StacksBlock {
            header, 
            txs
        }
    }
    
    pub fn block_hash(&self) -> BlockHeaderHash {
        self.header.block_hash()
    }

    /// NOTE: the caller must call header.validate_burnchain() separately
    pub fn validate(&self, parent_header: &StacksBlockHeader, parent_microblock_stream: &Vec<StacksMicroblock>) -> bool {
        if parent_microblock_stream.len() == 0 {
            // this block should attach directly to its parent
            if !self.header.validate_parent(parent_header, None) {
                test_debug!("Invalid Stacks block {}: header does not match parent", self.block_hash().to_hex());
                return false;
            }
        }
        else {
            // this block should attach to the end of this microblock stream
            if !parent_microblock_stream[0].validate(&parent_header.block_hash(), None, &parent_header.microblock_pubkey_hash) {
                test_debug!("Invalid Stacks block {}: parent microblock stream entry 0 is invalid", self.block_hash().to_hex());
                return false;
            }

            for i in 1..parent_microblock_stream.len() {
                // parent stream must all be contiguous and valid
                if !parent_microblock_stream[i].validate(&parent_microblock_stream[i-1].block_hash(), Some(parent_microblock_stream[i-1].sequence), &parent_header.microblock_pubkey_hash) {
                    test_debug!("Invalid Stacks block {}: parent microblock stream entry {} is invalid", self.block_hash().to_hex(), i);
                    return false;
                }
            }
            
            if !self.header.validate_parent(parent_header, Some(&parent_microblock_stream[parent_microblock_stream.len()-1])) {
                test_debug!("Invalid Stacks block {}: header does not match parent or microblock parent", self.block_hash().to_hex());
                return false;
            }
        }

        // apply all of this parent stream's transactions and this block's transactions.
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
        let sequence : u8                   = read_next(buf, index_ptr, max_size)?;
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

impl StacksMicroblockHeader {
    pub fn sign(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        self.signature = MessageSignature::empty();
        let bytes = self.serialize();
        
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512Trunc256::new();

        sha2.input(&bytes[..]);
        digest_bits.copy_from_slice(sha2.result().as_slice());

        let sig = privkey.sign(&digest_bits)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.signature = sig;
        Ok(())
    }

    pub fn verify(&mut self, pubk_hash: &Hash160) -> Result<(), net_error> {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512Trunc256::new();

        let sig_bits = self.signature.clone();
        self.signature = MessageSignature::empty();
        let bytes = self.serialize();
        self.signature = sig_bits;
        
        sha2.input(&bytes[..]);
        digest_bits.copy_from_slice(sha2.result().as_slice());

        let pubk = StacksPublicKey::recover_to_pubkey(&digest_bits, &self.signature)
            .map_err(|_ve| net_error::VerifyingError("Failed to verify signature: failed to recover public key".to_string()))?;
        
        if StacksBlockHeader::pubkey_hash(&pubk) != *pubk_hash {
            return Err(net_error::VerifyingError("Failed to verify signature: public key did not recover to expected hash"));
        }

        Ok(())
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        let bytes = self.serialize();
        BlockHeaderHash::from_data(&bytes[..])
    }

    /// Create the first microblock header in a microblock stream.
    /// The header will not be signed
    pub fn initial_unsigned(parent_block_hash: &BlockHeaderHash, tx_merkle_root: &Sha512_256) -> StacksMicroblockHeader {
        StacksMicroblockHeader {
            version: 0,
            sequence: 0,
            prev_block: parent_block_hash.clone(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty()
        }
    }

    /// Create an unsigned microblock header from its parent
    /// Return an error on overflow
    pub fn from_parent_unsigned(parent_header: &StacksMicroblockHeader, tx_merkle_root: &Sha512_256) -> Option<StacksMicroblockHeader> {
        let next_sequence = match parent_header.sequence.checked_add(1) {
            Ok(next) => {
                next
            },
            Err(_) => {
                return None;
            }
        };

        StacksMicroblockHeader {
            version: 0,
            sequence: next_sequence,
            prev_block: parent_header.block_hash(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty()
        }
    }

    pub fn validate_parent(&self, parent_hash: &BlockHeaderHash, parent_sequence: Option<u8>, parent_pubkey_hash: &Hash160) -> bool {
        match parent_sequence {
            Some(seq) => {
                match seq.checked_add(1) {
                    Ok(my_seq) => {
                        if self.sequence != my_seq {
                            test_debug!("Invalid microblock {}: sequence {} != {}", self.block_hash().to_hex(), self.sequence, my_seq);
                            return false;
                        }
                    },
                    Err(_) => {
                        // parent sequence is the largest sequence, so this block cannot be valid.
                        // A subsequent leader can declare this microblock as a duplicate, and
                        // steal this block's miner's coinbase.
                        test_debug!("Invalid microblock {}: sequence {} overflow", self.block_hash().to_hex(), self.sequence);
                        return false;
                    }
                };
            },
            None => {
                if self.sequence != 0 {
                    test_debug!("Invalid microblock {}: sequence {} != 0", self.block_hash().to_hex(), self.sequence);
                    return false;
                }
            }
        }

        if self.parent_hash != parent_hash {
            test_debug!("Invalid microblock {}: parent hash {} != {}", self.block_hash().to_hex(), self.sequence);
            return false;
        }

        let mut dup = self.clone();
        if dup.verify(parent_pubkey).is_err() {
            test_debug!("Invalid microblock {}: failed to verify", self.block_hash().to_hex());
            return false;
        }

        return true;
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


impl StacksMicroblock {
    pub fn initial_unsigned(parent_block_hash: &BlockHeaderHash, txs: Vec<StacksTransaction>) -> StacksMicroblock {
        let txids = txs.iter().map(|ref tx| tx.txid()).collect();
        let merkle_tree = MerkleTree::<Sha512_256>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header = StacksMicroblockHeader::initial_unsigned(parent_block_hash, &tx_merkle_root);
        StacksMicroblock {
            header: header,
            txs: txs
        }
    }

    pub fn from_parent_unsigned(parent_header: &StacksMicroblockHeader, txs: Vec<StacksTransaction>) -> StacksMicroblock {
        let txids = txs.iter().map(|ref tx| tx.txid()).collect();
        let merkle_tree = MerkleTree::<Sha512_256>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header = StacksMicroblockHeader::from_parent_unsigned(parent_header, &tx_merkle_root);
        StacksMicroblock {
            header: header,
            txs: txs
        }
    }

    pub fn sign(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        self.header.sign(privk)
    }

    pub fn verify(&mut self, pubk_hash: &Hash160) -> Result<(), net_error> {
        self.header.verify(pubk_hash)
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        self.header.block_hash()
    }

    pub fn validate(&self, parent_hash: &BlockHeaderHash, parent_sequence: Option<u8>, parent_pubkey_hash: &Hash160) -> bool {
        self.header.validate(parent_hash, parent_sequence, parent_pubkey_hash)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use chainstate::stacks::*;
    use net::*;
    use net::codec::*;
    use net::codec::test::*;

    use util::hash::*;

    #[test]
    fn block_ecvrf_proof() {
        let proof_bytes = hex_bytes("024c1484fcb05cecdb4dbfb9bf4e08e7f529aea3b3a2515716ad4e9cf7bace6c91181b6bb7d8201c5a85a11c626d1848aa2ac4d188c7e24a94faa32d1eec48d600fad7c55c7e71adb6a7dd6c73f6fc02").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        check_codec_and_corruption::<VRFProof>(&proof, &proof_bytes);
    }
   
    #[test]
    fn block_work_score() {
        let work_score = StacksWorkScore {
            burn: 123,
            work: 456
        };
        let work_score_bytes = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 123,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 200,
        ];
        
        check_codec_and_corruption::<StacksWorkScore>(&work_score, &work_score_bytes);
    }
}
