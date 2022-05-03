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

use std::collections::{HashMap, HashSet};
use std::io;
use std::io::prelude::*;
use std::io::{Read, Write};

use sha2::Digest;
use sha2::Sha512Trunc256;

use crate::codec::MAX_MESSAGE_LEN;
use crate::types::StacksPublicKeyBuffer;
use burnchains::PrivateKey;
use burnchains::PublicKey;
use chainstate::burn::operations::*;
use chainstate::burn::ConsensusHash;
use chainstate::burn::*;
use chainstate::stacks::Error;
use chainstate::stacks::*;
use core::*;
use net::Error as net_error;
use util::hash::MerkleTree;
use util::hash::Sha512Trunc256Sum;
use util::retry::BoundReader;
use util::secp256k1::MessageSignature;
use util::vrf::*;

use crate::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::BurnchainHeaderHash;
use crate::types::chainstate::StacksBlockId;
use crate::types::chainstate::TrieHash;
use crate::types::chainstate::{BlockHeaderHash, StacksWorkScore, VRFSeed};
use chainstate::stacks::StacksBlockHeader;
use chainstate::stacks::StacksMicroblockHeader;

impl StacksMessageCodec for StacksBlockHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.serialize(fd, false)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksBlockHeader, codec_error> {
        let version: u8 = read_next(fd)?;
        let total_work: StacksWorkScore = read_next(fd)?;
        let proof: VRFProof = read_next(fd)?;
        let parent_block: BlockHeaderHash = read_next(fd)?;
        let parent_microblock: BlockHeaderHash = read_next(fd)?;
        let parent_microblock_sequence: u16 = read_next(fd)?;
        let tx_merkle_root: Sha512Trunc256Sum = read_next(fd)?;
        let state_index_root: TrieHash = read_next(fd)?;
        let withdrawal_merkle_root: Sha512Trunc256Sum = read_next(fd)?;
        let pubkey_hash_buf: Hash160 = read_next(fd)?;
        let miner_signatures: MessageSignatureList = read_next(fd)?;

        Ok(StacksBlockHeader {
            version,
            total_work,
            proof,
            parent_block,
            parent_microblock,
            parent_microblock_sequence,
            tx_merkle_root,
            state_index_root,
            withdrawal_merkle_root,
            microblock_pubkey_hash: pubkey_hash_buf,
            miner_signatures,
        })
    }
}

impl StacksBlockHeader {
    /// Serialize the transaction without the other signatures, and sign the result.
    pub fn sign(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        let mut bytes = vec![];
        self.serialize(&mut bytes, true)
            .expect("BUG: failed to serialize to a vec");
        let sha2 = Sha512Trunc256Sum::from_data(bytes.as_slice());
        let sig = privk
            .sign(sha2.as_ref())
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.miner_signatures.add_signature(sig);
        Ok(())
    }

    /// Serialize `this` to to `fd` in an internally decided order.
    ///
    /// If `empty_sig` is true, write an empty list for `miner_signatures`, instead of whatever is
    /// actually in `this`. This is used to create a consistent object that can be signed multiple
    /// times.
    fn serialize<W: Write>(&self, fd: &mut W, empty_sig: bool) -> Result<(), codec_error> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.total_work)?;
        write_next(fd, &self.proof)?;
        write_next(fd, &self.parent_block)?;
        write_next(fd, &self.parent_microblock)?;
        write_next(fd, &self.parent_microblock_sequence)?;
        write_next(fd, &self.tx_merkle_root)?;
        write_next(fd, &self.state_index_root)?;
        write_next(fd, &self.withdrawal_merkle_root)?;
        write_next(fd, &self.microblock_pubkey_hash)?;
        if empty_sig {
            write_next(fd, &MessageSignatureList::empty())?;
        } else {
            write_next(fd, &self.miner_signatures)?;
        }
        Ok(())
    }
    pub fn pubkey_hash(pubk: &StacksPublicKey) -> Hash160 {
        Hash160::from_node_public_key(pubk)
    }

    pub fn genesis_block_header() -> StacksBlockHeader {
        StacksBlockHeader {
            version: STACKS_BLOCK_VERSION,
            total_work: StacksWorkScore::genesis(),
            proof: VRFProof::empty(),
            parent_block: BOOT_BLOCK_HASH.clone(),
            parent_microblock: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            parent_microblock_sequence: 0,
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            state_index_root: TrieHash([0u8; 32]),
            withdrawal_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            microblock_pubkey_hash: Hash160([0u8; 20]),
            miner_signatures: MessageSignatureList::empty(),
        }
    }

    /// Is this a first-mined block header?  i.e. builds off of the boot code?
    pub fn is_first_mined(&self) -> bool {
        self.parent_block == FIRST_STACKS_BLOCK_HASH.clone()
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        if self.total_work.work == 0 {
            // this is the boot block
            return FIRST_STACKS_BLOCK_HASH.clone();
        }
        let mut buf = vec![];
        self.consensus_serialize(&mut buf)
            .expect("BUG: failed to serialize to a vec");
        BlockHeaderHash::from_serialized_header(&buf[..])
    }

    /// This is the "block hash" used for extending the state index root.
    /// This method is necessary because the index root must be globally unique (but, the same stacks
    /// block header can show up multiple times on different burn chain forks and different PoX
    /// forks).  Thus, we mix it with a burnchain block's ConsensusHash, which identifies both the
    /// burnchain block and the PoX fork.
    pub fn make_index_block_hash(
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> StacksBlockId {
        StacksBlockId::new(consensus_hash, block_hash)
    }

    pub fn index_block_hash(&self, consensus_hash: &ConsensusHash) -> StacksBlockId {
        let block_hash = self.block_hash();
        StacksBlockHeader::make_index_block_hash(consensus_hash, &block_hash)
    }

    pub fn from_parent(
        parent_header: &StacksBlockHeader,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
        total_work: &StacksWorkScore,
        proof: &VRFProof,
        tx_merkle_root: &Sha512Trunc256Sum,
        state_index_root: &TrieHash,
        microblock_pubkey_hash: &Hash160,
        miner_signatures: &MessageSignatureList,
    ) -> StacksBlockHeader {
        let (parent_microblock, parent_microblock_sequence) = match parent_microblock_header {
            Some(header) => (header.block_hash(), header.sequence),
            None => (EMPTY_MICROBLOCK_PARENT_HASH.clone(), 0),
        };

        StacksBlockHeader {
            version: STACKS_BLOCK_VERSION,
            total_work: total_work.clone(),
            proof: proof.clone(),
            parent_block: parent_header.block_hash(),
            parent_microblock: parent_microblock,
            parent_microblock_sequence: parent_microblock_sequence,
            tx_merkle_root: tx_merkle_root.clone(),
            state_index_root: state_index_root.clone(),
            withdrawal_merkle_root: parent_header.withdrawal_merkle_root.clone(),
            microblock_pubkey_hash: microblock_pubkey_hash.clone(),
            miner_signatures: miner_signatures.clone(),
        }
    }

    pub fn from_parent_empty(
        parent_header: &StacksBlockHeader,
        parent_microblock_header: Option<&StacksMicroblockHeader>,
        work_delta: &StacksWorkScore,
        proof: &VRFProof,
        microblock_pubkey_hash: &Hash160,
        miner_signatures: &MessageSignatureList,
    ) -> StacksBlockHeader {
        StacksBlockHeader::from_parent(
            parent_header,
            parent_microblock_header,
            work_delta,
            proof,
            &Sha512Trunc256Sum([0u8; 32]),
            &TrieHash([0u8; 32]),
            microblock_pubkey_hash,
            miner_signatures,
        )
    }

    /// Validate this block header against the burnchain.
    /// Used to determine whether or not we'll keep a block around (even if we don't yet have its parent).
    /// * burn_chain_tip is the BlockSnapshot encoding the sortition that selected this block for
    /// inclusion in the Stacks blockchain chain state.
    /// * stacks_chain_tip is the BlockSnapshot for the parent Stacks block this header builds on
    /// (i.e. this is the BlockSnapshot that corresponds to the parent of the given block_commit).
    pub fn validate_burnchain(
        &self,
        burn_chain_tip: &BlockSnapshot,
        block_commit: &LeaderBlockCommitOp,
    ) -> Result<(), Error> {
        // the burn chain tip's sortition must have chosen given block commit
        assert_eq!(
            burn_chain_tip.winning_stacks_block_hash,
            block_commit.block_header_hash
        );
        assert_eq!(burn_chain_tip.winning_block_txid, block_commit.txid);

        // this header must match the header that won sortition on the burn chain
        if self.block_hash() != burn_chain_tip.winning_stacks_block_hash {
            let msg = format!(
                "Invalid Stacks block header {}: invalid commit: {} != {}",
                self.block_hash(),
                self.block_hash(),
                burn_chain_tip.winning_stacks_block_hash
            );
            debug!("{}", msg);
            return Err(Error::InvalidStacksBlock(msg));
        }

        // not verified by this method:
        // * parent_microblock and parent_microblock_sequence (checked in process_block())
        // * total_work.work (need the parent block header for that)
        // * tx_merkle_root     (already verified; validated on deserialization)
        // * state_index_root   (validated on process_block())
        Ok(())
    }

    /// Does this header have a microblock parent?
    pub fn has_microblock_parent(&self) -> bool {
        self.parent_microblock != EMPTY_MICROBLOCK_PARENT_HASH
            || self.parent_microblock_sequence != 0
    }
}

impl StacksMessageCodec for StacksBlock {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.header)?;
        write_next(fd, &self.txs)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksBlock, codec_error> {
        // NOTE: don't worry about size clamps here; do that when receiving the data from the peer
        // network.  This code assumes that the block will be small enough.
        let header: StacksBlockHeader = read_next(fd)?;
        let txs: Vec<StacksTransaction> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        // there must be at least one transaction (the coinbase)
        if txs.len() == 0 {
            warn!("Invalid block: Zero-transaction block");
            return Err(codec_error::DeserializeError(
                "Invalid block: zero transactions".to_string(),
            ));
        }

        // all transactions must have anchor mode either OnChainOnly or Any
        // (no OffChainOnly allowed)
        if !StacksBlock::validate_anchor_mode(&txs, true) {
            warn!("Invalid block: Found offchain-only transaction");
            return Err(codec_error::DeserializeError(
                "Invalid block: Found offchain-only transaction".to_string(),
            ));
        }

        // all transactions are unique
        if !StacksBlock::validate_transactions_unique(&txs) {
            warn!("Invalid block: Found duplicate transaction");
            return Err(codec_error::DeserializeError(
                "Invalid block: found duplicate transaction".to_string(),
            ));
        }

        // header and transactions must be consistent
        let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();

        if tx_merkle_root != header.tx_merkle_root {
            warn!("Invalid block: Tx Merkle root mismatch");
            return Err(codec_error::DeserializeError(
                "Invalid block: tx Merkle root mismatch".to_string(),
            ));
        }

        // must be only one coinbase
        let mut coinbase_count = 0;
        for tx in txs.iter() {
            match tx.payload {
                TransactionPayload::Coinbase(_) => {
                    coinbase_count += 1;
                    if coinbase_count > 1 {
                        return Err(codec_error::DeserializeError(
                            "Invalid block: multiple coinbases found".to_string(),
                        ));
                    }
                }
                _ => {}
            }
        }

        // coinbase is present at the right place
        if !StacksBlock::validate_coinbase(&txs, true) {
            warn!("Invalid block: no coinbase found at first transaction slot");
            return Err(codec_error::DeserializeError(
                "Invalid block: no coinbase found at first transaction slot".to_string(),
            ));
        }

        Ok(StacksBlock { header, txs })
    }
}

impl StacksBlock {
    pub fn from_parent(
        parent_header: &StacksBlockHeader,
        parent_microblock_header: &StacksMicroblockHeader,
        txs: Vec<StacksTransaction>,
        work_delta: &StacksWorkScore,
        proof: &VRFProof,
        state_index_root: &TrieHash,
        microblock_pubkey_hash: &Hash160,
        miner_signatures: &MessageSignatureList,
    ) -> StacksBlock {
        let txids = txs
            .iter()
            .map(|ref tx| tx.txid().as_bytes().to_vec())
            .collect();
        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header = StacksBlockHeader::from_parent(
            parent_header,
            Some(parent_microblock_header),
            work_delta,
            proof,
            &tx_merkle_root,
            state_index_root,
            microblock_pubkey_hash,
            miner_signatures,
        );
        StacksBlock { header, txs }
    }

    pub fn genesis_block() -> StacksBlock {
        StacksBlock {
            header: StacksBlockHeader::genesis_block_header(),
            txs: vec![],
        }
    }

    /// Is this a first-mined block?  i.e. builds off of the boot code?
    pub fn is_first_mined(&self) -> bool {
        self.header.is_first_mined()
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        self.header.block_hash()
    }

    pub fn index_block_hash(&self, consensus_hash: &ConsensusHash) -> StacksBlockId {
        self.header.index_block_hash(consensus_hash)
    }

    /// Find and return the coinbase transaction.  It's always the first transaction.
    /// If there are 0 coinbase txs, or more than 1, then return None
    pub fn get_coinbase_tx(&self) -> Option<StacksTransaction> {
        if self.txs.len() == 0 {
            return None;
        }
        match self.txs[0].payload {
            TransactionPayload::Coinbase(_) => Some(self.txs[0].clone()),
            _ => None,
        }
    }

    /// verify no duplicate txids
    pub fn validate_transactions_unique(txs: &Vec<StacksTransaction>) -> bool {
        // no duplicates
        let mut txids = HashMap::new();
        for (i, tx) in txs.iter().enumerate() {
            let txid = tx.txid();
            if txids.get(&txid).is_some() {
                warn!(
                    "Duplicate tx {}: at index {} and {}",
                    txid,
                    txids.get(&txid).unwrap(),
                    i
                );
                test_debug!("{:?}", &tx);
                return false;
            }
            txids.insert(txid, i);
        }
        return true;
    }

    /// verify all txs are same mainnet/testnet
    pub fn validate_transactions_network(txs: &Vec<StacksTransaction>, mainnet: bool) -> bool {
        for tx in txs {
            if mainnet && !tx.is_mainnet() {
                warn!("Tx {} is not mainnet", tx.txid());
                return false;
            } else if !mainnet && tx.is_mainnet() {
                warn!("Tx {} is not testnet", tx.txid());
                return false;
            }
        }
        return true;
    }

    /// verify all txs are same chain ID
    pub fn validate_transactions_chain_id(txs: &Vec<StacksTransaction>, chain_id: u32) -> bool {
        for tx in txs {
            if tx.chain_id != chain_id {
                warn!(
                    "Tx {} has chain ID {:08x}; expected {:08x}",
                    tx.txid(),
                    tx.chain_id,
                    chain_id
                );
                return false;
            }
        }
        return true;
    }

    /// verify anchor modes
    pub fn validate_anchor_mode(txs: &Vec<StacksTransaction>, anchored: bool) -> bool {
        for tx in txs {
            match (anchored, tx.anchor_mode) {
                (true, TransactionAnchorMode::OffChainOnly) => {
                    warn!(
                        "Tx {} is off-chain-only; expected on-chain-only or any",
                        tx.txid()
                    );
                    return false;
                }
                (false, TransactionAnchorMode::OnChainOnly) => {
                    warn!(
                        "Tx {} is on-chain-only; expected off-chain-only or any",
                        tx.txid()
                    );
                    return false;
                }
                (_, _) => {}
            }
        }
        return true;
    }

    /// verify that a coinbase is present and is on-chain only, or is absent
    pub fn validate_coinbase(txs: &Vec<StacksTransaction>, check_present: bool) -> bool {
        let mut found_coinbase = false;
        let mut coinbase_index = 0;
        for (i, tx) in txs.iter().enumerate() {
            match tx.payload {
                TransactionPayload::Coinbase(_) => {
                    if !check_present {
                        warn!("Found unexpected coinbase tx {}", tx.txid());
                        return false;
                    }

                    if found_coinbase {
                        warn!("Found duplicate coinbase tx {}", tx.txid());
                        return false;
                    }

                    if tx.anchor_mode != TransactionAnchorMode::OnChainOnly {
                        warn!("Invalid coinbase tx {}: not on-chain only", tx.txid());
                        return false;
                    }
                    found_coinbase = true;
                    coinbase_index = i;
                }
                _ => {}
            }
        }

        if coinbase_index != 0 {
            warn!("Found coinbase at index {} (expected 0)", coinbase_index);
            return false;
        }

        match (check_present, found_coinbase) {
            (true, true) => {
                return true;
            }
            (false, false) => {
                return true;
            }
            (true, false) => {
                error!("Expected coinbase, but not found");
                return false;
            }
            (false, true) => {
                error!("Found coinbase, but it was unexpected");
                return false;
            }
        }
    }

    /// static sanity checks on transactions.
    pub fn validate_transactions_static(&self, mainnet: bool, chain_id: u32) -> bool {
        if !StacksBlock::validate_transactions_unique(&self.txs) {
            return false;
        }
        if !StacksBlock::validate_transactions_network(&self.txs, mainnet) {
            return false;
        }
        if !StacksBlock::validate_transactions_chain_id(&self.txs, chain_id) {
            return false;
        }
        if !StacksBlock::validate_anchor_mode(&self.txs, true) {
            return false;
        }
        if !StacksBlock::validate_coinbase(&self.txs, true) {
            return false;
        }
        return true;
    }

    /// Does this block have a microblock parent?
    pub fn has_microblock_parent(&self) -> bool {
        self.header.has_microblock_parent()
    }
}

impl StacksMessageCodec for MessageSignatureList {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        let sigs = self.signatures();
        write_next(fd, sigs)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<MessageSignatureList, codec_error> {
        let signatures: Vec<MessageSignature> = read_next(fd)?;

        // signature must be well-formed
        for signature in &signatures {
            let _ = signature
                .to_secp256k1_recoverable()
                .ok_or(codec_error::DeserializeError(
                    "Failed to parse signature".to_string(),
                ))?;
        }

        Ok(MessageSignatureList::from_vec(signatures))
    }
}

impl StacksMessageCodec for StacksMicroblockHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.serialize(fd, false)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksMicroblockHeader, codec_error> {
        let version: u8 = read_next(fd)?;
        let sequence: u16 = read_next(fd)?;
        let prev_block: BlockHeaderHash = read_next(fd)?;
        let tx_merkle_root: Sha512Trunc256Sum = read_next(fd)?;
        let miner_signatures: MessageSignatureList = read_next(fd)?;

        Ok(StacksMicroblockHeader {
            version,
            sequence,
            prev_block,
            tx_merkle_root,
            miner_signatures,
        })
    }
}

impl StacksMicroblockHeader {
    pub fn sign(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        self.miner_signatures = MessageSignatureList::empty();
        let mut bytes = vec![];
        self.serialize(&mut bytes, true)
            .expect("BUG: failed to serialize to a vec");

        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512Trunc256::new();

        sha2.input(&bytes[..]);
        digest_bits.copy_from_slice(sha2.result().as_slice());

        let sig = privk
            .sign(&digest_bits)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.miner_signatures.add_signature(sig);
        Ok(())
    }

    fn serialize<W: Write>(&self, fd: &mut W, empty_sig: bool) -> Result<(), codec_error> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.sequence)?;
        write_next(fd, &self.prev_block)?;
        write_next(fd, &self.tx_merkle_root)?;
        if empty_sig {
            write_next(fd, &MessageSignatureList::empty())?;
        } else {
            write_next(fd, self.miner_signatures.signatures())?;
        }
        Ok(())
    }

    pub fn check_recover_pubkey(&self) -> Result<Vec<Hash160>, net_error> {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512Trunc256::new();

        let mut bytes = vec![];
        self.serialize(&mut bytes, true)
            .expect("BUG: failed to serialize to a vec");
        sha2.input(&bytes[..]); // new
        digest_bits.copy_from_slice(sha2.result().as_slice());

        let mut hashes = vec![];
        for signature in self.miner_signatures.signatures() {
            let mut pubk =
                StacksPublicKey::recover_to_pubkey(&digest_bits, &signature).map_err(|_ve| {
                    test_debug!(
                        "Failed to verify signature: failed to recover public key from {:?}: {:?}",
                        &signature,
                        &_ve
                    );
                    net_error::VerifyingError(
                        "Failed to verify signature: failed to recover public key".to_string(),
                    )
                })?;

            pubk.set_compressed(true);
            hashes.push(StacksBlockHeader::pubkey_hash(&pubk));
        }
        Ok(hashes)
    }

    pub fn verify(&self, pubk_hash: &Hash160) -> Result<(), net_error> {
        let pubkh_vec = self.check_recover_pubkey()?;

        for pubkh in &pubkh_vec {
            if *pubkh == *pubk_hash {
                return Ok(());
            }
        }
        info!(
            "Failed to verify miner_signatures: public key did not recover to hash {:?}",
            &pubkh_vec
        );
        return Err(net_error::VerifyingError(format!(
            "Failed to verify miner_signatures: public key did not recover to expected hash {:?}",
            &pubkh_vec
        )));
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize to a vec");
        BlockHeaderHash::from_serialized_header(&bytes[..])
    }

    /// Create the first microblock header in a microblock stream.
    /// The header will not be signed
    pub fn first_unsigned(
        parent_block_hash: &BlockHeaderHash,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> StacksMicroblockHeader {
        StacksMicroblockHeader {
            version: 0,
            sequence: 0,
            prev_block: parent_block_hash.clone(),
            tx_merkle_root: tx_merkle_root.clone(),
            miner_signatures: MessageSignatureList::empty(),
        }
    }

    /// Create the first microblock header in a microblock stream for an empty microblock stream.
    /// The header will not be signed
    pub fn first_empty_unsigned(parent_block_hash: &BlockHeaderHash) -> StacksMicroblockHeader {
        StacksMicroblockHeader::first_unsigned(parent_block_hash, &Sha512Trunc256Sum([0u8; 32]))
    }

    /// Create an unsigned microblock header from its parent
    /// Return an error on overflow
    pub fn from_parent_unsigned(
        parent_header: &StacksMicroblockHeader,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> Option<StacksMicroblockHeader> {
        let next_sequence = match parent_header.sequence.checked_add(1) {
            Some(next) => next,
            None => {
                return None;
            }
        };

        Some(StacksMicroblockHeader {
            version: 0,
            sequence: next_sequence,
            prev_block: parent_header.block_hash(),
            tx_merkle_root: tx_merkle_root.clone(),
            miner_signatures: MessageSignatureList::empty(),
        })
    }
}

impl StacksMessageCodec for StacksMicroblock {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.header)?;
        write_next(fd, &self.txs)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksMicroblock, codec_error> {
        // NOTE: maximum size must be checked elsewhere!
        let header: StacksMicroblockHeader = read_next(fd)?;
        let txs: Vec<StacksTransaction> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        if txs.len() == 0 {
            warn!("Invalid microblock: zero transactions");
            return Err(codec_error::DeserializeError(
                "Invalid microblock: zero transactions".to_string(),
            ));
        }

        if !StacksBlock::validate_transactions_unique(&txs) {
            warn!("Invalid microblock: duplicate transaction");
            return Err(codec_error::DeserializeError(
                "Invalid microblock: duplicate transaction".to_string(),
            ));
        }

        if !StacksBlock::validate_anchor_mode(&txs, false) {
            warn!("Invalid microblock: found on-chain-only transaction");
            return Err(codec_error::DeserializeError(
                "Invalid microblock: found on-chain-only transaction".to_string(),
            ));
        }

        // header and transactions must be consistent
        let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();

        if tx_merkle_root != header.tx_merkle_root {
            return Err(codec_error::DeserializeError(
                "Invalid microblock: tx Merkle root mismatch".to_string(),
            ));
        }

        if !StacksBlock::validate_coinbase(&txs, false) {
            warn!("Invalid microblock: found coinbase transaction");
            return Err(codec_error::DeserializeError(
                "Invalid microblock: found coinbase transaction".to_string(),
            ));
        }

        Ok(StacksMicroblock { header, txs })
    }
}

impl StacksMicroblock {
    pub fn first_unsigned(
        parent_block_hash: &BlockHeaderHash,
        txs: Vec<StacksTransaction>,
    ) -> StacksMicroblock {
        let txids = txs
            .iter()
            .map(|ref tx| tx.txid().as_bytes().to_vec())
            .collect();
        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header = StacksMicroblockHeader::first_unsigned(parent_block_hash, &tx_merkle_root);
        StacksMicroblock {
            header: header,
            txs: txs,
        }
    }

    pub fn from_parent_unsigned(
        parent_header: &StacksMicroblockHeader,
        txs: Vec<StacksTransaction>,
    ) -> Option<StacksMicroblock> {
        let txids = txs
            .iter()
            .map(|ref tx| tx.txid().as_bytes().to_vec())
            .collect();
        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txids);
        let tx_merkle_root = merkle_tree.root();
        let header =
            match StacksMicroblockHeader::from_parent_unsigned(parent_header, &tx_merkle_root) {
                Some(h) => h,
                None => {
                    return None;
                }
            };

        Some(StacksMicroblock {
            header: header,
            txs: txs,
        })
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

    /// static sanity checks on transactions.
    pub fn validate_transactions_static(&self, mainnet: bool, chain_id: u32) -> bool {
        if !StacksBlock::validate_transactions_unique(&self.txs) {
            return false;
        }
        if !StacksBlock::validate_transactions_network(&self.txs, mainnet) {
            return false;
        }
        if !StacksBlock::validate_transactions_chain_id(&self.txs, chain_id) {
            return false;
        }
        if !StacksBlock::validate_anchor_mode(&self.txs, false) {
            return false;
        }
        if !StacksBlock::validate_coinbase(&self.txs, false) {
            return false;
        }
        return true;
    }
}

#[cfg(test)]
mod test {
    use address::*;
    use burnchains::BurnchainBlockHeader;
    use burnchains::BurnchainSigner;
    use burnchains::Txid;
    use chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
    use chainstate::stacks::address::StacksAddressExtensions;
    use chainstate::stacks::test::make_codec_test_block;
    use chainstate::stacks::test::*;
    use chainstate::stacks::*;
    use net::codec::test::*;
    use net::codec::*;
    use net::*;
    use std::error::Error;
    use util::hash::*;

    use crate::types::chainstate::StacksAddress;

    use super::*;

    #[test]
    fn codec_stacks_block_ecvrf_proof() {
        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        check_codec_and_corruption::<VRFProof>(&proof, &proof_bytes);
    }

    #[test]
    fn codec_stacks_block_work_score() {
        let work_score = StacksWorkScore {
            burn: 123,
            work: 456,
        };
        let work_score_bytes = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 123, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 200,
        ];

        check_codec_and_corruption::<StacksWorkScore>(&work_score, &work_score_bytes);
    }

    #[test]
    fn codec_encode_message_signature_list() {
        // Empty list, edge case.
        let list = MessageSignatureList::empty();
        let expected_bytes = vec![0, 0, 0, 0];
        check_codec_and_corruption::<MessageSignatureList>(&list, &expected_bytes);

        // Two-element list, typical case.
        let list = MessageSignatureList::from_vec(vec![
            MessageSignature([0u8; 65]),
            MessageSignature([1u8; 65]),
        ]);
        let expected_bytes = vec![
            0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        check_codec_and_corruption::<MessageSignatureList>(&list, &expected_bytes);
    }

    #[test]
    fn codec_stacks_block_header() {
        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        let header = StacksBlockHeader {
            version: 0x12,
            total_work: StacksWorkScore {
                burn: 123,
                work: 456,
            },
            proof: proof,
            parent_block: FIRST_STACKS_BLOCK_HASH.clone(),
            parent_microblock: BlockHeaderHash([1u8; 32]),
            parent_microblock_sequence: 3,
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            state_index_root: TrieHash([3u8; 32]),
            withdrawal_merkle_root: Sha512Trunc256Sum([4u8; 32]),
            microblock_pubkey_hash: Hash160([4u8; 20]),
            miner_signatures: MessageSignatureList::empty(),
        };

        let header_bytes = vec![
            // version
            0x12, // work score
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 123, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 200, // proof
            0x92, 0x75, 0xdf, 0x67, 0xa6, 0x8c, 0x87, 0x45, 0xc0, 0xff, 0x97, 0xb4, 0x82, 0x01,
            0xee, 0x6d, 0xb4, 0x47, 0xf7, 0xc9, 0x3b, 0x23, 0xae, 0x24, 0xcd, 0xc2, 0x40, 0x0f,
            0x52, 0xfd, 0xb0, 0x8a, 0x1a, 0x6a, 0xc7, 0xec, 0x71, 0xbf, 0x9c, 0x9c, 0x76, 0xe9,
            0x6e, 0xe4, 0x67, 0x5e, 0xbf, 0xf6, 0x06, 0x25, 0xaf, 0x28, 0x71, 0x85, 0x01, 0x04,
            0x7b, 0xfd, 0x87, 0xb8, 0x10, 0xc2, 0xd2, 0x13, 0x9b, 0x73, 0xc2, 0x3b, 0xd6, 0x9d,
            0xe6, 0x63, 0x60, 0x95, 0x3a, 0x64, 0x2c, 0x2a, 0x33, 0x0a, // parent block
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // parent microblock
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, // parent microblock sequence
            0x00, 0x03, // tx merkle root
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, // state index root
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, // withdrawal merkle root
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04, // public key hash buf
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, // signature list (empty)
            0x00, 0x00, 0x00, 0x00,
        ];

        check_codec_and_corruption::<StacksBlockHeader>(&header, &header_bytes);
    }

    #[test]
    fn codec_stacks_microblock_header() {
        let header = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            miner_signatures: MessageSignatureList::from_single(MessageSignature([2u8; 65])),
        };

        let header_bytes = vec![
            // version
            0x12, // sequence
            0x00, 0x34, // prev block
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // tx merkle root
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, // miner_signatures
            0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ];

        check_codec_and_corruption::<StacksMicroblockHeader>(&header, &header_bytes);
    }

    #[test]
    fn codec_stacks_block() {
        /*
        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap());
        let mut tx_coinbase = StacksTransaction::new(TransactionVersion::Mainnet,
                                                     origin_auth.clone(),
                                                     TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));

        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;

        // make a block with each and every kind of transaction
        let mut all_txs = codec_all_transactions(&TransactionVersion::Testnet, 0x80000000, &TransactionAnchorMode::OnChainOnly, &TransactionPostConditionMode::Allow);

        // remove all coinbases, except for an initial coinbase
        let mut txs_anchored = vec![];
        txs_anchored.push(tx_coinbase);

        for tx in all_txs.drain(..) {
            match tx.payload {
                TransactionPayload::Coinbase(_) => {
                    continue;
                },
                _ => {}
            }
            txs_anchored.push(tx);
        }

        let txid_vecs = txs_anchored
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let tr = tx_merkle_root.as_bytes().to_vec();

        let work_score = StacksWorkScore {
            burn: 123,
            work: 456
        };

        let parent_header = StacksBlockHeader {
            version: 0x01,
            total_work: StacksWorkScore {
                burn: 234,
                work: 567,
            },
            proof: proof.clone(),
            parent_block: BlockHeaderHash([5u8; 32]),
            parent_microblock: BlockHeaderHash([6u8; 32]),
            parent_microblock_sequence: 4,
            tx_merkle_root: Sha512Trunc256Sum([7u8; 32]),
            state_index_root: TrieHash([8u8; 32]),
            microblock_pubkey_hash: Hash160([9u8; 20])
        };


        let mut block = StacksBlock::from_parent(&parent_header, &parent_microblock_header, txs_anchored.clone(), &work_score, &proof, &TrieHash([2u8; 32]), &Hash160([3u8; 20]));
        block.header.version = 0x24;
        */

        let mut block = make_codec_test_block(100000000);
        block.header.version = 0x24;

        let ph = block.header.parent_block.as_bytes().to_vec();
        let mh = block.header.parent_microblock.as_bytes().to_vec();
        let tr = block.header.tx_merkle_root.as_bytes().to_vec();
        let sr = block.header.state_index_root.as_bytes().to_vec();
        let wr = block.header.withdrawal_merkle_root.as_bytes().to_vec();
        let pk = block.header.microblock_pubkey_hash.as_bytes().to_vec();

        let mut block_bytes = vec![
            // header
            // version
            0x24, // work score (parent work score + current work score)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 234, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 55, // proof
            0x92, 0x75, 0xdf, 0x67, 0xa6, 0x8c, 0x87, 0x45, 0xc0, 0xff, 0x97, 0xb4, 0x82, 0x01,
            0xee, 0x6d, 0xb4, 0x47, 0xf7, 0xc9, 0x3b, 0x23, 0xae, 0x24, 0xcd, 0xc2, 0x40, 0x0f,
            0x52, 0xfd, 0xb0, 0x8a, 0x1a, 0x6a, 0xc7, 0xec, 0x71, 0xbf, 0x9c, 0x9c, 0x76, 0xe9,
            0x6e, 0xe4, 0x67, 0x5e, 0xbf, 0xf6, 0x06, 0x25, 0xaf, 0x28, 0x71, 0x85, 0x01, 0x04,
            0x7b, 0xfd, 0x87, 0xb8, 0x10, 0xc2, 0xd2, 0x13, 0x9b, 0x73, 0xc2, 0x3b, 0xd6, 0x9d,
            0xe6, 0x63, 0x60, 0x95, 0x3a, 0x64, 0x2c, 0x2a, 0x33, 0x0a, // parent block
            ph[0], ph[1], ph[2], ph[3], ph[4], ph[5], ph[6], ph[7], ph[8], ph[9], ph[10], ph[11],
            ph[12], ph[13], ph[14], ph[15], ph[16], ph[17], ph[18], ph[19], ph[20], ph[21], ph[22],
            ph[23], ph[24], ph[25], ph[26], ph[27], ph[28], ph[29], ph[30], ph[31],
            // parent microblock
            mh[0], mh[1], mh[2], mh[3], mh[4], mh[5], mh[6], mh[7], mh[8], mh[9], mh[10], mh[11],
            mh[12], mh[13], mh[14], mh[15], mh[16], mh[17], mh[18], mh[19], mh[20], mh[21], mh[22],
            mh[23], mh[24], mh[25], mh[26], mh[27], mh[28], mh[29], mh[30], mh[31],
            // parent microblock sequence
            0x00, 0x04, // tx merkle root
            tr[0], tr[1], tr[2], tr[3], tr[4], tr[5], tr[6], tr[7], tr[8], tr[9], tr[10], tr[11],
            tr[12], tr[13], tr[14], tr[15], tr[16], tr[17], tr[18], tr[19], tr[20], tr[21], tr[22],
            tr[23], tr[24], tr[25], tr[26], tr[27], tr[28], tr[29], tr[30], tr[31],
            // state index root
            sr[0], sr[1], sr[2], sr[3], sr[4], sr[5], sr[6], sr[7], sr[8], sr[9], sr[10], sr[11],
            sr[12], sr[13], sr[14], sr[15], sr[16], sr[17], sr[18], sr[19], sr[20], sr[21], sr[22],
            sr[23], sr[24], sr[25], sr[26], sr[27], sr[28], sr[29], sr[30], sr[31],
            // withdrawal merkle root
            wr[0], wr[1], wr[2], wr[3], wr[4], wr[5], wr[6], wr[7], wr[8], wr[9], wr[10], wr[11],
            wr[12], wr[13], wr[14], wr[15], wr[16], wr[17], wr[18], wr[19], wr[20], wr[21], wr[22],
            wr[23], wr[24], wr[25], wr[26], wr[27], wr[28], wr[29], wr[30], wr[31],
            // public key hash buf
            pk[0], pk[1], pk[2], pk[3], pk[4], pk[5], pk[6], pk[7], pk[8], pk[9], pk[10], pk[11],
            pk[12], pk[13], pk[14], pk[15], pk[16], pk[17], pk[18], pk[19],
            // signature list
            0x00, 0x00, 0x00, 0x00,
        ];

        check_codec_and_corruption::<StacksBlockHeader>(&block.header, &block_bytes);

        let mut tx_bytes: Vec<u8> = vec![];
        block.txs.consensus_serialize(&mut tx_bytes).unwrap();
        block_bytes.append(&mut tx_bytes);

        eprintln!(
            "block is {} bytes with {} txs",
            block_bytes.len(),
            block.txs.len()
        );
        check_codec_and_corruption::<StacksBlock>(&block, &block_bytes);
    }

    #[test]
    fn codec_stacks_microblock() {
        // make a block with each and every kind of transaction
        let all_txs = codec_all_transactions(
            &TransactionVersion::Testnet,
            0x80000000,
            &TransactionAnchorMode::OffChainOnly,
            &TransactionPostConditionMode::Allow,
        );

        // remove all coinbases
        let mut txs_anchored = vec![];

        for tx in all_txs.iter() {
            match tx.payload {
                TransactionPayload::Coinbase(_) => {
                    continue;
                }
                _ => {}
            }
            txs_anchored.push(tx);
        }

        // make microblocks with 3 transactions each (or fewer)
        for i in 0..(all_txs.len() / 3) {
            let txs = vec![
                all_txs[3 * i].clone(),
                all_txs[3 * i + 1].clone(),
                all_txs[3 * i + 2].clone(),
            ];

            let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            let tx_merkle_root = merkle_tree.root();
            let tr = tx_merkle_root.as_bytes().to_vec();

            let header = StacksMicroblockHeader {
                version: 0x12,
                sequence: 0x34,
                prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
                tx_merkle_root: tx_merkle_root,
                miner_signatures: MessageSignatureList::from_single(MessageSignature([
                    0x00, 0x35, 0x44, 0x45, 0xa1, 0xdc, 0x98, 0xa1, 0xbd, 0x27, 0x98, 0x4d, 0xbe,
                    0x69, 0x97, 0x9a, 0x5c, 0xd7, 0x78, 0x86, 0xb4, 0xd9, 0x13, 0x4a, 0xf5, 0xc4,
                    0x0e, 0x63, 0x4d, 0x96, 0xe1, 0xcb, 0x44, 0x5b, 0x97, 0xde, 0x5b, 0x63, 0x25,
                    0x82, 0xd3, 0x17, 0x04, 0xf8, 0x67, 0x06, 0xa7, 0x80, 0x88, 0x6e, 0x6e, 0x38,
                    0x1b, 0xfe, 0xd6, 0x52, 0x28, 0x26, 0x73, 0x58, 0x26, 0x2d, 0x20, 0x3f, 0xe6,
                ])),
            };

            let mut block_bytes = vec![
                // header
                // version
                0x12, // sequence
                0x00, 0x34, // prev block
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, // tx merkle root
                tr[0], tr[1], tr[2], tr[3], tr[4], tr[5], tr[6], tr[7], tr[8], tr[9], tr[10],
                tr[11], tr[12], tr[13], tr[14], tr[15], tr[16], tr[17], tr[18], tr[19], tr[20],
                tr[21], tr[22], tr[23], tr[24], tr[25], tr[26], tr[27], tr[28], tr[29], tr[30],
                tr[31], // miner_signatures
                0x00, 0x00, 0x00, 0x01, 0x00, 0x35, 0x44, 0x45, 0xa1, 0xdc, 0x98, 0xa1, 0xbd, 0x27,
                0x98, 0x4d, 0xbe, 0x69, 0x97, 0x9a, 0x5c, 0xd7, 0x78, 0x86, 0xb4, 0xd9, 0x13, 0x4a,
                0xf5, 0xc4, 0x0e, 0x63, 0x4d, 0x96, 0xe1, 0xcb, 0x44, 0x5b, 0x97, 0xde, 0x5b, 0x63,
                0x25, 0x82, 0xd3, 0x17, 0x04, 0xf8, 0x67, 0x06, 0xa7, 0x80, 0x88, 0x6e, 0x6e, 0x38,
                0x1b, 0xfe, 0xd6, 0x52, 0x28, 0x26, 0x73, 0x58, 0x26, 0x2d, 0x20, 0x3f, 0xe6,
            ];

            let mut tx_bytes: Vec<u8> = vec![];
            txs.consensus_serialize(&mut tx_bytes).unwrap();
            block_bytes.append(&mut tx_bytes);

            let mblock = StacksMicroblock {
                header: header,
                txs: txs,
            };

            check_codec_and_corruption::<StacksMicroblock>(&mblock, &block_bytes);
        }
    }

    #[test]
    fn stacks_microblock_sign_verify() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let mut mblock_header = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            miner_signatures: MessageSignatureList::empty(),
        };

        let pubk = StacksPublicKey::from_private(&privk);
        let pubkh = Hash160::from_node_public_key(&pubk);

        mblock_header.sign(&privk).unwrap();
        mblock_header.verify(&pubkh).unwrap();
    }

    #[test]
    fn stacks_microblock_sign_verify_uncompressed() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let mut mblock_header = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            miner_signatures: MessageSignatureList::empty(),
        };

        let mut pubk = StacksPublicKey::from_private(&privk);
        pubk.set_compressed(false);

        let mut pubk_compressed = StacksPublicKey::from_private(&privk);
        pubk_compressed.set_compressed(true);

        let pubkh = Hash160::from_data(&pubk.to_bytes());
        let pubkh_compressed = Hash160::from_data(&pubk_compressed.to_bytes());

        mblock_header.sign(&privk).unwrap();
        mblock_header.verify(&pubkh).unwrap_err();
        mblock_header.verify(&pubkh_compressed).unwrap();
    }

    #[test]
    fn stacks_header_validate_burnchain() {
        let mut header = StacksBlockHeader {
            version: 0x01,
            total_work: StacksWorkScore {
                burn: 234,
                work: 567,
            },
            proof: VRFProof::empty(),
            parent_block: BlockHeaderHash([5u8; 32]),
            parent_microblock: BlockHeaderHash([6u8; 32]),
            parent_microblock_sequence: 4,
            tx_merkle_root: Sha512Trunc256Sum([7u8; 32]),
            state_index_root: TrieHash([8u8; 32]),
            withdrawal_merkle_root: Sha512Trunc256Sum([9u8; 32]),
            microblock_pubkey_hash: Hash160([11u8; 20]),
            miner_signatures: MessageSignatureList::empty(),
        };

        let mut burn_chain_tip = BlockSnapshot::initial(122, &BurnchainHeaderHash([3u8; 32]), 0);
        let mut stacks_chain_tip = BlockSnapshot::initial(122, &BurnchainHeaderHash([3u8; 32]), 1);
        let sortition_chain_tip = BlockSnapshot::initial(122, &BurnchainHeaderHash([3u8; 32]), 2);

        let block_commit = LeaderBlockCommitOp {
            block_header_hash: header.block_hash(),
            withdrawal_merkle_root: header.withdrawal_merkle_root,
            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf")
                    .unwrap(),
            )
            .unwrap(),
            burn_header_hash: BurnchainHeaderHash([0xff; 32]),
        };

        burn_chain_tip.winning_stacks_block_hash = header.block_hash();
        burn_chain_tip.winning_block_txid = block_commit.txid.clone();

        stacks_chain_tip.winning_stacks_block_hash = header.parent_block.clone();
        stacks_chain_tip.total_burn = header.total_work.burn;

        // should fail due to bad commit
        header.version += 1;
        assert!(header
            .validate_burnchain(&burn_chain_tip, &block_commit,)
            .unwrap_err()
            .to_string()
            .find("invalid commit")
            .is_some());
    }

    #[test]
    fn stacks_block_invalid() {
        let header = StacksBlockHeader {
            version: 0x01,
            total_work: StacksWorkScore {
                burn: 234,
                work: 567,
            },
            proof: VRFProof::empty(),
            parent_block: BlockHeaderHash([5u8; 32]),
            parent_microblock: BlockHeaderHash([6u8; 32]),
            parent_microblock_sequence: 4,
            tx_merkle_root: Sha512Trunc256Sum([7u8; 32]),
            state_index_root: TrieHash([8u8; 32]),
            withdrawal_merkle_root: Sha512Trunc256Sum([9u8; 32]),
            microblock_pubkey_hash: Hash160([11u8; 20]),
            miner_signatures: MessageSignatureList::empty(),
        };

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );
        let tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            origin_auth.clone(),
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
        );

        let tx_coinbase_2 = StacksTransaction::new(
            TransactionVersion::Testnet,
            origin_auth.clone(),
            TransactionPayload::Coinbase(CoinbasePayload([1u8; 32])),
        );

        let mut tx_invalid_coinbase = tx_coinbase.clone();
        tx_invalid_coinbase.anchor_mode = TransactionAnchorMode::OffChainOnly;

        let stx_address = StacksAddress {
            version: 0,
            bytes: Hash160([0u8; 20]),
        };
        let mut tx_invalid_anchor = StacksTransaction::new(
            TransactionVersion::Testnet,
            origin_auth.clone(),
            TransactionPayload::TokenTransfer(
                stx_address.into(),
                123,
                TokenTransferMemo([1u8; 34]),
            ),
        );

        tx_invalid_anchor.anchor_mode = TransactionAnchorMode::OffChainOnly;

        let mut tx_dup = tx_invalid_anchor.clone();
        tx_dup.anchor_mode = TransactionAnchorMode::OnChainOnly;

        let txs_bad_coinbase = vec![tx_invalid_coinbase.clone()];
        let txs_no_coinbase = vec![tx_dup.clone()];
        let txs_multiple_coinbases = vec![tx_coinbase.clone(), tx_coinbase_2.clone()];
        let txs_bad_anchor = vec![tx_coinbase.clone(), tx_invalid_anchor.clone()];
        let txs_dup = vec![tx_coinbase.clone(), tx_dup.clone(), tx_dup.clone()];

        let get_tx_root = |txs: &Vec<StacksTransaction>| {
            let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            let tx_merkle_root = merkle_tree.root();
            tx_merkle_root
        };

        let mut block_header_no_coinbase = header.clone();
        block_header_no_coinbase.tx_merkle_root = get_tx_root(&txs_no_coinbase);

        let mut block_header_multiple_coinbase = header.clone();
        block_header_multiple_coinbase.tx_merkle_root = get_tx_root(&txs_multiple_coinbases);

        let mut block_header_invalid_coinbase = header.clone();
        block_header_invalid_coinbase.tx_merkle_root = get_tx_root(&txs_bad_coinbase);

        let mut block_header_invalid_anchor = header.clone();
        block_header_invalid_anchor.tx_merkle_root = get_tx_root(&txs_bad_anchor);

        let mut block_header_dup_tx = header.clone();
        block_header_dup_tx.tx_merkle_root = get_tx_root(&txs_dup);

        let mut block_header_empty = header.clone();
        block_header_empty.tx_merkle_root = get_tx_root(&vec![]);

        let invalid_blocks = vec![
            (
                StacksBlock {
                    header: block_header_no_coinbase,
                    txs: txs_no_coinbase,
                },
                "no coinbase found",
            ),
            (
                StacksBlock {
                    header: block_header_multiple_coinbase,
                    txs: txs_multiple_coinbases,
                },
                "multiple coinbases found",
            ),
            (
                StacksBlock {
                    header: block_header_invalid_anchor,
                    txs: txs_bad_anchor,
                },
                "Found offchain-only transaction",
            ),
            (
                StacksBlock {
                    header: block_header_dup_tx,
                    txs: txs_dup,
                },
                "found duplicate transaction",
            ),
            (
                StacksBlock {
                    header: block_header_empty,
                    txs: vec![],
                },
                "zero transactions",
            ),
        ];
        for (ref block, ref msg) in invalid_blocks.iter() {
            let mut bytes: Vec<u8> = vec![];
            block.consensus_serialize(&mut bytes).unwrap();
            assert!(StacksBlock::consensus_deserialize(&mut &bytes[..])
                .unwrap_err()
                .to_string()
                .find(msg)
                .is_some());
        }
    }

    #[test]
    fn stacks_microblock_invalid() {
        let header = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
            miner_signatures: MessageSignatureList::empty(),
        };

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );
        let tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            origin_auth.clone(),
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
        );

        let mut tx_coinbase_offchain = tx_coinbase.clone();
        tx_coinbase_offchain.anchor_mode = TransactionAnchorMode::OffChainOnly;

        let stx_address = StacksAddress {
            version: 0,
            bytes: Hash160([0u8; 20]),
        };
        let mut tx_invalid_anchor = StacksTransaction::new(
            TransactionVersion::Testnet,
            origin_auth.clone(),
            TransactionPayload::TokenTransfer(
                stx_address.into(),
                123,
                TokenTransferMemo([1u8; 34]),
            ),
        );

        tx_invalid_anchor.anchor_mode = TransactionAnchorMode::OnChainOnly;

        let mut tx_dup = tx_invalid_anchor.clone();
        tx_dup.anchor_mode = TransactionAnchorMode::OffChainOnly;

        let txs_coinbase = vec![tx_coinbase.clone()];
        let txs_offchain_coinbase = vec![tx_coinbase_offchain.clone()];
        let txs_bad_anchor = vec![tx_invalid_anchor.clone()];
        let txs_dup = vec![tx_dup.clone(), tx_dup.clone()];

        let get_tx_root = |txs: &Vec<StacksTransaction>| {
            let txid_vecs = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            let tx_merkle_root = merkle_tree.root();
            tx_merkle_root
        };

        let mut block_header_coinbase = header.clone();
        block_header_coinbase.tx_merkle_root = get_tx_root(&txs_coinbase);

        let mut block_header_offchain_coinbase = header.clone();
        block_header_offchain_coinbase.tx_merkle_root = get_tx_root(&txs_coinbase);

        let mut block_header_invalid_anchor = header.clone();
        block_header_invalid_anchor.tx_merkle_root = get_tx_root(&txs_bad_anchor);

        let mut block_header_dup_tx = header.clone();
        block_header_dup_tx.tx_merkle_root = get_tx_root(&txs_dup);

        let mut block_header_empty = header.clone();
        block_header_empty.tx_merkle_root = get_tx_root(&vec![]);

        let invalid_blocks = vec![
            (
                StacksMicroblock {
                    header: block_header_offchain_coinbase,
                    txs: txs_offchain_coinbase,
                },
                "invalid anchor mode for Coinbase",
            ),
            (
                StacksMicroblock {
                    header: block_header_coinbase,
                    txs: txs_coinbase,
                },
                "found on-chain-only transaction",
            ),
            (
                StacksMicroblock {
                    header: block_header_invalid_anchor,
                    txs: txs_bad_anchor,
                },
                "found on-chain-only transaction",
            ),
            (
                StacksMicroblock {
                    header: block_header_dup_tx,
                    txs: txs_dup,
                },
                "duplicate transaction",
            ),
            (
                StacksMicroblock {
                    header: block_header_empty,
                    txs: vec![],
                },
                "zero transactions",
            ),
        ];
        for (ref block, ref msg) in invalid_blocks.iter() {
            let mut bytes: Vec<u8> = vec![];
            block.consensus_serialize(&mut bytes).unwrap();
            assert!(StacksMicroblock::consensus_deserialize(&mut &bytes[..])
                .unwrap_err()
                .to_string()
                .find(msg)
                .is_some());
        }
    }

    // TODO:
    // * size limits
}
