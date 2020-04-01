use std::io;
use std::io::prelude::*;
use std::io::{Read, Write};
use rand::RngCore;

use burnchains::{BurnchainSigner, PrivateKey};
use chainstate::burn::{BlockHeaderHash, ConsensusHash, Opcodes, VRFSeed};
use chainstate::stacks::StacksAddress;
use net::StacksMessageCodec;
use net::codec::{write_next};
use net::Error as net_error;
use util::hash::Hash160;
use util::vrf::VRFPublicKey;
use util::secp256k1::{MessageSignature, Secp256k1PublicKey, Secp256k1PrivateKey};


#[derive(Debug, Clone)]
pub enum BurnchainOperationType {
    LeaderBlockCommit(LeaderBlockCommitPayload),
    LeaderKeyRegister(LeaderKeyRegisterPayload),
    UserBurnSupport(UserBurnSupportPayload)
}


#[derive(Debug, PartialEq, Clone, Eq)]
pub struct LeaderBlockCommitPayload {
    pub block_header_hash: BlockHeaderHash, // hash of Stacks block header (double-sha256)
    pub new_seed: VRFSeed,                  // new seed for this block
    pub parent_block_ptr: u32,              // pointer to the block that contains the parent block hash 
    pub parent_vtxindex: u16,               // offset in the parent block where the parent block hash can be found
    pub key_block_ptr: u32,                 // pointer to the block that contains the leader key registration 
    pub key_vtxindex: u16,                  // offset in the block where the leader key can be found
    pub memo: Vec<u8>,                      // extra unused byte

    pub burn_fee: u64,                      // how many burn tokens (e.g. satoshis) were destroyed to produce this block
    pub input: BurnchainSigner,             // burn chain keys that must match the key registration
}

impl StacksMessageCodec for LeaderBlockCommitPayload {

    /*
        Wire format:

        0      2  3            35               67     71     73    77   79     80
        |------|--|-------------|---------------|------|------|-----|-----|-----|
         magic  op   block hash     new seed     parent parent key   key   memo
                                                block  txoff  block txoff
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        write_next(fd, &(Opcodes::LeaderBlockCommit as u8))?;
        write_next(fd, &self.block_header_hash)?;
        fd.write_all(&self.new_seed.as_bytes()[..]).map_err(net_error::WriteError)?;
        write_next(fd, &self.parent_block_ptr)?;
        write_next(fd, &self.parent_vtxindex)?;
        write_next(fd, &self.key_block_ptr)?;
        write_next(fd, &self.key_vtxindex)?;

        let memo = match self.memo.len() > 0 {
            true => self.memo[0],
            false => 0x00,
        };
        write_next(fd, &memo)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<LeaderBlockCommitPayload, net_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct LeaderKeyRegisterPayload {
    pub consensus_hash: ConsensusHash,      // consensus hash at time of issuance
    pub public_key: VRFPublicKey,           // EdDSA public key 
    pub memo: Vec<u8>,                      // extra bytes in the op-return
    pub address: StacksAddress,             // hash of public key(s) that will send the leader block commit
}

impl StacksMessageCodec for LeaderKeyRegisterPayload {

    /*
        Wire format:

        0      2  3              23                       55                          80
        |------|--|---------------|-----------------------|---------------------------|
         magic  op consensus hash    proving public key               memo
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        write_next(fd, &(Opcodes::LeaderKeyRegister as u8))?;
        write_next(fd, &self.consensus_hash)?;
        fd.write_all(&self.public_key.as_bytes()[..]).map_err(net_error::WriteError)?;    
        let memo_len = 25;
        let mut memo = self.memo.clone();
        memo.resize(memo_len, 0);
        fd.write_all(&memo).map_err(net_error::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<LeaderKeyRegisterPayload, net_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct UserBurnSupportPayload {
    pub address: StacksAddress,
    pub consensus_hash: ConsensusHash,
    pub public_key: VRFPublicKey,
    pub key_block_ptr: u32,
    pub key_vtxindex: u16,
    pub block_header_hash_160: Hash160,
    pub burn_fee: u64,
}

impl StacksMessageCodec for UserBurnSupportPayload {

    /*
        Wire format:

        0      2  3              22                       54                 74       78        80
        |------|--|---------------|-----------------------|------------------|--------|---------|
         magic  op consensus hash   proving public key       block hash 160   key blk  key
                (truncated by 1)                                                        vtxindex
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        write_next(fd, &(Opcodes::UserBurnSupport as u8))?;
        write_next(fd, &self.consensus_hash)?;
        fd.write_all(&self.public_key.as_bytes()[..]).map_err(net_error::WriteError)?;    
        write_next(fd, &self.block_header_hash_160)?;
        write_next(fd, &self.key_block_ptr)?;
        write_next(fd, &self.key_vtxindex)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<UserBurnSupportPayload, net_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}


pub struct BurnchainOpSigner {
    secret_key: Secp256k1PrivateKey,
    is_one_off: bool,
    is_disposed: bool,
    usages: u8,
    session_id: [u8; 16]
}

impl BurnchainOpSigner {

    pub fn new(secret_key: Secp256k1PrivateKey, is_one_off: bool) -> BurnchainOpSigner {
        let mut rng = rand::thread_rng();
        let mut session_id = [0u8; 16];
        rng.fill_bytes(&mut session_id);
        BurnchainOpSigner {
            secret_key: secret_key,
            usages: 0,
            is_one_off,
            is_disposed: false,
            session_id,
        }
    }

    pub fn get_public_key(&mut self) -> Secp256k1PublicKey {
        let public_key = Secp256k1PublicKey::from_private(&self.secret_key);
        public_key
    }

    pub fn sign_message(&mut self, hash: &[u8]) -> Option<MessageSignature> {
        if self.is_disposed {
            return None;
        }

        let signature = match self.secret_key.sign(hash) {
            Ok(r) => r,
            _ => return None
        };
        self.usages += 1;
        
        if self.is_one_off && self.usages == 1 {
            self.is_disposed = true;
        }

        Some(signature)
    }

    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }
}
