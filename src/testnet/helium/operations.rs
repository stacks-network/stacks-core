use std::io;
use std::io::prelude::*;
use std::io::{Read, Write};
use burnchains::BurnchainSigner;
use chainstate::burn::{BlockHeaderHash, ConsensusHash, Opcodes, VRFSeed};
use chainstate::stacks::StacksAddress;
use net::StacksMessageCodec;
use net::codec::{write_next};
use net::Error as net_error;
use util::hash::Hash160;
use util::vrf::VRFPublicKey;


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

        Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

        The values parent-block, parent-txoff, key-block, and key-txoff are in network byte order.

        parent-delta and parent-txoff will both be 0 if this block builds off of the genesis block.
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        write_next(fd, &self.block_header_hash)?;
        // write_next(fd, &self.new_seed)?;
        write_next(fd, &self.parent_block_ptr)?;
        write_next(fd, &self.parent_vtxindex)?;
        write_next(fd, &self.key_block_ptr)?;
        let memo = match self.memo.len() > 0 {
            true => self.memo[0],
            false => 0x00,
        };
        write_next(fd, &memo)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<LeaderBlockCommitPayload, net_error> {
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

    
        Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        write_next(fd, &self.consensus_hash)?;
        // write_next(fd, &self.public_key)?;

        // todo(ludo): handle memo
        // todo(ludo): check network order?
        let memo = match self.memo.len() > 0 {
            true => self.memo[0],
            false => 0x00,
        };
        write_next(fd, &memo)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<LeaderKeyRegisterPayload, net_error> {
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

        Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        write_next(fd, &self.consensus_hash)?;
        // write_next(fd, &self.public_key)?;
        write_next(fd, &self.block_header_hash_160)?;
        write_next(fd, &self.key_block_ptr)?;
        write_next(fd, &self.key_vtxindex)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<UserBurnSupportPayload, net_error> {
        unimplemented!();
    }
}

