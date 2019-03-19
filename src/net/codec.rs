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

use std::mem::size_of;

use burnchains::BurnchainHeaderHash;
use burnchains::PrivateKey;
use burnchains::PublicKey;

use chainstate::burn::ConsensusHash;
use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksMicroblock;
use chainstate::stacks::StacksTransaction;

use util::hash::Sha256Sum;
use util::hash::DoubleSha256;
use util::hash::Hash160;
use util::hash::MerkleHashFunc;
use util::secp256k1::Secp256k1PublicKey;

use net::*;
use net::Error as net_error;

use core::PEER_VERSION;

use sha2::Sha256;
use sha2::Digest;

use util::log;

// macro for determining how big an inv bitvec can be, given its bitlen 
macro_rules! BITVEC_LEN {
    ($bitvec:expr) => ((($bitvec) / 8 + if ($bitvec) % 8 > 0 { 1 } else { 0 }) as u32)
}

impl MessageSignature {
    pub fn empty() -> MessageSignature {
        MessageSignature([0u8; 80])
    }

    // encode a generic vector of octets as a length-prefixed list of bytes
    pub fn from_sig(sig: &Vec<u8>) -> Option<MessageSignature> {
        if sig.len() >= 79 {
            return None;
        }
        let mut buf = [0u8; 80];
        buf[0] = sig.len() as u8;
        for i in 0..sig.len() {
            buf[i+1] = sig[i];
        }
        Some(MessageSignature(buf))
    }

    pub fn to_sig(&self) -> Option<Vec<u8>> {
        let buflen = self.0[0];
        if buflen > 79 {
            // corrupt
            return None;
        }
        let mut ret = vec![];
        ret.extend_from_slice(&self.0[1..((buflen+1) as usize)]);
        Some(ret)
    }
}

// serialize helper 
pub fn write_next<T: StacksMessageCodec>(buf: &mut Vec<u8>, item: &T) {
    let mut item_buf = item.serialize();
    buf.append(&mut item_buf);
}

// deserialize helper 
pub fn read_next<T: StacksMessageCodec>(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<T, net_error> {
    let item: T = T::deserialize(buf, index, max_size)?;
    Ok(item)
}

// deserialize helper for bound-sized vectors
// Parse `max_items` or `num_items` items of an array, up to `max_size_bytes` consumed.
// Parse exactly `num_items` if max_items = 0.  Otherwise, ignore num_items
fn read_next_vec<T: StacksMessageCodec + Sized>(buf: &Vec<u8>, index_ptr: &mut u32, max_size_bytes: u32, num_items: u32, max_items: u32) -> Result<Vec<T>, net_error> {
    let index = *index_ptr;
    if index > u32::max_value() - 4 {
        return Err(net_error::OverflowError);
    }
    if index + 4 > max_size_bytes {
        return Err(net_error::OverflowError);
    }
    if (buf.len() as u32) < index + 4 {
        return Err(net_error::UnderflowError);
    }

    let mut len_index : u32 = 0;
    let mut vec_index : u32 = 0;

    let len_buf = buf[(index as usize)..((index+4) as usize)].to_vec();
    let len = u32::deserialize(&len_buf, &mut len_index, 4)?;

    if max_items > 0 {
        if len > max_items {
            // too many items
            return Err(net_error::DeserializeError);
        }
    }
    else {
        if len != num_items {
            // inexact item count
            return Err(net_error::DeserializeError);
        }
    }
    
    vec_index = index + len_index;

    let mut ret = vec![];
    for i in 0..len {
        let next_item = T::deserialize(buf, &mut vec_index, max_size_bytes)?;
        ret.push(next_item);
    }

    *index_ptr = vec_index;
    Ok(ret)
}

pub fn read_next_at_most<T: StacksMessageCodec + Sized>(buf: &Vec<u8>, index_ptr: &mut u32, max_size_bytes: u32, max_items: u32) -> Result<Vec<T>, net_error> {
    read_next_vec::<T>(buf, index_ptr, max_size_bytes, 0, max_items)
}

pub fn read_next_exact<T: StacksMessageCodec + Sized>(buf: &Vec<u8>, index_ptr: &mut u32, max_size_bytes: u32, num_items: u32) -> Result<Vec<T>, net_error> {
    read_next_vec::<T>(buf, index_ptr, max_size_bytes, num_items, 0)
}

impl StacksMessageCodec for u8 {
    fn serialize(&self) -> Vec<u8> {
        vec![*self]
    }
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<u8, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 1 {
            return Err(net_error::OverflowError);
        }
        if index + 1 > max_size {
            return Err(net_error::OverflowError);
        }
        if (buf.len() as u32) < index + 1 {
            return Err(net_error::UnderflowError);
        }

        let next = buf[index as usize];

        *index_ptr += 1;
        
        Ok(next)
    }
}

impl StacksMessageCodec for u16 {
    fn serialize(&self) -> Vec<u8> {
        // big-endian 
        let be = u16::to_be(*self);
        vec![(be & 0x00ff) as u8, ((be & 0xff00) >> 8) as u8]
    }
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<u16, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 2 {
            return Err(net_error::OverflowError);
        }
        if index + 2 > max_size {
            return Err(net_error::OverflowError);
        }
        if (buf.len() as u32) < index + 2 {
            return Err(net_error::UnderflowError);
        }

        let lower : u16 = buf[index as usize] as u16;
        let upper : u16 = buf[(index+1) as usize] as u16;

        *index_ptr += 2;

        Ok(u16::from_be(lower | (upper << 8)))
    }
}

impl StacksMessageCodec for u32 {
    fn serialize(&self) -> Vec<u8> {
        // big-endian 
        let be = u32::to_be(*self);
        vec![
            ((be & 0x000000ff) as u8),
            ((be & 0x0000ff00) >> 8) as u8,
            ((be & 0x00ff0000) >> 16) as u8,
            ((be & 0xff000000) >> 24) as u8
        ]
    }
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<u32, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 4 {
            return Err(net_error::OverflowError);
        }
        if index + 4 > max_size {
            return Err(net_error::OverflowError);
        }
        if (buf.len() as u32) < index + 4 {
            return Err(net_error::UnderflowError);
        }

        let i1 : u32 = buf[index as usize] as u32;
        let i2 : u32 = buf[(index+1) as usize] as u32;
        let i3 : u32 = buf[(index+2) as usize] as u32;
        let i4 : u32 = buf[(index+3) as usize] as u32;

        *index_ptr += 4;

        Ok(u32::from_be(
            i1 |
            (i2 << 8) |
            (i3 << 16) |
            (i4 << 24)
        ))
    }
}

impl StacksMessageCodec for u64 {
    fn serialize(&self) -> Vec<u8> {
        // big-endian 
        let be = u64::to_be(*self);
        vec![
            ((be & 0x00000000000000ff) as u8),
            ((be & 0x000000000000ff00) >> 8) as u8,
            ((be & 0x0000000000ff0000) >> 16) as u8,
            ((be & 0x00000000ff000000) >> 24) as u8,
            ((be & 0x000000ff00000000) >> 32) as u8,
            ((be & 0x0000ff0000000000) >> 40) as u8,
            ((be & 0x00ff000000000000) >> 48) as u8,
            ((be & 0xff00000000000000) >> 56) as u8
        ]
    }
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<u64, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 8 {
            return Err(net_error::OverflowError);
        }
        if index + 8 > max_size {
            return Err(net_error::OverflowError);
        }
        if (buf.len() as u32) < index + 8 {
            return Err(net_error::UnderflowError);
        }

        let i0 : u64 = buf[(index) as usize] as u64;
        let i1 : u64 = buf[(index+1) as usize] as u64;
        let i2 : u64 = buf[(index+2) as usize] as u64;
        let i3 : u64 = buf[(index+3) as usize] as u64;
        let i4 : u64 = buf[(index+4) as usize] as u64;
        let i5 : u64 = buf[(index+5) as usize] as u64;
        let i6 : u64 = buf[(index+6) as usize] as u64;
        let i7 : u64 = buf[(index+7) as usize] as u64;
        
        *index_ptr += 8;

        Ok(u64::from_be(
            i0 |
            (i1 << 8) |
            (i2 << 16) |
            (i3 << 24) |
            (i4 << 32) |
            (i5 << 40) |
            (i6 << 48) |
            (i7 << 56)
        ))
    }
}

impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }
    
    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, net_error> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| net_error::DeserializeError)
    }
}

impl<T> StacksMessageCodec for Vec<T>
where
    T: StacksMessageCodec + Sized
{
    fn serialize(&self) -> Vec<u8> {
        if self.len() >= ARRAY_MAX_LEN as usize {
            // over 4.1 billion entries -- this is not okay
            panic!("FATAL ERROR array too long");
        }
        
        let mut ret = vec![];
        let mut size_buf = (self.len() as u32).serialize();
        ret.append(&mut size_buf);

        for i in 0..self.len() {
            let mut byte_list = self[i].serialize();
            ret.append(&mut byte_list);
        }
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<Vec<T>, net_error> {
        read_next_at_most::<T>(buf, index_ptr, max_size, u32::max_value())
    }
}

impl Preamble {
    /// Make an empty preamble with the given version and fork-set identifier, and payload length.
    pub fn new(network_id: u32, block_height: u64, consensus_hash: &ConsensusHash, stable_block_height: u64, stable_consensus_hash: &ConsensusHash, payload_len: u32) -> Preamble {
        Preamble {
            peer_version: PEER_VERSION as u32,
            network_id: network_id,
            seq: 0,
            burn_block_height: block_height,
            burn_consensus_hash: consensus_hash.clone(),
            burn_stable_block_height: stable_block_height,
            burn_stable_consensus_hash: stable_consensus_hash.clone(),
            additional_data: DoubleSha256::empty(),
            signature: MessageSignature::empty(),
            payload_len: payload_len,
        }
    }

    /// Given the serialized message type and bits, sign the resulting message and store the
    /// signature.  message_bits includes the relayers, payload type, and payload.
    pub fn sign<PK>(&mut self, message_bits: &[u8], privkey: &PK) -> Result<(), net_error>
    where
        PK: PrivateKey
    {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha256::new();

        // serialize the premable with a blank signature
        let old_signature = self.signature.clone();
        self.signature = MessageSignature::empty();
        let preamble_bits = self.serialize();
        self.signature = old_signature;

        sha2.input(&preamble_bits[..]);
        sha2.input(message_bits);
        
        digest_bits.copy_from_slice(sha2.result().as_slice());

        let sig_bits = privkey.sign(&digest_bits)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        let sig = MessageSignature::from_sig(&sig_bits)
            .ok_or(net_error::SigningError("Failed to serialize signature".to_string()))?;

        self.signature = sig;
        Ok(())
    }

    /// Given the serialized message type and bits, verify the signature.
    /// message_bits includes the relayers, payload type, and payload
    pub fn verify<PUBK>(&mut self, message_bits: &[u8], pubkey: &PUBK) -> Result<(), net_error>
    where
        PUBK: PublicKey
    {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha256::new();

        // serialize the preamble with a blank signature 
        let sig_bits = self.signature.clone();
        self.signature = MessageSignature::empty();
        let preamble_bits = self.serialize();
        self.signature = sig_bits;

        sha2.input(&preamble_bits[..]);
        sha2.input(message_bits);

        digest_bits.copy_from_slice(sha2.result().as_slice());
        let sig = self.signature.to_sig()
            .ok_or(net_error::DeserializeError)?;

        let res = pubkey.verify(&digest_bits, &sig)
            .map_err(|_ve| net_error::VerifyingError("Failed to verify signature".to_string()))?;

        if res {
            Ok(())
        }
        else {
            Err(net_error::VerifyingError("Invalid message signature".to_string()))
        }
    }
}

impl StacksMessageCodec for Preamble {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.peer_version);
        write_next(&mut ret, &self.network_id);
        write_next(&mut ret, &self.seq);
        write_next(&mut ret, &self.burn_block_height);
        write_next(&mut ret, &self.burn_consensus_hash);
        write_next(&mut ret, &self.burn_stable_block_height);
        write_next(&mut ret, &self.burn_stable_consensus_hash);
        write_next(&mut ret, &self.additional_data);
        write_next(&mut ret, &self.signature);
        write_next(&mut ret, &self.payload_len);
        ret
    }
    
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<Preamble, net_error> {
        let mut index = *index_ptr;
        let peer_version: u32                           = read_next(buf, &mut index, max_size)?;
        let network_id: u32                             = read_next(buf, &mut index, max_size)?;
        let seq: u32                                    = read_next(buf, &mut index, max_size)?;
        let burn_block_height: u64                      = read_next(buf, &mut index, max_size)?;
        let burn_consensus_hash : ConsensusHash         = read_next(buf, &mut index, max_size)?;
        let burn_stable_block_height: u64               = read_next(buf, &mut index, max_size)?;
        let burn_stable_consensus_hash : ConsensusHash  = read_next(buf, &mut index, max_size)?;
        let additional_data : DoubleSha256              = read_next(buf, &mut index, max_size)?;
        let signature : MessageSignature                = read_next(buf, &mut index, max_size)?;
        let payload_len : u32                           = read_next(buf, &mut index, max_size)?;

        // test_debug!("preamble {}-{:?}/{}-{:?}, {} bytes", burn_block_height, burn_consensus_hash, burn_stable_block_height, burn_stable_consensus_hash, payload_len);

        // minimum is 5 bytes -- a zero-length vector (4 bytes of 0) plus a type identifier (1 byte)
        if payload_len < 5 {
            test_debug!("Payload len is too small: {}", payload_len);
            return Err(net_error::DeserializeError);
        }

        if payload_len >= MAX_MESSAGE_LEN {
            test_debug!("Payload len is too big: {}", payload_len);
            return Err(net_error::DeserializeError);
        }

        *index_ptr = index;

        Ok(Preamble {
            peer_version,
            network_id,
            seq,
            burn_block_height,
            burn_consensus_hash,
            burn_stable_block_height,
            burn_stable_consensus_hash,
            additional_data,
            signature,
            payload_len
        })
    }
}

impl StacksMessageCodec for GetBlocksData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.burn_height_start);
        write_next(&mut ret, &self.burn_header_hash_start);
        write_next(&mut ret, &self.burn_height_end);
        write_next(&mut ret, &self.burn_header_hash_end);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<GetBlocksData, net_error> {
        let mut index = *index_ptr;
        let burn_height_start : u64                         = read_next(buf, &mut index, max_size)?;
        let burn_header_hash_start : BurnchainHeaderHash    = read_next(buf, &mut index, max_size)?;
        let burn_height_end : u64                           = read_next(buf, &mut index, max_size)?;
        let burn_header_hash_end : BurnchainHeaderHash      = read_next(buf, &mut index, max_size)?;

        if burn_height_end - burn_height_start > BLOCKS_INV_DATA_MAX_BITLEN as u64 {
            // requested too long of a range 
            return Err(net_error::DeserializeError);
        }

        *index_ptr = index;

        Ok(GetBlocksData {
            burn_height_start,
            burn_header_hash_start,
            burn_height_end,
            burn_header_hash_end
        })
    }
}

impl StacksMessageCodec for MicroblocksInvData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.hashes);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<MicroblocksInvData, net_error> {
        let mut index = *index_ptr;

        let hashes : Vec<BlockHeaderHash> = read_next_at_most::<BlockHeaderHash>(buf, &mut index, max_size, MICROBLOCKS_INV_DATA_MAX_HASHES)?;

        *index_ptr = index;

        Ok(MicroblocksInvData {
            hashes
        })
    }
}

impl StacksMessageCodec for BlocksInvData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.bitlen);
        write_next(&mut ret, &self.bitvec);
        write_next(&mut ret, &self.microblocks_inventory);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<BlocksInvData, net_error> {
        let mut index = *index_ptr;

        let bitlen : u16                                     = read_next(buf, &mut index, max_size)?;
        if bitlen > BLOCKS_INV_DATA_MAX_BITLEN as u16 {
            return Err(net_error::DeserializeError);
        }

        let bitvec : Vec<u8>                                = read_next_exact::<u8>(buf, &mut index, max_size, BITVEC_LEN!(bitlen))?;
        let microblocks_inventory : Vec<MicroblocksInvData> = read_next_exact::<MicroblocksInvData>(buf, &mut index, max_size, bitlen as u32)?;

        *index_ptr = index;

        Ok(BlocksInvData {
            bitlen,
            bitvec,
            microblocks_inventory
        })
    }
}

impl StacksMessageCodec for BlocksData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.blocks);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<BlocksData, net_error> {
        let mut index = *index_ptr;
        
        let blocks : Vec<StacksBlock> = read_next(buf, &mut index, max_size)?;
        
        *index_ptr = index;

        Ok(BlocksData {
            blocks
        })
    }
}

impl StacksMessageCodec for GetMicroblocksData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.burn_header_height);
        write_next(&mut ret, &self.burn_header_hash);
        write_next(&mut ret, &self.block_header_hash);
        write_next(&mut ret, &self.microblocks_header_hash);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<GetMicroblocksData, net_error> {
        let mut index = *index_ptr;

        let burn_header_height: u64                     = read_next(buf, &mut index, max_size)?;
        let burn_header_hash: BurnchainHeaderHash       = read_next(buf, &mut index, max_size)?;
        let block_header_hash: BlockHeaderHash          = read_next(buf, &mut index, max_size)?;
        let microblocks_header_hash: BlockHeaderHash    = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(GetMicroblocksData {
            burn_header_hash,
            burn_header_height,
            block_header_hash,
            microblocks_header_hash
        })
    }
}

impl StacksMessageCodec for MicroblocksData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.microblocks);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<MicroblocksData, net_error> {
        let mut index = *index_ptr;

        let microblocks : Vec<StacksMicroblock> = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(MicroblocksData {
            microblocks
        })
    }
}

impl StacksMessageCodec for NeighborAddress {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.addrbytes);
        write_next(&mut ret, &self.port);
        write_next(&mut ret, &self.public_key_hash);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<NeighborAddress, net_error> {
        let mut index = *index_ptr;

        let addrbytes: PeerAddress      = read_next(buf, &mut index, max_size)?;
        let port : u16                  = read_next(buf, &mut index, max_size)?;
        let public_key_hash: Hash160    = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(NeighborAddress {
            addrbytes,
            port,
            public_key_hash
        })
    }
}

impl StacksMessageCodec for NeighborsData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.neighbors);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<NeighborsData, net_error> {
        // don't allow list of more than the pre-set number of neighbors
        let mut index = *index_ptr;
        
        let neighbors : Vec<NeighborAddress> = read_next_at_most::<NeighborAddress>(buf, &mut index, max_size, MAX_NEIGHBORS_DATA_LEN)?;

        *index_ptr = index;

        Ok(NeighborsData {
            neighbors
        })
    }
}

impl StacksMessageCodec for HandshakeData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.addrbytes);
        write_next(&mut ret, &self.port);
        write_next(&mut ret, &self.services);
        write_next(&mut ret, &self.node_public_key);
        write_next(&mut ret, &self.expire_block_height);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<HandshakeData, net_error> {
        let mut index = *index_ptr;

        let addrbytes: PeerAddress                  = read_next(buf, &mut index, max_size)?;
        let port : u16                              = read_next(buf, &mut index, max_size)?;
        let services : u16                          = read_next(buf, &mut index, max_size)?;
        let node_public_key : StacksPublicKeyBuffer = read_next(buf, &mut index, max_size)?;
        let expire_block_height : u64               = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(HandshakeData {
            addrbytes,
            port,
            services,
            node_public_key,
            expire_block_height
        })
    }
}

impl StacksMessageCodec for HandshakeAcceptData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.heartbeat_interval);
        write_next(&mut ret, &self.node_public_key);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<HandshakeAcceptData, net_error> {
        let mut index = *index_ptr;

        let heartbeat_interval : u32                = read_next(buf, &mut index, max_size)?;
        let node_public_key : StacksPublicKeyBuffer = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(HandshakeAcceptData {
            heartbeat_interval,
            node_public_key
        })
    }
}

impl StacksMessageCodec for NackData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.error_code);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<NackData, net_error> {
        let mut index = *index_ptr;

        let error_code : u32 = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(NackData {
            error_code
        })
    }
}

impl StacksMessageCodec for RelayData {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.peer);
        write_next(&mut ret, &self.seq);
        write_next(&mut ret, &self.signature);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<RelayData, net_error> {
        let mut index = *index_ptr;

        let peer : NeighborAddress          = read_next(buf, &mut index, max_size)?;
        let seq : u32                       = read_next(buf, &mut index, max_size)?;
        let signature : MessageSignature    = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(RelayData {
            peer,
            seq,
            signature
        })
    }
}

/// Serialize a Stacks message to its wireformat.
pub fn message_serialize(msg: &StacksMessageType) -> Vec<u8> {
    match msg {
        StacksMessageType::Handshake(ref m) => m.serialize(),
        StacksMessageType::HandshakeAccept(ref m) => m.serialize(),
        StacksMessageType::HandshakeReject => vec![],
        StacksMessageType::GetNeighbors => vec![],
        StacksMessageType::Neighbors(ref m) => m.serialize(),
        StacksMessageType::GetBlocksInv(ref m) => m.serialize(),
        StacksMessageType::BlocksInv(ref m) => m.serialize(),
        StacksMessageType::GetBlocks(ref m) => m.serialize(),
        StacksMessageType::Blocks(ref m) => m.serialize(),
        StacksMessageType::GetMicroblocks(ref m) => m.serialize(),
        StacksMessageType::Microblocks(ref m) => m.serialize(),
        StacksMessageType::Transaction(ref m) => m.serialize(),
        StacksMessageType::Nack(ref m) => m.serialize(),
        StacksMessageType::Ping => vec![],
    }
}

/// Deserialize a Stacks message from its wireformat
pub fn message_deserialize(message_id: u8, bits: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksMessageType, net_error> {
    match message_id {
        StacksMessageID::Handshake => { let m = HandshakeData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::Handshake(m)) },
        StacksMessageID::HandshakeAccept => { let m = HandshakeAcceptData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::HandshakeAccept(m)) },
        StacksMessageID::HandshakeReject => { Ok(StacksMessageType::HandshakeReject) },
        StacksMessageID::GetNeighbors => { Ok(StacksMessageType::GetNeighbors) },
        StacksMessageID::Neighbors => { let m = NeighborsData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::Neighbors(m)) },
        StacksMessageID::GetBlocksInv => { let m = GetBlocksData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::GetBlocksInv(m)) },
        StacksMessageID::BlocksInv => { let m = BlocksInvData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::BlocksInv(m)) },
        StacksMessageID::GetBlocks => { let m = GetBlocksData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::GetBlocks(m)) },
        StacksMessageID::Blocks => { let m = BlocksData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::Blocks(m)) },
        StacksMessageID::GetMicroblocks => { let m = GetMicroblocksData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::GetMicroblocks(m)) },
        StacksMessageID::Microblocks => { let m = MicroblocksData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::Microblocks(m)) },
        StacksMessageID::Transaction => { let m = StacksTransaction::deserialize(bits, index, max_size)?; Ok(StacksMessageType::Transaction(m)) },
        StacksMessageID::Nack => { let m = NackData::deserialize(bits, index, max_size)?; Ok(StacksMessageType::Nack(m)) },
        StacksMessageID::Ping => { Ok(StacksMessageType::Ping) },
        _ => { Err(net_error::UnrecognizedMessageID) }
    }
}

/// Match up a message type to its message ID 
pub fn message_type_to_id(msg: &StacksMessageType) -> u8 {
    match msg {
        StacksMessageType::Handshake(ref _m) => StacksMessageID::Handshake,
        StacksMessageType::HandshakeAccept(ref _m) => StacksMessageID::HandshakeAccept,
        StacksMessageType::HandshakeReject => StacksMessageID::HandshakeReject,
        StacksMessageType::GetNeighbors => StacksMessageID::GetNeighbors,
        StacksMessageType::Neighbors(ref _m) => StacksMessageID::Neighbors,
        StacksMessageType::GetBlocksInv(ref _m) => StacksMessageID::GetBlocksInv,
        StacksMessageType::BlocksInv(ref _m) => StacksMessageID::BlocksInv,
        StacksMessageType::GetBlocks(ref _m) => StacksMessageID::GetBlocks,
        StacksMessageType::Blocks(ref _m) => StacksMessageID::Blocks,
        StacksMessageType::GetMicroblocks(ref _m) => StacksMessageID::GetMicroblocks,
        StacksMessageType::Microblocks(ref _m) => StacksMessageID::Microblocks,
        StacksMessageType::Transaction(ref _m) => StacksMessageID::Transaction,
        StacksMessageType::Nack(ref _m) => StacksMessageID::Nack,
        StacksMessageType::Ping => StacksMessageID::Ping,
    }
}

impl StacksMessageCodec for StacksMessage {
    fn serialize(&self) -> Vec<u8> {
        let message_id : u8 = message_type_to_id(&self.payload);
        
        let mut ret = vec![];
        write_next(&mut ret, &self.preamble);
        write_next(&mut ret, &self.relayers);
        write_next(&mut ret, &message_id);

        let mut payload_bits = message_serialize(&self.payload);
        ret.append(&mut payload_bits);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMessage, net_error> {
        let mut index = *index_ptr;
        let mut preamble: Preamble = read_next(buf, &mut index, max_size)?;
        let msg = StacksMessage::payload_parse(&mut preamble, buf, &mut index, max_size)?;
        *index_ptr = index;
        Ok(msg)
    }
}

impl StacksMessage {
    /// Create an unsigned Stacks message
    pub fn new(network_id: u32, block_height: u64, consensus_hash: &ConsensusHash, stable_block_height: u64, stable_consensus_hash: &ConsensusHash, message: StacksMessageType) -> StacksMessage {
        let preamble = Preamble::new(network_id, block_height, consensus_hash, stable_block_height, stable_consensus_hash, 0);
        StacksMessage {
            preamble: preamble, 
            relayers: vec![],
            payload: message
        }
    }

    /// Sign the stacks message 
    fn do_sign<PRIVK: PrivateKey>(&mut self, private_key: &PRIVK) -> Result<(), net_error> {
        let mut message_bits = vec![];
        message_bits.append(&mut self.relayers.serialize());
        message_bits.push(message_type_to_id(&self.payload));
        message_bits.append(&mut message_serialize(&self.payload));

        self.preamble.payload_len = message_bits.len() as u32;
        self.preamble.sign(&message_bits[..], private_key)
    }

    /// Sign the StacksMessage.  The StacksMessage must _not_ have any relayers (i.e. we're
    /// originating this messsage).
    pub fn sign<PRIVK: PrivateKey>(&mut self, seq: u32, private_key: &PRIVK) -> Result<(), net_error> {
        if self.relayers.len() > 0 {
            return Err(net_error::InvalidMessage);
        }
        self.preamble.seq = seq;
        self.do_sign(private_key)
    }

    /// Sign the StacksMessage and add ourselves as a relayer.
    /// Fails if the relayers vector would be too long 
    pub fn sign_relay<PRIVK: PrivateKey>(&mut self, private_key: &PRIVK, our_seq: u32, our_addr: &NeighborAddress) -> Result<(), net_error> {
        if self.relayers.len() >= (MAX_RELAYERS_LEN as usize) {
            return Err(net_error::InvalidMessage);
        }
        
        // don't sign if signed more than once 
        for relayer in &self.relayers {
            if relayer.peer.public_key_hash == our_addr.public_key_hash {
                return Err(net_error::InvalidMessage);
            }
        }

        // save relayer state 
        let our_relay = RelayData {
            peer: our_addr.clone(),
            seq: self.preamble.seq,
            signature: self.preamble.signature.clone()
        };

        self.relayers.push(our_relay);
        self.preamble.seq = our_seq;
        self.do_sign(private_key)
    }

    fn do_payload_deserialize<PUBK: PublicKey>(public_key_opt: Option<&PUBK>, preamble: &mut Preamble, buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMessage, net_error> {
        let mut index = *index_ptr;

        // don't numeric overflow
        if index > u32::max_value() - preamble.payload_len {
            return Err(net_error::OverflowError);
        }

        if index + preamble.payload_len > max_size {
            return Err(net_error::OverflowError);
        }

        // don't read over the buffer 
        if index + preamble.payload_len > (buf.len() as u32) {
            return Err(net_error::UnderflowError);
        }

        // verify signature
        if public_key_opt.is_some() {
            let payload_len = preamble.payload_len;
            preamble.verify(&buf[(index as usize)..((index + payload_len) as usize)], public_key_opt.unwrap())?;
        }

        let max_payload_size = if index + preamble.payload_len < max_size { index + preamble.payload_len } else { max_size };

        // consume the rest of the message
        let relayers: Vec<RelayData>    = read_next_at_most::<RelayData>(buf, &mut index, max_payload_size, MAX_RELAYERS_LEN)?;
        let message_id : u8             = read_next(buf, &mut index, max_payload_size)?;
        let payload: StacksMessageType  = message_deserialize(message_id, buf, &mut index, max_payload_size)?;

        *index_ptr = index;

        Ok(StacksMessage {
            preamble: preamble.clone(),
            relayers: relayers,
            payload: payload,
        })
    }
    
    pub fn payload_deserialize<PUBK: PublicKey>(public_key: &PUBK, preamble: &mut Preamble, buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMessage, net_error> {
        StacksMessage::do_payload_deserialize(Some(public_key), preamble, buf, index_ptr, max_size)
    }

    pub fn payload_parse(preamble: &mut Preamble, buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksMessage, net_error> {
        StacksMessage::do_payload_deserialize::<Secp256k1PublicKey>(None, preamble, buf, index_ptr, max_size)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use util::hash::hex_bytes;

    #[test]
    fn codec_primitive_types() {
        let a : u8 = 0x01;
        let b : u16 = 0x0203;
        let c : u32 = 0x04050607;
        let d : u64 = 0x08090a0b0c0d0e0f;

        let a_bits = a.serialize();
        let b_bits = b.serialize();
        let c_bits = c.serialize();
        let d_bits = d.serialize();

        assert_eq!(a_bits, [0x01]);
        assert_eq!(b_bits, [0x02, 0x03]);
        assert_eq!(c_bits, [0x04, 0x05, 0x06, 0x07]);
        assert_eq!(d_bits, [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);

        let mut index : u32 = 0;
        assert_eq!(u8::deserialize(&a_bits, &mut index, 1).unwrap(), a);
        assert_eq!(index, 1);

        index = 0;
        assert_eq!(u16::deserialize(&b_bits, &mut index, 2).unwrap(), b);
        assert_eq!(index, 2);

        index = 0;
        assert_eq!(u32::deserialize(&c_bits, &mut index, 4).unwrap(), c);
        assert_eq!(index, 4);

        index = 0;
        assert_eq!(u64::deserialize(&d_bits, &mut index, 8).unwrap(), d);
        assert_eq!(index, 8);

        index = 0;

        // overflowing maximum allowed size
        assert!(u8::deserialize(&a_bits, &mut index, 0) == Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert!(u16::deserialize(&b_bits, &mut index, 1) == Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert!(u32::deserialize(&c_bits, &mut index, 3) == Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert!(u64::deserialize(&d_bits, &mut index, 7) == Err(net_error::OverflowError));
        assert_eq!(index, 0);

        // buffer is too short
        assert!(u8::deserialize(&vec![], &mut index, 1) == Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert!(u16::deserialize(&b_bits[0..1].to_vec(), &mut index, 2) == Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert!(u32::deserialize(&c_bits[0..3].to_vec(), &mut index, 4) == Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert!(u64::deserialize(&d_bits[0..6].to_vec(), &mut index, 8) == Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        // index would overflow 
        index = u32::max_value();
        assert!(u8::deserialize(&a_bits, &mut index, 1) == Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value());

        index = u32::max_value() - 1;
        assert!(u16::deserialize(&b_bits, &mut index, 2) == Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 1);

        index = u32::max_value() - 3;
        assert!(u32::deserialize(&c_bits, &mut index, 4) == Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - 7;
        assert!(u64::deserialize(&d_bits, &mut index, 8) == Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 7);
    }

    #[test]
    fn codec_primitive_vector() {
        let v1 : Vec<u8> = vec![];
        let r1 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
        
        let v2 : Vec<u8> = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let r2 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x0a,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

        let v3 : Vec<u16> = vec![];
        let r3 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];

        let v4 : Vec<u16> = vec![0xf000, 0xf101, 0xf202, 0xf303, 0xf404, 0xf505, 0xf606, 0xf707, 0xf808, 0xf909];
        let r4 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x0a,
                                0xf0, 0x00, 0xf1, 0x01, 0xf2, 0x02, 0xf3, 0x03, 0xf4, 0x04, 0xf5, 0x05, 0xf6, 0x06, 0xf7, 0x07, 0xf8, 0x08, 0xf9, 0x09];

        let v5 : Vec<u32> = vec![];
        let r5 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];

        let v6 : Vec<u32> = vec![0xa0b0f000,
                                 0xa1b1f101,
                                 0xa2b2f202,
                                 0xa3b3f303,
                                 0xa4b4f404,
                                 0xa5b5f505,
                                 0xa6b6f606,
                                 0xa7b7f707,
                                 0xa8b8f808,
                                 0xa9b9f909];
        let r6 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x0a,
                                0xa0, 0xb0, 0xf0, 0x00,
                                0xa1, 0xb1, 0xf1, 0x01,
                                0xa2, 0xb2, 0xf2, 0x02,
                                0xa3, 0xb3, 0xf3, 0x03,
                                0xa4, 0xb4, 0xf4, 0x04,
                                0xa5, 0xb5, 0xf5, 0x05,
                                0xa6, 0xb6, 0xf6, 0x06,
                                0xa7, 0xb7, 0xf7, 0x07,
                                0xa8, 0xb8, 0xf8, 0x08,
                                0xa9, 0xb9, 0xf9, 0x09];

        let v7 : Vec<u64> = vec![];
        let r7 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];

        let v8 : Vec<u64> = vec![0x1020304050607080,
                                 0x1121314151617181,
                                 0x1222324252627282,
                                 0x1323334353637383,
                                 0x1424344454647484,
                                 0x1525354555657585,
                                 0x1626364656667686,
                                 0x1727374757677787,
                                 0x1828384858687888];
        let r8 : Vec<u8> = vec![0x00, 0x00, 0x00, 0x09,
                                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81,
                                0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82,
                                0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83,
                                0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84,
                                0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85,
                                0x16, 0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0x86,
                                0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87,
                                0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88];

        // serialize
        assert_eq!(v1.serialize(), r1);
        assert_eq!(v2.serialize(), r2);
        assert_eq!(v3.serialize(), r3);
        assert_eq!(v4.serialize(), r4);
        assert_eq!(v5.serialize(), r5);
        assert_eq!(v6.serialize(), r6);
        assert_eq!(v7.serialize(), r7);
        assert_eq!(v8.serialize(), r8);

        let mut index = 0;
        
        // deserialize
        assert_eq!(Vec::<u8>::deserialize(&r1, &mut index, 4).unwrap(), v1);
        assert_eq!(index, 4);
        
        index = 0;
        assert_eq!(Vec::<u8>::deserialize(&r2, &mut index, (4 + v2.len()) as u32).unwrap(), v2);
        assert_eq!(index, (4 + v2.len()) as u32);

        index = 0;
        assert_eq!(Vec::<u16>::deserialize(&r3, &mut index, 4).unwrap(), v3);
        assert_eq!(index, 4);
        
        index = 0;
        assert_eq!(Vec::<u16>::deserialize(&r4, &mut index, (4 + v4.len() * 2) as u32).unwrap(), v4);
        assert_eq!(index, (4 + v4.len() * 2) as u32);

        index = 0;
        assert_eq!(Vec::<u32>::deserialize(&r5, &mut index, 4).unwrap(), v5);
        assert_eq!(index, 4);

        index = 0;
        assert_eq!(Vec::<u32>::deserialize(&r6, &mut index, (4 + v6.len() * 4) as u32).unwrap(), v6);
        assert_eq!(index, (4 + v6.len() * 4) as u32);

        index = 0;
        assert_eq!(Vec::<u64>::deserialize(&r7, &mut index, 4).unwrap(), v7);
        assert_eq!(index, 4);

        index = 0;
        assert_eq!(Vec::<u64>::deserialize(&r8, &mut index, (4 + v8.len() * 8) as u32).unwrap(), v8);
        assert_eq!(index, (4 + v8.len() * 8) as u32);
        
        index = 0;

        // overflow maximum allowed size
        assert_eq!(Vec::<u8>::deserialize(&r1, &mut index, 3), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u8>::deserialize(&r2, &mut index, (4 + v2.len() - 1) as u32), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u16>::deserialize(&r3, &mut index, 3), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u16>::deserialize(&r4, &mut index, (4 + v4.len() * 2 - 1) as u32), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u32>::deserialize(&r5, &mut index, 3), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u32>::deserialize(&r6, &mut index, (4 + v6.len() * 4 - 1) as u32), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u64>::deserialize(&r7, &mut index, 3), Err(net_error::OverflowError));
        assert_eq!(index, 0);
        
        assert_eq!(Vec::<u64>::deserialize(&r8, &mut index, (4 + v8.len() * 8 - 1) as u32), Err(net_error::OverflowError));
        assert_eq!(index, 0);

        // underflow the input buffer
        assert_eq!(Vec::<u8>::deserialize(&r1[0..2].to_vec(), &mut index, 4), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u8>::deserialize(&r2[0..r2.len()-1].to_vec(), &mut index, (4 + v2.len()) as u32), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u16>::deserialize(&r3[0..2].to_vec(), &mut index, 4), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u16>::deserialize(&r4[0..r4.len()-1].to_vec(), &mut index, (4 + v4.len() * 2) as u32), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u32>::deserialize(&r5[0..2].to_vec(), &mut index, 4), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u32>::deserialize(&r6[0..r6.len()-1].to_vec(), &mut index, (4 + v6.len() * 4) as u32), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Vec::<u64>::deserialize(&r7[0..2].to_vec(), &mut index, 4), Err(net_error::UnderflowError));
        assert_eq!(index, 0);
        
        assert_eq!(Vec::<u64>::deserialize(&r8[0..r8.len()-1].to_vec(), &mut index, (4 + v8.len() * 8) as u32), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        // index would overflow
        index = u32::max_value() - 3;
        assert_eq!(Vec::<u8>::deserialize(&r1, &mut index, 4), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - ((4 + v2.len() - 1) as u32);
        assert_eq!(Vec::<u8>::deserialize(&r2, &mut index, (4 + v2.len()) as u32), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - ((4 + v2.len() - 1) as u32));

        index = u32::max_value() - 3;
        assert_eq!(Vec::<u16>::deserialize(&r3, &mut index, 4), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - ((4 + v2.len()*2 - 1) as u32);
        assert_eq!(Vec::<u16>::deserialize(&r4, &mut index, (4 + v4.len() * 2) as u32), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - ((4 + v2.len()*2 - 1) as u32));

        index = u32::max_value() - 3;
        assert_eq!(Vec::<u32>::deserialize(&r5, &mut index, 4), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - ((4 + v2.len()*4 - 1) as u32);
        assert_eq!(Vec::<u32>::deserialize(&r6, &mut index, (4 + v6.len() * 4) as u32), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - ((4 + v2.len()*4 - 1) as u32));

        index = u32::max_value() - 3;
        assert_eq!(Vec::<u64>::deserialize(&r7, &mut index, 4), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - 3);
        
        index = u32::max_value() - ((4 + v2.len()*8 - 1) as u32);
        assert_eq!(Vec::<u64>::deserialize(&r8, &mut index, (4 + v8.len() * 8) as u32), Err(net_error::OverflowError));
        assert_eq!(index, u32::max_value() - ((4 + v2.len()*8 - 1) as u32));
    }

    #[test]
    fn codec_primitive_vector_corrupt() {
        let v : Vec<u32> = vec![0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10];
        let r : Vec<u8> = vec![0x00, 0x00, 0x00, 0x04,
                               0x01, 0x02, 0x03, 0x04,
                               0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c,
                               0x0d, 0x0e, 0x0f, 0x10];

        // decodes to [0x01020304, 0x05060708, 0x090a0b0c]
        let r_length_too_short : Vec<u8> = 
                          vec![0x00, 0x00, 0x00, 0x03,
                               0x01, 0x02, 0x03, 0x04,
                               0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c,
                               0x0d, 0x0e, 0x0f, 0x10];

        // does not decode -- not enough data follows
        let r_length_too_long : Vec<u8> = 
                          vec![0x00, 0x00, 0x00, 0x05,
                               0x01, 0x02, 0x03, 0x04,
                               0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c,
                               0x0d, 0x0e, 0x0f, 0x10];
        
        let r_bytes_not_aligned : Vec<u8> =
                          vec![0x00, 0x00, 0x00, 0x04,
                               0x01, 0x02, 0x03, 0x04,
                               0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c,
                               0x0d, 0x0e, 0x0f];

        // does not decode -- cannot possibly have enough data
        let r_huge_length : Vec<u8> = 
                          vec![0xff, 0xff, 0xff, 0xfe,
                               0x01, 0x02, 0x03, 0x04,
                               0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c,
                               0x0d, 0x0e, 0x0f, 0x10];

        // correct decode
        let mut index = 0;
        assert_eq!(Vec::<u32>::deserialize(&r, &mut index, 20).unwrap(), v);
        assert_eq!(index, 20);

        // correct decode, but underrun
        index = 0;
        assert_eq!(Vec::<u32>::deserialize(&r_length_too_short, &mut index, 20).unwrap(), vec![0x01020304, 0x05060708, 0x090a0b0c]);
        assert_eq!(index, 16);
        
        index = 0;

        // overflow -- tried to read past max_size
        assert_eq!(Vec::<u32>::deserialize(&r_length_too_long, &mut index, 20), Err(net_error::OverflowError));
        assert_eq!(index, 0);
        
        // underflow -- ran out of bytes to read
        assert_eq!(Vec::<u32>::deserialize(&r_length_too_long, &mut index, 24), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        // overflow -- tried to read past max size
        assert_eq!(Vec::<u32>::deserialize(&r_bytes_not_aligned, &mut index, 19), Err(net_error::OverflowError));
        assert_eq!(index, 0);
        
        // underflow -- ran out of bytes to read
        assert_eq!(Vec::<u32>::deserialize(&r_bytes_not_aligned, &mut index, 20), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        // overflow -- tried to read past max size
        assert_eq!(Vec::<u32>::deserialize(&r_huge_length, &mut index, 20), Err(net_error::OverflowError));
        assert_eq!(index, 0);
        
        // underflow -- ran out of bytes to read
        assert_eq!(Vec::<u32>::deserialize(&r_huge_length, &mut index, 0xffffffff), Err(net_error::UnderflowError));
        assert_eq!(index, 0);
    }

    fn check_codec_and_corruption<T : StacksMessageCodec + fmt::Debug + Clone + PartialEq>(obj: &T, bytes: &Vec<u8>) -> () {
        assert_eq!(obj.serialize(), *bytes);
        
        let mut index = 0;
        assert_eq!(T::deserialize(bytes, &mut index, bytes.len() as u32).unwrap(), *obj);
        assert_eq!(index, bytes.len() as u32);

        // corrupt 
        index = 0;
        let underflow_res = T::deserialize(&bytes[0..((bytes.len()-1) as usize)].to_vec(), &mut index, bytes.len() as u32);
        if underflow_res.is_ok() {
            test_debug!("\nMissing Underflow: Parsed {:?}\nFrom {:?}\nindex = {}; remaining = {:?}\n", &underflow_res.unwrap(), &bytes[0..((bytes.len()-1) as usize)].to_vec(), index, &bytes[index as usize..bytes.len()].to_vec());
        }
        
        index = 0;
        let underflow_cmp = T::deserialize(&bytes[0..((bytes.len()-1) as usize)].to_vec(), &mut index, bytes.len() as u32);
        assert_eq!(underflow_cmp, Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        let overflow_res = T::deserialize(bytes, &mut index, (bytes.len() - 1) as u32);
        if overflow_res.is_ok() {
            test_debug!("\nMissing Overflow: Parsed {:?}\nFrom {:?}\nindex = {}; max_size = {}; remaining = {:?}\n", &overflow_res.unwrap(), &bytes, index, bytes.len() - 1, &bytes[index as usize..bytes.len()].to_vec());
        }

        index = 0;
        let overflow_cmp = T::deserialize(bytes, &mut index, (bytes.len() - 1) as u32);
        assert_eq!(overflow_cmp, Err(net_error::OverflowError));
        assert_eq!(index, 0);
    }

    #[test]
    fn codec_Preamble() {
        let preamble = Preamble {
            peer_version: 0x01020304,
            network_id: 0x05060708,
            seq: 0x090a0b0c,
            burn_block_height: 0x00001122,
            burn_consensus_hash: ConsensusHash::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
            burn_stable_block_height: 0x00001111,
            burn_stable_consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            additional_data: DoubleSha256::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            signature: MessageSignature::from_bytes(&hex_bytes("4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444").unwrap()).unwrap(),
            payload_len: 0x000007ff,
        };
        let preamble_bytes : Vec<u8> = vec![
            // peer_version
            0x01, 0x02, 0x03, 0x04,
            // network_id
            0x05, 0x06, 0x07, 0x08,
            // seq
            0x09, 0x0a, 0x0b, 0x0c,
            // burn_block_height
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22,
            // burn_consensus_hash
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // stable_burn_block_height
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
            // stable_burn_consensus_hash
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            // additional_data
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            // signature
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            // payload_len
            0x00, 0x00, 0x07, 0xff
        ];

        assert_eq!(preamble.serialize(), preamble_bytes);
        assert_eq!(preamble_bytes.len() as u32, PREAMBLE_ENCODED_SIZE);

        let mut index = 0;
        assert_eq!(Preamble::deserialize(&preamble_bytes, &mut index, PREAMBLE_ENCODED_SIZE).unwrap(), preamble);
        assert_eq!(index, PREAMBLE_ENCODED_SIZE);

        // corrupt 
        index = 0;
        assert_eq!(Preamble::deserialize(&preamble_bytes[0..((PREAMBLE_ENCODED_SIZE-1) as usize)].to_vec(), &mut index, PREAMBLE_ENCODED_SIZE), Err(net_error::UnderflowError));
        assert_eq!(index, 0);

        assert_eq!(Preamble::deserialize(&preamble_bytes, &mut index, PREAMBLE_ENCODED_SIZE - 1), Err(net_error::OverflowError));
        assert_eq!(index, 0);
    }

    #[test]
    fn codec_GetBlocksData() {
        let getblocksdata = GetBlocksData {
            burn_height_start: 0x0001020304050607,
            burn_header_hash_start: BurnchainHeaderHash::from_bytes(&hex_bytes("5555555555555555555555555555555555555555555555555555555555555555").unwrap()).unwrap(),
            burn_height_end: 0x0001020304050607 + (BLOCKS_INV_DATA_MAX_BITLEN as u64),
            burn_header_hash_end: BurnchainHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap(),
        };

        let getblocksdata_bytes : Vec<u8> = vec![
            // burn_height_start
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            // burn_header_hash_start
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            // burn_height_end
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x16, 0x07,
            // burn_header_hash_end
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ];

        check_codec_and_corruption::<GetBlocksData>(&getblocksdata, &getblocksdata_bytes);

        // should fail to decode if the block range is too big 
        let getblocksdata_range_too_big = GetBlocksData {
            burn_height_start: 0x0001020304050607,
            burn_header_hash_start: BurnchainHeaderHash::from_bytes(&hex_bytes("5555555555555555555555555555555555555555555555555555555555555555").unwrap()).unwrap(),
            burn_height_end: 0x0001020304050607 + (BLOCKS_INV_DATA_MAX_BITLEN as u64) + 1,
            burn_header_hash_end: BurnchainHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap(),
        };

        let bytes = getblocksdata_range_too_big.serialize();

        let mut index = 0;
        assert_eq!(GetBlocksData::deserialize(&bytes, &mut index, bytes.len() as u32), Err(net_error::DeserializeError));
    }

    #[test]
    fn codec_MicroblocksInvData() {
        let mut maximal_microblock_hashes : Vec<BlockHeaderHash> = vec![];
        for i in 0..MICROBLOCKS_INV_DATA_MAX_HASHES {
            maximal_microblock_hashes.push(BlockHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap());
        }

        let mut too_big_microblock_hashes = maximal_microblock_hashes.clone();
        too_big_microblock_hashes.push(BlockHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap());

        let data = MicroblocksInvData {
            hashes: maximal_microblock_hashes.clone()
        };

        let mut bytes : Vec<u8> = vec![
            // microblock hashes length 
            0x00, 0x00, 0x10, 0x00,
        ];
        for h in &maximal_microblock_hashes {
            bytes.append(&mut h.as_bytes().to_vec().clone());
        }

        check_codec_and_corruption::<MicroblocksInvData>(&data, &bytes);

        // empty 
        let empty_data = MicroblocksInvData {
            hashes: vec![]
        };
        let empty_bytes : Vec<u8> = vec![
            // hashes len
            0x00, 0x00, 0x00, 0x00,
        ];

        check_codec_and_corruption::<MicroblocksInvData>(&empty_data, &empty_bytes);

        // one entry 
        let one_block = MicroblocksInvData {
            hashes: vec![
                BlockHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap()
            ]
        };
        let one_block_bytes : Vec<u8> = vec![
            // microblock hashes len 
            0x00, 0x00, 0x00, 0x01,
            // single hash
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
        ];

        check_codec_and_corruption::<MicroblocksInvData>(&one_block, &one_block_bytes);

        // should fail to decode if its too big 
        let too_big = MicroblocksInvData {
            hashes: too_big_microblock_hashes.clone()
        };
        let too_big_bytes = too_big.serialize();

        let mut index = 0;
        assert_eq!(MicroblocksInvData::deserialize(&too_big_bytes, &mut index, too_big_bytes.len() as u32), Err(net_error::DeserializeError));
        assert_eq!(index, 0);
    }

    #[test]
    fn codec_BlocksInvData() {
        // maximially big BlocksInvData
        let maximal_bitvec : Vec<u8> = vec![0xff, 0xff, 0xff, 0xfe];
        let mut too_big_bitvec : Vec<u8> = vec![];
        for i in 0..BLOCKS_INV_DATA_MAX_BITLEN+1 {
            too_big_bitvec.push(0xff);
        }

        let mut maximal_microblocks_inventory = vec![];
        let mut too_big_microblocks_inventory = vec![];

        // must get the message down to 32 MB
        for _i in 0..31 {
            let mut hashes = vec![];
            // for _j in 0..MICROBLOCKS_INV_DATA_MAX_HASHES {
            for _j in 0..1 {
                hashes.push(BlockHeaderHash::from_bytes(&hex_bytes("7777777777777777777777777777777777777777777777777777777777777777").unwrap()).unwrap());
            }
            let microblock_inv = MicroblocksInvData {
                hashes
            };
            maximal_microblocks_inventory.push(microblock_inv.clone());
            too_big_microblocks_inventory.push(microblock_inv);
        }

        too_big_microblocks_inventory.push(MicroblocksInvData {
            hashes: vec![]
        });

        let maximal_blocksinvdata = BlocksInvData {
            bitlen: 31,
            bitvec: maximal_bitvec.clone(),
            microblocks_inventory: maximal_microblocks_inventory.clone()
        };

        let maximal_microblocks_inventory_bytes = maximal_microblocks_inventory.serialize();
        let mut maximal_blocksinvdata_bytes : Vec<u8> = vec![];
        // bitlen 
        maximal_blocksinvdata_bytes.append(&mut vec![0x00, 0x1f]);
        // bitvec
        maximal_blocksinvdata_bytes.append(&mut vec![0x00, 0x00, 0x00, 0x04]);
        maximal_blocksinvdata_bytes.append(&mut maximal_bitvec.clone());
        // microblocks inventory 
        maximal_blocksinvdata_bytes.append(&mut maximal_microblocks_inventory_bytes.clone());

        assert!((maximal_blocksinvdata_bytes.len() as u32) < MAX_MESSAGE_LEN);

        check_codec_and_corruption::<BlocksInvData>(&maximal_blocksinvdata, &maximal_blocksinvdata_bytes);
        
        let mut index = 0;

        // should fail to decode if the bitlen is too big 
        let too_big_blocksinvdata = BlocksInvData {
            bitlen: (BLOCKS_INV_DATA_MAX_BITLEN + 1) as u16,
            bitvec: too_big_bitvec.clone(),
            microblocks_inventory: too_big_microblocks_inventory.clone(),
        };
        let too_big_blocksinvdata_bytes = too_big_blocksinvdata.serialize();

        assert_eq!(BlocksInvData::deserialize(&too_big_blocksinvdata_bytes, &mut index, too_big_blocksinvdata_bytes.len() as u32).unwrap_err(), net_error::DeserializeError);
        assert_eq!(index, 0);

        // should fail to decode if the bitlen doesn't match the bitvec
        let long_bitlen = BlocksInvData {
            bitlen: 1,
            bitvec: vec![0xff, 0x01],
            microblocks_inventory: vec![
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
            ]
        };
        let long_bitlen_bytes = long_bitlen.serialize();

        assert_eq!(BlocksInvData::deserialize(&long_bitlen_bytes, &mut index, long_bitlen_bytes.len() as u32), Err(net_error::DeserializeError));
        assert_eq!(index, 0);

        let short_bitlen = BlocksInvData {
            bitlen: 9,
            bitvec: vec![0xff],
            microblocks_inventory: vec![
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
                MicroblocksInvData {
                    hashes: vec![]
                },
            ]
        };
        let short_bitlen_bytes = short_bitlen.serialize();
        
        assert_eq!(BlocksInvData::deserialize(&short_bitlen_bytes, &mut index, short_bitlen_bytes.len() as u32), Err(net_error::DeserializeError));
        assert_eq!(index, 0);

        // should fail if microblocks inventory doesn't match bitlen 
        let wrong_microblocks_inv = BlocksInvData {
            bitlen: 2,
            bitvec: vec![0x03],
            microblocks_inventory: vec![
                MicroblocksInvData {
                    hashes: vec![]
                },
            ]
        };
        let wrong_microblocks_inv_bytes = wrong_microblocks_inv.serialize();

        assert_eq!(BlocksInvData::deserialize(&wrong_microblocks_inv_bytes, &mut index, wrong_microblocks_inv_bytes.len() as u32), Err(net_error::DeserializeError));
        assert_eq!(index, 0);

        // empty 
        let empty_inv = BlocksInvData {
            bitlen: 0,
            bitvec: vec![],
            microblocks_inventory: vec![]
        };
        let empty_inv_bytes = vec![
            // bitlen
            0x00, 0x00, 0x00, 0x00,
            // bitvec 
            0x00, 0x00, 0x00, 0x00,
            // microblock inv 
            0x00, 0x00, 0x00, 0x00
        ];

        check_codec_and_corruption::<BlocksInvData>(&maximal_blocksinvdata, &maximal_blocksinvdata_bytes);
    }

    #[test]
    fn codec_GetMicroblocksData() {
        let data = GetMicroblocksData {
            burn_header_height: 0x0001020304050607,
            burn_header_hash: BurnchainHeaderHash::from_bytes(&hex_bytes("8888888888888888888888888888888888888888888888888888888888888888").unwrap()).unwrap(),
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("9999999999999999999999999999999999999999999999999999999999999999").unwrap()).unwrap(),
            microblocks_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()).unwrap(),
        };
        let bytes = vec![
            // burn header height 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            // burn header hash
            0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
            // block header hash 
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            // microblocks header hash 
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
        ];

        check_codec_and_corruption::<GetMicroblocksData>(&data, &bytes);
    }

    #[test]
    fn codec_NeighborAddress() {
        let data = NeighborAddress {
            addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
            port: 12345,
            public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
        };
        let bytes = vec![
            // addrbytes 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            // port 
            0x30, 0x39,
            // public key hash 
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
        ];

        assert_eq!(bytes.len() as u32, NEIGHBOR_ADDRESS_ENCODED_SIZE);
        check_codec_and_corruption::<NeighborAddress>(&data, &bytes);
    }

    #[test]
    fn codec_NeighborsData() {
        let data = NeighborsData {
            neighbors: vec![
                NeighborAddress {
                    addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                    port: 12345,
                    public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
                },
                NeighborAddress {
                    addrbytes: PeerAddress([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]),
                    port: 23456,
                    public_key_hash: Hash160::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                },
            ]
        };
        let bytes = vec![
            // length 
            0x00, 0x00, 0x00, 0x02,
            // addrbytes 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            // port 
            0x30, 0x39,
            // public key hash 
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // addrbytes 
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            // port 
            0x5b, 0xa0,
            // public key hash 
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
        ];

        check_codec_and_corruption::<NeighborsData>(&data, &bytes);
    }

    #[test]
    fn codec_HandshakeData() {
        let data = HandshakeData {
            addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
            port: 12345,
            services: 0x0001,
            node_public_key: StacksPublicKeyBuffer::from_bytes(&hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb").unwrap()).unwrap(),
            expire_block_height: 0x0102030405060708
        };
        let bytes = vec![
            // addrbytes 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            // port 
            0x30, 0x39,
            // services 
            0x00, 0x01,
            // public key 
            0x03, 0x4e, 0x31, 0x6b, 0xe0, 0x48, 0x70, 0xce, 0xf1, 0x79, 0x5f, 0xba, 0x64, 0xd5, 0x81, 0xcf, 0x64, 0xba, 0xd0, 0xc8, 0x94, 0xb0, 0x1a, 0x06, 0x8f, 0xb9, 0xed, 0xf8, 0x53, 0x21, 0xdc, 0xd9, 0xbb,
            // expire block height 
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        ];

        check_codec_and_corruption::<HandshakeData>(&data, &bytes);
    }

    #[test]
    fn codec_HandshakeAcceptData() {
        let data = HandshakeAcceptData {
            heartbeat_interval: 0x01020304,
            node_public_key: StacksPublicKeyBuffer::from_bytes(&hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb").unwrap()).unwrap(),
        };
        let bytes = vec![
            // heartbeat 
            0x01, 0x02, 0x03, 0x04,
            // node public key 
            0x03, 0x4e, 0x31, 0x6b, 0xe0, 0x48, 0x70, 0xce, 0xf1, 0x79, 0x5f, 0xba, 0x64, 0xd5, 0x81, 0xcf, 0x64, 0xba, 0xd0, 0xc8, 0x94, 0xb0, 0x1a, 0x06, 0x8f, 0xb9, 0xed, 0xf8, 0x53, 0x21, 0xdc, 0xd9, 0xbb,
        ];

        check_codec_and_corruption::<HandshakeAcceptData>(&data, &bytes);
    }

    #[test]
    fn codec_NackData() {
        let data = NackData {
            error_code: 0x01020304,
        };
        let bytes = vec![
            // error code 
            0x01, 0x02, 0x03, 0x04
        ];

        check_codec_and_corruption::<NackData>(&data, &bytes);
    }

    #[test]
    fn codec_RelayData() {
        let data = RelayData {
            peer: NeighborAddress {
                addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                port: 12345,
                public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
            },
            seq: 0x01020304,
            signature: MessageSignature::from_bytes(&hex_bytes("4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444").unwrap()).unwrap(),
        };
        let bytes = vec![
            // peer.addrbytes
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            // peer.port
            0x30, 0x39,
            // peer.public_key_hash
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // seq
            0x01, 0x02, 0x03, 0x04,
            // signature
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        ];

        check_codec_and_corruption::<RelayData>(&data, &bytes);
    }

    #[test]
    fn codec_StacksMessage() {
        let payloads: Vec<StacksMessageType> = vec![
            StacksMessageType::Handshake(HandshakeData {
                addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                port: 12345,
                services: 0x0001,
                node_public_key: StacksPublicKeyBuffer::from_bytes(&hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb").unwrap()).unwrap(),
                expire_block_height: 0x0102030405060708
            }),
            StacksMessageType::HandshakeAccept(HandshakeAcceptData {
                heartbeat_interval: 0x01020304,
                node_public_key: StacksPublicKeyBuffer::from_bytes(&hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb").unwrap()).unwrap(),
            }),
            StacksMessageType::HandshakeReject,
            StacksMessageType::GetNeighbors,
            StacksMessageType::Neighbors(NeighborsData {
                neighbors: vec![
                    NeighborAddress {
                        addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                        port: 12345,
                        public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
                    },
                    NeighborAddress {
                        addrbytes: PeerAddress([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]),
                        port: 23456,
                        public_key_hash: Hash160::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                    },
                ]
            }),
            StacksMessageType::GetBlocksInv(GetBlocksData {
                burn_height_start: 0x0001020304050607,
                burn_header_hash_start: BurnchainHeaderHash::from_bytes(&hex_bytes("5555555555555555555555555555555555555555555555555555555555555555").unwrap()).unwrap(),
                burn_height_end: 0x0001020304050607 + (BLOCKS_INV_DATA_MAX_BITLEN as u64),
                burn_header_hash_end: BurnchainHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap(),
            }),
            StacksMessageType::BlocksInv(BlocksInvData {
                bitlen: 2,
                bitvec: vec![0x03],
                microblocks_inventory: vec![
                    MicroblocksInvData {
                        hashes: vec![]
                    },
                    MicroblocksInvData {
                        hashes: vec![]
                    },
                ]
            }),
            StacksMessageType::GetBlocks(GetBlocksData {
                burn_height_start: 0x0001020304050607,
                burn_header_hash_start: BurnchainHeaderHash::from_bytes(&hex_bytes("5555555555555555555555555555555555555555555555555555555555555555").unwrap()).unwrap(),
                burn_height_end: 0x0001020304050607 + (BLOCKS_INV_DATA_MAX_BITLEN as u64),
                burn_header_hash_end: BurnchainHeaderHash::from_bytes(&hex_bytes("6666666666666666666666666666666666666666666666666666666666666666").unwrap()).unwrap(),
            }),
            // TODO: Blocks
            StacksMessageType::GetMicroblocks(GetMicroblocksData {
                burn_header_height: 0x0001020304050607,
                burn_header_hash: BurnchainHeaderHash::from_bytes(&hex_bytes("8888888888888888888888888888888888888888888888888888888888888888").unwrap()).unwrap(),
                block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("9999999999999999999999999999999999999999999999999999999999999999").unwrap()).unwrap(),
                microblocks_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()).unwrap(),
            }),
            // TODO: Microblocks
            // TODO: Transaction
            StacksMessageType::Nack(NackData {
                error_code: 0x01020304
            }),
            StacksMessageType::Ping
        ];

        let mut maximal_relayers : Vec<RelayData> = vec![];
        let mut too_many_relayers : Vec<RelayData> = vec![];
        for i in 0..MAX_RELAYERS_LEN {
            let next_relayer = RelayData {
                peer: NeighborAddress {
                    addrbytes: PeerAddress([i as u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                    port: 12345 + (i as u16),
                    public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
                },
                seq: 0x01020304 + i,
                signature: MessageSignature::from_bytes(&hex_bytes("4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444").unwrap()).unwrap(),
            };
            too_many_relayers.push(next_relayer.clone());
            maximal_relayers.push(next_relayer);
        }
        too_many_relayers.push(RelayData {
            peer: NeighborAddress {
                addrbytes: PeerAddress([0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                port: 65535,
                public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
            },
            seq: 0x010203ff,
            signature: MessageSignature::from_bytes(&hex_bytes("4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444").unwrap()).unwrap(),
        });

        let relayers_bytes = maximal_relayers.serialize();
        let too_many_relayer_bytes = too_many_relayers.serialize();

        for payload in &payloads {
            // just testing codec; don't worry about signatures
            // (only payload_len must be valid)
            let payload_bytes = message_serialize(&payload);

            let preamble = Preamble {
                peer_version: 0x01020304,
                network_id: 0x05060708,
                seq: 0x090a0b0c,
                burn_block_height: 0x00001122,
                burn_consensus_hash: ConsensusHash::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
                burn_stable_block_height: 0x00001111,
                burn_stable_consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                additional_data: DoubleSha256::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                signature: MessageSignature::from_bytes(&hex_bytes("4444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444").unwrap()).unwrap(),
                payload_len: (relayers_bytes.len() + payload_bytes.len() + 1) as u32,
            };

            let stacks_message = StacksMessage {
                preamble: preamble.clone(),
                relayers: maximal_relayers.clone(),
                payload: payload.clone()
            };

            let mut stacks_message_bytes : Vec<u8> = vec![];
            stacks_message_bytes.append(&mut preamble.serialize());
            stacks_message_bytes.append(&mut relayers_bytes.clone());
            stacks_message_bytes.append(&mut vec![message_type_to_id(&payload)]);
            stacks_message_bytes.append(&mut payload_bytes.clone());

            test_debug!("Test {:?}", &payload);
            check_codec_and_corruption::<StacksMessage>(&stacks_message, &stacks_message_bytes);

            let mut index = 0;

            // preamble length must be consistent with relayers and payload
            let mut preamble_short_len = preamble.clone();
            preamble_short_len.payload_len -= 1;

            let stacks_message_short_len = StacksMessage {
                preamble: preamble_short_len.clone(),
                relayers: maximal_relayers.clone(),
                payload: payload.clone()
            };
            let stacks_message_short_len_bytes = stacks_message_short_len.serialize();

            // expect overflow error, since index will exceed the expected maximum size
            assert_eq!(StacksMessage::deserialize(&stacks_message_short_len_bytes, &mut index, stacks_message_short_len_bytes.len() as u32).unwrap_err(), net_error::OverflowError);
            assert_eq!(index, 0);

            // can't have too many relayers 
            let mut preamble_too_many_relayers = preamble.clone();
            preamble_too_many_relayers.payload_len = (too_many_relayer_bytes.len() + payload_bytes.len() + 1) as u32;

            let stacks_message_too_many_relayers = StacksMessage {
                preamble: preamble_too_many_relayers.clone(),
                relayers: too_many_relayers.clone(),
                payload: payload.clone()
            };
            let stacks_message_too_many_relayers_bytes = stacks_message_too_many_relayers.serialize();

            assert_eq!(StacksMessage::deserialize(&stacks_message_too_many_relayers_bytes, &mut index, stacks_message_too_many_relayers_bytes.len() as u32).unwrap_err(), net_error::DeserializeError);
            assert_eq!(index, 0);
        }
    }
} 
