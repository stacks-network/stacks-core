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

use std::io;
use std::io::prelude::*;
use std::io::Read;

use burnchains::BurnchainHeaderHash;
use burnchains::PrivateKey;
use burnchains::PublicKey;
use burnchains::BurnchainView;

use chainstate::burn::ConsensusHash;
use chainstate::burn::BlockHeaderHash;

use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksMicroblock;
use chainstate::stacks::StacksTransaction;

use util::hash::DoubleSha256;
use util::hash::Hash160;
use util::hash::MerkleHashFunc;
use util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey};

use net::*;
use net::Error as net_error;
use net::db::LocalPeer;

use core::PEER_VERSION;

use sha2::Sha512Trunc256;
use sha2::Digest;

use util::secp256k1::MessageSignature;
use util::secp256k1::MESSAGE_SIGNATURE_ENCODED_SIZE;

use util::log;

use rand;
use rand::Rng;

// macro for determining how big an inv bitvec can be, given its bitlen 
macro_rules! BITVEC_LEN {
    ($bitvec:expr) => ((($bitvec) / 8 + if ($bitvec) % 8 > 0 { 1 } else { 0 }) as u32)
}

// serialize helper 
pub fn write_next<T: StacksMessageCodec>(buf: &mut Vec<u8>, item: &T) {
    let mut item_buf = item.consensus_serialize();
    buf.append(&mut item_buf);
}

// deserialize helper 
pub fn read_next<T: StacksMessageCodec>(buf: &[u8], index: &mut u32, max_size: u32) -> Result<T, net_error> {
    let item: T = T::consensus_deserialize(buf, index, max_size)?;
    Ok(item)
}

// deserialize helper for bound-sized vectors
// Parse `max_items` or `num_items` items of an array, up to `max_size_bytes` consumed.
// Parse exactly `num_items` if max_items = 0.  Otherwise, ignore num_items
fn read_next_vec<T: StacksMessageCodec + Sized>(buf: &[u8], index_ptr: &mut u32, max_size_bytes: u32, num_items: u32, max_items: u32) -> Result<Vec<T>, net_error> {
    let index = *index_ptr;
    if index > u32::max_value() - 4 {
        return Err(net_error::OverflowError(format!("Would overflow u32 when parsing array length (index {})", index)));
    }
    if index + 4 > max_size_bytes {
        return Err(net_error::OverflowError(format!("Would read beyond end of buffer when parsing array length (index {}, len {})", index, buf.len())));
    }
    if (buf.len() as u32) < index + 4 {
        return Err(net_error::UnderflowError(format!("Not enough bytes to read array length (index {}, len {})", index, buf.len())));
    }

    let mut len_index : u32 = 0;
    let mut vec_index : u32 = 0;

    let len_buf = buf[(index as usize)..((index+4) as usize)].to_vec();
    let len = u32::consensus_deserialize(&len_buf, &mut len_index, 4)?;

    if max_items > 0 {
        if len > max_items {
            // too many items
            return Err(net_error::DeserializeError(format!("Array has too many items ({} > {}", len, max_items)));
        }
    }
    else {
        if len != num_items {
            // inexact item count
            return Err(net_error::DeserializeError(format!("Array has incorrect number of items ({} != {})", len, num_items)));
        }
    }
    
    vec_index = index + len_index;

    let mut ret = vec![];
    for _i in 0..len {
        let next_item = T::consensus_deserialize(buf, &mut vec_index, max_size_bytes)?;
        ret.push(next_item);
    }

    *index_ptr = vec_index;
    Ok(ret)
}

pub fn read_next_at_most<T: StacksMessageCodec + Sized>(buf: &[u8], index_ptr: &mut u32, max_size_bytes: u32, max_items: u32) -> Result<Vec<T>, net_error> {
    read_next_vec::<T>(buf, index_ptr, max_size_bytes, 0, max_items)
}

pub fn read_next_exact<T: StacksMessageCodec + Sized>(buf: &[u8], index_ptr: &mut u32, max_size_bytes: u32, num_items: u32) -> Result<Vec<T>, net_error> {
    read_next_vec::<T>(buf, index_ptr, max_size_bytes, num_items, 0)
}

impl StacksMessageCodec for u8 {
    fn consensus_serialize(&self) -> Vec<u8> {
        vec![*self]
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<u8, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 1 {
            return Err(net_error::OverflowError("Would overflow u32 to read 1 byte".to_string()));
        }
        if index + 1 > max_size {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read 1 byte".to_string()));
        }
        if (buf.len() as u32) < index + 1 {
            return Err(net_error::UnderflowError("Not enough bytes remaining to read 1 byte".to_string()));
        }

        let next = buf[index as usize];

        *index_ptr += 1;
        
        Ok(next)
    }
}

impl StacksMessageCodec for u16 {
    fn consensus_serialize(&self) -> Vec<u8> {
        // big-endian 
        self.to_be_bytes().to_vec()
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<u16, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 2 {
            return Err(net_error::OverflowError("Would overflow u32 to read 2 bytes".to_string()));
        }
        if index + 2 > max_size {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read 2 bytes".to_string()));
        }
        if (buf.len() as u32) < index + 2 {
            return Err(net_error::UnderflowError("Not enough bytes remaining to read 2 bytes".to_string()));
        }

        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&buf[(index as usize)..((index + 2) as usize)]);

        let ret = u16::from_be_bytes(bytes);
        *index_ptr += 2;

        Ok(ret)
    }
}

impl StacksMessageCodec for u32 {
    fn consensus_serialize(&self) -> Vec<u8> {
        // big-endian 
        self.to_be_bytes().to_vec()
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<u32, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 4 {
            return Err(net_error::OverflowError("Would overflow u32 to read 4 bytes".to_string()));
        }
        if index + 4 > max_size {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read 4 bytes".to_string()));
        }
        if (buf.len() as u32) < index + 4 {
            return Err(net_error::UnderflowError("Not enough bytes remaining to read 4 bytes".to_string()));
        }
        
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&buf[(index as usize)..((index + 4) as usize)]);
       
        let ret = u32::from_be_bytes(bytes);
        *index_ptr += 4;

        Ok(ret)
    }
}

impl StacksMessageCodec for u64 {
    fn consensus_serialize(&self) -> Vec<u8> {
        // big-endian
        self.to_be_bytes().to_vec()
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<u64, net_error> {
        let index = *index_ptr;
        if index > u32::max_value() - 8 {
            return Err(net_error::OverflowError("Would overflow u32 to read 8 bytes".to_string()));
        }
        if index + 8 > max_size {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read 8 bytes".to_string()));
        }
        if (buf.len() as u32) < index + 8 {
            return Err(net_error::UnderflowError("Not enough bytes remaining to read 8 bytes".to_string()));
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&buf[(index as usize)..((index + 8) as usize)]);
       
        let ret = u64::from_be_bytes(bytes);
        *index_ptr += 8;

        Ok(ret)
    }
}

impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes_compressed();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }
    
    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, net_error> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| net_error::DeserializeError("Failed to decode Stacks public key".to_string()))
    }
}

impl<T> StacksMessageCodec for Vec<T>
where
    T: StacksMessageCodec + Sized
{
    fn consensus_serialize(&self) -> Vec<u8> {
        if self.len() >= ARRAY_MAX_LEN as usize {
            // over 4.1 billion entries -- this is not okay
            panic!("FATAL ERROR array too long");
        }
        
        let mut ret = vec![];
        let mut size_buf = (self.len() as u32).consensus_serialize();
        ret.append(&mut size_buf);

        for i in 0..self.len() {
            let mut byte_list = self[i].consensus_serialize();
            ret.append(&mut byte_list);
        }
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<Vec<T>, net_error> {
        read_next_at_most::<T>(buf, index_ptr, max_size, u32::max_value())
    }
}

impl Preamble {
    /// Make an empty preamble with the given version and fork-set identifier, and payload length.
    pub fn new(peer_version: u32, network_id: u32, block_height: u64, consensus_hash: &ConsensusHash, stable_block_height: u64, stable_consensus_hash: &ConsensusHash, payload_len: u32) -> Preamble {
        Preamble {
            peer_version: peer_version,
            network_id: network_id,
            seq: 0,
            burn_block_height: block_height,
            burn_consensus_hash: consensus_hash.clone(),
            burn_stable_block_height: stable_block_height,
            burn_stable_consensus_hash: stable_consensus_hash.clone(),
            additional_data: 0,
            signature: MessageSignature::empty(),
            payload_len: payload_len,
        }
    }

    /// Given the serialized message type and bits, sign the resulting message and store the
    /// signature.  message_bits includes the relayers, payload type, and payload.
    pub fn sign(&mut self, message_bits: &[u8], privkey: &Secp256k1PrivateKey) -> Result<(), net_error> {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512Trunc256::new();

        // serialize the premable with a blank signature
        let old_signature = self.signature.clone();
        self.signature = MessageSignature::empty();
        let preamble_bits = self.consensus_serialize();
        self.signature = old_signature;

        sha2.input(&preamble_bits[..]);
        sha2.input(message_bits);
        
        digest_bits.copy_from_slice(sha2.result().as_slice());

        let sig = privkey.sign(&digest_bits)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.signature = sig;
        Ok(())
    }

    /// Given the serialized message type and bits, verify the signature.
    /// message_bits includes the relayers, payload type, and payload
    pub fn verify(&mut self, message_bits: &[u8], pubkey: &Secp256k1PublicKey) -> Result<(), net_error> {
        let mut digest_bits = [0u8; 32];
        let mut sha2 = Sha512Trunc256::new();

        // serialize the preamble with a blank signature 
        let sig_bits = self.signature.clone();
        self.signature = MessageSignature::empty();
        let preamble_bits = self.consensus_serialize();
        self.signature = sig_bits;

        sha2.input(&preamble_bits[..]);
        sha2.input(message_bits);

        digest_bits.copy_from_slice(sha2.result().as_slice());
        
        let res = pubkey.verify(&digest_bits, &self.signature)
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
    fn consensus_serialize(&self) -> Vec<u8> {
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
    
    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<Preamble, net_error> {
        let mut index = *index_ptr;
        let peer_version: u32                           = read_next(buf, &mut index, max_size)?;
        let network_id: u32                             = read_next(buf, &mut index, max_size)?;
        let seq: u32                                    = read_next(buf, &mut index, max_size)?;
        let burn_block_height: u64                      = read_next(buf, &mut index, max_size)?;
        let burn_consensus_hash : ConsensusHash         = read_next(buf, &mut index, max_size)?;
        let burn_stable_block_height: u64               = read_next(buf, &mut index, max_size)?;
        let burn_stable_consensus_hash : ConsensusHash  = read_next(buf, &mut index, max_size)?;
        let additional_data : u32                       = read_next(buf, &mut index, max_size)?;
        let signature : MessageSignature                = read_next(buf, &mut index, max_size)?;
        let payload_len : u32                           = read_next(buf, &mut index, max_size)?;

        // test_debug!("preamble {}-{:?}/{}-{:?}, {} bytes", burn_block_height, burn_consensus_hash, burn_stable_block_height, burn_stable_consensus_hash, payload_len);

        // minimum is 5 bytes -- a zero-length vector (4 bytes of 0) plus a type identifier (1 byte)
        if payload_len < 5 {
            test_debug!("Payload len is too small: {}", payload_len);
            return Err(net_error::DeserializeError(format!("Payload len is too small: {}", payload_len)));
        }

        if payload_len >= MAX_MESSAGE_LEN {
            test_debug!("Payload len is too big: {}", payload_len);
            return Err(net_error::DeserializeError(format!("Payload len is too big: {}", payload_len)));
        }

        if burn_block_height <= burn_stable_block_height {
            test_debug!("burn block height {} <= burn stable block height {}", burn_block_height, burn_stable_block_height);
            return Err(net_error::DeserializeError(format!("Burn block height {} <= burn stable block height {}", burn_block_height, burn_stable_block_height)));
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
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.burn_height_start);
        write_next(&mut ret, &self.burn_header_hash_start);
        write_next(&mut ret, &self.burn_height_end);
        write_next(&mut ret, &self.burn_header_hash_end);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<GetBlocksData, net_error> {
        let mut index = *index_ptr;
        let burn_height_start : u64                         = read_next(buf, &mut index, max_size)?;
        let burn_header_hash_start : BurnchainHeaderHash    = read_next(buf, &mut index, max_size)?;
        let burn_height_end : u64                           = read_next(buf, &mut index, max_size)?;
        let burn_header_hash_end : BurnchainHeaderHash      = read_next(buf, &mut index, max_size)?;

        if burn_height_end - burn_height_start > BLOCKS_INV_DATA_MAX_BITLEN as u64 {
            // requested too long of a range 
            return Err(net_error::DeserializeError(format!("Block diff is too big for inv ({} - {})", burn_height_start, burn_height_end)));
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
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.last_microblock_hash);
        write_next(&mut ret, &self.last_sequence);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<MicroblocksInvData, net_error> {
        let mut index = *index_ptr;

        let last_microblock_hash : BlockHeaderHash = read_next(buf, &mut index, max_size)?;
        let last_sequence : u16 = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(MicroblocksInvData {
            last_microblock_hash,
            last_sequence
        })
    }
}

impl StacksMessageCodec for BlocksInvData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.bitlen);
        write_next(&mut ret, &self.bitvec);
        write_next(&mut ret, &self.microblocks_inventory);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<BlocksInvData, net_error> {
        let mut index = *index_ptr;

        let bitlen : u16                                     = read_next(buf, &mut index, max_size)?;
        if bitlen > BLOCKS_INV_DATA_MAX_BITLEN as u16 {
            return Err(net_error::DeserializeError(format!("bitlen is bigger than max bitlen inv ({})", bitlen)));
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
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.blocks);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<BlocksData, net_error> {
        let mut index = *index_ptr;
        
        let blocks : Vec<StacksBlock> = read_next(buf, &mut index, max_size)?;
        
        *index_ptr = index;

        Ok(BlocksData {
            blocks
        })
    }
}

impl StacksMessageCodec for GetMicroblocksData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.burn_header_height);
        write_next(&mut ret, &self.burn_header_hash);
        write_next(&mut ret, &self.block_header_hash);
        write_next(&mut ret, &self.microblocks_header_hash);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<GetMicroblocksData, net_error> {
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
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.microblocks);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<MicroblocksData, net_error> {
        let mut index = *index_ptr;

        let microblocks : Vec<StacksMicroblock> = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(MicroblocksData {
            microblocks
        })
    }
}

impl NeighborAddress {
    pub fn from_neighbor(n: &Neighbor) -> NeighborAddress {
        NeighborAddress {
            addrbytes: n.addr.addrbytes.clone(),
            port: n.addr.port,
            public_key_hash: Hash160::from_data(&n.public_key.to_bytes_compressed()[..])
        }
    }
}

impl StacksMessageCodec for NeighborAddress {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.addrbytes);
        write_next(&mut ret, &self.port);
        write_next(&mut ret, &self.public_key_hash);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<NeighborAddress, net_error> {
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
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.neighbors);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<NeighborsData, net_error> {
        // don't allow list of more than the pre-set number of neighbors
        let mut index = *index_ptr;
        
        let neighbors : Vec<NeighborAddress> = read_next_at_most::<NeighborAddress>(buf, &mut index, max_size, MAX_NEIGHBORS_DATA_LEN)?;

        *index_ptr = index;

        Ok(NeighborsData {
            neighbors
        })
    }
}

impl HandshakeData {
    pub fn from_local_peer(local_peer: &LocalPeer) -> HandshakeData {
        HandshakeData {
            addrbytes: local_peer.addrbytes.clone(),
            port: local_peer.port,
            services: local_peer.services,
            node_public_key: StacksPublicKeyBuffer::from_public_key(&Secp256k1PublicKey::from_private(&local_peer.private_key)),
            expire_block_height: local_peer.private_key_expire
        }
    }
}

impl StacksMessageCodec for HandshakeData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.addrbytes);
        write_next(&mut ret, &self.port);
        write_next(&mut ret, &self.services);
        write_next(&mut ret, &self.node_public_key);
        write_next(&mut ret, &self.expire_block_height);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<HandshakeData, net_error> {
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

impl HandshakeAcceptData {
    pub fn new(local_peer: &LocalPeer, heartbeat_interval: u32) -> HandshakeAcceptData {
        HandshakeAcceptData {
            handshake: HandshakeData::from_local_peer(local_peer),
            heartbeat_interval: heartbeat_interval
        }
    }
}

impl StacksMessageCodec for HandshakeAcceptData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.handshake);
        write_next(&mut ret, &self.heartbeat_interval);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<HandshakeAcceptData, net_error> {
        let mut index = *index_ptr;

        let handshake : HandshakeData               = read_next(buf, &mut index, max_size)?;
        let heartbeat_interval : u32                = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(HandshakeAcceptData {
            handshake,
            heartbeat_interval,
        })
    }
}

impl NackData {
    pub fn new(error_code: u32) -> NackData {
        NackData {
            error_code
        }
    }
}

impl StacksMessageCodec for NackData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.error_code);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<NackData, net_error> {
        let mut index = *index_ptr;
        let error_code : u32 = read_next(buf, &mut index, max_size)?;
        *index_ptr = index;

        Ok(NackData {
            error_code
        })
    }
}

impl PingData {
    pub fn new() -> PingData {
        let mut rng = rand::thread_rng();
        let n = rng.gen();
        PingData {
            nonce: n
        }
    }
}

impl StacksMessageCodec for PingData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.nonce);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<PingData, net_error> {
        let mut index = *index_ptr;
        let nonce : u32 = read_next(buf, &mut index, max_size)?;
        *index_ptr = index;

        Ok(PingData {
            nonce
        })
    }
}

impl PongData {
    pub fn from_ping(p: &PingData) -> PongData {
        PongData {
            nonce: p.nonce
        }
    }
}

impl StacksMessageCodec for PongData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.nonce);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<PongData, net_error> {
        let mut index = *index_ptr;
        let nonce: u32 = read_next(buf, &mut index, max_size)?;
        *index_ptr = index;

        Ok(PongData {
            nonce
        })
    }
}

impl StacksMessageCodec for RelayData {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.peer);
        write_next(&mut ret, &self.seq);
        write_next(&mut ret, &self.signature);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<RelayData, net_error> {
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

impl StacksMessageType {
    pub fn get_message_id(&self) -> u8 {
        let msgtype = match *self {
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
            StacksMessageType::Ping(ref _m) => StacksMessageID::Ping,
            StacksMessageType::Pong(ref _m) => StacksMessageID::Pong
        };
        msgtype as u8
    }

    pub fn get_message_name(&self) -> &'static str {
        match *self {
            StacksMessageType::Handshake(ref _m) => "Handshake",
            StacksMessageType::HandshakeAccept(ref _m) => "HandshakeAccept",
            StacksMessageType::HandshakeReject => "HandshakeReject",
            StacksMessageType::GetNeighbors => "GetNeighbors",
            StacksMessageType::Neighbors(ref _m) => "Neighbors",
            StacksMessageType::GetBlocksInv(ref _m) => "GetBlocksInv",
            StacksMessageType::BlocksInv(ref _m) => "BlocksInv",
            StacksMessageType::GetBlocks(ref _m) => "GetBlocks",
            StacksMessageType::Blocks(ref _m) => "Blocks",
            StacksMessageType::GetMicroblocks(ref _m) => "GetMicroblocks",
            StacksMessageType::Microblocks(ref _m) => "Microblocks",
            StacksMessageType::Transaction(ref _m) => "Transaction",
            StacksMessageType::Nack(ref _m) => "Nack",
            StacksMessageType::Ping(ref _m) => "Ping",
            StacksMessageType::Pong(ref _m) => "Pong"
        }
    }
}

impl StacksMessageCodec for StacksMessageType {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &(self.get_message_id() as u8));
        let mut body = match *self {
            StacksMessageType::Handshake(ref m) => m.consensus_serialize(),
            StacksMessageType::HandshakeAccept(ref m) => m.consensus_serialize(),
            StacksMessageType::HandshakeReject => vec![],
            StacksMessageType::GetNeighbors => vec![],
            StacksMessageType::Neighbors(ref m) => m.consensus_serialize(),
            StacksMessageType::GetBlocksInv(ref m) => m.consensus_serialize(),
            StacksMessageType::BlocksInv(ref m) => m.consensus_serialize(),
            StacksMessageType::GetBlocks(ref m) => m.consensus_serialize(),
            StacksMessageType::Blocks(ref m) => m.consensus_serialize(),
            StacksMessageType::GetMicroblocks(ref m) => m.consensus_serialize(),
            StacksMessageType::Microblocks(ref m) => m.consensus_serialize(),
            StacksMessageType::Transaction(ref m) => m.consensus_serialize(),
            StacksMessageType::Nack(ref m) => m.consensus_serialize(),
            StacksMessageType::Ping(ref m) => m.consensus_serialize(),
            StacksMessageType::Pong(ref m) => m.consensus_serialize()
        };
        ret.append(&mut body);
        ret
    }

    fn consensus_deserialize(bits: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<StacksMessageType, net_error> {
        let mut index = *index_ptr;
        let message_id : u8 = read_next(bits, &mut index, max_size)?;
        let message = match message_id {
            x if x == StacksMessageID::Handshake as u8 => { let m = HandshakeData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Handshake(m) },
            x if x == StacksMessageID::HandshakeAccept as u8 => { let m = HandshakeAcceptData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::HandshakeAccept(m) },
            x if x == StacksMessageID::HandshakeReject as u8 => { StacksMessageType::HandshakeReject },
            x if x == StacksMessageID::GetNeighbors as u8 => { StacksMessageType::GetNeighbors },
            x if x == StacksMessageID::Neighbors as u8 => { let m = NeighborsData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Neighbors(m) },
            x if x == StacksMessageID::GetBlocksInv as u8 => { let m = GetBlocksData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::GetBlocksInv(m) },
            x if x == StacksMessageID::BlocksInv as u8 => { let m = BlocksInvData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::BlocksInv(m) },
            x if x == StacksMessageID::GetBlocks as u8 => { let m = GetBlocksData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::GetBlocks(m) },
            x if x == StacksMessageID::Blocks as u8 => { let m = BlocksData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Blocks(m) },
            x if x == StacksMessageID::GetMicroblocks as u8 => { let m = GetMicroblocksData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::GetMicroblocks(m) },
            x if x == StacksMessageID::Microblocks as u8 => { let m = MicroblocksData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Microblocks(m) },
            x if x == StacksMessageID::Transaction as u8 => { let m = StacksTransaction::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Transaction(m) },
            x if x == StacksMessageID::Nack as u8 => { let m = NackData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Nack(m) },
            x if x == StacksMessageID::Ping as u8 => { let m = PingData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Ping(m) },
            x if x == StacksMessageID::Pong as u8 => { let m = PongData::consensus_deserialize(bits, &mut index, max_size)?; StacksMessageType::Pong(m) },
            _ => { return Err(net_error::DeserializeError("Unrecognized message ID".to_string())); }
        };
        *index_ptr = index;
        Ok(message)
    }
}

impl StacksMessageCodec for StacksMessage {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.preamble);
        write_next(&mut ret, &self.relayers);
        write_next(&mut ret, &self.payload);
        ret
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<StacksMessage, net_error> {
        let mut index = *index_ptr;
        let preamble: Preamble = read_next(buf, &mut index, max_size)?;
        if preamble.payload_len > MAX_MESSAGE_LEN - PREAMBLE_ENCODED_SIZE {
            return Err(net_error::DeserializeError("Message would be too big".to_string()));
        }

        let max_payload_size = if index + preamble.payload_len < max_size { index + preamble.payload_len } else { max_size };
        let relayers: Vec<RelayData> = read_next_at_most::<RelayData>(buf, &mut index, max_payload_size, MAX_RELAYERS_LEN)?;
        let payload : StacksMessageType = read_next(buf, &mut index, max_payload_size)?;

        let message = StacksMessage {
            preamble,
            relayers,
            payload
        };

        *index_ptr = index;
        Ok(message)
    }
}

impl StacksMessage {
    /// Create an unsigned Stacks p2p message
    pub fn new(peer_version: u32, network_id: u32, block_height: u64, consensus_hash: &ConsensusHash, stable_block_height: u64, stable_consensus_hash: &ConsensusHash, message: StacksMessageType) -> StacksMessage {
        let preamble = Preamble::new(peer_version, network_id, block_height, consensus_hash, stable_block_height, stable_consensus_hash, 0);
        StacksMessage {
            preamble: preamble, 
            relayers: vec![],
            payload: message
        }
    }

    /// Create an unsigned Stacks message
    pub fn from_chain_view(peer_version: u32, network_id: u32, chain_view: &BurnchainView, message: StacksMessageType) -> StacksMessage {
        StacksMessage::new(peer_version, network_id, chain_view.burn_block_height, &chain_view.burn_consensus_hash, chain_view.burn_stable_block_height, &chain_view.burn_stable_consensus_hash, message)
    }

    /// represent as neighbor key 
    pub fn to_neighbor_key(&self, addrbytes: &PeerAddress, port: u16) -> NeighborKey {
        NeighborKey {
            peer_version: self.preamble.peer_version,
            network_id: self.preamble.network_id,
            addrbytes: addrbytes.clone(),
            port: port
        }
    }

    /// Sign the stacks message
    fn do_sign(&mut self, private_key: &Secp256k1PrivateKey) -> Result<(), net_error> {
        let mut message_bits = vec![];
        message_bits.append(&mut self.relayers.consensus_serialize());
        message_bits.append(&mut self.payload.consensus_serialize());

        self.preamble.payload_len = message_bits.len() as u32;
        self.preamble.sign(&message_bits[..], private_key)
    }

    /// Sign the StacksMessage.  The StacksMessage must _not_ have any relayers (i.e. we're
    /// originating this messsage).
    pub fn sign(&mut self, seq: u32, private_key: &Secp256k1PrivateKey) -> Result<(), net_error> {
        if self.relayers.len() > 0 {
            return Err(net_error::InvalidMessage);
        }
        self.preamble.seq = seq;
        self.do_sign(private_key)
    }

    /// Sign the StacksMessage and add ourselves as a relayer.
    /// Fails if the relayers vector would be too long 
    pub fn sign_relay(&mut self, private_key: &Secp256k1PrivateKey, our_seq: u32, our_addr: &NeighborAddress) -> Result<(), net_error> {
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

    pub fn deserialize_body(buf: &[u8], index_ptr: &mut u32, payload_len: u32, max_size: u32) -> Result<(Vec<RelayData>, StacksMessageType), net_error> {
        let mut index = *index_ptr;

        // don't numeric overflow
        if index > u32::max_value() - payload_len {
            return Err(net_error::OverflowError(format!("Would overflow u32 to read {} bytes of message body", payload_len)));
        }

        if index + payload_len > max_size {
            return Err(net_error::OverflowError(format!("Would read beyond end of buffer to read {} bytes of message body", payload_len)));
        }

        // don't read over the buffer 
        if index + payload_len > (buf.len() as u32) {
            return Err(net_error::UnderflowError(format!("Not enough bytes to read a message body (need {}, have {})", index + payload_len, buf.len())));
        }
        
        let max_payload_size = if index + payload_len < max_size { index + payload_len } else { max_size };
        
        let relayers: Vec<RelayData>    = read_next_at_most::<RelayData>(buf, &mut index, max_payload_size, MAX_RELAYERS_LEN)?;
        let payload : StacksMessageType = read_next(buf, &mut index, max_payload_size)?;

        *index_ptr = index;
        Ok((relayers, payload))
    }

    /// Verify this message by treating the public key buffer as a secp256k1 public key.
    /// Fails if:
    /// * the signature doesn't match
    /// * the buffer doesn't encode a secp256k1 public key
    pub fn verify_secp256k1(&mut self, public_key: &StacksPublicKeyBuffer) -> Result<(), net_error> {
        let secp256k1_pubkey = public_key.to_public_key()?;
        
        let mut message_bits = vec![];
        message_bits.append(&mut self.relayers.consensus_serialize());
        message_bits.append(&mut self.payload.consensus_serialize());

        self.preamble.verify(&message_bits, &secp256k1_pubkey).and_then(|_m| Ok(()))
    }
}

impl MessageSequence for StacksMessage {
    fn request_id(&self) -> u32 {
        self.preamble.seq
    }

    fn get_message_name(&self) -> &'static str {
        self.payload.get_message_name()
    }
}

impl ProtocolFamily for StacksP2P {
    type Message = StacksMessage;

    /// How big can a P2P preamble get?
    fn preamble_size_hint() -> usize {
        PREAMBLE_ENCODED_SIZE as usize
    }

    /// StacksP2P deals with Preambles
    fn read_preamble(buf: &[u8]) -> Result<(NetworkPreamble, usize), net_error> {
        if buf.len() < PREAMBLE_ENCODED_SIZE as usize {
            return Err(net_error::UnderflowError("Not enough bytes to form a P2P preamble".to_string()));
        }

        let mut index = 0;
        let preamble = Preamble::consensus_deserialize(buf, &mut index, buf.len() as u32)?;
        Ok((NetworkPreamble::P2P(preamble), index as usize))
    }

    /// StacksP2P deals with StacksMessages
    fn read_payload(preamble: &NetworkPreamble, buf: &[u8]) -> Result<StacksMessage, net_error> {
        match preamble {
            NetworkPreamble::P2P(p2p_preamble) => {
                let (relayers, payload) = StacksMessage::deserialize_body(buf, &mut 0, p2p_preamble.payload_len, buf.len() as u32)?;
                let message = StacksMessage {
                    preamble: p2p_preamble.clone(),
                    relayers: relayers,
                    payload: payload
                };
                Ok(message)
            },
            _ => {
                Err(net_error::WrongProtocolFamily)
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use util::hash::hex_bytes;
    use util::secp256k1::*;

    fn check_overflow<T>(r: Result<T, net_error>) -> bool {
        match r {
            Ok(_) => {
                test_debug!("did not get an overflow error, or any error");
                false
            },
            Err(e) => match e {
                net_error::OverflowError(_) => true,
                _ => {
                    test_debug!("did not get an overflow error, but got {:?}", &e);
                    false
                }
            }
        }
    }

    fn check_underflow<T>(r: Result<T, net_error>)  -> bool {
        match r {
            Ok(_) => {
                test_debug!("did not get an underflow error, or any error");
                false
            },
            Err(e) => match e {
                net_error::UnderflowError(_) => true,
                _ => {
                    test_debug!("did not get an underflow error, but got {:?}", &e);
                    false
                }
            }
        }
    }

    fn check_deserialize<T>(r: Result<T, net_error>) -> bool {
        match r {
            Ok(_) => false,
            Err(e) => match e {
                net_error::DeserializeError(_) => true,
                _ => false
            }
        }
    }

    #[test]
    fn codec_primitive_types() {
        let a : u8 = 0x01;
        let b : u16 = 0x0203;
        let c : u32 = 0x04050607;
        let d : u64 = 0x08090a0b0c0d0e0f;

        let a_bits = a.consensus_serialize();
        let b_bits = b.consensus_serialize();
        let c_bits = c.consensus_serialize();
        let d_bits = d.consensus_serialize();

        assert_eq!(a_bits, [0x01]);
        assert_eq!(b_bits, [0x02, 0x03]);
        assert_eq!(c_bits, [0x04, 0x05, 0x06, 0x07]);
        assert_eq!(d_bits, [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);

        let mut index : u32 = 0;
        assert_eq!(u8::consensus_deserialize(&a_bits, &mut index, 1).unwrap(), a);
        assert_eq!(index, 1);

        index = 0;
        assert_eq!(u16::consensus_deserialize(&b_bits, &mut index, 2).unwrap(), b);
        assert_eq!(index, 2);

        index = 0;
        assert_eq!(u32::consensus_deserialize(&c_bits, &mut index, 4).unwrap(), c);
        assert_eq!(index, 4);

        index = 0;
        assert_eq!(u64::consensus_deserialize(&d_bits, &mut index, 8).unwrap(), d);
        assert_eq!(index, 8);

        index = 0;

        // overflowing maximum allowed size
        assert!(check_overflow(u8::consensus_deserialize(&a_bits, &mut index, 0)));
        assert_eq!(index, 0);

        assert!(check_overflow(u16::consensus_deserialize(&b_bits, &mut index, 1)));
        assert_eq!(index, 0);

        assert!(check_overflow(u32::consensus_deserialize(&c_bits, &mut index, 3)));
        assert_eq!(index, 0);

        assert!(check_overflow(u64::consensus_deserialize(&d_bits, &mut index, 7)));
        assert_eq!(index, 0);

        // buffer is too short
        assert!(check_underflow(u8::consensus_deserialize(&vec![], &mut index, 1)));
        assert_eq!(index, 0);

        assert!(check_underflow(u16::consensus_deserialize(&b_bits[0..1].to_vec(), &mut index, 2)));
        assert_eq!(index, 0);

        assert!(check_underflow(u32::consensus_deserialize(&c_bits[0..3].to_vec(), &mut index, 4)));
        assert_eq!(index, 0);

        assert!(check_underflow(u64::consensus_deserialize(&d_bits[0..6].to_vec(), &mut index, 8)));
        assert_eq!(index, 0);

        // index would overflow 
        index = u32::max_value();
        assert!(check_overflow(u8::consensus_deserialize(&a_bits, &mut index, 1)));
        assert_eq!(index, u32::max_value());

        index = u32::max_value() - 1;
        assert!(check_overflow(u16::consensus_deserialize(&b_bits, &mut index, 2)));
        assert_eq!(index, u32::max_value() - 1);

        index = u32::max_value() - 3;
        assert!(check_overflow(u32::consensus_deserialize(&c_bits, &mut index, 4)));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - 7;
        assert!(check_overflow(u64::consensus_deserialize(&d_bits, &mut index, 8)));
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
        assert_eq!(v1.consensus_serialize(), r1);
        assert_eq!(v2.consensus_serialize(), r2);
        assert_eq!(v3.consensus_serialize(), r3);
        assert_eq!(v4.consensus_serialize(), r4);
        assert_eq!(v5.consensus_serialize(), r5);
        assert_eq!(v6.consensus_serialize(), r6);
        assert_eq!(v7.consensus_serialize(), r7);
        assert_eq!(v8.consensus_serialize(), r8);

        let mut index = 0;
        
        // deserialize
        assert_eq!(Vec::<u8>::consensus_deserialize(&r1, &mut index, 4).unwrap(), v1);
        assert_eq!(index, 4);
        
        index = 0;
        assert_eq!(Vec::<u8>::consensus_deserialize(&r2, &mut index, (4 + v2.len()) as u32).unwrap(), v2);
        assert_eq!(index, (4 + v2.len()) as u32);

        index = 0;
        assert_eq!(Vec::<u16>::consensus_deserialize(&r3, &mut index, 4).unwrap(), v3);
        assert_eq!(index, 4);
        
        index = 0;
        assert_eq!(Vec::<u16>::consensus_deserialize(&r4, &mut index, (4 + v4.len() * 2) as u32).unwrap(), v4);
        assert_eq!(index, (4 + v4.len() * 2) as u32);

        index = 0;
        assert_eq!(Vec::<u32>::consensus_deserialize(&r5, &mut index, 4).unwrap(), v5);
        assert_eq!(index, 4);

        index = 0;
        assert_eq!(Vec::<u32>::consensus_deserialize(&r6, &mut index, (4 + v6.len() * 4) as u32).unwrap(), v6);
        assert_eq!(index, (4 + v6.len() * 4) as u32);

        index = 0;
        assert_eq!(Vec::<u64>::consensus_deserialize(&r7, &mut index, 4).unwrap(), v7);
        assert_eq!(index, 4);

        index = 0;
        assert_eq!(Vec::<u64>::consensus_deserialize(&r8, &mut index, (4 + v8.len() * 8) as u32).unwrap(), v8);
        assert_eq!(index, (4 + v8.len() * 8) as u32);
        
        index = 0;

        // overflow maximum allowed size
        assert!(check_overflow(Vec::<u8>::consensus_deserialize(&r1, &mut index, 3)));
        assert_eq!(index, 0);

        assert!(check_overflow(Vec::<u8>::consensus_deserialize(&r2, &mut index, (4 + v2.len() - 1) as u32)));
        assert_eq!(index, 0);

        assert!(check_overflow(Vec::<u16>::consensus_deserialize(&r3, &mut index, 3)));
        assert_eq!(index, 0);

        assert!(check_overflow(Vec::<u16>::consensus_deserialize(&r4, &mut index, (4 + v4.len() * 2 - 1) as u32)));
        assert_eq!(index, 0);

        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r5, &mut index, 3)));
        assert_eq!(index, 0);

        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r6, &mut index, (4 + v6.len() * 4 - 1) as u32)));
        assert_eq!(index, 0);

        assert!(check_overflow(Vec::<u64>::consensus_deserialize(&r7, &mut index, 3)));
        assert_eq!(index, 0);
        
        assert!(check_overflow(Vec::<u64>::consensus_deserialize(&r8, &mut index, (4 + v8.len() * 8 - 1) as u32)));
        assert_eq!(index, 0);

        // underflow the input buffer
        assert!(check_underflow(Vec::<u8>::consensus_deserialize(&r1[0..2].to_vec(), &mut index, 4)));
        assert_eq!(index, 0);

        assert!(check_underflow(Vec::<u8>::consensus_deserialize(&r2[0..r2.len()-1].to_vec(), &mut index, (4 + v2.len()) as u32)));
        assert_eq!(index, 0);

        assert!(check_underflow(Vec::<u16>::consensus_deserialize(&r3[0..2].to_vec(), &mut index, 4)));
        assert_eq!(index, 0);

        assert!(check_underflow(Vec::<u16>::consensus_deserialize(&r4[0..r4.len()-1].to_vec(), &mut index, (4 + v4.len() * 2) as u32)));
        assert_eq!(index, 0);

        assert!(check_underflow(Vec::<u32>::consensus_deserialize(&r5[0..2].to_vec(), &mut index, 4)));
        assert_eq!(index, 0);

        assert!(check_underflow(Vec::<u32>::consensus_deserialize(&r6[0..r6.len()-1].to_vec(), &mut index, (4 + v6.len() * 4) as u32)));
        assert_eq!(index, 0);

        assert!(check_underflow(Vec::<u64>::consensus_deserialize(&r7[0..2].to_vec(), &mut index, 4)));
        assert_eq!(index, 0);
        
        assert!(check_underflow(Vec::<u64>::consensus_deserialize(&r8[0..r8.len()-1].to_vec(), &mut index, (4 + v8.len() * 8) as u32)));
        assert_eq!(index, 0);

        // index would overflow
        index = u32::max_value() - 3;
        assert!(check_overflow(Vec::<u8>::consensus_deserialize(&r1, &mut index, 4)));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - ((4 + v2.len() - 1) as u32);
        assert!(check_overflow(Vec::<u8>::consensus_deserialize(&r2, &mut index, (4 + v2.len()) as u32)));
        assert_eq!(index, u32::max_value() - ((4 + v2.len() - 1) as u32));

        index = u32::max_value() - 3;
        assert!(check_overflow(Vec::<u16>::consensus_deserialize(&r3, &mut index, 4)));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - ((4 + v2.len()*2 - 1) as u32);
        assert!(check_overflow(Vec::<u16>::consensus_deserialize(&r4, &mut index, (4 + v4.len() * 2) as u32)));
        assert_eq!(index, u32::max_value() - ((4 + v2.len()*2 - 1) as u32));

        index = u32::max_value() - 3;
        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r5, &mut index, 4)));
        assert_eq!(index, u32::max_value() - 3);

        index = u32::max_value() - ((4 + v2.len()*4 - 1) as u32);
        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r6, &mut index, (4 + v6.len() * 4) as u32)));
        assert_eq!(index, u32::max_value() - ((4 + v2.len()*4 - 1) as u32));

        index = u32::max_value() - 3;
        assert!(check_overflow(Vec::<u64>::consensus_deserialize(&r7, &mut index, 4)));
        assert_eq!(index, u32::max_value() - 3);
        
        index = u32::max_value() - ((4 + v2.len()*8 - 1) as u32);
        assert!(check_overflow(Vec::<u64>::consensus_deserialize(&r8, &mut index, (4 + v8.len() * 8) as u32)));
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
        assert_eq!(Vec::<u32>::consensus_deserialize(&r, &mut index, 20).unwrap(), v);
        assert_eq!(index, 20);

        // correct decode, but underrun
        index = 0;
        assert_eq!(Vec::<u32>::consensus_deserialize(&r_length_too_short, &mut index, 20).unwrap(), vec![0x01020304, 0x05060708, 0x090a0b0c]);
        assert_eq!(index, 16);
        
        index = 0;

        // overflow -- tried to read past max_size
        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r_length_too_long, &mut index, 20)));
        assert_eq!(index, 0);
        
        // underflow -- ran out of bytes to read
        assert!(check_underflow(Vec::<u32>::consensus_deserialize(&r_length_too_long, &mut index, 24)));
        assert_eq!(index, 0);

        // overflow -- tried to read past max size
        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r_bytes_not_aligned, &mut index, 19)));
        assert_eq!(index, 0);
        
        // underflow -- ran out of bytes to read
        assert!(check_underflow(Vec::<u32>::consensus_deserialize(&r_bytes_not_aligned, &mut index, 20)));
        assert_eq!(index, 0);

        // overflow -- tried to read past max size
        assert!(check_overflow(Vec::<u32>::consensus_deserialize(&r_huge_length, &mut index, 20)));
        assert_eq!(index, 0);
        
        // underflow -- ran out of bytes to read
        assert!(check_underflow(Vec::<u32>::consensus_deserialize(&r_huge_length, &mut index, 0xffffffff)));
        assert_eq!(index, 0);
    }

    pub fn check_codec_and_corruption<T : StacksMessageCodec + fmt::Debug + Clone + PartialEq>(obj: &T, bytes: &Vec<u8>) -> () {
        assert_eq!(obj.consensus_serialize(), *bytes);
        
        let mut index = 0;
        let res = T::consensus_deserialize(bytes, &mut index, bytes.len() as u32);
        if res.is_err() {
            test_debug!("\nFailed to parse to {:?}: {:?}", obj, bytes);
            test_debug!("error: {:?}", &res);
            assert!(false);
        }
        assert_eq!(index, bytes.len() as u32);

        // corrupt 
        index = 0;
        let underflow_res = T::consensus_deserialize(&bytes[0..((bytes.len()-1) as usize)].to_vec(), &mut index, bytes.len() as u32);
        if underflow_res.is_ok() {
            test_debug!("\nMissing Underflow: Parsed {:?}\nFrom {:?}\nindex = {}; remaining = {:?}\n", &underflow_res.unwrap(), &bytes[0..((bytes.len()-1) as usize)].to_vec(), index, &bytes[index as usize..bytes.len()].to_vec());
        }
        
        index = 0;
        let underflow_cmp = T::consensus_deserialize(&bytes[0..((bytes.len()-1) as usize)].to_vec(), &mut index, bytes.len() as u32);
        assert!(check_underflow(underflow_cmp));
        assert_eq!(index, 0);

        let overflow_res = T::consensus_deserialize(bytes, &mut index, (bytes.len() - 1) as u32);
        if overflow_res.is_ok() {
            test_debug!("\nMissing Overflow: Parsed {:?}\nFrom {:?}\nindex = {}; max_size = {}; remaining = {:?}\n", &overflow_res.unwrap(), &bytes, index, bytes.len() - 1, &bytes[index as usize..bytes.len()].to_vec());
        }

        index = 0;
        let overflow_cmp = T::consensus_deserialize(bytes, &mut index, (bytes.len() - 1) as u32);
        assert!(check_overflow(overflow_cmp));
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
            additional_data: 0x33333333,
            signature: MessageSignature::from_raw(&vec![0x44; 65]),
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
            0x33, 0x33, 0x33, 0x33,
            // signature
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44,
            // payload_len
            0x00, 0x00, 0x07, 0xff
        ];

        assert_eq!(preamble.consensus_serialize(), preamble_bytes);
        assert_eq!(preamble_bytes.len() as u32, PREAMBLE_ENCODED_SIZE);

        let mut index = 0;
        assert_eq!(Preamble::consensus_deserialize(&preamble_bytes, &mut index, PREAMBLE_ENCODED_SIZE).unwrap(), preamble);
        assert_eq!(index, PREAMBLE_ENCODED_SIZE);

        // corrupt 
        index = 0;
        assert!(check_underflow(Preamble::consensus_deserialize(&preamble_bytes[0..((PREAMBLE_ENCODED_SIZE-1) as usize)].to_vec(), &mut index, PREAMBLE_ENCODED_SIZE)));
        assert_eq!(index, 0);

        assert!(check_overflow(Preamble::consensus_deserialize(&preamble_bytes, &mut index, PREAMBLE_ENCODED_SIZE - 1)));
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

        let bytes = getblocksdata_range_too_big.consensus_serialize();

        let mut index = 0;
        assert!(check_deserialize(GetBlocksData::consensus_deserialize(&bytes, &mut index, bytes.len() as u32)));
    }

    #[test]
    fn codec_MicroblocksInvData() {
        let data = MicroblocksInvData {
            last_microblock_hash: BlockHeaderHash([0x66; 32]),
            last_sequence: 1
        };
        let bytes : Vec<u8> = vec![
            // hash
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            // seq
            0x00, 0x01
        ];
        check_codec_and_corruption::<MicroblocksInvData>(&data, &bytes);
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
            let microblock_inv = MicroblocksInvData {
                last_microblock_hash: BlockHeaderHash([0x01; 32]),
                last_sequence: _i
            };
            maximal_microblocks_inventory.push(microblock_inv.clone());
            too_big_microblocks_inventory.push(microblock_inv);
        }

        too_big_microblocks_inventory.push(MicroblocksInvData {
            last_microblock_hash: BlockHeaderHash([0xff; 32]),
            last_sequence: 0xff
        });

        let maximal_blocksinvdata = BlocksInvData {
            bitlen: 31,
            bitvec: maximal_bitvec.clone(),
            microblocks_inventory: maximal_microblocks_inventory.clone()
        };

        let maximal_microblocks_inventory_bytes = maximal_microblocks_inventory.consensus_serialize();
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
        let too_big_blocksinvdata_bytes = too_big_blocksinvdata.consensus_serialize();

        assert!(check_deserialize(BlocksInvData::consensus_deserialize(&too_big_blocksinvdata_bytes, &mut index, too_big_blocksinvdata_bytes.len() as u32)));
        assert_eq!(index, 0);

        // should fail to decode if the bitlen doesn't match the bitvec
        let long_bitlen = BlocksInvData {
            bitlen: 1,
            bitvec: vec![0xff, 0x01],
            microblocks_inventory: vec![
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x01; 32]),
                    last_sequence: 1,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x02; 32]),
                    last_sequence: 2,
                },
            ]
        };
        let long_bitlen_bytes = long_bitlen.consensus_serialize();

        assert!(check_deserialize(BlocksInvData::consensus_deserialize(&long_bitlen_bytes, &mut index, long_bitlen_bytes.len() as u32)));
        assert_eq!(index, 0);

        let short_bitlen = BlocksInvData {
            bitlen: 9,
            bitvec: vec![0xff],
            microblocks_inventory: vec![
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x01; 32]),
                    last_sequence: 1,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x02; 32]),
                    last_sequence: 2,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x03; 32]),
                    last_sequence: 3,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x04; 32]),
                    last_sequence: 4,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x05; 32]),
                    last_sequence: 5,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x06; 32]),
                    last_sequence: 6,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x07; 32]),
                    last_sequence: 7,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x08; 32]),
                    last_sequence: 8,
                },
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x09; 32]),
                    last_sequence: 9,
                },
            ]
        };
        let short_bitlen_bytes = short_bitlen.consensus_serialize();
        
        assert!(check_deserialize(BlocksInvData::consensus_deserialize(&short_bitlen_bytes, &mut index, short_bitlen_bytes.len() as u32)));
        assert_eq!(index, 0);

        // should fail if microblocks inventory doesn't match bitlen 
        let wrong_microblocks_inv = BlocksInvData {
            bitlen: 2,
            bitvec: vec![0x03],
            microblocks_inventory: vec![
                MicroblocksInvData {
                    last_microblock_hash: BlockHeaderHash([0x09; 32]),
                    last_sequence: 9,
                },
            ]
        };
        let wrong_microblocks_inv_bytes = wrong_microblocks_inv.consensus_serialize();

        assert!(check_deserialize(BlocksInvData::consensus_deserialize(&wrong_microblocks_inv_bytes, &mut index, wrong_microblocks_inv_bytes.len() as u32)));
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
            handshake: HandshakeData { 
                addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                port: 12345,
                services: 0x0001,
                node_public_key: StacksPublicKeyBuffer::from_bytes(&hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb").unwrap()).unwrap(),
                expire_block_height: 0x0102030405060708
            },
            heartbeat_interval: 0x01020304,
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
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            // heartbeat 
            0x01, 0x02, 0x03, 0x04,
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
            signature: MessageSignature::from_raw(&vec![0x44; 65]),
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
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44
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
                handshake: HandshakeData {
                    addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                    port: 12345,
                    services: 0x0001,
                    node_public_key: StacksPublicKeyBuffer::from_bytes(&hex_bytes("034e316be04870cef1795fba64d581cf64bad0c894b01a068fb9edf85321dcd9bb").unwrap()).unwrap(),
                    expire_block_height: 0x0102030405060708
                }
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
                        last_microblock_hash: BlockHeaderHash([0xa3; 32]),
                        last_sequence: 0xa3,
                    },
                    MicroblocksInvData {
                        last_microblock_hash: BlockHeaderHash([0xa4; 32]),
                        last_sequence: 0xa4,
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
            StacksMessageType::Ping(PingData {
                nonce: 0x01020304
            }),
            StacksMessageType::Pong(PongData {
                nonce: 0x01020304
            }),
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
                signature: MessageSignature::from_raw(&vec![0x44; 65]),
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
            signature: MessageSignature::from_raw(&vec![0x44; 65]),
        });

        let relayers_bytes = maximal_relayers.consensus_serialize();
        let too_many_relayer_bytes = too_many_relayers.consensus_serialize();

        for payload in &payloads {
            // just testing codec; don't worry about signatures
            // (only payload_len must be valid)
            let payload_bytes = payload.consensus_serialize();

            let preamble = Preamble {
                peer_version: 0x01020304,
                network_id: 0x05060708,
                seq: 0x090a0b0c,
                burn_block_height: 0x00001122,
                burn_consensus_hash: ConsensusHash::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
                burn_stable_block_height: 0x00001111,
                burn_stable_consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                additional_data: 0x33333333,
                signature: MessageSignature::from_raw(&vec![0x44; 65]),
                payload_len: (relayers_bytes.len() + payload_bytes.len()) as u32,
            };

            let stacks_message = StacksMessage {
                preamble: preamble.clone(),
                relayers: maximal_relayers.clone(),
                payload: payload.clone()
            };

            let mut stacks_message_bytes : Vec<u8> = vec![];
            stacks_message_bytes.append(&mut preamble.consensus_serialize());
            stacks_message_bytes.append(&mut relayers_bytes.clone());
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
            let stacks_message_short_len_bytes = stacks_message_short_len.consensus_serialize();

            // expect overflow error, since index will exceed the expected maximum size
            assert!(check_overflow(StacksMessage::consensus_deserialize(&stacks_message_short_len_bytes, &mut index, stacks_message_short_len_bytes.len() as u32)));
            assert_eq!(index, 0);

            // can't have too many relayers 
            let mut preamble_too_many_relayers = preamble.clone();
            preamble_too_many_relayers.payload_len = (too_many_relayer_bytes.len() + payload_bytes.len() + 1) as u32;

            let stacks_message_too_many_relayers = StacksMessage {
                preamble: preamble_too_many_relayers.clone(),
                relayers: too_many_relayers.clone(),
                payload: payload.clone()
            };
            let stacks_message_too_many_relayers_bytes = stacks_message_too_many_relayers.consensus_serialize();

            assert!(check_deserialize(StacksMessage::consensus_deserialize(&stacks_message_too_many_relayers_bytes, &mut index, stacks_message_too_many_relayers_bytes.len() as u32)));
            assert_eq!(index, 0);
        }
    }

    #[test]
    fn codec_sign_and_verify() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey_buf = StacksPublicKeyBuffer::from_public_key(&Secp256k1PublicKey::from_private(&privkey));

        let mut ping = StacksMessage::new(PEER_VERSION, 0x9abcdef0,
                                          12345,
                                          &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                          12339,
                                          &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                          StacksMessageType::Ping(PingData { nonce: 0x01020304 }));

        ping.sign(444, &privkey).unwrap();
        ping.verify_secp256k1(&pubkey_buf).unwrap();
    }

    #[test]
    fn codec_stacks_public_key_roundtrip() {
        for i in 0..100 {
            let privkey = Secp256k1PrivateKey::new();
            let pubkey = Secp256k1PublicKey::from_private(&privkey);

            let pubkey_buf = StacksPublicKeyBuffer::from_public_key(&pubkey);
            let pubkey_2 = pubkey_buf.to_public_key().unwrap();

            assert_eq!(pubkey, pubkey_2);
        }
    }
} 
