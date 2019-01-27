/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

/// This module contains the code for processing the burn chain state database

pub mod db;
pub mod operations;

pub const CHAINSTATE_VERSION: &'static str = "21.0.0.0";
pub const CONSENSUS_HASH_LIFETIME : u32 = 24;

use burnchains::Txid;

use sha2::Sha256;

use crypto::ripemd160::Ripemd160;

pub struct ConsensusHash([u8; 20]);
impl_array_newtype!(ConsensusHash, u8, 20);
impl_array_hexstring_fmt!(ConsensusHash);
impl_byte_array_newtype!(ConsensusHash, u8, 20);

pub struct BlockHeaderHash([u8; 32]);
impl_array_newtype!(BlockHeaderHash, u8, 32);
impl_array_hexstring_fmt!(BlockHeaderHash);
impl_byte_array_newtype!(BlockHeaderHash, u8, 32);

pub struct VRFSeed([u8; 32]);
impl_array_newtype!(VRFSeed, u8, 32);
impl_array_hexstring_fmt!(VRFSeed);
impl_byte_array_newtype!(VRFSeed, u8, 32);

// operations hash -- the sha256 hash of a sequence of transaction IDs 
pub struct OpsHash([u8; 32]);
impl_array_newtype!(OpsHash, u8, 32);
impl_array_hexstring_fmt!(OpsHash);
impl_byte_array_newtype!(OpsHash, u8, 32);

impl OpsHash {
    pub fn from_txids(txids: &Vec<Txid>) -> OpsHash {
        // NOTE: unlike stacks v1, we calculate the ops hash simply
        // from a hash-chain of txids.  There is no weird serialization
        // of operations, and we don't construct a merkle tree over
        // operations anymore (it's needlessly complex).
        use sha2::Digest;
        let mut hasher = Sha256::new();
        for txid in txids {
            hasher.input(txid.as_bytes());
        }
        let result = hasher.result();

        let mut result_32 = [0u8; 32];
        result_32.copy_from_slice(&result[0..32]);
        OpsHash(result_32)
    }
}

impl ConsensusHash {
    /// Instantiate a consensus hash from this block's operations hash
    /// and a geometric series of previous consensus hashes.  Note that
    /// prev_consensus_hashes should be in order from most-recent to
    /// least-recent.
    pub fn from_ops(opshash: &OpsHash, prev_consensus_hashes: &Vec<ConsensusHash>) -> ConsensusHash {
        // NOTE: unlike stacks v1, we calculate the next consensus hash
        // simply as a hash-chain of the new ops hash and the sequence of 
        // previous consensus hashes.  We don't turn them into Merkle trees first.
        let result;
        {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.input(opshash.as_bytes());
            for ch in prev_consensus_hashes {
                hasher.input(ch.as_bytes());
            }
            result = hasher.result();
        }

        use crypto::digest::Digest;
        let mut r160 = Ripemd160::new();
        r160.input(&result);
        
        let mut ch_bytes = [0u8; 20];
        r160.result(&mut ch_bytes);
        ConsensusHash(ch_bytes)
    }
}

