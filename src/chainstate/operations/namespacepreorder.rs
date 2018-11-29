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

use chainstate::operations::{BlockstackOperation, BlockstackOperationType};
use chainstate::operations::Error as op_error;

use chainstate::db::namedb::NameDB;

use burnchains::{BurnchainTransaction, PublicKey};
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
use burnchains::ConsensusHash;
use burnchains::Txid;
use burnchains::Hash160;

/*
# consensus hash fields (ORDER MATTERS!) 
FIELDS = [
    'preorder_hash',        # hash(namespace_id,sender,reveal_addr)
    'consensus_hash',       # consensus hash at the time issued
    'op',                   # bytecode describing the operation (not necessarily 1 byte)
    'op_fee',               # fee paid for the namespace to the burn address
    'txid',                 # transaction ID
    'vtxindex',             # the index in the block where the tx occurs
    'block_number',         # block number at which this transaction occurred
    'sender',               # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address'               # address from the scriptPubKey
]

# save everything
MUTATE_FIELDS = FIELDS[:] + [
    'token_fee'
]

@state_preorder("check_preorder_collision")
def check( state_engine, nameop, block_id, checked_ops ):
*/

#[derive(Debug)]
pub struct NamespacePreorderOp {
    preorder_hash: Hash160,             // hash(namesapce_id, sender, reveal_addr)
    consensus_hash: ConsensusHash,      // consensus hash at time of issuance
    op: u8,                             // bytecode describing the operation
    op_fee: u64,                        // satoshi fee paid for the namespace to the burn address
    txid: Txid,                         // transaction ID
    vtxindex: u64,                      // index in the block where this tx occurs
    block_number: u64,                  // block height at which this tx occurs
    sender: String,                     // hex string of the scriptpubkey of the principal that sent this transaction 
    sender_pubkey: String,              // if the sender is a p2pkh script, this is the public key as a hex string
    address: String,                    // serialized address from the scriptpubkey
    token_fee: u64                      // microstacks paid for this namespace
}

impl NamespacePreorderOp {
    fn parse_data(data: &Vec<u8>) -> Option<(Hash160, ConsensusHash, Option<u64>)> {
        /*
            wire format (Pre-STACKs Phase 1)

            0     2   3                                      23               39
            |-----|---|--------------------------------------|----------------|
            magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash

            wire format (Post-STACKs phase 1)

            0     2   3                                      23               39                         47
            |-----|---|--------------------------------------|----------------|--------------------------|
            magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash    token fee (little-endian)

            Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        if data.len() != 36 && data.len() != 44 {
            // can't be either format
            warn!("NAMESPACE_PREORDER payload is malformed");
            return None;
        }

        let preorder_hash = Hash160::from_vec(&data[0..20].to_vec()).unwrap();
        let consensus_hash = ConsensusHash::from_vec(&data[20..34].to_vec()).unwrap();
        let token_fee_opt = 
            if data.len() == 44 {
                // have token free as well
                let token_fee_bytes = &data[36..44];
                Some((token_fee_bytes[0] as u64) << (7 * 8) +
                     (token_fee_bytes[1] as u64) << (6 * 8) +
                     (token_fee_bytes[2] as u64) << (5 * 8) +
                     (token_fee_bytes[3] as u64) << (4 * 8) + 
                     (token_fee_bytes[4] as u64) << (3 * 8) +
                     (token_fee_bytes[5] as u64) << (2 * 8) +
                     (token_fee_bytes[6] as u64) << (1 * 8) +
                      token_fee_bytes[7])
            }
            else {
                None
            };

        return Some((preorder_hash, consensus_hash, token_fee_opt));
    }

    pub fn from_tx(tx: &BurnchainTransaction<BitcoinAddress, BitcoinPublicKey>) -> Result<NamespacePreorderOp, op_error> {
        let parse_data_opt = NamespacePreorderOp::parse_data(&tx.data);
        if parse_data_opt.is_none() {
            return Err(op_error::ParseError)
        }

        let (preorder_hash, consensus_hash, token_fee_opt) = parse_data_opt.unwrap();

        return Err(op_error::NotImplemented);
    }
}

impl BlockstackOperation for NamespacePreorderOp {
    fn check(&self, db: &NameDB, block_height: u64, checked_block_ops: &Vec<BlockstackOperationType>) -> bool {
        return false;
    }

    fn consensus_serialize(&self) -> String {
        return String::from("");
    }
}
