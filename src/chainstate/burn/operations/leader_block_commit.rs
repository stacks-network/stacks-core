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

use std::io::{Read, Write};

use address::AddressHashMode;
use chainstate::burn::ConsensusHash;
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::Opcodes;
use chainstate::burn::{BlockHeaderHash, VRFSeed};
use chainstate::burn::db::sortdb::SortitionHandleConn;

use chainstate::stacks::index::TrieHash;

use chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    UserBurnSupportOp,
    BlockstackOperation,
    BlockstackOperationType,
    parse_u32_from_be,
    parse_u16_from_be
};

use chainstate::stacks::StacksPublicKey;
use chainstate::stacks::StacksPrivateKey;

use burnchains::{BurnchainTransaction, PublicKey};
use burnchains::Txid;
use burnchains::Address;
use burnchains::BurnchainHeaderHash;
use burnchains::Burnchain;
use burnchains::BurnchainBlockHeader;
use burnchains::{
    BurnchainSigner,
    BurnchainRecipient
};

use net::StacksMessageCodec;
use net::codec::{write_next};
use net::Error as net_error;

use util::log;
use util::hash::to_hex;
use util::vrf::VRF;
use util::vrf::VRFPublicKey;
use util::vrf::VRFPrivateKey;

use chainstate::stacks::index::storage::TrieFileStorage;

// return type from parse_data below
struct ParsedData {
    block_header_hash: BlockHeaderHash,
    new_seed: VRFSeed,
    parent_block_ptr: u32,
    parent_vtxindex: u16,
    key_block_ptr: u32,
    key_vtxindex: u16,
    memo: Vec<u8>
}

impl LeaderBlockCommitOp {
    pub fn initial(block_header_hash: &BlockHeaderHash, block_height: u64, new_seed: &VRFSeed, paired_key: &LeaderKeyRegisterOp, burn_fee: u64, input: &BurnchainSigner) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            block_height: block_height,
            new_seed: new_seed.clone(),
            key_block_ptr: paired_key.block_height as u32,
            key_vtxindex: paired_key.vtxindex as u16,
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            memo: vec![0x00],
            burn_fee: burn_fee,
            input: input.clone(),
            block_header_hash: block_header_hash.clone(),

            // to be filled in 
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    #[cfg(test)]
    pub fn new(block_header_hash: &BlockHeaderHash, block_height: u64, new_seed: &VRFSeed, parent: &LeaderBlockCommitOp, key_block_ptr: u32, key_vtxindex: u16, burn_fee: u64, input: &BurnchainSigner) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            new_seed: new_seed.clone(),
            key_block_ptr: key_block_ptr,
            key_vtxindex: key_vtxindex,
            parent_block_ptr: parent.block_height as u32,
            parent_vtxindex: parent.vtxindex as u16,
            memo: vec![],
            burn_fee: burn_fee,
            input: input.clone(),
            block_header_hash: block_header_hash.clone(),

            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
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

        if data.len() < 77 {
            // too short
            warn!("LEADER_BLOCK_COMMIT payload is malformed ({} bytes)", data.len());
            return None;
        }

        let block_header_hash = BlockHeaderHash::from_bytes(&data[0..32]).unwrap();
        let new_seed = VRFSeed::from_bytes(&data[32..64]).unwrap();
        let parent_block_ptr = parse_u32_from_be(&data[64..68]).unwrap();
        let parent_vtxindex = parse_u16_from_be(&data[68..70]).unwrap();
        let key_block_ptr = parse_u32_from_be(&data[70..74]).unwrap();
        let key_vtxindex = parse_u16_from_be(&data[74..76]).unwrap();
        let memo = data[76..77].to_vec();

        Some(ParsedData {
            block_header_hash,
            new_seed,
            parent_block_ptr,
            parent_vtxindex,
            key_block_ptr,
            key_vtxindex,
            memo
        })
    }

    fn parse_from_tx(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction) -> Result<LeaderBlockCommitOp, op_error> {
        // can't be too careful...
        let inputs = tx.get_signers();
        let outputs = tx.get_recipients();

        if inputs.len() == 0 {
            warn!("Invalid tx: inputs: {}, outputs: {}", inputs.len(), outputs.len());
            return Err(op_error::InvalidInput);
        }

        if outputs.len() == 0 {
            warn!("Invalid tx: inputs: {}, outputs: {}", inputs.len(), outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != (Opcodes::LeaderBlockCommit as u8) {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        }

        // outputs[0] should be the burn output
        if !outputs[0].address.is_burn() {
            // wrong burn output
            warn!("Invalid tx: burn output missing (got {:?})", outputs[0]);
            return Err(op_error::ParseError);
        }

        let burn_fee = outputs[0].amount;
        if burn_fee == 0 {
            // didn't burn
            warn!("Invalid tx: no burn quantity");
            return Err(op_error::ParseError);
        }

        let data = match LeaderBlockCommitOp::parse_data(&tx.data()) {
            None => {
                warn!("Invalid tx data");
                return Err(op_error::ParseError);
            },
            Some(d) => d
        };

        // basic sanity checks 
        if data.parent_block_ptr == 0 {
            if data.parent_vtxindex != 0 {
                warn!("Invalid tx: parent block back-pointer must be positive");
                return Err(op_error::ParseError);
            }
            // if parent block ptr and parent vtxindex are both 0, then this block's parent is
            // the genesis block.
        }

        if data.parent_block_ptr as u64 >= block_height {
            warn!("Invalid tx: parent block back-pointer {} exceeds block height {}", data.parent_block_ptr, block_height);
            return Err(op_error::ParseError);
        }

        if data.key_block_ptr == 0 {
            warn!("Invalid tx: key block back-pointer must be positive");
            return Err(op_error::ParseError);
        }

        if data.key_block_ptr as u64 >= block_height {
            warn!("Invalid tx: key block back-pointer {} exceeds block height {}", data.key_block_ptr, block_height);
            return Err(op_error::ParseError);
        }

        Ok(LeaderBlockCommitOp {
            block_header_hash: data.block_header_hash,
            new_seed: data.new_seed,
            parent_block_ptr: data.parent_block_ptr,
            parent_vtxindex: data.parent_vtxindex,
            key_block_ptr: data.key_block_ptr,
            key_vtxindex: data.key_vtxindex,
            memo: data.memo,

            burn_fee: burn_fee,
            input: inputs[0].clone(),

            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height: block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StacksMessageCodec for LeaderBlockCommitOp {

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
        if self.memo.len() > 0 {
            write_next(fd, &self.memo[0])?;
        }
        else {
            write_next(fd, &0u8)?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<LeaderBlockCommitOp, net_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl BlockstackOperation for LeaderBlockCommitOp {
    fn from_tx(block_header: &BurnchainBlockHeader, tx: &BurnchainTransaction) -> Result<LeaderBlockCommitOp, op_error> {
        LeaderBlockCommitOp::parse_from_tx(block_header.block_height, &block_header.block_hash, tx)
    }
        
    fn check(&self, _burnchain: &Burnchain, tx: &SortitionHandleConn) -> Result<(), op_error> {
        let leader_key_block_height = self.key_block_ptr as u64;
        let parent_block_height = self.parent_block_ptr as u64;
        
        /////////////////////////////////////////////////////////////////////////////////////
        // There must be a burn
        /////////////////////////////////////////////////////////////////////////////////////
        
        if self.burn_fee == 0 {
            warn!("Invalid block commit: no burn amount");
            return Err(op_error::BlockCommitBadInput);
        }
        
        /////////////////////////////////////////////////////////////////////////////////////
        // This tx must occur after the start of the network
        /////////////////////////////////////////////////////////////////////////////////////
    
        let first_block_snapshot = tx.get_first_block_snapshot()?;

        if self.block_height < first_block_snapshot.block_height {
            warn!("Invalid block commit: predates genesis height {}", first_block_snapshot.block_height);
            return Err(op_error::BlockCommitPredatesGenesis);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // Block must be unique in this burnchain fork
        /////////////////////////////////////////////////////////////////////////////////////
        
        let is_already_committed = tx.expects_stacks_block_in_fork(&self.block_header_hash)?;

        if is_already_committed {
            warn!("Invalid block commit: already committed to {}", self.block_header_hash);
            return Err(op_error::BlockCommitAlreadyExists);
        }
        
        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted *unused* key from a LeaderKeyRegister
        /////////////////////////////////////////////////////////////////////////////////////

        if leader_key_block_height >= self.block_height {
            warn!("Invalid block commit: references leader key in the same or later block ({} >= {})", leader_key_block_height, self.block_height);
            return Err(op_error::BlockCommitNoLeaderKey);
        }

        let register_key = tx.get_leader_key_at(leader_key_block_height, self.key_vtxindex.into())?
            .ok_or_else(|| {
                warn!("Invalid block commit: no corresponding leader key at {},{} in fork {}", leader_key_block_height, self.key_vtxindex, &tx.context.chain_tip);
                op_error::BlockCommitNoLeaderKey
            })?;

        let is_key_consumed = tx.is_leader_key_consumed(&register_key)?;

        if is_key_consumed {
            warn!("Invalid block commit: leader key at ({},{}) is already used as in fork {}", register_key.block_height, register_key.vtxindex, &tx.context.chain_tip);
            return Err(op_error::BlockCommitLeaderKeyAlreadyUsed);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted block from a LeaderBlockCommit, or this
        // LeaderBlockCommit must build off of the genesis block.  If _not_ building off of the
        // genesis block, then the parent block must be in a different epoch (i.e. its parent must
        // be committed already).
        /////////////////////////////////////////////////////////////////////////////////////

        if parent_block_height == self.block_height {
            // tried to build off a block in the same epoch (not allowed)
            warn!("Invalid block commit: cannot build off of a commit in the same block");
            return Err(op_error::BlockCommitNoParent);
        }
        else if self.parent_block_ptr != 0 || self.parent_vtxindex != 0 {
            // not building off of genesis, so the parent block must exist
            let has_parent = tx.get_block_commit_parent(parent_block_height, self.parent_vtxindex.into())?
                .is_some();
            if !has_parent {
                warn!("Invalid block commit: no parent block in this fork");
                return Err(op_error::BlockCommitNoParent);
            }
        }
        
        /////////////////////////////////////////////////////////////////////////////////////
        // This LeaderBlockCommit's input public keys must match the address of its LeaderKeyRegister
        // -- the hash of the inputs' public key(s) must equal the hash contained within the
        // LeaderKeyRegister's address.  Note that we only need to check the address bytes,
        // not the entire address (since finding two sets of different public keys that
        // hash to the same address is considered intractible).
        //
        // Under the hood, the blockchain further ensures that the tx was signed with the
        // associated private keys, so only the private key owner(s) are in a position to 
        // reveal the keys that hash to the address's hash.
        /////////////////////////////////////////////////////////////////////////////////////

        let input_address_bytes = self.input.to_address_bits();
        let addr_bytes = register_key.address.to_bytes();

        if input_address_bytes != addr_bytes {
            warn!("Invalid block commit: leader key at ({},{}) has address bytes {}, but this tx input has address bytes {}",
                  register_key.block_height, register_key.vtxindex, &to_hex(&addr_bytes), &to_hex(&input_address_bytes[..]));
            return Err(op_error::BlockCommitBadInput);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::Txid;
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;
    use burnchains::BurnchainBlockHeader;

    use burnchains::bitcoin::BitcoinNetworkType;

    use address::AddressHashMode;

    use deps::bitcoin::network::serialize::deserialize;
    use deps::bitcoin::blockdata::transaction::Transaction;
    
    use chainstate::burn::{BlockHeaderHash, ConsensusHash, VRFSeed};
    
    use chainstate::burn::operations::{
        LeaderBlockCommitOp,
        LeaderKeyRegisterOp,
        UserBurnSupportOp,
        BlockstackOperation,
        BlockstackOperationType
    };

    use util::vrf::VRFPublicKey;
    use util::hash::{hex_bytes, to_hex};
    use util::log;
    use util::get_epoch_time_secs;
    
    use chainstate::stacks::StacksAddress;
    use chainstate::stacks::StacksPublicKey;

    use chainstate::burn::db::sortdb::*;
    use chainstate::burn::db::*;
    use chainstate::burn::*;

    struct OpFixture {
        txstr: String,
        opstr: String,
        result: Option<LeaderBlockCommitOp>
    }

    struct CheckFixture {
        op: LeaderBlockCommitOp,
        res: Result<(), op_error>
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str)
            .map_err(|_e| "failed to decode hex string")?;
        let tx = deserialize(&tx_bin.to_vec())
            .map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    #[test]
    fn test_parse() {
        let vtxindex = 1;
        let block_height = 0x71706363;  // epoch number must be strictly smaller than block height
        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let tx_fixtures = vec![
            OpFixture {
                // valid
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100eba8c0a57c1eb71cdfba0874de63cf37b3aace1e56dcbd61701548194a79af34022041dd191256f3f8a45562e5d60956bb871421ba69db605716250554b23b08277b012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645b222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "69645b2222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333340414243505160616263707180".to_string(),
                result: Some(LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 0x40414243,
                    parent_vtxindex: 0x5051,
                    key_block_ptr: 0x60616263,
                    key_vtxindex: 0x7071,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1, 
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: vtxindex,
                    block_height: block_height,
                    burn_header_hash: burn_header_hash,
                })
            },
            OpFixture {
                // invalid -- wrong opcode 
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006946304302207129fa2054a61cdb4b7db0b8fab6e8ff4af0edf979627aa5cf41665b7475a451021f70032b48837df091223c1d0bb57fb0298818eb11d0c966acff4b82f4b2d5c8012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645c222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- wrong burn address
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100e25f5f9f660339cd665caba231d5bdfc3f0885bcc0b3f85dc35564058c9089d702206aa142ea6ccd89e56fdc0743cdcf3a2744e133f335e255e9370e4f8a6d0f6ffd012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645b222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000188aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- bad OP_RETURN (missing memo)
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100c6c3ccc9b5a6ba5161706f3a5e4518bc3964e8de1cf31dbfa4d38082535c88e902205860de620cfe68a72d5a1fc3be1171e6fd8b2cdde0170f76724faca0db5ee0b6012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000526a4c4f69645b2222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333340414243505160616263707139300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "".to_string(),
                result: None,
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let header = match tx_fixture.result {
                Some(ref op) => {
                    BurnchainBlockHeader {
                        block_height: op.block_height,
                        block_hash: op.burn_header_hash.clone(),
                        parent_block_hash: op.burn_header_hash.clone(),
                        num_txs: 1,
                        timestamp: get_epoch_time_secs()
                    }
                },
                None => {
                    BurnchainBlockHeader {
                        block_height: 0,
                        block_hash: BurnchainHeaderHash([0u8; 32]),
                        parent_block_hash: BurnchainHeaderHash([0u8; 32]),
                        num_txs: 0,
                        timestamp: get_epoch_time_secs()
                    }
                }
            };
            let burnchain_tx = BurnchainTransaction::Bitcoin(parser.parse_tx(&tx, vtxindex as usize).unwrap());
            let op = LeaderBlockCommitOp::from_tx(&header, &burnchain_tx);

            match (op, tx_fixture.result) {
                (Ok(parsed_tx), Some(result)) => {

                    let opstr = {
                        let mut buffer= vec![];
                        let mut magic_bytes = BLOCKSTACK_MAGIC_MAINNET.as_bytes().to_vec();
                        buffer.append(&mut magic_bytes);
                        parsed_tx.consensus_serialize(&mut buffer).expect("FATAL: invalid operation");
                        to_hex(&buffer)
                    };

                    assert_eq!(tx_fixture.opstr, opstr);
                    assert_eq!(parsed_tx, result);
                },
                (Err(_e), None) => {},
                (Ok(_parsed_tx), None) => {
                    test_debug!("Parsed a tx when we should not have");
                    assert!(false);
                },
                (Err(_e), Some(_result)) => {
                    test_debug!("Did not parse a tx when we should have");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_check() {
        let first_block_height = 121;
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000123").unwrap();
        
        let block_122_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000001220").unwrap();
        let block_123_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000001230").unwrap();
        let block_124_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000001240").unwrap();
        let block_125_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000001250").unwrap();
        let block_126_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000001260").unwrap();

        let block_header_hashes = [
            block_122_hash.clone(),
            block_123_hash.clone(),
            block_124_hash.clone(),
            block_125_hash.clone(),
            block_126_hash.clone()
        ];
        
        let burnchain = Burnchain {
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: first_block_height,
            first_block_hash: first_burn_hash.clone()
        };
        
        let leader_key_1 = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a914306231b2782b5f80d944bf69f9d46a1453a0a0eb88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
            vtxindex: 456,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };
        
        let leader_key_2 = LeaderKeyRegisterOp { 
            consensus_hash: ConsensusHash::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
            public_key: VRFPublicKey::from_bytes(&hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c").unwrap()).unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(&BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &hex_bytes("76a914306231b2782b5f80d944bf69f9d46a1453a0a0eb88ac").unwrap()).unwrap()),

            txid: Txid::from_bytes_be(&hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7").unwrap()).unwrap(),
            vtxindex: 457,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        // consumes leader_key_1
        let block_commit_1 = LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
            new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 124,
            key_vtxindex: 456,
            memo: vec![0x80],

            burn_fee: 12345,
            input: BurnchainSigner {
                public_keys: vec![
                    StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                ],
                num_sigs: 1, 
                hash_mode: AddressHashMode::SerializeP2PKH
            },

            txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
            vtxindex: 444,
            block_height: 125,
            burn_header_hash: block_125_hash.clone(),
        };

        let mut db = SortitionDB::connect_test(first_block_height, &first_burn_hash).unwrap();
        let block_ops = vec![
            // 122
            vec![],
            // 123
            vec![],
            // 124
            vec![
                BlockstackOperationType::LeaderKeyRegister(leader_key_1.clone()),
                BlockstackOperationType::LeaderKeyRegister(leader_key_2.clone()),
            ],
            // 125
            vec![
                BlockstackOperationType::LeaderBlockCommit(block_commit_1.clone())
            ],
            // 126
            vec![]
        ];

        let consumed_leader_keys = vec![
            // 122
            vec![],
            // 123
            vec![],
            // 124 
            vec![],
            // 125
            vec![
                leader_key_1.clone()
            ],
            // 126
            vec![]
        ];

        let tip_index_root = {
            let mut prev_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap(); 
            for i in 0..block_header_hashes.len() {
                let mut snapshot_row = BlockSnapshot {
                    block_height: (i + 1 + first_block_height as usize) as u64,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: block_header_hashes[i].clone(),
                    sortition_id: SortitionId(block_header_hashes[i as usize].0.clone()),
                    pox_id: PoxId::stubbed(),
                    parent_burn_header_hash: prev_snapshot.burn_header_hash.clone(),
                    consensus_hash: ConsensusHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(i+1) as u8]).unwrap(),
                    ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i as u8]).unwrap(),
                    total_burn: i as u64,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: (i + 1) as u64,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_burn_hash: BurnchainHeaderHash([0u8; 32])
                };
                let mut tx = SortitionHandleTx::begin(&mut db, &prev_snapshot.sortition_id).unwrap();
                let next_index_root = tx.append_chain_tip_snapshot(&prev_snapshot, &snapshot_row, &block_ops[i], &consumed_leader_keys[i]).unwrap();
                
                snapshot_row.index_root = next_index_root;
                tx.commit().unwrap();

                prev_snapshot = snapshot_row;
            }
            
            prev_snapshot.index_root.clone()
        };
        
        let block_height = 124;

        let fixtures = vec![
            CheckFixture {
                // reject -- predates start block
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 50,
                    parent_vtxindex: 456,
                    key_block_ptr: 1,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1, 
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 444,
                    block_height: 80,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitPredatesGenesis),
            },
            CheckFixture {
                // reject -- no such leader key 
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 1,
                    parent_vtxindex: 444,
                    key_block_ptr: 2,
                    key_vtxindex: 400,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoLeaderKey),
            },
            CheckFixture {
                // reject -- leader key consumed already
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 124,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 456,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitLeaderKeyAlreadyUsed),
            },
            CheckFixture {
                // reject -- previous block must exist 
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 445,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoParent),
            },
            CheckFixture {
                // reject -- previous block must exist in a different block 
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 126,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoParent),
            },
            CheckFixture {
                // reject -- tx input does not match any leader keys
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("03984286096373539ae529bd997c92792d4e5b5967be72979a42f587a625394116").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitBadInput),
            },
            CheckFixture {
                // reject -- fee is 0 
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 0,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitBadInput)
            },
            CheckFixture {
                // accept -- consumes leader_key_2
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(())
            },
            CheckFixture {
                // accept -- builds directly off of genesis block and consumes leader_key_2
                op: LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(())
            }
        ];

        for fixture in fixtures {
            let header = BurnchainBlockHeader {
                block_height: fixture.op.block_height,
                block_hash: fixture.op.burn_header_hash.clone(),
                parent_block_hash: fixture.op.burn_header_hash.clone(),
                num_txs: 1,
                timestamp: get_epoch_time_secs()
            };
            let ic = db.index_handle(&SortitionId::stubbed(&fixture.op.burn_header_hash));
            assert_eq!(format!("{:?}", &fixture.res), format!("{:?}", &fixture.op.check(&burnchain, &ic)));
        }
    }
}

