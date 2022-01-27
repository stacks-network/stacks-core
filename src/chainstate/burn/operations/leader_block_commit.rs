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

use std::convert::TryFrom;
use std::io::{Read, Write};

use crate::burnchains::{BitcoinNetworkType, SubnetStacksEvent, SubnetStacksEventType};
use crate::codec::{write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksAddress, VRFSeed};
use crate::types::proof::TrieHash;
use address::AddressHashMode;
use burnchains::Address;
use burnchains::Burnchain;
use burnchains::BurnchainBlockHeader;
use burnchains::Txid;
use burnchains::{BurnchainRecipient, BurnchainSigner};
use burnchains::{BurnchainTransaction, PublicKey};
use chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::operations::{
    parse_u16_from_be, parse_u32_from_be, BlockstackOperationType, LeaderBlockCommitOp,
    LeaderKeyRegisterOp, UserBurnSupportOp,
};
use chainstate::burn::ConsensusHash;
use chainstate::burn::Opcodes;
use chainstate::burn::SortitionId;
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::{StacksPrivateKey, StacksPublicKey};
use core::STACKS_EPOCH_2_05_MARKER;
use core::{StacksEpoch, StacksEpochId};
use net::Error as net_error;
use util::hash::to_hex;
use util::log;
use util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

// return type from parse_data below
struct ParsedData {
    block_header_hash: BlockHeaderHash,
    new_seed: VRFSeed,
    parent_block_ptr: u32,
    parent_vtxindex: u16,
    key_block_ptr: u32,
    key_vtxindex: u16,
    burn_parent_modulus: u8,
    memo: u8,
}

pub static OUTPUTS_PER_COMMIT: usize = 2;
pub static BURN_BLOCK_MINED_AT_MODULUS: u64 = 5;

impl TryFrom<&SubnetStacksEvent> for LeaderBlockCommitOp {
    type Error = op_error;

    fn try_from(value: &SubnetStacksEvent) -> Result<Self, Self::Error> {
        if let SubnetStacksEventType::BlockCommit {
            ref subnet_block_hash,
        } = value.event
        {
            Ok(LeaderBlockCommitOp {
                block_header_hash: subnet_block_hash.clone(),
                txid: value.txid.clone(),
                // use the StacksBlockId in the L1 event as the burnchain header hash
                burn_header_hash: BurnchainHeaderHash(value.in_block.0.clone()),
            })
        } else {
            Err(op_error::ParseError)
        }
    }
}

impl LeaderBlockCommitOp {
    #[cfg(test)]
    pub fn initial(
        block_header_hash: &BlockHeaderHash,
        block_height: u64,
        new_seed: &VRFSeed,
        paired_key: &LeaderKeyRegisterOp,
        burn_fee: u64,
        input: &(Txid, u32),
        apparent_sender: &BurnchainSigner,
    ) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            sunset_burn: 0,
            block_height: block_height,
            burn_parent_modulus: if block_height > 0 {
                ((block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8
            } else {
                BURN_BLOCK_MINED_AT_MODULUS as u8 - 1
            },
            new_seed: new_seed.clone(),
            key_block_ptr: paired_key.block_height as u32,
            key_vtxindex: paired_key.vtxindex as u16,
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            memo: vec![0x00],
            burn_fee: burn_fee,
            input: input.clone(),
            block_header_hash: block_header_hash.clone(),
            commit_outs: vec![],
            apparent_sender: apparent_sender.clone(),

            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        }
    }

    #[cfg(test)]
    pub fn new(
        block_header_hash: &BlockHeaderHash,
        block_height: u64,
        new_seed: &VRFSeed,
        parent: &LeaderBlockCommitOp,
        key_block_ptr: u32,
        key_vtxindex: u16,
        burn_fee: u64,
        input: &(Txid, u32),
        apparent_sender: &BurnchainSigner,
    ) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            sunset_burn: 0,
            new_seed: new_seed.clone(),
            key_block_ptr: key_block_ptr,
            key_vtxindex: key_vtxindex,
            parent_block_ptr: parent.block_height as u32,
            parent_vtxindex: parent.vtxindex as u16,
            memo: vec![],
            burn_fee: burn_fee,
            input: input.clone(),
            block_header_hash: block_header_hash.clone(),
            commit_outs: vec![],
            apparent_sender: apparent_sender.clone(),

            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_parent_modulus: BURN_BLOCK_MINED_AT_MODULUS as u8 - 1,

            burn_header_hash: BurnchainHeaderHash::zero(),
        }
    }

    #[cfg(test)]
    pub fn set_burn_height(&mut self, height: u64) {
        self.block_height = height;
        self.burn_parent_modulus = if height > 0 {
            (height - 1) % BURN_BLOCK_MINED_AT_MODULUS
        } else {
            BURN_BLOCK_MINED_AT_MODULUS - 1
        } as u8;
    }

    pub fn is_parent_genesis(&self) -> bool {
        panic!("Not implemented")
    }

    pub fn is_first_block(&self) -> bool {
        panic!("Not implemented")
    }
}

#[derive(Debug)]
pub struct RewardSetInfo {
    pub anchor_block: BlockHeaderHash,
    pub recipients: Vec<(StacksAddress, u16)>,
}

#[derive(Debug, Clone)]
pub struct MissedBlockCommit {
    pub txid: Txid,
    pub input: (Txid, u32),
    pub intended_sortition: SortitionId,
}

impl MissedBlockCommit {
    pub fn spent_txid(&self) -> &Txid {
        &self.input.0
    }

    pub fn spent_output(&self) -> u32 {
        self.input.1
    }
}

impl RewardSetInfo {
    /// Takes an Option<RewardSetInfo> and produces the commit_outs
    ///   for a corresponding LeaderBlockCommitOp. If RewardSetInfo is none,
    ///   the LeaderBlockCommitOp will use burn addresses.
    pub fn into_commit_outs(from: Option<RewardSetInfo>, mainnet: bool) -> Vec<StacksAddress> {
        if let Some(recipient_set) = from {
            let mut outs: Vec<_> = recipient_set
                .recipients
                .into_iter()
                .map(|(recipient, _)| recipient)
                .collect();
            while outs.len() < OUTPUTS_PER_COMMIT {
                outs.push(StacksAddress::burn_address(mainnet));
            }
            outs
        } else {
            (0..OUTPUTS_PER_COMMIT)
                .map(|_| StacksAddress::burn_address(mainnet))
                .collect()
        }
    }
}

impl LeaderBlockCommitOp {
    pub fn check(
        &self,
        burnchain: &Burnchain,
        tx: &mut SortitionHandleTx,
        reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<(), op_error> {
        // good to go!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use address::AddressHashMode;
    use burnchains::bitcoin::address::*;
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::*;
    use burnchains::*;
    use chainstate::burn::db::sortdb::tests::test_append_snapshot;
    use chainstate::burn::db::sortdb::*;
    use chainstate::burn::db::*;
    use chainstate::burn::operations::*;
    use chainstate::burn::ConsensusHash;
    use chainstate::burn::*;
    use chainstate::stacks::StacksPublicKey;
    use core::{
        StacksEpoch, StacksEpochId, PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0,
        PEER_VERSION_EPOCH_2_05, STACKS_EPOCH_MAX,
    };
    use deps::bitcoin::blockdata::transaction::Transaction;
    use deps::bitcoin::network::serialize::{deserialize, serialize_hex};
    use util::get_epoch_time_secs;
    use util::hash::*;
    use util::vrf::VRFPublicKey;

    use crate::types::chainstate::StacksAddress;
    use crate::types::chainstate::{BlockHeaderHash, SortitionId, VRFSeed};

    use super::*;

    use rand::thread_rng;
    use rand::RngCore;
    use vm::costs::ExecutionCost;

    struct OpFixture {
        txstr: String,
        opstr: String,
        result: Option<LeaderBlockCommitOp>,
    }

    struct CheckFixture {
        op: LeaderBlockCommitOp,
        res: Result<(), op_error>,
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex string")?;
        let tx = deserialize(&tx_bin.to_vec()).map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    #[test]
    fn test_parse_sunset_end() {
        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843021;
        burnchain.pox_constants.sunset_end = 16843022;

        let err = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap_err();

        assert!(if let op_error::BlockCommitBadOutputs = err {
            true
        } else {
            false
        });

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843021;
        burnchain.pox_constants.sunset_end = 16843022;

        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap();

        assert_eq!(op.commit_outs.len(), 1);
        assert!(op.commit_outs[0].is_burn());
        assert_eq!(op.burn_fee, 10);
    }

    #[test]
    fn test_parse_pox_commits() {
        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 30,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap();

        // should have 2 commit outputs, summing to 20 burned units
        assert_eq!(op.commit_outs.len(), 2);
        assert_eq!(op.burn_fee, 20);
        // the third output, because it's a burn, should have counted as a sunset_burn
        assert_eq!(op.sunset_burn, 30);

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 9,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // burn amount should have been 10, not 9
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap_err()
        {
            op_error::ParseError => {}
            _ => unreachable!(),
        };

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap();

        // should have 2 commit outputs
        assert_eq!(op.commit_outs.len(), 2);
        assert_eq!(op.burn_fee, 26);
        // the third output, because it's not a burn, should not have counted as a sunset_burn
        assert_eq!(op.sunset_burn, 0);

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![BitcoinTxOutput {
                units: 13,
                address: BitcoinAddress {
                    addrtype: BitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                },
            }],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // not enough PoX outputs
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap_err()
        {
            op_error::InvalidInput => {}
            _ => unreachable!(),
        };

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // unequal PoX outputs
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap_err()
        {
            op_error::ParseError => {}
            _ => unreachable!(),
        };

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // 0 total burn
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            &tx,
        )
        .unwrap_err()
        {
            op_error::ParseError => {}
            _ => unreachable!(),
        };
    }

    #[test]
    fn test_parse() {
        let vtxindex = 1;
        let block_height = 0x71706363; // epoch number must be strictly smaller than block height
        let burn_header_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let tx_fixtures = vec![
            OpFixture {
                // valid
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100eba8c0a57c1eb71cdfba0874de63cf37b3aace1e56dcbd61701548194a79af34022041dd191256f3f8a45562e5d60956bb871421ba69db605716250554b23b08277b012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000040000000000000000536a4c5069645b22222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333404142435051606162637071fa39300000000000001976a914000000000000000000000000000000000000000088ac39300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".into(),
                opstr: "69645b22222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333404142435051606162637071fa".to_string(),
                result: Some(LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 0x40414243,
                    parent_vtxindex: 0x5051,
                    key_block_ptr: 0x60616263,
                    key_vtxindex: 0x7071,
                    memo: vec![0x1f],

                    commit_outs: vec![
                        StacksAddress { version: 26, bytes: Hash160::empty() },
                        StacksAddress { version: 26, bytes: Hash160::empty() }
                    ],

                    burn_fee: 24690,
                    input: (Txid([0x11; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![
                            StacksPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH
                    },

                    txid: Txid::from_hex("502f3e5756de7e1bdba8c713cd2daab44adb5337d14ff668fdc57cc27d67f0d4").unwrap(),
                    vtxindex: vtxindex,
                    block_height: block_height,
                    burn_parent_modulus: ((block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
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

        let mut is_first = false;
        for tx_fixture in tx_fixtures {
            let mut tx = make_tx(&tx_fixture.txstr).unwrap();
            if is_first {
                eprintln!("TX outputs: {}", tx.output.len());
                tx.output.insert(
                    2,
                    StacksAddress::burn_address(false).to_bitcoin_tx_out(12345),
                );
                is_first = false;
                eprintln!("Updated txstr = {}", serialize_hex(&tx).unwrap());
                assert!(false);
            }

            let header = match tx_fixture.result {
                Some(ref op) => BurnchainBlockHeader {
                    block_height: op.block_height,
                    block_hash: op.burn_header_hash.clone(),
                    parent_block_hash: op.burn_header_hash.clone(),
                    num_txs: 1,
                    timestamp: get_epoch_time_secs(),
                },
                None => BurnchainBlockHeader {
                    block_height: 0,
                    block_hash: BurnchainHeaderHash::zero(),
                    parent_block_hash: BurnchainHeaderHash::zero(),
                    num_txs: 0,
                    timestamp: get_epoch_time_secs(),
                },
            };
            let burnchain_tx =
                BurnchainTransaction::Bitcoin(parser.parse_tx(&tx, vtxindex as usize).unwrap());

            let mut burnchain = Burnchain::regtest("nope");
            burnchain.pox_constants.sunset_start = block_height;
            burnchain.pox_constants.sunset_end = block_height + 1;

            let op = LeaderBlockCommitOp::from_tx(&burnchain, &header, &burnchain_tx);

            match (op, tx_fixture.result) {
                (Ok(parsed_tx), Some(result)) => {
                    let opstr = {
                        let mut buffer = vec![];
                        let mut magic_bytes = BLOCKSTACK_MAGIC_MAINNET.as_bytes().to_vec();
                        buffer.append(&mut magic_bytes);
                        parsed_tx
                            .consensus_serialize(&mut buffer)
                            .expect("FATAL: invalid operation");
                        to_hex(&buffer)
                    };

                    assert_eq!(tx_fixture.opstr, opstr);
                    assert_eq!(parsed_tx, result);
                }
                (Err(_e), None) => {}
                (Ok(_parsed_tx), None) => {
                    eprintln!("Parsed a tx when we should not have");
                    assert!(false);
                }
                (Err(_e), Some(_result)) => {
                    eprintln!("Did not parse a tx when we should have");
                    assert!(false);
                }
            };
        }
    }

    #[test]
    fn test_check() {
        let first_block_height = 121;
        let first_burn_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000123",
        )
        .unwrap();

        let block_122_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001220",
        )
        .unwrap();
        let block_123_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001230",
        )
        .unwrap();
        let block_124_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001240",
        )
        .unwrap();
        let block_125_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001250",
        )
        .unwrap();
        let block_126_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001260",
        )
        .unwrap();

        let block_header_hashes = [
            block_122_hash.clone(),
            block_123_hash.clone(),
            block_124_hash.clone(),
            block_125_hash.clone(), // prepare phase
            block_126_hash.clone(), // prepare phase
        ];

        let burnchain = Burnchain {
            pox_constants: PoxConstants::new(6, 2, 2, 25, 5, 5000, 10000),
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height,
            initial_reward_start_block: first_block_height,
            first_block_timestamp: 0,
            first_block_hash: first_burn_hash.clone(),
        };

        let leader_key_1 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(
                &BitcoinAddress::from_scriptpubkey(
                    BitcoinNetworkType::Testnet,
                    &hex_bytes("76a914306231b2782b5f80d944bf69f9d46a1453a0a0eb88ac").unwrap(),
                )
                .unwrap(),
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 456,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        let leader_key_2 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(
                &BitcoinAddress::from_scriptpubkey(
                    BitcoinNetworkType::Testnet,
                    &hex_bytes("76a914306231b2782b5f80d944bf69f9d46a1453a0a0eb88ac").unwrap(),
                )
                .unwrap(),
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 457,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        // consumes leader_key_1
        let block_commit_1 = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222222222222222222222222222")
                    .unwrap(),
            )
            .unwrap(),
            new_seed: VRFSeed::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333333333333333333333333333")
                    .unwrap(),
            )
            .unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 124,
            key_vtxindex: 456,
            memo: vec![0x80],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 444,
            block_height: 125,
            burn_parent_modulus: (124 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
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
            vec![BlockstackOperationType::LeaderBlockCommit(
                block_commit_1.clone(),
            )],
            // 126
            vec![],
        ];

        let tip_index_root = {
            let mut prev_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
            for i in 0..block_header_hashes.len() {
                let mut snapshot_row = BlockSnapshot {
                    accumulated_coinbase_ustx: 0,
                    pox_valid: true,
                    block_height: (i + 1 + first_block_height as usize) as u64,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: block_header_hashes[i].clone(),
                    sortition_id: SortitionId(block_header_hashes[i as usize].0.clone()),
                    parent_sortition_id: prev_snapshot.sortition_id.clone(),
                    parent_burn_header_hash: prev_snapshot.burn_header_hash.clone(),
                    consensus_hash: ConsensusHash::from_bytes(&[
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (i + 1) as u8,
                    ])
                    .unwrap(),
                    ops_hash: OpsHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    total_burn: i as u64,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: (i + 1) as u64,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
                };
                let mut tx =
                    SortitionHandleTx::begin(&mut db, &prev_snapshot.sortition_id).unwrap();
                let next_index_root = tx
                    .append_chain_tip_snapshot(
                        &prev_snapshot,
                        &snapshot_row,
                        &block_ops[i],
                        &vec![],
                        None,
                        None,
                        None,
                    )
                    .unwrap();

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
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 50,
                    parent_vtxindex: 456,
                    key_block_ptr: 1,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 80,
                    burn_parent_modulus: (79 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitPredatesGenesis),
            },
            CheckFixture {
                // reject -- no such leader key
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 1,
                    parent_vtxindex: 444,
                    key_block_ptr: 2,
                    key_vtxindex: 400,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoLeaderKey),
            },
            CheckFixture {
                // reject -- previous block must exist
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 445,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    commit_outs: vec![],
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoParent),
            },
            CheckFixture {
                // reject -- previous block must exist in a different block
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 126,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoParent),
            },
            CheckFixture {
                // reject -- tx input does not match any leader keys
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "03984286096373539ae529bd997c92792d4e5b5967be72979a42f587a625394116",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // reject -- fee is 0
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 0,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitBadInput),
            },
            CheckFixture {
                // accept -- consumes leader_key_2
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // accept -- builds directly off of genesis block and consumes leader_key_2
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // accept -- also consumes leader_key_1
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 456,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner {
                        public_keys: vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                        num_sigs: 1,
                        hash_mode: AddressHashMode::SerializeP2PKH,
                    },

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
        ];

        for (ix, fixture) in fixtures.iter().enumerate() {
            eprintln!("Processing {}", ix);
            let header = BurnchainBlockHeader {
                block_height: fixture.op.block_height,
                block_hash: fixture.op.burn_header_hash.clone(),
                parent_block_hash: fixture.op.burn_header_hash.clone(),
                num_txs: 1,
                timestamp: get_epoch_time_secs(),
            };
            let mut ic = SortitionHandleTx::begin(
                &mut db,
                &SortitionId::stubbed(&fixture.op.burn_header_hash),
            )
            .unwrap();
            assert_eq!(
                format!("{:?}", &fixture.res),
                format!("{:?}", &fixture.op.check(&burnchain, &mut ic, None))
            );
        }
    }

    #[test]
    fn test_epoch_marker_2_05() {
        let first_block_height = 121;
        let first_burn_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let burnchain = Burnchain {
            pox_constants: PoxConstants::new(6, 2, 2, 25, 5, 5000, 10000),
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height,
            initial_reward_start_block: first_block_height,
            first_block_timestamp: 0,
            first_block_hash: first_burn_hash.clone(),
        };

        let epoch_2_05_start = 125;

        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let db_path_dir = format!("/tmp/test-blockstack-sortdb-{}", to_hex(&buf));

        let mut db = SortitionDB::connect(
            &db_path_dir,
            first_block_height,
            &first_burn_hash,
            get_epoch_time_secs(),
            &vec![
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch10,
                    start_height: 0,
                    end_height: first_block_height,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_1_0,
                },
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch20,
                    start_height: first_block_height,
                    end_height: epoch_2_05_start,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_0,
                },
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch2_05,
                    start_height: epoch_2_05_start,
                    end_height: STACKS_EPOCH_MAX,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_05,
                },
            ],
            true,
        )
        .unwrap();

        let leader_key = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash([0x01; 20]),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_string("ST23T8X3WGA59XM4RA7NE4ZAG332V10PSS135TTZR")
                .unwrap(),
            txid: Txid([0x01; 32]),
            vtxindex: 456,
            block_height: first_block_height + 1,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_pre_2_05 = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x02; 32]),
            new_seed: VRFSeed([0x03; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![0x80],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            txid: Txid([0x02; 32]),
            vtxindex: 444,
            block_height: first_block_height + 2,
            burn_parent_modulus: ((first_block_height + 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_valid = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x03; 32]),
            new_seed: VRFSeed([0x04; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_05_MARKER],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "024d8cdaef508d665dd9dd50ca7e9fbd9e7984ec8bfac8f02dea9f02a9232af1d7",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            txid: Txid([0x03; 32]),
            vtxindex: 444,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_valid_bigger_epoch = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x03; 32]),
            new_seed: VRFSeed([0x04; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_05_MARKER + 1],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "024d8cdaef508d665dd9dd50ca7e9fbd9e7984ec8bfac8f02dea9f02a9232af1d7",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            txid: Txid([0x13; 32]),
            vtxindex: 444,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_invalid_bad_memo = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x04; 32]),
            new_seed: VRFSeed([0x05; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_05_MARKER - 1],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02b20f7d690afa0464d7eb17bdd86820261fb1acfdf489b2442a205a693da231ac",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            txid: Txid([0x04; 32]),
            vtxindex: 445,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_invalid_no_memo = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x05; 32]),
            new_seed: VRFSeed([0x06; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02e371309f1c25abc5f00353d74632c6f5b95eb80e1e1edb9ba53e14b0d47bc0de",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            txid: Txid([0x05; 32]),
            vtxindex: 446,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let all_leader_key_ops = vec![leader_key];

        let all_block_commit_ops = vec![
            (block_commit_pre_2_05, true),
            (block_commit_post_2_05_valid, true),
            (block_commit_post_2_05_valid_bigger_epoch, true),
            (block_commit_post_2_05_invalid_bad_memo, false),
            (block_commit_post_2_05_invalid_no_memo, false),
        ];

        let mut sn = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
        for i in sn.block_height..(epoch_2_05_start + 2) {
            eprintln!("Block {}", i);
            let mut byte_pattern = [0u8; 32];
            byte_pattern[24..32].copy_from_slice(&i.to_be_bytes());
            let next_hash = BurnchainHeaderHash(byte_pattern);

            let mut block_ops = vec![];
            for op in all_leader_key_ops.iter() {
                if op.block_height == i + 1 {
                    let mut block_op = op.clone();
                    block_op.burn_header_hash = next_hash.clone();
                    block_ops.push(BlockstackOperationType::LeaderKeyRegister(block_op));
                }
            }

            {
                let tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
                eprintln!("Tip sortition is {}", &tip.sortition_id);
                let mut ic = SortitionHandleTx::begin(&mut db, &tip.sortition_id).unwrap();

                for (op, pass) in all_block_commit_ops.iter() {
                    if op.block_height == i + 1 {
                        match op.check(&burnchain, &mut ic, None) {
                            Ok(_) => {
                                assert!(
                                    pass,
                                    "Check succeeded when it should have failed: {:?}",
                                    &op
                                );
                                block_ops
                                    .push(BlockstackOperationType::LeaderBlockCommit(op.clone()));
                            }
                            Err(op_error::BlockCommitBadEpoch) => {
                                assert!(
                                    !pass,
                                    "Check failed when it should have succeeded: {:?}",
                                    &op
                                );
                            }
                            Err(e) => {
                                panic!("Unexpected error variant {}", &e);
                            }
                        }
                    }
                }
            }
            sn = test_append_snapshot(&mut db, next_hash, &block_ops);
        }
    }
}
