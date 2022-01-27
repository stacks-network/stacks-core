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

use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;

use address::AddressHashMode;
use burnchains::Address;
use burnchains::Burnchain;
use burnchains::PublicKey;
use burnchains::Txid;
use burnchains::{BurnchainRecipient, BurnchainSigner, BurnchainTransaction};
use chainstate::burn::operations::{
    leader_block_commit::MissedBlockCommit, BlockstackOperationType, LeaderBlockCommitOp,
    LeaderKeyRegisterOp, UserBurnSupportOp,
};
use chainstate::stacks::StacksPublicKey;
use core::MINING_COMMITMENT_WINDOW;
use monitoring;
use util::hash::Hash160;
use util::log;
use util::uint::BitArray;
use util::uint::Uint256;
use util::uint::Uint512;
use util::vrf::VRFPublicKey;

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::types::chainstate::StacksAddress;
    use address::AddressHashMode;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::BitcoinNetworkType;
    use burnchains::Address;
    use burnchains::Burnchain;
    use burnchains::BurnchainSigner;
    use burnchains::PublicKey;
    use burnchains::Txid;
    use chainstate::burn::operations::{
        leader_block_commit::{MissedBlockCommit, BURN_BLOCK_MINED_AT_MODULUS},
        BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp, UserBurnSupportOp,
    };
    use chainstate::burn::ConsensusHash;
    use chainstate::stacks::StacksPublicKey;
    use core::MINING_COMMITMENT_WINDOW;
    use util::hash::hex_bytes;
    use util::hash::Hash160;
    use util::log;
    use util::uint::BitArray;
    use util::uint::Uint256;
    use util::uint::Uint512;
    use util::vrf::*;

    use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};
    use crate::types::chainstate::{SortitionId, VRFSeed};

    use super::BurnSamplePoint;

    struct BurnDistFixture {
        consumed_leader_keys: Vec<LeaderKeyRegisterOp>,
        block_commits: Vec<LeaderBlockCommitOp>,
        user_burns: Vec<UserBurnSupportOp>,
        res: Vec<BurnSamplePoint>,
    }

    fn make_user_burn(
        burn_fee: u64,
        vrf_ident: u32,
        block_id: u64,
        txid_id: u64,
        block_height: u64,
    ) -> UserBurnSupportOp {
        let mut block_header_hash = [0; 32];
        block_header_hash[0..8].copy_from_slice(&block_id.to_be_bytes());
        let mut txid = [3; 32];
        txid[0..8].copy_from_slice(&txid_id.to_be_bytes());
        let txid = Txid(txid);

        UserBurnSupportOp {
            address: StacksAddress {
                version: 0,
                bytes: Hash160([0; 20]),
            },
            consensus_hash: ConsensusHash([0; 20]),
            public_key: VRFPublicKey::from_private(&VRFPrivateKey::new()),
            key_block_ptr: vrf_ident,
            key_vtxindex: 0,
            block_header_hash_160: Hash160::from_sha256(&block_header_hash),
            burn_fee,
            txid,
            vtxindex: 0,  // index in the block where this tx occurs
            block_height, // block height at which this tx occurs
            burn_header_hash: BurnchainHeaderHash([0; 32]), // hash of burnchain block with this tx
        }
    }

    fn make_missed_commit(txid_id: u64, input_tx: u64) -> MissedBlockCommit {
        let mut txid = [0; 32];
        txid[0..8].copy_from_slice(&txid_id.to_be_bytes());
        let mut input_txid = [0; 32];
        input_txid[0..8].copy_from_slice(&input_tx.to_be_bytes());
        let txid = Txid(txid);
        let input_txid = Txid(input_txid);
        MissedBlockCommit {
            txid,
            input: (input_txid, 3),
            intended_sortition: SortitionId([0; 32]),
        }
    }

    fn make_block_commit(
        burn_fee: u64,
        vrf_ident: u32,
        block_id: u64,
        txid_id: u64,
        input_tx: Option<u64>,
        block_ht: u64,
    ) -> LeaderBlockCommitOp {
        let mut block_header_hash = [0; 32];
        block_header_hash[0..8].copy_from_slice(&block_id.to_be_bytes());
        let mut txid = [0; 32];
        txid[0..8].copy_from_slice(&txid_id.to_be_bytes());
        let mut input_txid = [0; 32];
        if let Some(input_tx) = input_tx {
            input_txid[0..8].copy_from_slice(&input_tx.to_be_bytes());
        } else {
            // no txid will match
            input_txid.copy_from_slice(&[1; 32]);
        }
        let txid = Txid(txid);
        let input_txid = Txid(input_txid);

        LeaderBlockCommitOp {
            block_header_hash: BlockHeaderHash(block_header_hash),
            new_seed: VRFSeed([0; 32]),
            parent_block_ptr: (block_id - 1) as u32,
            parent_vtxindex: 0,
            key_block_ptr: vrf_ident,
            key_vtxindex: 0,
            memo: vec![],
            burn_fee,
            input: (input_txid, 3),
            apparent_sender: BurnchainSigner::new_p2pkh(&StacksPublicKey::new()),
            commit_outs: vec![],
            sunset_burn: 0,
            txid,
            vtxindex: 0,
            block_height: block_ht,
            burn_parent_modulus: if block_ht > 0 {
                ((block_ht - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8
            } else {
                BURN_BLOCK_MINED_AT_MODULUS as u8 - 1
            },
            burn_header_hash: BurnchainHeaderHash([0; 32]),
        }
    }

    #[test]
    fn make_mean_min_median_sunset_in_window() {
        //    miner 1:  3 4 5 4 5 4
        //       ub  :  1 0 0 0 0 0
        //                    | sunset end
        //    miner 2:  1 3 3 3 3 3
        //       ub  :  1 0 0 0 0 0
        //              0 1 0 0 0 0
        //                   ..

        // miner 1 => min = 1, median = 1, last_burn = 4
        // miner 2 => min = 1, median = 1, last_burn = 3

        let mut commits = vec![
            vec![
                make_block_commit(3, 1, 1, 1, None, 1),
                make_block_commit(1, 2, 2, 2, None, 1),
            ],
            vec![
                make_block_commit(4, 3, 3, 3, Some(1), 2),
                make_block_commit(3, 4, 4, 4, Some(2), 2),
            ],
            vec![
                make_block_commit(5, 5, 5, 5, Some(3), 3),
                make_block_commit(3, 6, 6, 6, Some(4), 3),
            ],
            vec![
                make_block_commit(4, 7, 7, 7, Some(5), 4),
                make_block_commit(3, 8, 8, 8, Some(6), 4),
            ],
            vec![
                make_block_commit(5, 9, 9, 9, Some(7), 5),
                make_block_commit(3, 10, 10, 10, Some(8), 5),
            ],
            vec![
                make_block_commit(4, 11, 11, 11, Some(9), 6),
                make_block_commit(3, 12, 12, 12, Some(10), 6),
            ],
        ];
        let user_burns = vec![
            vec![make_user_burn(1, 1, 1, 1, 1), make_user_burn(1, 2, 2, 2, 1)],
            vec![make_user_burn(1, 4, 4, 4, 2)],
            vec![make_user_burn(1, 6, 6, 6, 3)],
            vec![make_user_burn(1, 8, 8, 8, 4)],
            vec![make_user_burn(1, 10, 10, 10, 5)],
            vec![make_user_burn(1, 12, 12, 12, 6)],
        ];

        let mut result = BurnSamplePoint::make_min_median_distribution(
            commits.clone(),
            vec![vec![]; (MINING_COMMITMENT_WINDOW - 1) as usize],
            vec![false, false, false, true, true, true],
        );

        assert_eq!(result.len(), 2, "Should be two miners");

        result.sort_by_key(|sample| sample.candidate.txid);

        // block-commits are currently malformed -- the post-sunset commits spend the wrong UTXO.
        assert_eq!(result[0].burns, 1);
        assert_eq!(result[1].burns, 1);

        // make sure that we're associating with the last commit in the window.
        assert_eq!(result[0].candidate.txid, commits[5][0].txid);
        assert_eq!(result[1].candidate.txid, commits[5][1].txid);

        assert_eq!(result[0].user_burns.len(), 0);
        assert_eq!(result[1].user_burns.len(), 0);

        // now correct the back pointers so that they point
        //   at the correct UTXO position *post-sunset*
        for (ix, window_slice) in commits.iter_mut().enumerate() {
            if ix >= 4 {
                for commit in window_slice.iter_mut() {
                    commit.input.1 = 2;
                }
            }
        }

        //    miner 1:  3 4 5 4 5 4
        //    miner 2:  1 3 3 3 3 3
        // miner 1 => min = 3, median = 4, last_burn = 4
        // miner 2 => min = 1, median = 3, last_burn = 3

        let mut result = BurnSamplePoint::make_min_median_distribution(
            commits.clone(),
            vec![vec![]; (MINING_COMMITMENT_WINDOW - 1) as usize],
            vec![false, false, false, true, true, true],
        );

        assert_eq!(result.len(), 2, "Should be two miners");

        result.sort_by_key(|sample| sample.candidate.txid);

        assert_eq!(result[0].burns, 4);
        assert_eq!(result[1].burns, 3);

        // make sure that we're associating with the last commit in the window.
        assert_eq!(result[0].candidate.txid, commits[5][0].txid);
        assert_eq!(result[1].candidate.txid, commits[5][1].txid);

        assert_eq!(result[0].user_burns.len(), 0);
        assert_eq!(result[1].user_burns.len(), 0);
    }

    #[test]
    fn make_mean_min_median() {
        // test case 1:
        //    miner 1:  3 4 5 4 5 4
        //       ub  :  1 0 0 0 0 0
        //    miner 2:  1 3 3 3 3 3
        //       ub  :  1 0 0 0 0 0
        //              0 1 0 0 0 0
        //                   ..

        // user burns are ignored:
        //
        // miner 1 => min = 3, median = 4, last_burn = 4
        // miner 2 => min = 1, median = 3, last_burn = 3

        let commits = vec![
            vec![
                make_block_commit(3, 1, 1, 1, None, 1),
                make_block_commit(1, 2, 2, 2, None, 1),
            ],
            vec![
                make_block_commit(4, 3, 3, 3, Some(1), 2),
                make_block_commit(3, 4, 4, 4, Some(2), 2),
            ],
            vec![
                make_block_commit(5, 5, 5, 5, Some(3), 3),
                make_block_commit(3, 6, 6, 6, Some(4), 3),
            ],
            vec![
                make_block_commit(4, 7, 7, 7, Some(5), 4),
                make_block_commit(3, 8, 8, 8, Some(6), 4),
            ],
            vec![
                make_block_commit(5, 9, 9, 9, Some(7), 5),
                make_block_commit(3, 10, 10, 10, Some(8), 5),
            ],
            vec![
                make_block_commit(4, 11, 11, 11, Some(9), 6),
                make_block_commit(3, 12, 12, 12, Some(10), 6),
            ],
        ];
        let user_burns = vec![
            vec![make_user_burn(1, 1, 1, 1, 1), make_user_burn(1, 2, 2, 2, 1)],
            vec![make_user_burn(1, 4, 4, 4, 2)],
            vec![make_user_burn(1, 6, 6, 6, 3)],
            vec![make_user_burn(1, 8, 8, 8, 4)],
            vec![make_user_burn(1, 10, 10, 10, 5)],
            vec![make_user_burn(1, 12, 12, 12, 6)],
        ];

        let mut result = BurnSamplePoint::make_min_median_distribution(
            commits.clone(),
            vec![vec![]; (MINING_COMMITMENT_WINDOW - 1) as usize],
            vec![false, false, false, false, false, false],
        );

        assert_eq!(result.len(), 2, "Should be two miners");

        result.sort_by_key(|sample| sample.candidate.txid);

        assert_eq!(result[0].burns, 4);
        assert_eq!(result[1].burns, 3);

        // make sure that we're associating with the last commit in the window.
        assert_eq!(result[0].candidate.txid, commits[5][0].txid);
        assert_eq!(result[1].candidate.txid, commits[5][1].txid);

        assert_eq!(result[0].user_burns.len(), 0);
        assert_eq!(result[1].user_burns.len(), 0);

        // test case 2:
        //    miner 1:  4 4 5 4 5 3
        //    miner 2:  4 4 4 4 4 1
        //       ub  :  0 0 0 0 0 2
        //               *split*

        // miner 1 => min = 3, median = 4, last_burn = 3
        // miner 2 => min = 1, median = 4, last_burn = 1

        let commits = vec![
            vec![
                make_block_commit(4, 1, 1, 1, None, 1),
                make_block_commit(4, 2, 2, 2, None, 1),
            ],
            vec![
                make_block_commit(4, 3, 3, 3, Some(1), 2),
                make_block_commit(4, 4, 4, 4, Some(2), 2),
            ],
            vec![
                make_block_commit(5, 5, 5, 5, Some(3), 3),
                make_block_commit(4, 6, 6, 6, Some(4), 3),
            ],
            vec![
                make_block_commit(4, 7, 7, 7, Some(5), 4),
                make_block_commit(4, 8, 8, 8, Some(6), 4),
            ],
            vec![
                make_block_commit(5, 9, 9, 9, Some(7), 5),
                make_block_commit(4, 10, 10, 10, Some(8), 5),
            ],
            vec![
                make_block_commit(3, 11, 11, 11, Some(9), 6),
                make_block_commit(1, 11, 11, 12, Some(10), 6),
            ],
        ];
        let user_burns = vec![
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![make_user_burn(2, 11, 11, 1, 6)],
        ];

        let mut result = BurnSamplePoint::make_min_median_distribution(
            commits.clone(),
            vec![vec![]; (MINING_COMMITMENT_WINDOW - 1) as usize],
            vec![false, false, false, false, false, false],
        );

        assert_eq!(result.len(), 2, "Should be two miners");

        result.sort_by_key(|sample| sample.candidate.txid);

        assert_eq!(result[0].burns, 3);
        assert_eq!(result[1].burns, 1);

        // make sure that we're associating with the last commit in the window.
        assert_eq!(result[0].candidate.txid, commits[5][0].txid);
        assert_eq!(result[1].candidate.txid, commits[5][1].txid);

        assert_eq!(result[0].user_burns.len(), 0);
        assert_eq!(result[1].user_burns.len(), 0);
    }

    #[test]
    fn missed_block_commits() {
        // test case 1:
        //    miner 1:  3 4 5 4 missed 4
        //    miner 2:  3 3 missed 3 3 3
        //
        // miner 1 => min = 0, median = 4, last_burn = 4
        // miner 2 => min = 0, median = 3, last_burn = 3

        let commits = vec![
            vec![
                make_block_commit(3, 1, 1, 1, None, 1),
                make_block_commit(1, 2, 2, 2, None, 1),
            ],
            vec![
                make_block_commit(4, 3, 3, 3, Some(1), 2),
                make_block_commit(3, 4, 4, 4, Some(2), 2),
            ],
            vec![make_block_commit(5, 5, 5, 5, Some(3), 3)],
            vec![
                make_block_commit(4, 7, 7, 7, Some(5), 4),
                make_block_commit(3, 8, 8, 8, Some(6), 4),
            ],
            vec![make_block_commit(3, 10, 10, 10, Some(8), 5)],
            vec![
                make_block_commit(4, 11, 11, 11, Some(9), 6),
                make_block_commit(3, 12, 12, 12, Some(10), 6),
            ],
        ];

        let missed_commits = vec![
            vec![],
            vec![],
            vec![make_missed_commit(6, 4)],
            vec![],
            vec![make_missed_commit(9, 7)],
        ];

        let mut result = BurnSamplePoint::make_min_median_distribution(
            commits.clone(),
            missed_commits.clone(),
            vec![false, false, false, false, false, false],
        );

        assert_eq!(result.len(), 2, "Should be two miners");

        result.sort_by_key(|sample| sample.candidate.txid);

        assert_eq!(result[0].burns, 4);
        assert_eq!(result[1].burns, 3);

        // make sure that we're associating with the last commit in the window.
        assert_eq!(result[0].candidate.txid, commits[5][0].txid);
        assert_eq!(result[1].candidate.txid, commits[5][1].txid);
    }

    #[test]
    fn make_burn_distribution() {
        let first_burn_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

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
                    &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap(),
                )
                .unwrap(),
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 456,
            block_height: 123,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
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
                    &hex_bytes("76a91432b6c66189da32bd0a9f00ee4927f569957d71aa88ac").unwrap(),
                )
                .unwrap(),
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 457,
            block_height: 122,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
        };

        let leader_key_3 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("de8af7037e522e65d2fe2d63fb1b764bfea829df78b84444338379df13144a02")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![01, 02, 03, 04, 05],
            address: StacksAddress::from_bitcoin_address(
                &BitcoinAddress::from_scriptpubkey(
                    BitcoinNetworkType::Testnet,
                    &hex_bytes("76a91432b6c66189da32bd0a9f00ee4927f569957d71aa88ac").unwrap(),
                )
                .unwrap(),
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("eb54704f71d4a2d1128d60ffccced547054b52250ada6f3e7356165714f44d4c")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 10,
            block_height: 121,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000012",
            )
            .unwrap(),
        };

        let user_burn_noblock = UserBurnSupportOp {
            address: StacksAddress::new(1, Hash160([1u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("4444444444444444444444444444444444444444").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            block_header_hash_160: Hash160::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333").unwrap(),
            )
            .unwrap(),
            key_block_ptr: 1,
            key_vtxindex: 772,
            burn_fee: 12345,

            txid: Txid::from_bytes_be(
                &hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 12,
            block_height: 124,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let user_burn_1 = UserBurnSupportOp {
            address: StacksAddress::new(2, Hash160([2u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("4444444444444444444444444444444444444444").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            block_header_hash_160: Hash160::from_bytes(
                &hex_bytes("7150f635054b87df566a970b21e07030d6444bf2").unwrap(),
            )
            .unwrap(), // 22222....2222
            key_block_ptr: 123,
            key_vtxindex: 456,
            burn_fee: 10000,

            txid: Txid::from_bytes_be(
                &hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 13,
            block_height: 124,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let user_burn_1_2 = UserBurnSupportOp {
            address: StacksAddress::new(3, Hash160([3u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("4444444444444444444444444444444444444444").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            block_header_hash_160: Hash160::from_bytes(
                &hex_bytes("7150f635054b87df566a970b21e07030d6444bf2").unwrap(),
            )
            .unwrap(), // 22222....2222
            key_block_ptr: 123,
            key_vtxindex: 456,
            burn_fee: 30000,

            txid: Txid::from_bytes_be(
                &hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 14,
            block_height: 124,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let user_burn_2 = UserBurnSupportOp {
            address: StacksAddress::new(4, Hash160([4u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("4444444444444444444444444444444444444444").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c")
                    .unwrap(),
            )
            .unwrap(),
            block_header_hash_160: Hash160::from_bytes(
                &hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap(),
            )
            .unwrap(), // 22222....2223
            key_block_ptr: 122,
            key_vtxindex: 457,
            burn_fee: 20000,

            txid: Txid::from_bytes_be(
                &hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716d")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 15,
            block_height: 124,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let user_burn_2_2 = UserBurnSupportOp {
            address: StacksAddress::new(5, Hash160([5u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("4444444444444444444444444444444444444444").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c")
                    .unwrap(),
            )
            .unwrap(),
            block_header_hash_160: Hash160::from_bytes(
                &hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap(),
            )
            .unwrap(), // 22222....2223
            key_block_ptr: 122,
            key_vtxindex: 457,
            burn_fee: 40000,

            txid: Txid::from_bytes_be(
                &hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 16,
            block_height: 124,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let user_burn_nokey = UserBurnSupportOp {
            address: StacksAddress::new(6, Hash160([6u8; 20])),
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("4444444444444444444444444444444444444444").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("3f3338db51f2b1f6ac0cf6177179a24ee130c04ef2f9849a64a216969ab60e70")
                    .unwrap(),
            )
            .unwrap(),
            block_header_hash_160: Hash160::from_bytes(
                &hex_bytes("037a1e860899a4fa823c18b66f6264d20236ec58").unwrap(),
            )
            .unwrap(),
            key_block_ptr: 121,
            key_vtxindex: 772,
            burn_fee: 12345,

            txid: Txid::from_bytes_be(
                &hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716e")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 17,
            block_height: 124,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

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
            parent_block_ptr: 111,
            parent_vtxindex: 456,
            key_block_ptr: 123,
            key_vtxindex: 456,
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

            commit_outs: vec![],

            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 443,
            block_height: 124,
            burn_parent_modulus: (123 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let block_commit_2 = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222222222222222222222222223")
                    .unwrap(),
            )
            .unwrap(),
            new_seed: VRFSeed::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333333333333333333333333334")
                    .unwrap(),
            )
            .unwrap(),
            parent_block_ptr: 112,
            parent_vtxindex: 111,
            key_block_ptr: 122,
            key_vtxindex: 457,
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

            commit_outs: vec![],

            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27d0")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 444,
            block_height: 124,
            burn_parent_modulus: (123 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        let block_commit_3 = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222222222222222222222222224")
                    .unwrap(),
            )
            .unwrap(),
            new_seed: VRFSeed::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333333333333333333333333335")
                    .unwrap(),
            )
            .unwrap(),
            parent_block_ptr: 113,
            parent_vtxindex: 111,
            key_block_ptr: 121,
            key_vtxindex: 10,
            memo: vec![0x80],

            burn_fee: 23456,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            commit_outs: vec![],

            txid: Txid::from_bytes_be(
                &hex_bytes("301dc687a9f06a1ae87a013f27133e9cec0843c2983567be73e185827c7c13de")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 445,
            block_height: 124,
            burn_parent_modulus: (123 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000004",
            )
            .unwrap(),
        };

        /*
         You can generate the burn sample ranges with this Python script:
         #!/usr/bin/python

         import sys

         a = eval(sys.argv[1])
         b = eval(sys.argv[2])

         s = '{:0128x}'.format((a * (2**256 - 1)) / b).decode('hex')[::-1];
         l = ['0x{:016x}'.format(int(s[(8*i):(8*(i+1))][::-1].encode('hex'),16)) for i in range(0,(256/8/8))]

         print float(a) / b
         print '{:0128x}'.format((a * (2**256 - 1)) / b)
         print '[' + ', '.join(l) + ']'
        */

        let fixtures: Vec<BurnDistFixture> = vec![
            BurnDistFixture {
                consumed_leader_keys: vec![],
                block_commits: vec![],
                user_burns: vec![],
                res: vec![],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone()],
                block_commits: vec![block_commit_1.clone()],
                user_burns: vec![],
                res: vec![BurnSamplePoint {
                    burns: block_commit_1.burn_fee.into(),
                    range_start: Uint256::zero(),
                    range_end: Uint256::max(),
                    candidate: block_commit_1.clone(),
                    user_burns: vec![],
                }],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone(), leader_key_2.clone()],
                block_commits: vec![block_commit_1.clone(), block_commit_2.clone()],
                user_burns: vec![],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                ],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone(), leader_key_2.clone()],
                block_commits: vec![block_commit_1.clone(), block_commit_2.clone()],
                user_burns: vec![user_burn_noblock.clone()],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                ],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone(), leader_key_2.clone()],
                block_commits: vec![block_commit_1.clone(), block_commit_2.clone()],
                user_burns: vec![user_burn_nokey.clone()],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                ],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone(), leader_key_2.clone()],
                block_commits: vec![block_commit_1.clone(), block_commit_2.clone()],
                user_burns: vec![
                    user_burn_noblock.clone(),
                    user_burn_1.clone(),
                    user_burn_nokey.clone(),
                ],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                ],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone(), leader_key_2.clone()],
                block_commits: vec![block_commit_1.clone(), block_commit_2.clone()],
                user_burns: vec![
                    user_burn_noblock.clone(),
                    user_burn_1.clone(),
                    user_burn_2.clone(),
                    user_burn_nokey.clone(),
                ],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                ],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![leader_key_1.clone(), leader_key_2.clone()],
                block_commits: vec![block_commit_1.clone(), block_commit_2.clone()],
                user_burns: vec![
                    user_burn_noblock.clone(),
                    user_burn_1.clone(),
                    user_burn_1_2.clone(),
                    user_burn_2.clone(),
                    user_burn_2_2.clone(),
                    user_burn_nokey.clone(),
                ],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0xffffffffffffffff,
                            0x7fffffffffffffff,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                ],
            },
            BurnDistFixture {
                consumed_leader_keys: vec![
                    leader_key_1.clone(),
                    leader_key_2.clone(),
                    leader_key_3.clone(),
                ],
                block_commits: vec![
                    block_commit_1.clone(),
                    block_commit_2.clone(),
                    block_commit_3.clone(),
                ],
                user_burns: vec![
                    user_burn_noblock.clone(),
                    user_burn_1.clone(),
                    user_burn_1_2.clone(),
                    user_burn_2.clone(),
                    user_burn_2_2.clone(),
                    user_burn_nokey.clone(),
                ],
                res: vec![
                    BurnSamplePoint {
                        burns: block_commit_1.burn_fee.into(),
                        range_start: Uint256::zero(),
                        range_end: Uint256([
                            0x3ed94d3cb0a84709,
                            0x0963dded799a7c1a,
                            0x70989faf596c8b65,
                            0x41a3ed94d3cb0a84,
                        ]),
                        candidate: block_commit_1.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: block_commit_2.burn_fee.into(),
                        range_start: Uint256([
                            0x3ed94d3cb0a84709,
                            0x0963dded799a7c1a,
                            0x70989faf596c8b65,
                            0x41a3ed94d3cb0a84,
                        ]),
                        range_end: Uint256([
                            0x7db29a7961508e12,
                            0x12c7bbdaf334f834,
                            0xe1313f5eb2d916ca,
                            0x8347db29a7961508,
                        ]),
                        candidate: block_commit_2.clone(),
                        user_burns: vec![],
                    },
                    BurnSamplePoint {
                        burns: (block_commit_3.burn_fee).into(),
                        range_start: Uint256([
                            0x7db29a7961508e12,
                            0x12c7bbdaf334f834,
                            0xe1313f5eb2d916ca,
                            0x8347db29a7961508,
                        ]),
                        range_end: Uint256::max(),
                        candidate: block_commit_3.clone(),
                        user_burns: vec![],
                    },
                ],
            },
        ];

        for i in 0..fixtures.len() {
            let f = &fixtures[i];
            eprintln!("Fixture #{}", i);
            let dist = BurnSamplePoint::make_distribution(
                f.block_commits.iter().cloned().collect(),
                f.consumed_leader_keys.iter().cloned().collect(),
                f.user_burns.iter().cloned().collect(),
            );
            assert_eq!(dist, f.res);
        }
    }
}
