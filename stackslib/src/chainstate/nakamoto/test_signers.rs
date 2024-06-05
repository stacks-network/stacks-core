// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::util::hash::MerkleHashFunc;
use clarity::util::secp256k1::{MessageSignature, Secp256k1PrivateKey, Secp256k1PublicKey};
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::types::*;
use hashbrown::HashMap;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use stacks_common::address::*;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{
    BlockHeaderHash, SortitionId, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::util::hash::Hash160;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};
use wsts::curve::point::Point;
use wsts::traits::Aggregator;

use self::boot::RewardSet;
use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::{
    ChainsCoordinator, Error as CoordinatorError, OnChainRewardSetProvider,
};
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{NakamotoSignerEntry, PoxStartCycleInfo};
use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::miner::*;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::core::{BOOT_BLOCK_HASH, STACKS_EPOCH_3_0_MARKER};
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::net::relay::Relayer;
use crate::util_lib::boot::boot_code_addr;
use crate::util_lib::db::Error as db_error;

#[derive(Debug, Clone, PartialEq)]
pub struct TestSigners {
    /// The parties that will sign the blocks
    pub signer_parties: Vec<wsts::v2::Party>,
    /// The commitments to the polynomials for the aggregate public key
    pub poly_commitments: HashMap<u32, wsts::common::PolyCommitment>,
    /// The aggregate public key
    pub aggregate_public_key: Point,
    /// The total number of key ids distributed among signer_parties
    pub num_keys: u32,
    /// The number of vote shares required to sign a block
    pub threshold: u32,
    /// The key ids distributed among signer_parties
    pub party_key_ids: Vec<Vec<u32>>,
    /// The cycle for which the signers are valid
    pub cycle: u64,
    /// The signer's private keys
    pub signer_keys: Vec<Secp256k1PrivateKey>,
}

impl Default for TestSigners {
    fn default() -> Self {
        let mut rng = rand_core::OsRng::default();
        let num_keys = 10;
        let threshold = 7;
        let party_key_ids: Vec<Vec<u32>> =
            vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8], vec![9, 10]];
        let num_parties = party_key_ids.len().try_into().unwrap();

        // Create the parties
        let mut signer_parties: Vec<wsts::v2::Party> = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| {
                wsts::v2::Party::new(
                    pid.try_into().unwrap(),
                    pkids,
                    num_parties,
                    num_keys,
                    threshold,
                    &mut rng,
                )
            })
            .collect();

        let mut signer_keys = Vec::<Secp256k1PrivateKey>::new();
        for _ in 0..num_keys {
            signer_keys.push(Secp256k1PrivateKey::default());
        }

        // Generate an aggregate public key
        let poly_commitments = match wsts::v2::test_helpers::dkg(&mut signer_parties, &mut rng) {
            Ok(poly_commitments) => poly_commitments,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };
        let mut sig_aggregator = wsts::v2::Aggregator::new(num_keys, threshold);
        sig_aggregator
            .init(&poly_commitments)
            .expect("aggregator init failed");
        let aggregate_public_key = sig_aggregator.poly[0];
        Self {
            signer_parties,
            aggregate_public_key,
            poly_commitments,
            num_keys,
            threshold,
            party_key_ids,
            cycle: 0,
            signer_keys,
        }
    }
}

impl TestSigners {
    /// Generate TestSigners using a list of signer keys
    pub fn new(signer_keys: Vec<Secp256k1PrivateKey>) -> Self {
        TestSigners::default_with_signers(signer_keys)
    }

    /// Internal function to generate aggregate key information
    fn default_with_signers(signer_keys: Vec<Secp256k1PrivateKey>) -> Self {
        let mut rng = rand_core::OsRng::default();
        let num_keys = 10;
        let threshold = 7;
        let party_key_ids: Vec<Vec<u32>> =
            vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8], vec![9, 10]];
        let num_parties = party_key_ids.len().try_into().unwrap();

        // Create the parties
        let mut signer_parties: Vec<wsts::v2::Party> = party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| {
                wsts::v2::Party::new(
                    pid.try_into().unwrap(),
                    pkids,
                    num_parties,
                    num_keys,
                    threshold,
                    &mut rng,
                )
            })
            .collect();

        // Generate an aggregate public key
        let poly_commitments = match wsts::v2::test_helpers::dkg(&mut signer_parties, &mut rng) {
            Ok(poly_commitments) => poly_commitments,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };
        let mut sig_aggregator = wsts::v2::Aggregator::new(num_keys, threshold);
        sig_aggregator
            .init(&poly_commitments)
            .expect("aggregator init failed");
        let aggregate_public_key = sig_aggregator.poly[0];
        Self {
            signer_parties,
            aggregate_public_key,
            poly_commitments,
            num_keys,
            threshold,
            party_key_ids,
            cycle: 0,
            signer_keys,
        }
    }

    /// Sign a Nakamoto block using [`Self::signer_keys`].
    ///
    /// N.B. If any of [`Self::signer_keys`] are not in the reward set, the resulting
    /// signatures will be invalid. Use [`Self::sign_block_with_reward_set()`] to ensure
    /// that any signer keys not in the reward set are not included.
    pub fn sign_nakamoto_block(&mut self, block: &mut NakamotoBlock, cycle: u64) {
        // Update the aggregate public key if the cycle has changed
        if self.cycle != cycle {
            self.generate_aggregate_key(cycle);
        }

        let signer_signature = self.generate_block_signatures(&block);

        test_debug!(
            "Signed Nakamoto block {} with {} signatures (rc {})",
            block.block_id(),
            signer_signature.len(),
            cycle
        );
        block.header.signer_signature = signer_signature;
    }

    /// Sign a NakamotoBlock and maintain the order and membership
    /// of the reward set signers in the resulting signatures.
    ///
    /// If any of [`Self::signer_keys`] are not in the reward set, their signatures
    /// will not be included.
    pub fn sign_block_with_reward_set(&self, block: &mut NakamotoBlock, reward_set: &RewardSet) {
        let signatures = self.generate_ordered_signatures(block, reward_set);
        block.header.signer_signature = signatures;
    }

    /// Synthesize a reward set from the signer for the purposes of signing and verifying blocks
    /// later on
    pub fn synthesize_reward_set(&self) -> RewardSet {
        let mut signer_entries = vec![];
        let mut pox_addrs = vec![];
        for key in self.signer_keys.iter() {
            let signing_key_vec = Secp256k1PublicKey::from_private(key).to_bytes_compressed();
            let mut signing_key = [0u8; 33];
            signing_key[0..33].copy_from_slice(&signing_key_vec[0..33]);

            let nakamoto_signer_entry = NakamotoSignerEntry {
                signing_key,
                stacked_amt: 100_000_000_000,
                weight: 1,
            };
            let pox_addr = PoxAddress::Standard(
                StacksAddress {
                    version: AddressHashMode::SerializeP2PKH.to_version_testnet(),
                    bytes: Hash160::from_data(&nakamoto_signer_entry.signing_key),
                },
                Some(AddressHashMode::SerializeP2PKH),
            );
            signer_entries.push(nakamoto_signer_entry);
            pox_addrs.push(pox_addr);
        }

        RewardSet {
            rewarded_addresses: pox_addrs,
            start_cycle_state: PoxStartCycleInfo {
                missed_reward_slots: vec![],
            },
            signers: Some(signer_entries),
            pox_ustx_threshold: Some(100_000_000_000),
        }
    }

    /// Sign a Nakamoto block and generate a vec of signatures. The signatures will
    /// be ordered by the signer's public keys, but will not be checked against the
    /// reward set.
    fn generate_block_signatures(&self, block: &NakamotoBlock) -> Vec<MessageSignature> {
        let msg = block.header.signer_signature_hash().0;
        let mut keys = self.signer_keys.clone();
        keys.sort_by(|a, b| {
            let a = Secp256k1PublicKey::from_private(a).to_bytes_compressed();
            let b = Secp256k1PublicKey::from_private(b).to_bytes_compressed();
            a.cmp(&b)
        });
        keys.iter().map(|key| key.sign(&msg).unwrap()).collect()
    }

    /// Sign a Nakamoto block using the aggregate key.
    /// NB: this function is current unused.
    #[allow(dead_code)]
    fn sign_block_with_aggregate_key(&mut self, block: &NakamotoBlock) -> ThresholdSignature {
        let mut rng = rand_core::OsRng::default();
        let msg = block.header.signer_signature_hash().0;
        let (nonces, sig_shares, key_ids) =
            wsts::v2::test_helpers::sign(msg.as_slice(), &mut self.signer_parties, &mut rng);

        let mut sig_aggregator = wsts::v2::Aggregator::new(self.num_keys, self.threshold);
        sig_aggregator
            .init(&self.poly_commitments)
            .expect("aggregator init failed");
        let signature = sig_aggregator
            .sign(msg.as_slice(), &nonces, &sig_shares, &key_ids)
            .expect("aggregator sig failed");
        ThresholdSignature(signature)
    }

    /// Generate an list of signatures for a block. Only
    /// signers in the reward set will be included.
    pub fn generate_ordered_signatures(
        &self,
        block: &NakamotoBlock,
        reward_set: &RewardSet,
    ) -> Vec<MessageSignature> {
        let msg = block.header.signer_signature_hash().0;

        let test_signers_by_pk = self
            .signer_keys
            .iter()
            .cloned()
            .map(|s| {
                let pk = Secp256k1PublicKey::from_private(&s);
                (pk.to_bytes_compressed(), s)
            })
            .collect::<HashMap<_, _>>();

        let reward_set_keys = &reward_set
            .clone()
            .signers
            .unwrap()
            .iter()
            .map(|s| s.signing_key.to_vec())
            .collect::<Vec<_>>();

        let mut signatures = Vec::with_capacity(reward_set_keys.len());

        let mut missing_keys = 0;

        for key in reward_set_keys {
            if let Some(signer_key) = test_signers_by_pk.get(key) {
                let signature = signer_key.sign(&msg).unwrap();
                signatures.push(signature);
            } else {
                missing_keys += 1;
            }
        }
        if missing_keys > 0 {
            warn!(
                "TestSigners: {} keys are in the reward set but not in signer_keys",
                missing_keys
            );
        }

        signatures
    }

    // Generate and assign a new aggregate public key
    pub fn generate_aggregate_key(&mut self, cycle: u64) -> Point {
        // If the key is already generated for this cycle, return it
        if cycle == self.cycle {
            debug!("Returning cached aggregate key for cycle {}", cycle);
            return self.aggregate_public_key.clone();
        }

        debug!("Generating aggregate key for cycle {}", cycle);
        let mut rng = ChaCha20Rng::seed_from_u64(cycle);
        let num_parties = self.party_key_ids.len().try_into().unwrap();
        // Create the parties
        self.signer_parties = self
            .party_key_ids
            .iter()
            .enumerate()
            .map(|(pid, pkids)| {
                wsts::v2::Party::new(
                    pid.try_into().unwrap(),
                    pkids,
                    num_parties,
                    self.num_keys,
                    self.threshold,
                    &mut rng,
                )
            })
            .collect();
        self.poly_commitments =
            match wsts::v2::test_helpers::dkg(&mut self.signer_parties, &mut rng) {
                Ok(poly_commitments) => poly_commitments,
                Err(secret_errors) => {
                    panic!("Got secret errors from DKG: {:?}", secret_errors);
                }
            };
        let mut sig_aggregator = wsts::v2::Aggregator::new(self.num_keys, self.threshold);
        sig_aggregator
            .init(&self.poly_commitments)
            .expect("aggregator init failed");
        self.aggregate_public_key = sig_aggregator.poly[0];
        self.cycle = cycle;
        self.aggregate_public_key.clone()
    }
}
