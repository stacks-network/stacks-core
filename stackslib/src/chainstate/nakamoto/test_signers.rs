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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::types::*;
use hashbrown::HashMap;
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use stacks_common::address::*;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{BlockHeaderHash, SortitionId, StacksBlockId, VRFSeed};
use stacks_common::util::hash::Hash160;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};
use wsts::curve::point::Point;
use wsts::traits::Aggregator;

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
use crate::chainstate::nakamoto::coordinator::get_nakamoto_next_recipients;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::address::PoxAddress;
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
        }
    }
}

impl TestSigners {
    pub fn sign_nakamoto_block(&mut self, block: &mut NakamotoBlock, cycle: u64) {
        // Update the aggregate public key if the cycle has changed
        if self.cycle != cycle {
            self.generate_aggregate_key(cycle);
        }

        let mut rng = rand_core::OsRng;
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

        test_debug!(
            "Signed Nakamoto block {} with {} (rc {})",
            block.block_id(),
            &self.aggregate_public_key,
            cycle
        );
        block.header.signer_signature = ThresholdSignature(signature);
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
