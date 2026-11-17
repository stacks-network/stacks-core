// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Peers in a weighted signer set publish arbitrary state machine updates
//! (each decoded from fuzzer bytes, as the signer decodes them off the
//! wire) into a `GlobalStateEvaluator`. After every update, whatever the
//! evaluator reports as agreed must really have threshold weight behind it.

#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use libfuzzer_sys::fuzz_target;
use libsigner::v0::messages::StateMachineUpdate;
use libsigner::v0::signer_state::{GlobalStateEvaluator, MinerState};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::Hash160;

#[derive(Debug)]
struct Input<'a> {
    /// Each signer's weight. Reward sets have at most 4000 slots.
    weights: Vec<u16>,
    /// (signer index, serialized `StateMachineUpdate`)
    updates: Vec<(u8, &'a [u8])>,
}

impl<'a> Arbitrary<'a> for Input<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let n = u.int_in_range(1..=10)?;
        let weights = (0..n)
            .map(|_| u.int_in_range(1..=400))
            .collect::<ArbitraryResult<_>>()?;
        let updates = u
            .arbitrary_iter::<(u8, &[u8])>()?
            .collect::<ArbitraryResult<_>>()?;
        Ok(Self { weights, updates })
    }
}

fn address(i: usize) -> StacksAddress {
    StacksAddress::new(26, Hash160([i as u8; 20])).unwrap()
}

fn check(evaluator: &GlobalStateEvaluator) {
    let weight_of = |pred: &dyn Fn(&StateMachineUpdate) -> bool| -> u32 {
        evaluator
            .address_updates
            .iter()
            .filter(|(_, update)| pred(update))
            .map(|(addr, _)| evaluator.address_weights[addr])
            .sum()
    };

    let version = evaluator.determine_latest_supported_signer_protocol_version();
    if let Some(v) = version {
        let support = weight_of(&|u| u.local_supported_signer_protocol_version >= v);
        assert!(
            evaluator.reached_agreement(support),
            "version {v} chosen with only {support} of {} weight supporting it",
            evaluator.total_weight
        );
    }

    if let Some((burn_block, height)) = evaluator.determine_global_burn_view() {
        let support = weight_of(&|u| u.content.burn_block_view() == (burn_block, height));
        assert!(evaluator.reached_agreement(support));
    }

    if let Some(state) = evaluator.determine_global_state() {
        assert_eq!(Some(state.active_signer_protocol_version), version);
        let support = weight_of(&|u| {
            let (burn_block, height) = u.content.burn_block_view();
            *burn_block == state.burn_block
                && height == state.burn_block_height
                && MinerState::from(u.content.current_miner().clone()) == state.current_miner
        });
        assert!(
            evaluator.reached_agreement(support),
            "global state agreed with only {support} of {} weight",
            evaluator.total_weight
        );
    }
}

fuzz_target!(|input: Input| {
    let weights: HashMap<_, _> = input
        .weights
        .iter()
        .enumerate()
        .map(|(i, w)| (address(i), u32::from(*w)))
        .collect();
    let mut evaluator = GlobalStateEvaluator::new(HashMap::new(), weights);
    for (signer, bytes) in input.updates {
        let Ok(update) = StateMachineUpdate::consensus_deserialize(&mut &bytes[..]) else {
            continue;
        };
        let signer = usize::from(signer) % input.weights.len();
        assert!(evaluator.insert_update(address(signer), update));
        check(&evaluator);
    }
});
