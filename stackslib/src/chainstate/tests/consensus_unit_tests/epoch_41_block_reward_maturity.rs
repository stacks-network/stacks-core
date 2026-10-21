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

//! Epoch 4.1 makes `block-reward` (in `get-tenure-info?` and Clarity 2
//! `get-block-info?`) return `none` until Nakamoto has written the reward.
//! Before, the lookup only checked Stacks height, but Nakamoto writes a reward
//! `MINER_REWARD_MATURITY` tenures later, so a lookup in between made the block
//! invalid.

use std::collections::HashMap;

use clarity::types::StacksEpochId;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityVersion, ContractName, Value};
use rstest::rstest;
use stacks_common::consts::MINER_REWARD_MATURITY;

use crate::chainstate::nakamoto::{NakamotoChainState, StacksDBIndexed};
use crate::chainstate::stacks::StacksTransaction;
use crate::chainstate::tests::consensus::{
    ConsensusChain, ConsensusTest, ConsensusUtils, ExpectedResult, TestBlock, FAUCET_ADDRESS,
};

// The tenure and block counts below are laid out for the test maturity.
const _: () = assert!(MINER_REWARD_MATURITY == 2);

/// What a lookup of an unwritten reward fails its block with, before Epoch 4.1.
const NO_RECORDED_REWARD: &str = "matured block has no recorded reward";

/// Looks up the reward of the block `n` blocks back.
const TENURE_INFO_LOOKUP: &str = "
    (define-public (reward-back (n uint))
      (ok (get-tenure-info? block-reward (- stacks-block-height n))))";

/// Gives Clarity 2, which has no `stacks-block-height`, the Stacks height.
const STACKS_HEIGHT: &str = "(define-read-only (current) stacks-block-height)";

/// The Clarity 2 lookup. On the test chain's ID, its height is a Stacks height.
const BLOCK_INFO_LOOKUP: &str = "
    (define-public (reward-back (n uint))
      (ok (get-block-info? block-reward (- (contract-call? .stacks-height current) n))))";

/// Looks up the reward of the block at `height`.
const REWARD_AT: &str = "
    (define-public (reward-at (height uint))
      (ok (get-tenure-info? block-reward height)))";

fn block(transactions: Vec<StacksTransaction>) -> TestBlock {
    TestBlock { transactions }
}

/// A lookup of the closest block the Stacks-height check lets through.
fn lookup(nonce: u64, contract: &str) -> TestBlock {
    let blocks_back = Value::UInt((MINER_REWARD_MATURITY + 2).into());
    block(vec![ConsensusUtils::new_call_tx_with_args(
        nonce,
        contract,
        "reward-back",
        &[blocks_back],
    )])
}

fn reward_at(nonce: u64, height: u64) -> StacksTransaction {
    ConsensusUtils::new_call_tx_with_args(
        nonce,
        "reward-at",
        "reward-at",
        &[Value::UInt(height.into())],
    )
}

/// What each lookup in the block returned.
fn rewards(result: &ExpectedResult) -> Vec<Option<u128>> {
    let ExpectedResult::Success(block) = result else {
        panic!("block rejected: {result:?}");
    };
    block
        .transactions
        .iter()
        .map(|tx| {
            let reward = tx.return_type.clone().expect_result_ok().unwrap();
            reward
                .expect_optional()
                .unwrap()
                .map(|reward| reward.expect_u128().unwrap())
        })
        .collect()
}

/// Asserts the block failed on a lookup of an unwritten reward.
fn assert_rejected(result: &ExpectedResult) {
    assert!(
        matches!(result, ExpectedResult::Failure(failure) if failure.error.contains(NO_RECORDED_REWARD)),
        "{result:?}"
    );
}

/// A lookup made after the Stacks-height check passes but before Nakamoto writes
/// the reward fails the block before Epoch 4.1, and returns `none` from Epoch 4.1.
#[test]
fn test_block_reward_before_tenure_maturity() {
    // Each epoch's blocks extend the tenure that starts the epoch, so a lookup from
    // the fourth block on targets that tenure. Deploys go in Epoch 4.0, where they
    // can still pin Clarity 2.
    let epoch_40 = vec![
        block(vec![ConsensusUtils::new_deploy_tx(
            0,
            "stacks-height",
            STACKS_HEIGHT,
            None,
        )]),
        block(vec![ConsensusUtils::new_deploy_tx(
            1,
            "tenure-info",
            TENURE_INFO_LOOKUP,
            None,
        )]),
        block(vec![ConsensusUtils::new_deploy_tx(
            2,
            "block-info",
            BLOCK_INFO_LOOKUP,
            Some(ClarityVersion::Clarity2),
        )]),
        lookup(3, "tenure-info"),
        // A rejected block does not use its nonce.
        lookup(3, "block-info"),
    ];
    let epoch_41 = vec![
        block(vec![ConsensusUtils::new_transfer_tx(3)]),
        block(vec![ConsensusUtils::new_transfer_tx(4)]),
        block(vec![ConsensusUtils::new_transfer_tx(5)]),
        lookup(6, "tenure-info"),
        lookup(7, "block-info"),
    ];
    let epoch_blocks = HashMap::from([
        (StacksEpochId::Epoch40, epoch_40),
        (StacksEpochId::Epoch41, epoch_41),
    ]);
    let results = ConsensusTest::new(function_name!(), vec![], epoch_blocks).run();

    // One result per block above, Epoch 4.0's first.
    let [.., tenure_40, block_40, _, _, _, tenure_41, block_41] = results.as_slice() else {
        panic!("unexpected results: {results:?}");
    };
    assert_rejected(tenure_40);
    assert_rejected(block_40);
    assert_eq!(rewards(tenure_41), [None]);
    assert_eq!(rewards(block_41), [None]);
}

/// The first block of a tenure sees the rewards written before it, but not the
/// one it writes after its transactions run. A lookup of that one fails the block
/// before Epoch 4.1, and returns `none` from Epoch 4.1, also for a read-only call
/// at that block.
#[rstest]
#[case::epoch_40(StacksEpochId::Epoch40)]
#[case::epoch_41(StacksEpochId::Epoch41)]
fn test_block_reward_at_tenure_start(#[case] epoch: StacksEpochId) {
    let returns_none = epoch >= StacksEpochId::Epoch41;
    let name = format!("test_block_reward_at_tenure_start_{epoch:?}");
    let mut chain = ConsensusChain::new_in_epoch(&name, epoch);
    let deploy = ConsensusUtils::new_deploy_tx(0, "reward-at", REWARD_AT, None);
    chain.append_block(block(vec![deploy]), true);

    chain.test_chainstate.mine_nakamoto_tenure();
    let tenure_t = chain.tip().stacks_block_height;
    // Two blocks in T + 1 let the Stacks-height check pass for T + 1 from T + 3.
    chain.test_chainstate.mine_nakamoto_tenure();
    let tenure_t_plus_1 = chain.tip().stacks_block_height;
    chain.append_block(block(vec![ConsensusUtils::new_transfer_tx(1)]), true);
    chain.append_block(block(vec![ConsensusUtils::new_transfer_tx(2)]), true);

    // T + 2 writes T's reward (test maturity is 2 tenures).
    chain.test_chainstate.mine_nakamoto_tenure();
    let contract = QualifiedContractIdentifier::new(
        FAUCET_ADDRESS.clone().into(),
        ContractName::try_from("reward-at".to_string()).unwrap(),
    );
    let read_only = chain.eval_read_only_at_tip(
        &contract,
        &format!("(get-tenure-info? block-reward u{tenure_t})"),
    );
    assert_eq!(
        read_only.expect_optional().unwrap().is_some(),
        !returns_none
    );

    // T + 3 writes T + 1's reward.
    let start = chain.append_tenure_start_block(block(vec![
        reward_at(3, tenure_t),
        reward_at(4, tenure_t_plus_1),
    ]));
    let next_nonce = if returns_none {
        let [written, unwritten] = rewards(&start)[..] else {
            panic!("{start:?}");
        };
        assert!(written.is_some());
        assert_eq!(unwritten, None);
        5
    } else {
        assert_rejected(&start);
        chain.test_chainstate.mine_nakamoto_tenure();
        // A rejected block does not use its nonces.
        3
    };
    let next = chain.append_block(block(vec![reward_at(next_nonce, tenure_t_plus_1)]), true);
    assert!(matches!(rewards(&next)[..], [Some(_)]), "{next:?}");
}

/// The last epoch 2.x block writes the reward of the block `MINER_REWARD_MATURITY + 1`
/// below it, but the first Nakamoto tenure writes the one `MINER_REWARD_MATURITY`
/// below itself, so the block in between never gets one. Its lookup fails the block
/// before Epoch 4.1, and returns `none` from Epoch 4.1.
#[rstest]
#[case::epoch_40(StacksEpochId::Epoch40)]
#[case::epoch_41(StacksEpochId::Epoch41)]
fn test_block_reward_of_skipped_epoch_2_block(#[case] epoch: StacksEpochId) {
    let name = format!("test_block_reward_of_skipped_epoch_2_block_{epoch:?}");
    let mut chain = ConsensusChain::new_in_epoch(&name, epoch);
    let deploy = ConsensusUtils::new_deploy_tx(0, "reward-at", REWARD_AT, None);
    chain.append_block(block(vec![deploy]), true);

    let tip = chain.tip();
    let chainstate = chain.test_chainstate.chainstate_ref();
    let mut index_conn = chainstate.index_conn();
    let last_epoch_2 = (1..tip.stacks_block_height)
        .rev()
        .find(|height| {
            let block_id = index_conn
                .get_ancestor_block_id(*height, &tip.index_block_hash())
                .unwrap()
                .unwrap();
            NakamotoChainState::get_block_header(chainstate.db(), &block_id)
                .unwrap()
                .unwrap()
                .is_epoch_2_block()
        })
        .unwrap();
    let skipped = last_epoch_2 - MINER_REWARD_MATURITY;

    let neighbors = chain.append_block(
        block(vec![reward_at(1, skipped - 1), reward_at(2, skipped + 1)]),
        true,
    );
    assert!(rewards(&neighbors).iter().all(Option::is_some));
    let skipped_lookup = chain.append_block(block(vec![reward_at(3, skipped)]), true);
    if epoch >= StacksEpochId::Epoch41 {
        assert_eq!(rewards(&skipped_lookup), [None]);
    } else {
        assert_rejected(&skipped_lookup);
    }
}
