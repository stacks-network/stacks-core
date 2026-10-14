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
use std::env;
use std::time::Duration;

use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::SignerMessage;
use stacks::core::test_util::{make_stacks_transfer_serialized, to_addr};
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::{TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_REJECT_ALL_BLOCK_PROPOSAL};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, submit_tx};
use crate::tests::signer::v0::{
    get_stackerdb_signer_messages, wait_for_block_acceptance_from_signers,
    wait_for_block_pre_commits_from_signers, wait_for_block_proposal,
    wait_for_block_pushed_and_tip, wait_for_block_rejections_from_signers,
};

#[test]
#[ignore]
/// Tests that a miner recovers when an earlier proposal of its tenure-start block reaches
/// consensus after the miner has already re-mined and proposed a replacement.
///
/// Test Setup:
/// - 5 signers attached to one miner
/// - The miner's block rejection timeout is long, so it would keep waiting on its replacement
///   proposal well past the end of the test if it failed to notice the accepted sibling.
///
/// Test Execution:
/// 1. Configure 2 signers (40% of the weight) to reject all proposals.
/// 2. Mine a Bitcoin block; the miner proposes tenure-start block A.
/// 3. The other 3 signers pre-commit A; the 2 signers reject it, so the miner gives up on A.
/// 4. Make every signer ignore proposals, and allow the 2 signers to accept proposals again.
/// 5. The miner re-mines and proposes tenure-start block B, which every signer ignores.
/// 6. Allow proposals again and re-propose A; the 2 signers reconsider it and A is accepted.
/// 7. Submit a transfer.
///
/// Test Assertions:
/// - A becomes the canonical tip of the new tenure while the miner is waiting on B.
/// - Without a new Bitcoin block, the miner abandons B and mines block N+2 on top of A in the
///   same tenure.
fn miner_recovers_when_tenure_start_sibling_is_accepted() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |config| {
            config.miner.block_rejection_timeout_steps = [(0, Duration::from_secs(600))].into();
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", signer_test.running_nodes.conf.node.rpc_bind);
    let all_signers = signer_test.signer_test_pks();
    let rejecting_signers = all_signers.iter().take(2).cloned().collect::<Vec<_>>();
    let accepting_signers = all_signers.iter().skip(2).cloned().collect::<Vec<_>>();
    let miner_pk = StacksPublicKey::from_private(
        &signer_test
            .running_nodes
            .conf
            .miner
            .mining_key
            .clone()
            .unwrap(),
    );
    signer_test.boot_to_epoch_3();

    info!("------------------------- Propose Tenure-Start Block A -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers.clone());
    let expected_height = signer_test.get_peer_info().stacks_tip_height + 1;
    signer_test.mine_bitcoin_block();
    signer_test.wait_for_signer_state_update();
    let burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;

    let proposal_a = wait_for_block_proposal(30, expected_height, &miner_pk)
        .expect("Miner failed to propose tenure-start block A");
    let sighash_a = proposal_a.block.header.signer_signature_hash();
    wait_for_block_pre_commits_from_signers(30, &sighash_a, &accepting_signers)
        .expect("Accepting signers failed to pre-commit block A");
    wait_for_block_rejections_from_signers(30, &sighash_a, &rejecting_signers)
        .expect("Rejecting signers failed to reject block A");

    info!("------------------------- Ignore the Replacement Proposal B -------------------------");
    // The miner pauses `first_rejection_pause_ms` (5s by default) before re-mining, which leaves
    // time to make the signers ignore the replacement.
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signers.clone());
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);

    let mut sighash_b = None;
    wait_for(30, || {
        sighash_b = get_stackerdb_signer_messages()
            .into_iter()
            .find_map(|(_chunk, message)| {
                let SignerMessage::BlockProposal(proposal) = message else {
                    return None;
                };
                let sighash = proposal.block.header.signer_signature_hash();
                (proposal.block.header.chain_length == expected_height
                    && proposal.block.header.recover_miner_pk().as_ref() == Some(&miner_pk)
                    && sighash != sighash_a)
                    .then_some(sighash)
            });
        Ok(sighash_b.is_some())
    })
    .expect("Miner failed to propose a replacement tenure-start block B");
    let sighash_b = sighash_b.unwrap();
    info!("------------------------- Miner proposed B: {sighash_b} -------------------------");

    info!(
        "------------------------- Re-propose A so it Reaches Consensus -------------------------"
    );
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);
    let block_a = proposal_a.block.clone();
    signer_test.send_block_proposal(proposal_a, Duration::from_secs(30));
    wait_for_block_acceptance_from_signers(30, &sighash_a, &all_signers)
        .expect("All signers should have accepted block A after it was re-proposed");
    // The signers push A to the node themselves, so the miner never broadcasts it.
    wait_for(30, || {
        Ok(signer_test.get_peer_info().stacks_tip == block_a.header.block_hash())
    })
    .expect("Block A should have become the canonical tip");

    info!("------------------------- Miner Continues the Tenure on Top of A -------------------------");
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        0,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    // Well under the miner's 600s rejection timeout: a miner that didn't notice A would still be
    // waiting on B.
    let block_n_2 = wait_for_block_pushed_and_tip(60, expected_height + 1, &miner_pk, || {
        signer_test.get_peer_info().stacks_tip
    })
    .expect("Miner failed to mine block N+2 on top of the accepted sibling A");
    assert_eq!(block_n_2.header.parent_block_id, block_a.block_id());
    assert_eq!(
        block_n_2.header.consensus_hash, block_a.header.consensus_hash,
        "Block N+2 should be in the same tenure as A"
    );
    assert_eq!(
        get_chain_info(&signer_test.running_nodes.conf).burn_block_height,
        burn_height,
        "The miner should recover without a new Bitcoin block"
    );

    signer_test.shutdown();
}
