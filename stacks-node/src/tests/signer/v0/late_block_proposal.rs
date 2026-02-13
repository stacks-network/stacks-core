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
use libsigner::v0::messages::{BlockResponse, SignerMessage};
use pinny::tag;
use stacks::codec::StacksMessageCodec;
use stacks::core::test_util::{make_stacks_transfer_serialized, to_addr};
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::types::PublicKey;
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks_signer::v0::tests::TEST_IGNORE_ALL_BLOCK_PROPOSALS;
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, submit_tx, test_observer};
use crate::tests::signer::v0::{wait_for_block_proposal, wait_for_block_pushed};

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that a signer that receives a block proposal for a block that they have a block pushed event
/// for is rejected.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
///
/// Test Execution:
/// - Miner proposes a block N to all the signers
/// - Signer 1 is set to ignore any incoming proposals (simulate it not receiving the proposal)
/// - Signers 2-5 approve the block proposal
/// - The chain advances to block N
/// - Signer 1 is allowed to consider proposals again
/// - Block N is reproposed to all Signers
/// - Signer 1 rejects the proposal
///
/// Test Assertion:
/// All signers but Signer 1 accept the proposal
/// Signer 1 rejects the late proposal for block N with InvalidParentBlock reason
fn signer_rejects_proposal_after_block_pushed() {
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
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();
    let signer_1 = all_signers[0].clone();
    info!("------------------------- Ignore all Proposals for Signer 1 -------------------------"; "signer_public_key" => ?signer_1);
    test_observer::clear();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![signer_1.clone()]);
    info!("------------------------- Force Miner to Send a Block Proposal To Signers -------------------------");
    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    // submit a tx to force a block proposal
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    // Grab the proposal itself so it can be reproposed later
    let block_n_proposal =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pk)
            .expect("Timed out waiting for block N+1 to be proposed");
    let signer_signature_hash = block_n_proposal.block.header.signer_signature_hash();
    let _ = wait_for_block_pushed(30, &signer_signature_hash)
        .expect("Failed to get BlockPushed for block N");
    info!("------------------------- Advance Chain to Include Block N -------------------------");
    // Shouldn't have to wait long for the chain to advance
    wait_for(10, || {
        let info_after = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info_after.stacks_tip_height >= info_before.stacks_tip_height + 1)
    })
    .expect("Chain did not advance to block N+1");

    info!("------------------------- Verify Signer 1 did NOT respond to the Block Proposal -------------------------");
    let chunks = test_observer::get_stackerdb_chunks();
    for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
        let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice()) else {
            continue;
        };
        match message {
            SignerMessage::BlockResponse(BlockResponse::Rejected(rejected)) => {
                if rejected.signer_signature_hash == signer_signature_hash {
                    if rejected.signer_signature_hash == signer_signature_hash {
                        if rejected
                            .verify(&signer_1)
                            .expect("Failed to verify signature")
                        {
                            panic!("Signer 1 rejected the re-proposed block when it should have ignored it");
                        }
                    }
                }
            }
            SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) => {
                if accepted.signer_signature_hash == signer_signature_hash {
                    if signer_1
                        .verify(
                            accepted.signer_signature_hash.as_bytes(),
                            &accepted.signature,
                        )
                        .expect("Failed to verify signature")
                    {
                        panic!(
                            "Signer 1 accepted the block proposal when it should have ignored it"
                        );
                    }
                }
            }
            _ => continue,
        }
    }
    info!(
        "------------------------- Allow Signer 1 to Consider Proposals -------------------------"
    );
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);
    info!("------------------------- Re-Propose Block N to the Signers -------------------------");
    test_observer::clear();
    signer_test.send_block_proposal(block_n_proposal, Duration::from_secs(30));
    info!(
        "------------------------- Verify Signer 1 Rejected the Proposal -------------------------"
    );
    wait_for(30, || {
        let chunks: Vec<_> = test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .collect();
        for chunk in chunks {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");

            let SignerMessage::BlockResponse(BlockResponse::Rejected(rejected)) = message else {
                continue;
            };
            if rejected.signer_signature_hash == signer_signature_hash {
                return Ok(rejected
                    .verify(&signer_1)
                    .expect("Failed to verify signature")
                    && rejected.reason == "The block does not confirm the expected parent block.");
            }
        }
        Ok(false)
    })
    .expect("Timed out waiting for Signer 1 to reject the re-proposed block");
    signer_test.shutdown();
}
