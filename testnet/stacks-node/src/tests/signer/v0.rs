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

use std::env;
use std::time::Duration;

use libsigner::v0::messages::{
    BlockRejection, BlockResponse, MessageSlotID, RejectCode, SignerMessage,
};
use libsigner::{BlockProposal, SignerSession, StackerDBSession};
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::codec::StacksMessageCodec;
use stacks::libstackerdb::StackerDBChunkData;
use stacks::types::chainstate::StacksPrivateKey;
use stacks::util_lib::boot::boot_code_id;
use stacks_signer::client::{SignerSlotID, StackerDB};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::tests::nakamoto_integrations::boot_to_epoch_3_reward_set;
use crate::BurnchainController;

impl SignerTest<SpawnedSigner> {
    /// Run the test until the epoch 3 boundary
    fn boot_to_epoch_3(&mut self) {
        boot_to_epoch_3_reward_set(
            &self.running_nodes.conf,
            &self.running_nodes.blocks_processed,
            &self.signer_stacks_private_keys,
            &self.signer_stacks_private_keys,
            &mut self.running_nodes.btc_regtest_controller,
        );

        self.run_until_epoch_3_boundary();
    }
}
#[test]
#[ignore]
/// Test that a signer can respond to an invalid block proposal
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
///
/// Test Execution:
/// The stacks node is advanced to epoch 3.0 reward set calculation to ensure the signer set is determined.
/// An invalid block proposal is forcibly written to the miner's slot to simulate the miner proposing a block.
/// The signers process the invalid block by first verifying it against the stacks node block proposal endpoint.
/// The signers then broadcast a rejection of the miner's proposed block back to the respective .signers-XXX-YYY contract.
///
/// Test Assertion:
/// Each signer successfully rejects the invalid block proposal.
fn block_proposal_rejection() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers);
    signer_test.boot_to_epoch_3();
    let short_timeout = Duration::from_secs(30);

    info!("------------------------- Send Block Proposal To Signers -------------------------");
    let miners_contract_id = boot_code_id(MINERS_NAME, false);
    let mut session = StackerDBSession::new(
        &signer_test.running_nodes.conf.node.rpc_bind,
        miners_contract_id.clone(),
    );
    let block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    let block_signer_signature_hash = block.header.signer_signature_hash();
    let burn_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    let reward_cycle = signer_test.get_current_reward_cycle();
    let next_reward_cycle = reward_cycle + 1;
    let message = SignerMessage::BlockProposal(BlockProposal {
        block,
        burn_height,
        reward_cycle: next_reward_cycle,
    });
    // Just attempt to submit a chunk to all possible slots
    // We just need one to be successful
    // let mut results = vec![];
    // for i in 0..2 {
    //     let mut chunk = StackerDBChunkData::new(i, 0, message.serialize_to_vec());
    //     chunk
    //         .sign(
    //             &signer_test
    //                 .running_nodes
    //                 .conf
    //                 .miner
    //                 .mining_key
    //                 .expect("No mining key"),
    //         )
    //         .expect("Failed to sign message chunk");
    //     let result = session.put_chunk(&chunk).expect("Failed to put chunk");
    //     debug!("Test Put Chunk ACK: {result:?}");
    //     results.push(result);
    // }
    // assert!(
    //     results.iter().any(|result| result.accepted),
    //     "Failed to submit block proposal to signers"
    // );

    let miner_index = signer_test.get_miner_index();
    let mut chunk = StackerDBChunkData::new(miner_index.0, 0, message.serialize_to_vec());
    chunk
        .sign(
            &signer_test
                .running_nodes
                .conf
                .miner
                .mining_key
                .expect("No mining key"),
        )
        .expect("Failed to sign message chunk");
    let result = session.put_chunk(&chunk).expect("Failed to put chunk");
    debug!("Test Put Chunk ACK: {result:?}");
    assert!(
        result.accepted,
        "Failed to submit block proposal to signers"
    );

    info!("------------------------- Test Block Proposal Rejected -------------------------");
    // Verify that the node correctly rejected the node
    let proposed_signer_signature_hash =
        signer_test.wait_for_validate_reject_response(short_timeout);
    assert_eq!(proposed_signer_signature_hash, block_signer_signature_hash);

    let signer_slot_ids: Vec<_> = signer_test
        .get_signer_indices(next_reward_cycle)
        .iter()
        .map(|id| id.0)
        .collect();

    let mut stackerdb = StackerDB::new(
        &signer_test.running_nodes.conf.node.rpc_bind,
        StacksPrivateKey::new(), // We are just reading so don't care what the key is
        false,
        next_reward_cycle,
        SignerSlotID(0), // We are just reading so again, don't care about index.
    );

    let messages: Vec<SignerMessage> = StackerDB::get_messages(
        stackerdb
            .get_session_mut(&MessageSlotID::BlockResponse)
            .expect("Failed to get BlockResponse stackerdb session"),
        &signer_slot_ids,
    )
    .expect("Failed to get message from stackerdb");
    for message in messages {
        if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
            reason: _reason,
            reason_code,
            signer_signature_hash,
        })) = message
        {
            assert_eq!(signer_signature_hash, block_signer_signature_hash);
            assert!(matches!(reason_code, RejectCode::ValidationFailed(_)));
        } else {
            panic!("Unexpected message type");
        }
    }
    signer_test.shutdown();
}
