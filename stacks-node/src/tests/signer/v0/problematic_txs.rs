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

use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ContractName;
use libsigner::v0::messages::RejectReason;
use pinny::tag;
use stacks::chainstate::nakamoto::ProblematicTxMarker;
use stacks::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks_signer::v0::tests::TEST_IGNORE_ALL_BLOCK_PROPOSALS;
use stacks_signer::v0::SpawnedSigner;

use crate::nakamoto_node::miner::TEST_BROADCAST_PROPOSAL_STALL;
use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::tests::nakamoto_integrations::{enable_epoch_4_0, wait_for};
use crate::tests::neon_integrations::{get_chain_info, test_observer};
use crate::tests::signer::v0::{wait_for_block_proposal, wait_for_block_rejections_from_signers};
use crate::tests::signer::SignerTest;
use crate::tests::to_addr;

#[tag(bitcoind)]
#[test]
#[ignore]
/// In this first version of the `problematic_txs` feature, signers reject any
/// block proposal that marks any transactions as problematic, because the
///  criteria for what may legitimately appear in `problematic_txs` has not
/// been decided yet.
///
/// Test Setup:
/// The test spins up 5 Stacks signers, one miner Nakamoto node, and a
/// corresponding bitcoind instance, configured for and advanced to Epoch 4.0
/// (the first epoch in which `problematic_txs` markers are serialized into the
/// block header).
///
/// Test Execution:
/// 1. The miner mines a burn block to start a new tenure.
/// 2. The resulting block proposal is intercepted before signers process it.
/// 3. A `problematic_txs` marker is injected into the block header and the miner
///    signature is recomputed (markers are part of the version-1 signature hash
///    but not the transaction Merkle root).
/// 4. The modified block is proposed to the signers.
///
/// Test Assertion:
/// - All signers reject the block with `RejectReason::ProblematicTransactions`.
fn signers_reject_blocks_with_problematic_txs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let stake_amount: u128 = 100_000_000_000;
    let lock_cycles: u128 = 12;

    let agg_pubkey: [u8; 33] =
        Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(b"problematic-txs-agg"))
            .to_bytes_compressed()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes");

    let spender_sk = StacksPrivateKey::from_seed(b"problematic-txs-publisher");
    let spender_addr = to_addr(&spender_sk);
    let token_contract_name = "sbtc-token-stub";
    let registry_contract_name = "sbtc-registry-stub";
    let token_contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(token_contract_name.to_string()).expect("valid contract name"),
    );
    let registry_contract_id = QualifiedContractIdentifier::new(
        spender_addr.clone().into(),
        ContractName::try_from(registry_contract_name.to_string()).expect("valid contract name"),
    );

    let initial_balances = vec![(spender_addr, 1_000_000)];

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.node.pox_5_sbtc_contract = Some(token_contract_id.clone());
            node_config.node.pox_5_sbtc_registry_contract = Some(registry_contract_id.clone());
            enable_epoch_4_0(node_config);
        },
        None,
        None,
    );

    let conf = signer_test.running_nodes.conf.clone();
    let all_signers = signer_test.signer_test_pks();
    let miner_privk = signer_test.get_miner_key();
    let miner_pubk = StacksPublicKey::from_private(&miner_privk);

    signer_test.boot_to_epoch_4_with_pox5_lockups(
        &spender_sk,
        0,
        token_contract_name,
        registry_contract_name,
        &agg_pubkey,
        stake_amount,
        lock_cycles,
    );
    info!("------------------------- Reached Epoch 4.0 -------------------------");

    info!("------------------------- Start a new Tenure -------------------------");
    let info_before = get_chain_info(&conf);
    // Have signers ignore the original proposal so we can inject a modified one,
    // and have the miner ignore signer responses so it doesn't re-propose.
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(all_signers.clone());
    TEST_IGNORE_SIGNERS.set(true);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    wait_for(30, || {
        Ok(get_chain_info(&conf).burn_block_height >= info_before.burn_block_height)
    })
    .expect("Failed to wait for burn block height to update after mining a block");

    info!(
        "------------------------- Retrieve the block proposal to modify -------------------------"
    );
    let block_proposal =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pubk)
            .expect("Miner did not propose a tenure change block");
    // Pause further proposals from the miner for granular control.
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pubk.clone()]);
    // Allow signers to consider incoming proposals again.
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    info!("------------------------- Propose a block marking a transaction problematic -------------------------");
    test_observer::clear();
    let mut block = block_proposal.block.clone();
    // The signer gate rejects any non-empty `problematic_txs` list outright,
    // before consensus validates the markers, so the specific index and category
    // are irrelevant here — only that the list is non-empty.
    block.header.problematic_txs = vec![ProblematicTxMarker {
        tx_index: 1,
        category: 0,
    }];
    // `problematic_txs` is part of the (version-1) signature hash but not the
    // transaction Merkle root, so only the miner signature needs recomputing.
    block.header.sign_miner(&miner_privk).unwrap();

    let proposed_sighash = block.header.signer_signature_hash();
    signer_test.propose_block(block, Duration::from_secs(30));

    info!("------------------------- Confirm all signers reject with ProblematicTransactions -------------------------");
    let rejections = wait_for_block_rejections_from_signers(30, &proposed_sighash, &all_signers)
        .expect("Failed to find block rejections from all signers");
    rejections.iter().for_each(|rejection| {
        assert_eq!(
            rejection.response_data.reject_reason,
            RejectReason::ProblematicTransactions,
            "Reject reason is not ProblematicTransactions"
        );
    });

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}
