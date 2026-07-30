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

//! Integration test for a bitcoin reorg at the Epoch 4.0 activation height.
//!
//! The epoch schedule is keyed by burn block height and the Epoch 4.0
//! transition (pox-5 deployment) is fork-scoped Clarity state, so a reorg
//! that orphans the activation block must cleanly undo the transition and
//! the replacement chain must re-run it identically. This exercises that
//! path end-to-end against a real bitcoind.

use std::env;
use std::sync::atomic::Ordering;
use std::time::Duration;

use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ContractName;
use pinny::tag;
use stacks::chainstate::stacks::boot::POX_5_NAME;
use stacks::core::StacksEpochId;
use stacks::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util_lib::boot::boot_code_id;
use stacks_signer::v0::SpawnedSigner;

use super::{contract_source_exists, SignerTest};
use crate::nakamoto_node::miner::{fault_injection_stall_miner, fault_injection_unstall_miner};
use crate::tests::nakamoto_integrations::{enable_epoch_4_0, wait_for};
use crate::tests::neon_integrations::{
    call_read_only, get_account, get_chain_info, get_sortition_info,
};
use crate::tests::to_addr;
use crate::Keychain;

/// Orphan the Epoch 4.0 activation block on the bitcoin side and verify the
/// node cleanly re-activates Epoch 4.0 on the replacement chain -- the
/// regtest analogue of mainnet burn block 960230 being reorged back to
/// 960229 right at the hard fork.
///
/// Test Setup:
/// Five signers and one Nakamoto miner, with Epoch 4.0 at burn height 262.
/// The boundary sits mid reward phase of cycle 13, so the pox-4 signer set
/// stays in charge for the whole test and no pox-5 stake is needed.
///
/// Test Execution:
/// Boot into Epoch 4.0, then invalidate the activation block and rebuild on
/// top of its parent. Resume mining, then invalidate the (replacement)
/// activation block again, this time from several blocks deeper.
///
/// Test Assertion:
/// While the miner is stalled after each reorg, the canonical Stacks fork is
/// back below the boundary: pox-5 is absent and the miner nonce is rewound.
/// Once mining resumes, the node re-runs the transition: pox-5 is redeployed
/// with identical burnchain parameters and signed tenures continue.
#[tag(slow, bitcoind)]
#[test]
#[ignore]
fn bitcoin_reorg_of_epoch_4_0_activation_block() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;

    let agg_pubkey: [u8; 33] =
        Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(b"epoch-4-0-reorg-agg"))
            .to_bytes_compressed()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes");

    let spender_sk = StacksPrivateKey::from_seed(b"epoch-4-0-reorg-publisher");
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

    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
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
            Some(function_name!()),
        );
    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    let conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let miner_address = Keychain::default(conf.node.seed.clone())
        .origin_address(conf.is_mainnet())
        .unwrap();
    let activation_height = conf
        .burnchain
        .epochs
        .as_ref()
        .and_then(|epochs| epochs.get(StacksEpochId::Epoch40))
        .map(|epoch| epoch.start_height)
        .expect("Epoch 4.0 start height not configured");
    let pox_5_addr: StacksAddress = boot_code_id(POX_5_NAME, conf.is_mainnet()).issuer.into();

    // the burnchain parameters pox-5 is initialized with; they derive from
    // config constants only, so any fork must compute the same values
    let pox_info_params = || {
        let info = call_read_only(&conf, &pox_5_addr, POX_5_NAME, "get-pox-info", vec![])
            .result()
            .expect("get-pox-info call failed")
            .expect_result_ok()
            .expect("get-pox-info returned an error response")
            .expect_tuple()
            .expect("get-pox-info did not return a tuple");
        [
            "min-amount-ustx",
            "prepare-cycle-length",
            "first-burnchain-block-height",
            "reward-cycle-length",
        ]
        .map(|field| {
            info.get(field)
                .unwrap_or_else(|_| panic!("missing {field}"))
                .clone()
        })
    };

    let submitted_commits = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();

    // resume mining after a fork: the miner starts the tenure it won on the
    // replacement chain, then mines burn blocks until fresh commits re-fill
    // its mining frequency window (3 of the last 6) and tenures build on
    // each other again -- the first tenure changes on the replacement chain
    // can build off a stale view of the tenure tip
    let resume_mining_after_fork = || {
        signer_test.wait_for_nakamoto_block(60, || {});
        for _ in 0..8 {
            let latest = get_sortition_info(&conf);
            if latest.was_sortition && latest.last_sortition_ch == latest.stacks_parent_ch {
                break;
            }
            let commits_count = submitted_commits.load(Ordering::SeqCst);
            signer_test.mine_bitcoin_block();
            wait_for(30, || {
                Ok(submitted_commits.load(Ordering::SeqCst) > commits_count)
            })
            .expect("miner did not submit a fresh block commit");
        }
        let latest = get_sortition_info(&conf);
        assert_eq!(
            latest.last_sortition_ch, latest.stacks_parent_ch,
            "chain did not settle back into steady state"
        );
    };

    signer_test.boot_to_epoch_4(
        &spender_sk,
        0,
        token_contract_name,
        registry_contract_name,
        &agg_pubkey,
    );
    info!("------------------------- Reached Epoch 4.0 -------------------------");

    assert_eq!(
        get_chain_info(&conf).burn_block_height,
        activation_height + 1,
        "boot_to_epoch_4 should leave the chain one block past the boundary",
    );
    // pox-5 must be live before the fork, so asserting its absence during
    // the fork (and its presence afterwards) actually distinguishes
    // "transition undone and re-applied" from "never applied at all"
    wait_for(60, || {
        Ok(contract_source_exists(
            &http_origin,
            &pox_5_addr,
            POX_5_NAME,
        ))
    })
    .expect("pox-5 boot contract not deployed after crossing into Epoch 4.0");
    let pre_fork_pox_params = pox_info_params();
    let pre_fork_nonce = get_account(&http_origin, &miner_address).nonce;

    // Orphan the activation block and rebuild on top of its parent, up to
    // one block past the old tip so the node notices the fork (it only looks
    // for new blocks). While the miner is stalled, no new tenure can re-run
    // the transition.
    info!(
        "------------------------- Reorg the Epoch 4.0 activation block -------------------------"
    );
    fault_injection_stall_miner();
    let fork_tip = get_chain_info(&conf).burn_block_height;
    let activation_hash = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(activation_height);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&activation_hash);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(fork_tip - (activation_height - 1) + 1);
    assert_ne!(
        signer_test
            .running_nodes
            .btc_regtest_controller
            .get_block_hash(activation_height),
        activation_hash,
        "the activation block should have been replaced"
    );

    // once the node processes the reorg, the canonical Stacks fork is back
    // below the boundary: pox-5 is gone and the two orphaned tenures (at the
    // activation block and on top of it) are rewound
    wait_for(120, || {
        Ok(get_chain_info(&conf).burn_block_height == fork_tip + 1
            && !contract_source_exists(&http_origin, &pox_5_addr, POX_5_NAME))
    })
    .expect("node did not process the reorg of the Epoch 4.0 activation block");
    signer_test.check_signer_states_normal_missed_sortition();
    let post_shallow_fork_nonce = get_account(&http_origin, &miner_address).nonce;
    assert_eq!(
        post_shallow_fork_nonce,
        pre_fork_nonce - 4,
        "miner nonce should rewind by the two orphaned tenures"
    );

    fault_injection_unstall_miner();
    let rewound_tip = get_chain_info(&conf).stacks_tip_height;
    resume_mining_after_fork();
    assert!(
        get_chain_info(&conf).stacks_tip_height > rewound_tip,
        "chain did not resume producing signed blocks after the reorg"
    );

    // the replacement chain crossed the boundary again: the transition must
    // have re-run identically
    wait_for(120, || {
        Ok(contract_source_exists(
            &http_origin,
            &pox_5_addr,
            POX_5_NAME,
        ))
    })
    .expect("pox-5 boot contract not redeployed after the reorg");
    assert_eq!(
        pox_info_params(),
        pre_fork_pox_params,
        "pox-5 burnchain parameters changed across the reorg"
    );

    info!(
        "------------------------- Reorg the activation block from deeper -------------------------"
    );
    fault_injection_stall_miner();
    let fork_tip = get_chain_info(&conf).burn_block_height;
    let activation_hash = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(activation_height);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&activation_hash);
    // rebuild on top of the pre-activation tip, up to one block past the
    // old tip so the node notices the fork
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(fork_tip - (activation_height - 1) + 1);
    assert_ne!(
        signer_test
            .running_nodes
            .btc_regtest_controller
            .get_block_hash(activation_height),
        activation_hash,
        "the activation block should have been replaced"
    );

    wait_for(120, || {
        Ok(get_chain_info(&conf).burn_block_height == fork_tip + 1
            && !contract_source_exists(&http_origin, &pox_5_addr, POX_5_NAME))
    })
    .expect("node did not process the deep reorg of the Epoch 4.0 activation block");
    signer_test.check_signer_states_normal_missed_sortition();
    // the reorg orphaned exactly the tenures mined since the last fork
    assert_eq!(
        get_account(&http_origin, &miner_address).nonce,
        post_shallow_fork_nonce,
        "miner nonce should rewind to the pre-resume value"
    );

    fault_injection_unstall_miner();
    let rewound_tip = get_chain_info(&conf).stacks_tip_height;
    resume_mining_after_fork();
    assert!(
        get_chain_info(&conf).stacks_tip_height > rewound_tip,
        "chain did not resume producing signed blocks after the deep reorg"
    );

    wait_for(120, || {
        Ok(contract_source_exists(
            &http_origin,
            &pox_5_addr,
            POX_5_NAME,
        ))
    })
    .expect("pox-5 boot contract not redeployed after the deep reorg");
    assert_eq!(
        pox_info_params(),
        pre_fork_pox_params,
        "pox-5 burnchain parameters changed across the deep reorg"
    );

    signer_test.shutdown();
}
