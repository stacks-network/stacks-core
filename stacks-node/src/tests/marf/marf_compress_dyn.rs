// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! MARF integration tests exercising dynamic compression behavior,
//! including runtime enable/disable transitions within a single test run.

pub mod utils {
    use std::env;
    use std::time::Instant;

    use clarity::vm::types::PrincipalData;
    use rusqlite::Connection;
    use stacks::chainstate::burn::db::sortdb::SortitionDB;
    use stacks::clarity_vm::database::marf::fault_injection_marf_compression;
    use stacks::core::mempool::MemPoolWalkStrategy;
    use stacks::core::test_util::{insert_tx_in_mempool, make_stacks_transfer_serialized};
    use stacks::types::chainstate::{StacksAddress, StacksPrivateKey};
    use stacks_signer::v0::SpawnedSigner;

    use crate::nakamoto_node::miner::{fault_injection_stall_miner, fault_injection_unstall_miner};
    use crate::tests::nakamoto_integrations::wait_for;
    use crate::tests::neon_integrations::{get_account, test_observer};
    use crate::tests::signer::SignerTest;
    use crate::tests::{self};

    // NOTE: copied from `stacks-node::tests::signer::v0::large_mempool_base` and
    // reviewed to support dynamic marf compression switch during execution.
    pub fn large_mempool_base(marf_compress_step1: bool, marf_compress_step2: bool) {
        // This function intends to check the timing of the mempool iteration when
        // there are a large number of transactions in the mempool. It will boot to
        // epoch 3, fan out some STX transfers to a large number of accounts, wait for
        // these to all be mined, and then pause block mining, and submit a large
        // number of transactions to the mempool.  It will then unpause block mining
        // and wait for the first block to be mined. Since the default miner
        // configuration specifies to spend 5 seconds mining a block, we expect that
        // this first block should be proposed within 10 seconds and approved within
        // 20 seconds. We also verify that the block contains at least 5,000
        // transactions, since a lower count than that would indicate a clear
        // regression. Several tests below call this function, testing different
        // strategies and fees.
        if env::var("BITCOIND_TEST") != Ok("1".into()) {
            return;
        }

        let strategy = MemPoolWalkStrategy::GlobalFeeRate;
        let set_fee = || 180;

        // Set marf compression at the beginning
        fault_injection_marf_compression(marf_compress_step1);

        let transfer_fee = 180;
        let recipient = PrincipalData::from(StacksAddress::burn_address(false));

        // Start with 10 accounts with initial balances.
        let initial_sender_sks = (0..10)
            .map(|_| StacksPrivateKey::random())
            .collect::<Vec<_>>();
        let initial_sender_addrs = initial_sender_sks
            .iter()
            .map(|sk| tests::to_addr(sk))
            .collect::<Vec<_>>();

        // These 10 accounts will send to 25 accounts each, then those 260 accounts
        // will send to 25 accounts each, for a total of 6760 accounts.
        // At the end of the funding round, we want to have 6760 accounts with
        // enough balance to send 1 uSTX 25 times.
        // With a fee of 180 to 2000 uSTX per send, we need each account to have
        //   2001 * 25 = 50_025 uSTX.
        // The 260 accounts in the middle will need to have enough to send that
        // amount to 25 other accounts, plus the fee, and then enough to send the
        // transfers themselves as well:
        //   (50025 + 180) * 25 + 50025 = 1_305_150 uSTX.
        // The 10 initial accounts will need to have enough to send that amount to
        // 25 other accounts, plus enough to send the transfers themselves as well:
        //   (1305150 + 180) * 25 + 1305150 = 33_938_400 uSTX.
        let initial_balance = 33_938_400;
        let initial_balances = initial_sender_addrs
            .iter()
            .map(|addr| (addr.clone(), initial_balance))
            .collect::<Vec<_>>();

        let num_signers = 5;
        let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
            num_signers,
            initial_balances,
            |_| {},
            |conf| {
                conf.miner.mempool_walk_strategy = strategy;
            },
            None,
            None,
        );
        let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
        signer_test.boot_to_epoch_3();

        // This will hold tuples for all of our senders, with the sender pk and
        // the nonce
        let mut senders = initial_sender_sks
            .iter()
            .map(|sk| (sk, 0))
            .collect::<Vec<_>>();

        let mempool_db_path = format!(
            "{}/nakamoto-neon/chainstate/mempool.sqlite",
            signer_test.running_nodes.conf.node.working_dir
        );
        let chain_id = signer_test.running_nodes.conf.burnchain.chain_id;
        let burnchain = signer_test.running_nodes.conf.get_burnchain();
        let sortdb = burnchain.open_sortition_db(true).unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

        // Open a sqlite DB at mempool_db_path so that we can quickly add
        // transactions to the mempool.
        let mut conn = Connection::open(&mempool_db_path).unwrap();
        let db_tx = conn.transaction().unwrap();

        info!("Sending the first round of funding");
        let timer = Instant::now();
        let mut new_senders = vec![];
        for (sender_sk, nonce) in senders.iter_mut() {
            for _ in 0..25 {
                let recipient_sk = StacksPrivateKey::random();
                let recipient_addr = tests::to_addr(&recipient_sk);
                let sender_addr = tests::to_addr(sender_sk);
                let transfer_tx = make_stacks_transfer_serialized(
                    sender_sk,
                    *nonce,
                    transfer_fee,
                    chain_id,
                    &recipient_addr.into(),
                    1_305_150,
                );
                insert_tx_in_mempool(
                    &db_tx,
                    transfer_tx,
                    &sender_addr,
                    *nonce,
                    transfer_fee,
                    &tip.consensus_hash,
                    &tip.canonical_stacks_tip_hash,
                    tip.stacks_block_height,
                );
                *nonce += 1;
                new_senders.push(recipient_sk);
            }
        }
        db_tx.commit().unwrap();

        info!("Sending first round of funding took {:?}", timer.elapsed());

        // Wait for the first round of funding to be mined
        wait_for(120, || {
            for (sender_sk, nonce) in senders.iter() {
                let sender_addr = tests::to_addr(sender_sk);
                let account = get_account(&http_origin, &sender_addr);
                if account.nonce < *nonce {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .expect("Timed out waiting for first round of funding to be mined");

        info!(
            "Sending and mining first round of funding took {:?}",
            timer.elapsed()
        );

        // Add the new senders to the list of senders
        senders.extend(new_senders.iter().map(|sk| (sk, 0)));

        info!("Sending the second round of funding");
        // Set marf compression before starting second round
        fault_injection_marf_compression(marf_compress_step2);

        let db_tx = conn.transaction().unwrap();
        let timer = Instant::now();
        let mut new_senders = vec![];
        for (sender_sk, nonce) in senders.iter_mut() {
            for _ in 0..25 {
                let sender_addr = tests::to_addr(sender_sk);
                let recipient_sk = StacksPrivateKey::random();
                let recipient_addr = tests::to_addr(&recipient_sk);
                let transfer_tx = make_stacks_transfer_serialized(
                    sender_sk,
                    *nonce,
                    transfer_fee,
                    chain_id,
                    &recipient_addr.into(),
                    50_025,
                );
                insert_tx_in_mempool(
                    &db_tx,
                    transfer_tx,
                    &sender_addr,
                    *nonce,
                    transfer_fee,
                    &tip.consensus_hash,
                    &tip.canonical_stacks_tip_hash,
                    tip.stacks_block_height,
                );
                *nonce += 1;
                new_senders.push(recipient_sk);
            }
        }
        db_tx.commit().unwrap();

        info!("Sending second round of funding took {:?}", timer.elapsed());

        // Wait for the second round of funding to be mined
        wait_for(120, || {
            for (sender_sk, nonce) in senders.iter() {
                let sender_addr = tests::to_addr(sender_sk);
                let account = get_account(&http_origin, &sender_addr);
                if account.nonce < *nonce {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .expect("Timed out waiting for second round of funding to be mined");

        info!(
            "Sending and mining second round of funding took {:?}",
            timer.elapsed()
        );

        // Add the new senders to the list of senders
        senders.extend(new_senders.iter().map(|sk| (sk, 0)));

        info!("Pause mining and fill the mempool with the transfers");

        // Pause block mining
        fault_injection_stall_miner();

        let db_tx = conn.transaction().unwrap();
        let timer = Instant::now();

        // Fill the mempool with the transfers
        for _ in 0..25 {
            for (sender_sk, nonce) in senders.iter_mut() {
                let sender_addr = tests::to_addr(sender_sk);
                let fee = set_fee();
                assert!(fee >= 180 && fee <= 2000);
                let transfer_tx = make_stacks_transfer_serialized(
                    sender_sk, *nonce, fee, chain_id, &recipient, 1,
                );
                insert_tx_in_mempool(
                    &db_tx,
                    transfer_tx,
                    &sender_addr,
                    *nonce,
                    fee,
                    &tip.consensus_hash,
                    &tip.canonical_stacks_tip_hash,
                    tip.stacks_block_height,
                );
                *nonce += 1;
            }
        }
        db_tx.commit().unwrap();

        info!("Sending transfers took {:?}", timer.elapsed());

        let proposed_blocks_before = test_observer::get_mined_nakamoto_blocks().len();
        let blocks_before = test_observer::get_blocks().len();

        info!("Mining transfers...");

        // Unpause block mining
        fault_injection_unstall_miner();

        // Wait for the first block to be proposed.
        wait_for(30, || {
            let proposed_blocks = test_observer::get_mined_nakamoto_blocks().len();
            Ok(proposed_blocks > proposed_blocks_before)
        })
        .expect("Timed out waiting for first block to be mined");

        let blocks = test_observer::get_mined_nakamoto_blocks();
        let last_block = blocks.last().unwrap();
        info!(
            "First block contains {} transactions",
            last_block.tx_events.len()
        );
        if strategy == MemPoolWalkStrategy::NextNonceWithHighestFeeRate {
            assert!(last_block.tx_events.len() > 2000);
        }

        // Wait for the first block to be accepted.
        wait_for(60, || {
            let blocks = test_observer::get_blocks().len();
            Ok(blocks > blocks_before)
        })
        .expect("Timed out waiting for first block to be mined");

        signer_test.shutdown();
    }
}

/// Test copied from `stacks-node::tests::signer::v0::large_mempool_original_constant_fee`
/// Interesting because with full MARF compression produces patch nodes with 256 diffs (max diff allowed)
///
/// In this scenario, MARF compression **start disabled** for the first part of the test,
/// and **then enabled** for the second part of the test.
#[test]
#[ignore]
fn large_mempool_marf_compression_starts_disabled_and_then_enabled() {
    utils::large_mempool_base(false, true);
}

/// Test copied from `stacks-node::tests::signer::large_mempool_original_constant_fee`
/// Interesting because with full MARF compression produces patch nodes with 256 diffs (max diff allowed)
///
/// In this scenario, MARF compression **start enabled** for the first part of the test,
/// and **then disabled** for the second part of the test.
#[test]
#[ignore]
fn large_mempool_marf_compression_starts_enabled_and_then_disabled() {
    utils::large_mempool_base(true, false);
}
