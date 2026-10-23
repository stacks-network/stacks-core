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

use std::time::Duration;

use super::*;
use crate::burnchains::rpc::rpc_transport::{RpcAuth, RpcTransport};

fn pending_rpc(config: &Config, method: &str, params: Vec<serde_json::Value>) -> serde_json::Value {
    RpcTransport::new(
        format!("http://127.0.0.1:{}", config.burnchain.rpc_port),
        RpcAuth::Basic {
            username: "user".into(),
            password: "12345".into(),
        },
        Some(Duration::from_secs(5)),
    )
    .unwrap()
    .send("pending-fee-test", None, method, params)
    .unwrap()
}

fn pending_submit(
    btc: &mut BitcoinRegtestController,
    key: &Keychain,
    op: &LeaderBlockCommitOp,
) -> Result<Txid, BurnchainControllerError> {
    btc.submit_operation(
        StacksEpochId::Epoch31,
        BlockstackOperationType::LeaderBlockCommit(op.clone()),
        &mut key.generate_op_signer(),
    )
}

fn pending_fixture() -> (
    Keychain,
    Config,
    BitcoinCoreController,
    BitcoinRegtestController,
) {
    assert_eq!(env::var("BITCOIND_TEST").as_deref(), Ok("1"));
    let key = utils::create_keychain();
    let mut config = utils::create_miner_config();
    config.miner.segwit = true;
    config.burnchain.local_mining_public_key = Some(key.get_pub_key().to_hex());
    config.burnchain.pox_reward_length = Some(11);
    config.burnchain.satoshis_per_byte = 1;
    config.burnchain.rbf_fee_increment = 0;
    config.burnchain.max_rbf = 500;
    config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let mut bitcoind = BitcoinCoreController::from_stx_config(&config);
    bitcoind.start_bitcoind().unwrap();
    let mut btc = BitcoinRegtestController::new(config.clone(), None);
    btc.connect_dbs().unwrap();
    btc.bootstrap_chain(102);
    (key, config, bitcoind, btc)
}

// Exercise the real fresh-commit builder with an explicitly ordered RPC result,
// not just the comparator. No Bitcoin process or broadcast is needed here.
#[test]
fn pending_precise_fresh_utxo_order() {
    let mut server = mockito::Server::new();
    let policy = server
        .mock("POST", "/")
        .match_body(mockito::Matcher::PartialJson(serde_json::json!({
            "method": "getmempoolinfo"
        })))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(
            serde_json::json!({
                "id": "stacks", "error": null,
                "result": {"loaded": true, "mempoolminfee": 0.00001,
                    "minrelaytxfee": 0.00001, "incrementalrelayfee": 0.00001}
            })
            .to_string(),
        )
        .expect(8)
        .create();
    let key = utils::create_keychain();
    let mut config = utils::create_miner_config();
    config.burnchain.rpc_port = server.socket_address().port();
    config.miner.segwit = true;
    config.burnchain.rbf_fee_increment = 0;
    config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let script = SegwitBitcoinAddress::to_p2wpkh_tx_out(
        &Hash160::from_data(&key.get_pub_key().to_bytes_compressed()).0,
        0,
    )
    .script_pubkey;
    // (confirmations, amount): both RPC orders; confirmation age takes priority
    // over value; zero-confirmation change; equal-age smaller change; stable ties;
    // and only the needed prefix when one coin cannot cover the bid plus fee.
    let cases = [
        (vec![(100, 100_000), (1, 200_000)], vec![1]),
        (vec![(1, 200_000), (100, 100_000)], vec![0]),
        (vec![(1, 100_000), (0, 200_000)], vec![1]),
        (vec![(1, 200_000), (1, 100_000)], vec![1]),
        (vec![(1, 100_000), (1, 200_000)], vec![0]),
        (vec![(1, 100_000), (1, 100_000)], vec![0]),
        (vec![(100, 200_000), (2, 100_000), (1, 50_000)], vec![2, 1]),
        (vec![(1, 100_000)], vec![0]),
    ];
    for (specs, expected) in cases {
        let coins: Vec<_> = specs
            .iter()
            .enumerate()
            .map(|(index, &(confirmations, amount))| UTXO {
                txid: Sha256dHash::from_hex(&format!("{:064x}", index + 1)).unwrap(),
                vout: 3,
                script_pub_key: script.clone(),
                amount,
                confirmations,
            })
            .collect();
        let expected: Vec<_> = expected
            .into_iter()
            .map(|index| OutPoint {
                txid: coins[index].txid.clone(),
                vout: coins[index].vout,
            })
            .collect();
        let mut btc = BitcoinRegtestController::new_dummy(config.clone());
        let mut op = utils::create_templated_commit_op();
        op.burn_fee = 80_000;
        op.sunset_burn = 0;
        let fees = LeaderBlockCommitFees::estimated_fees_from_payload(&op, &config);
        let tx = btc
            .send_block_commit_operation_at_burnchain_height(
                StacksEpochId::Epoch31,
                op,
                &mut key.generate_op_signer(),
                Some(UTXOSet {
                    bhh: BurnchainHeaderHash([0; 32]),
                    utxos: coins,
                }),
                None,
                fees,
                &[],
                0,
            )
            .unwrap();
        assert_eq!(
            tx.input
                .iter()
                .map(|input| input.previous_output.clone())
                .collect::<Vec<_>>(),
            expected,
            "fresh selection for {specs:?}"
        );
        let owned = btc.get_ongoing_commit().unwrap();
        assert!(!owned.fees.is_rbf_enabled);
        assert_eq!(owned.utxos.utxos.len(), expected.len());
        let size = BitcoinRegtestController::commit_vsize(&tx, &owned.utxos).unwrap();
        assert!(owned.miner_fee >= replacement_pricing::rate_fee(1300, size).unwrap());
        assert!(owned.miner_fee <= 10_000);
        assert!(tx.output.last().unwrap().value >= DUST_UTXO_LIMIT);
    }
    policy.assert();
}

// Consecutive precise commits must spend the previous confirmed change even
// when older, independently sufficient funding comes first in the candidate set.
#[test]
#[ignore]
fn pending_precise_utxo_chain() {
    let (key, _config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let mut op = utils::create_templated_commit_op();
    op.burn_fee = 80_000;
    let mut previous_change = None;
    for _ in 0..4 {
        let mut coins = btc.get_all_utxos(&key.get_pub_key());
        assert!(coins.len() >= 2);
        coins.sort_by_key(|coin| (coin.confirmations, coin.amount));
        let preferred = OutPoint {
            txid: coins[0].txid.clone(),
            vout: coins[0].vout,
        };
        if let Some(previous) = &previous_change {
            assert_eq!(
                &preferred, previous,
                "previous change remains the preferred coin"
            );
        }
        coins.reverse(); // Force the wallet-order regression on every round.
        assert_ne!(coins[0].txid, preferred.txid);
        assert!(coins[0].amount > op.burn_fee + 10_000 + DUST_UTXO_LIMIT);
        let tx = btc
            .send_block_commit_operation(
                StacksEpochId::Epoch31,
                op.clone(),
                &mut key.generate_op_signer(),
                Some(UTXOSet {
                    bhh: btc.get_block_hash(0),
                    utxos: coins,
                }),
                None,
                None,
                &[],
            )
            .unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, preferred);
        let id = pending_submit(&mut btc, &key, &op).unwrap();
        assert_eq!(id, Txid::from_bitcoin_tx_hash(&tx.txid()));
        btc.build_next_block(1);
        assert!(btc.is_transaction_confirmed(&id));
        previous_change = Some(OutPoint {
            txid: tx.txid(),
            vout: (tx.output.len() - 1) as u32,
        });
        op.burn_fee += 10;
    }
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_precise_fresh_raise_retarget() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    btc.config.burnchain.block_commit_tx_estimated_size = 1000; // must not multiply precise fees
    let mut op = utils::create_templated_commit_op();
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let first_id = pending_submit(&mut btc, &key, &op).unwrap();
    let first = btc.get_ongoing_commit().unwrap();
    let size = pending_rpc(&config, "getmempoolentry", vec![first_id.to_hex().into()])["vsize"]
        .as_u64()
        .unwrap();
    assert!((replacement_pricing::rate_fee(1300, size).unwrap()
        ..=replacement_pricing::rate_fee(1300, size + 1).unwrap())
        .contains(&first.miner_fee));
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(4321);
    btc.ongoing_block_commit.as_mut().unwrap().retry_after = Instant::now();
    assert!(btc.pending_commit_needs_retry(false));
    btc.replacement_policy(&first)
        .expect("low precise fees must parse from Bitcoin's JSON representation");
    let raised = pending_submit(&mut btc, &key, &op).unwrap();
    let after = btc.get_ongoing_commit().unwrap();
    assert!(after.miner_fee < 1300, "no 1000-byte multiplier");
    assert_eq!(
        first.signed_tx.input[0].previous_output,
        after.signed_tx.input[0].previous_output
    );
    assert_eq!(
        &first.signed_tx.output[..first.signed_tx.output.len() - 1],
        &after.signed_tx.output[..after.signed_tx.output.len() - 1]
    );
    assert!(
        !btc.pending_commit_needs_retry(true),
        "new burn tip keeps normal relayer delay"
    );
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    assert!(!btc.pending_commit_needs_retry(false));
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    op.burn_fee += 10;
    let retarget = pending_submit(&mut btc, &key, &op).unwrap();
    let pending = btc.get_ongoing_commit().unwrap();
    assert!(
        pending.miner_fee > after.miner_fee,
        "required retarget still pays policy minimum"
    );
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(u64::MAX);
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    assert_eq!(btc.get_ongoing_commit().unwrap().txids, pending.txids);
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(0);
    btc.config.burnchain.block_commit_replacement_fee_max_sats = None;
    op.burn_fee += 10;
    let recovered = pending_submit(&mut btc, &key, &op).unwrap();
    assert_ne!(
        btc.get_ongoing_commit().unwrap().txids,
        pending.txids,
        "invalid hand edit must not prevent retarget using last valid fees"
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&recovered));
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    op.burn_fee += 10; // fresh payload, not a duplicate of the now-confirmed commit
    pending_submit(&mut btc, &key, &op).unwrap();
    let fresh = btc.get_ongoing_commit().unwrap();
    assert!(fresh.miner_fee < after.miner_fee);
    assert_ne!(raised, retarget);
    bitcoind.stop_bitcoind().unwrap();
}

// Seed and broadcast a valid owned attempt whose input order is the reverse of
// fresh selection. Fee-only RBF and a large payload bid cut must preserve both
// outpoints in that order, not apply the new fresh-selection rule to ownership.
#[test]
#[ignore]
fn pending_precise_owned_input_order() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let mut op = utils::create_templated_commit_op();
    op.burn_fee = 6_000_000_000; // Requires two regtest coinbases.
    let coins = btc.get_all_utxos(&key.get_pub_key());
    assert!(coins.len() >= 2);
    btc.send_block_commit_operation(
        StacksEpochId::Epoch31,
        op.clone(),
        &mut key.generate_op_signer(),
        Some(UTXOSet {
            bhh: btc.get_block_hash(0),
            utxos: coins.into_iter().take(2).collect(),
        }),
        None,
        None,
        &[],
    )
    .unwrap();
    let mut owned = btc.ongoing_block_commit.take().unwrap();
    assert_eq!(owned.utxos.utxos.len(), 2);
    owned.utxos.utxos.reverse();
    assert!(owned.utxos.utxos[0].confirmations > owned.utxos.utxos[1].confirmations);
    let mut tx = owned.signed_tx.clone();
    tx.input.clear();
    tx.output.pop(); // Rebuild change and signatures for the reversed input order.
    let cost = tx.output.iter().map(|output| output.value).sum::<u64>() + owned.miner_fee;
    assert!(btc.serialize_tx_with_inputs(
        StacksEpochId::Epoch31,
        &mut tx,
        cost,
        &mut owned.utxos,
        &mut key.generate_op_signer(),
        true,
        true,
    ));
    let expected: Vec<_> = tx
        .input
        .iter()
        .map(|input| input.previous_output.clone())
        .collect();
    owned.txids = vec![Txid::from_bitcoin_tx_hash(&tx.txid())];
    owned.signed_tx = tx.clone();
    owned.broadcast = CommitBroadcast::Unacknowledged(tx);
    btc.ongoing_block_commit = Some(owned);
    pending_submit(&mut btc, &key, &op).unwrap();

    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(4321);
    pending_submit(&mut btc, &key, &op).unwrap();
    let raised = btc.get_ongoing_commit().unwrap();
    assert!(raised.fees.is_rbf_enabled);
    assert_eq!(
        raised
            .signed_tx
            .input
            .iter()
            .map(|input| input.previous_output.clone())
            .collect::<Vec<_>>(),
        expected
    );
    op.burn_fee = 80_000; // One coin suffices now; ownership must still retain two.
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    let id = pending_submit(&mut btc, &key, &op).unwrap();
    let retargeted = btc.get_ongoing_commit().unwrap();
    assert!(retargeted.fees.is_rbf_enabled);
    assert_eq!(
        retargeted
            .signed_tx
            .input
            .iter()
            .map(|input| input.previous_output.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([id.to_hex()])
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&id));
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_precise_policy_outage_fresh_only() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(1300);
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let mut op = utils::create_templated_commit_op();
    for fault in [
        PendingFault::MempoolUnavailable,
        PendingFault::MempoolLoading,
    ] {
        let proxy = PendingFaultProxy::with_fault(&config, &mut btc, fault);
        // The observation fails repeatedly, but the genuine Bitcoin broadcast
        // must still accept a fresh configured-rate commit.
        let id = pending_submit(&mut btc, &key, &op).unwrap();
        let before = btc.get_ongoing_commit().unwrap();
        let size = pending_rpc(&config, "getmempoolentry", vec![id.to_hex().into()])["vsize"]
            .as_u64()
            .unwrap();
        assert!((replacement_pricing::rate_fee(1300, size).unwrap()
            ..=replacement_pricing::rate_fee(1300, size + 1).unwrap())
            .contains(&before.miner_fee));
        op.burn_fee += 10;
        assert!(
            pending_submit(&mut btc, &key, &op).is_err(),
            "replacement evidence is still mandatory"
        );
        assert_eq!(btc.get_ongoing_commit().unwrap().txids, before.txids);
        assert_eq!(proxy.sends.lock().unwrap().len(), 1);
        drop(proxy);
        btc.rpc_client = BitcoinRegtestController::create_rpc_client_unchecked(&config);
        btc.build_next_block(1);
        assert!(btc.is_transaction_confirmed(&id));
    }
    // Fallback still obeys the absolute cap; it never authorizes an over-cap tx.
    btc.config.burnchain.block_commit_fee_rate_sat_per_kvb = Some(100_000);
    op.burn_fee += 10;
    let proxy = PendingFaultProxy::with_fault(&config, &mut btc, PendingFault::MempoolUnavailable);
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    assert!(proxy.sends.lock().unwrap().is_empty());
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_pricing_raise_retarget_and_absolute_limit() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_tx_estimated_size = 370;
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    btc.config.burnchain.satoshis_per_byte = 3;
    let mut op = utils::create_templated_commit_op();
    pending_submit(&mut btc, &key, &op).unwrap();
    let original = btc.get_ongoing_commit().unwrap();
    assert_eq!(original.miner_fee, 1110);
    btc.config.burnchain.satoshis_per_byte = 4;
    let raised = pending_submit(&mut btc, &key, &op).unwrap();
    let first = btc.get_ongoing_commit().unwrap();
    assert_eq!(
        first.miner_fee, 1480,
        "no cumulative surcharge on market raise"
    );
    assert_eq!(
        first
            .signed_tx
            .input
            .iter()
            .map(|i| &i.previous_output)
            .collect::<Vec<_>>(),
        original
            .signed_tx
            .input
            .iter()
            .map(|i| &i.previous_output)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        &first.signed_tx.output[..first.signed_tx.output.len() - 1],
        &original.signed_tx.output[..original.signed_tx.output.len() - 1]
    );
    assert_eq!(
        bitcoin_amount(
            &pending_rpc(&config, "getmempoolentry", vec![raised.to_hex().into()])["fees"]["base"]
        )
        .unwrap(),
        1480
    );
    // Lowering the target and legacy ratio must not strand a payload retarget.
    btc.config.burnchain.satoshis_per_byte = 1;
    btc.config.burnchain.max_rbf = 50;
    op.burn_fee += 10;
    let retarget = pending_submit(&mut btc, &key, &op).unwrap();
    let second = btc.get_ongoing_commit().unwrap();
    let size = pending_rpc(&config, "getmempoolentry", vec![retarget.to_hex().into()])["vsize"]
        .as_u64()
        .unwrap();
    assert!((size..=size + 1).contains(&(second.miner_fee - first.miner_fee)));
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    // The explicit absolute ceiling still works, without losing ownership.
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(second.miner_fee);
    op.burn_fee += 10;
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::MaxFeeRateExceeded)
    ));
    assert_eq!(btc.get_ongoing_commit().unwrap().txids, second.txids);
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([retarget.to_hex()])
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&retarget));
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_pricing_rejection_and_lost_ack() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let op = utils::create_templated_commit_op();
    let original = pending_submit(&mut btc, &key, &op).unwrap();
    let before = btc.get_ongoing_commit().unwrap();
    let proxy = PendingFaultProxy::with_fault(&config, &mut btc, PendingFault::RejectBeforeSend);
    btc.config.burnchain.satoshis_per_byte = 3;
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    assert_eq!(btc.get_ongoing_commit().unwrap().txids, before.txids);
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([original.to_hex()])
    );
    drop(proxy);
    let proxy = PendingFaultProxy::with_fault(&config, &mut btc, PendingFault::LostAck);
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    let pending = btc.get_ongoing_commit().unwrap();
    let CommitBroadcast::Unacknowledged(signed) = pending.broadcast.clone() else {
        panic!("a lost acknowledgement must keep the signed bytes");
    };
    let retried = pending_submit(&mut btc, &key, &op).unwrap();
    assert_eq!(retried, Txid::from_bitcoin_tx_hash(&signed.txid()));
    let sends = proxy.sends.lock().unwrap().clone();
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[0], sends[1]);
    assert_eq!(
        btc.get_ongoing_commit().unwrap().miner_fee,
        pending.miner_fee
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&retried));
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_pricing_multi_input_retarget_and_modified_fee() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    btc.config.burnchain.satoshis_per_byte = 3;
    let mut op = utils::create_templated_commit_op();
    op.burn_fee = 6_000_000_000; // More than a single regtest coinbase.
                                 // Stock fresh selection filters out coins smaller than the whole bid.
                                 // Supply two real coins explicitly to exercise ownership of a multi-input
                                 // attempt without changing that unrelated wallet selection policy.
    let coins = btc.get_all_utxos(&key.get_pub_key());
    assert!(coins.len() >= 2);
    btc.send_block_commit_operation(
        StacksEpochId::Epoch31,
        op.clone(),
        &mut key.generate_op_signer(),
        Some(UTXOSet {
            bhh: btc.get_block_hash(0),
            utxos: coins.into_iter().take(2).collect(),
        }),
        None,
        None,
        &[],
    )
    .unwrap();
    let original = pending_submit(&mut btc, &key, &op).unwrap();
    let before = btc.get_ongoing_commit().unwrap();
    assert!(before.signed_tx.input.len() > 1);
    // Nonzero local fee deltas are deliberately unsupported, never silently copied.
    pending_rpc(
        &config,
        "prioritisetransaction",
        vec![original.to_hex().into(), 0.into(), 1000.into()],
    );
    btc.config.burnchain.satoshis_per_byte = 4;
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    assert_eq!(btc.get_ongoing_commit().unwrap().txids, before.txids);
    pending_rpc(
        &config,
        "prioritisetransaction",
        vec![original.to_hex().into(), 0.into(), (-1000).into()],
    );
    // A large bid cut must not drop an input or start a second transaction chain.
    op.burn_fee = 100_000;
    btc.config.burnchain.satoshis_per_byte = 1;
    let id = pending_submit(&mut btc, &key, &op).unwrap();
    let after = btc.get_ongoing_commit().unwrap();
    assert_eq!(
        before
            .signed_tx
            .input
            .iter()
            .map(|i| &i.previous_output)
            .collect::<Vec<_>>(),
        after
            .signed_tx
            .input
            .iter()
            .map(|i| &i.previous_output)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([id.to_hex()])
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&id));
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_limits_and_insufficient_change() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    let mut op = utils::create_templated_commit_op();
    // Leave enough for the original fee and mandatory change, but not a replacement.
    // A second spendable coin exists: fee-only RBF must not select it.
    op.burn_fee = 5_000_000_000 - op.sunset_burn - DUST_UTXO_LIMIT - 500;
    let id = pending_submit(&mut btc, &key, &op).unwrap();
    let before = btc.get_ongoing_commit().unwrap();
    btc.config.burnchain.satoshis_per_byte = 2;
    btc.config.burnchain.max_rbf = 50;
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::MaxFeeRateExceeded)
    ));
    btc.config.burnchain.max_rbf = 500;
    assert!(
        pending_submit(&mut btc, &key, &op).is_err(),
        "insufficient change must reject the build"
    );
    let after = btc.get_ongoing_commit().unwrap();
    assert_eq!(
        before.txids, after.txids,
        "failed build must retain the last viable transaction"
    );
    assert_eq!(before.fees.fee_rate, after.fees.fee_rate);
    assert_eq!(before.utxos.utxos, after.utxos.utxos);
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([id.to_hex()])
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&id));
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_unmanaged_retarget_cap() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_replacement_fee_max_sats = None;
    btc.config.burnchain.satoshis_per_byte = 5;
    btc.config.burnchain.rbf_fee_increment = 5;
    btc.config.burnchain.max_rbf = 150;
    let mut op = utils::create_templated_commit_op();
    let first = pending_submit(&mut btc, &key, &op).unwrap();
    op.burn_fee += 10;
    let second = pending_submit(&mut btc, &key, &op)
        .expect("legacy retarget must allow its first bump with default settings");
    assert_ne!(first, second);
    assert_eq!(btc.get_ongoing_commit().unwrap().fees.fee_rate, 10);
    op.burn_fee += 10;
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::MaxFeeRateExceeded)
    ));
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([second.to_hex()])
    );
    bitcoind.stop_bitcoind().unwrap();
}

// Real Bitcoin RPC remains authoritative. Only the response *after* acceptance is
// replaced by a transport error; all retries cross Bitcoin's actual mempool policy.
struct PendingFaultProxy {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    sends: Arc<std::sync::Mutex<Vec<String>>>,
}

#[derive(Clone, Copy)]
enum PendingFault {
    LostAck,
    ConfirmBeforeSend,
    RejectBeforeSend,
    AlreadyConfirmed,
    WalletWarmup,
    MempoolUnavailable,
    MempoolLoading,
}

impl PendingFaultProxy {
    fn start(
        config: &Config,
        btc: &mut BitcoinRegtestController,
        confirm_before_send: bool,
    ) -> Self {
        Self::with_fault(
            config,
            btc,
            if confirm_before_send {
                PendingFault::ConfirmBeforeSend
            } else {
                PendingFault::LostAck
            },
        )
    }

    fn with_fault(config: &Config, btc: &mut BitcoinRegtestController, mode: PendingFault) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let sends = Arc::new(std::sync::Mutex::new(vec![]));
        let recorded = sends.clone();
        let target = config.clone();
        let thread = std::thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            let mut fault = true;
            while !stopped.load(Ordering::SeqCst) {
                let Some(mut request) = server.recv_timeout(Duration::from_millis(100)).unwrap()
                else {
                    continue;
                };
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                let json: serde_json::Value = serde_json::from_str(&body).unwrap();
                if json["method"] == "getmempoolinfo"
                    && matches!(
                        mode,
                        PendingFault::MempoolUnavailable | PendingFault::MempoolLoading
                    )
                {
                    let (status, response) = if matches!(mode, PendingFault::MempoolUnavailable) {
                        (
                            503,
                            serde_json::json!({"id": json["id"], "result": null,
                            "error": {"code": -28, "message": "injected policy observation outage"}}),
                        )
                    } else {
                        (
                            200,
                            serde_json::json!({"id": json["id"], "error": null,
                            "result": {"loaded": false, "mempoolminfee": 0.00001, "minrelaytxfee": 0.00001}}),
                        )
                    };
                    request
                        .respond(
                            tiny_http::Response::from_string(response.to_string())
                                .with_status_code(status)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .unwrap(),
                                ),
                        )
                        .unwrap();
                    continue;
                }
                if fault
                    && matches!(mode, PendingFault::WalletWarmup)
                    && json["method"] == "listwallets"
                {
                    fault = false;
                    let response = serde_json::json!({"id": json["id"], "result": null,
                        "error": {"code": -28, "message": "Loading block index..."}});
                    request
                        .respond(
                            tiny_http::Response::from_string(response.to_string())
                                .with_status_code(500)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .unwrap(),
                                ),
                        )
                        .unwrap();
                    continue;
                }
                let is_send = json["method"] == "sendrawtransaction";
                if is_send {
                    recorded
                        .lock()
                        .unwrap()
                        .push(json["params"][0].as_str().unwrap().into());
                    if fault && matches!(mode, PendingFault::RejectBeforeSend) {
                        fault = false;
                        let response = serde_json::json!({"id": json["id"], "result": null,
                            "error": {"code": -26, "message": "injected policy rejection"}});
                        request
                            .respond(
                                tiny_http::Response::from_string(response.to_string())
                                    .with_status_code(500)
                                    .with_header(
                                        tiny_http::Header::from_bytes(
                                            "Content-Type",
                                            "application/json",
                                        )
                                        .unwrap(),
                                    ),
                            )
                            .unwrap();
                        continue;
                    }
                    if fault && matches!(mode, PendingFault::ConfirmBeforeSend) {
                        let address = utils::to_address_segwit_p2wpkh(
                            &utils::create_keychain().get_pub_key(),
                        )
                        .to_string();
                        pending_rpc(&target, "generatetoaddress", vec![1.into(), address.into()]);
                    }
                }
                let response = client
                    .post(format!(
                        "http://127.0.0.1:{}{}",
                        target.burnchain.rpc_port,
                        request.url()
                    ))
                    .basic_auth("user", Some("12345"))
                    .body(body)
                    .send()
                    .unwrap();
                let status = response.status().as_u16();
                let bytes = response.bytes().unwrap();
                if is_send && fault && matches!(mode, PendingFault::AlreadyConfirmed) {
                    fault = false;
                    assert_eq!(status, 200);
                    let address =
                        utils::to_address_segwit_p2wpkh(&utils::create_keychain().get_pub_key())
                            .to_string();
                    pending_rpc(&target, "generatetoaddress", vec![1.into(), address.into()]);
                    let response = serde_json::json!({"id": json["id"], "result": null,
                        "error": {"code": -27, "message": "Transaction already in block chain"}});
                    request
                        .respond(
                            tiny_http::Response::from_string(response.to_string())
                                .with_status_code(500)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .unwrap(),
                                ),
                        )
                        .unwrap();
                } else if is_send && fault && matches!(mode, PendingFault::LostAck) {
                    fault = false;
                    assert_eq!(
                        status, 200,
                        "Bitcoin must accept before the acknowledgement is lost"
                    );
                    let _ = request.respond(
                        tiny_http::Response::from_string("lost acknowledgement")
                            .with_status_code(502),
                    );
                } else {
                    if is_send {
                        fault = false;
                    }
                    let _ = request.respond(
                        tiny_http::Response::from_data(bytes.to_vec())
                            .with_status_code(status)
                            .with_header(
                                tiny_http::Header::from_bytes("Content-Type", "application/json")
                                    .unwrap(),
                            ),
                    );
                }
            }
        });
        let mut proxied = config.clone();
        proxied.burnchain.rpc_port = port;
        btc.rpc_client = BitcoinRegtestController::create_rpc_client_unchecked(&proxied);
        Self {
            stop,
            thread: Some(thread),
            sends,
        }
    }
}

impl Drop for PendingFaultProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
#[ignore]
fn pending_fee_wallet_startup_retries_warmup() {
    let (_key, config, mut bitcoind, mut btc) = pending_fixture();
    let proxy = PendingFaultProxy::with_fault(&config, &mut btc, PendingFault::WalletWarmup);
    // Exercise the actual startup entry point: the first listwallets gets a
    // Bitcoin -28/HTTP 500; its retry reaches the real, loaded Bitcoin wallet.
    btc.ensure_miner_wallet_loaded();
    assert!(btc.ensure_wallet_loaded().is_ok());
    assert!(
        proxy.sends.lock().unwrap().is_empty(),
        "startup must not submit a transaction"
    );
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_explicit_rejection() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    let op = utils::create_templated_commit_op();
    let original = pending_submit(&mut btc, &key, &op).unwrap();
    let before = btc.get_ongoing_commit().unwrap();
    let proxy = PendingFaultProxy::with_fault(&config, &mut btc, PendingFault::RejectBeforeSend);
    btc.config.burnchain.satoshis_per_byte = 3;
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    let after = btc.get_ongoing_commit().unwrap();
    assert_eq!(
        after.txids, before.txids,
        "rejected replacement must not become the tracked attempt"
    );
    assert_eq!(after.fees.fee_rate, before.fees.fee_rate);
    assert_eq!(after.fees.spent_in_attempts, before.fees.spent_in_attempts);
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([original.to_hex()])
    );
    let replacement = pending_submit(&mut btc, &key, &op).unwrap();
    let sends = proxy.sends.lock().unwrap().clone();
    assert_eq!(sends.len(), 2);
    assert_eq!(
        sends[0], sends[1],
        "rejection must not accumulate an additional fee surcharge"
    );
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([replacement.to_hex()])
    );
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_already_confirmed_ack() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    let op = utils::create_templated_commit_op();
    let proxy = PendingFaultProxy::with_fault(&config, &mut btc, PendingFault::AlreadyConfirmed);
    let id = pending_submit(&mut btc, &key, &op)
        .expect("confirmed transaction is acknowledged, not retried");
    assert!(btc.is_transaction_confirmed(&id));
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    assert_eq!(proxy.sends.lock().unwrap().len(), 1);
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_lost_ack() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    let op = utils::create_templated_commit_op();
    pending_submit(&mut btc, &key, &op).unwrap();
    let proxy = PendingFaultProxy::start(&config, &mut btc, false);
    btc.config.burnchain.satoshis_per_byte = 3;
    assert!(pending_submit(&mut btc, &key, &op).is_err());
    let in_pool = pending_rpc(&config, "getrawmempool", vec![]);
    assert_eq!(in_pool.as_array().unwrap().len(), 1);
    // The accepted level-3 replacement already covers level 4 through its
    // surcharge. A lost ack must still resend those exact bytes, not suppress
    // recovery or advance the replacement ladder at the new fresh-commit target.
    btc.config.burnchain.satoshis_per_byte = 4;
    let id = pending_submit(&mut btc, &key, &op)
        .expect("retry must retransmit exactly the accepted bytes");
    assert_eq!(in_pool, serde_json::json!([id.to_hex()]));
    let sends = proxy.sends.lock().unwrap().clone();
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[0], sends[1]);
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&id));
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_confirmation_race_and_reorg() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    let op = utils::create_templated_commit_op();
    let original = pending_submit(&mut btc, &key, &op).unwrap();
    let proxy = PendingFaultProxy::start(&config, &mut btc, true);
    btc.config.burnchain.satoshis_per_byte = 3;
    assert!(
        pending_submit(&mut btc, &key, &op).is_err(),
        "original confirms immediately before RBF broadcast"
    );
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    assert_eq!(
        proxy.sends.lock().unwrap().len(),
        1,
        "no new wallet spend after original confirms"
    );
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([])
    );
    assert!(btc.is_transaction_confirmed(&original));
    let tip = pending_rpc(&config, "getbestblockhash", vec![]);
    pending_rpc(&config, "invalidateblock", vec![tip]);
    assert!(!btc.is_transaction_confirmed(&original));
    btc.config.burnchain.satoshis_per_byte = 4;
    let replacement = pending_submit(&mut btc, &key, &op).unwrap();
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([replacement.to_hex()])
    );
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&replacement));
    drop(proxy);
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_real_replacements() {
    assert_eq!(
        env::var("BITCOIND_TEST").as_deref(),
        Ok("1"),
        "regtest must execute, not skip"
    );
    let key = utils::create_keychain();
    let mut config = utils::create_miner_config();
    config.miner.segwit = true;
    config.burnchain.local_mining_public_key = Some(key.get_pub_key().to_hex());
    config.burnchain.pox_reward_length = Some(11);
    config.burnchain.satoshis_per_byte = 1;
    config.burnchain.rbf_fee_increment = 0;
    config.burnchain.max_rbf = 500;
    config.burnchain.block_commit_replacement_fee_max_sats = Some(10_000);
    let mut bitcoind = BitcoinCoreController::from_stx_config(&config);
    bitcoind.start_bitcoind().unwrap();
    let mut btc = BitcoinRegtestController::new(config.clone(), None);
    btc.connect_dbs().unwrap();
    btc.bootstrap_chain(102);
    let op = utils::create_templated_commit_op();
    let mut id = pending_submit(&mut btc, &key, &op).unwrap();
    let original = pending_rpc(
        &config,
        "getrawtransaction",
        vec![id.to_hex().into(), true.into()],
    );
    let mut old_fee = pending_rpc(&config, "getmempoolentry", vec![id.to_hex().into()])["fees"]
        ["base"]
        .as_f64()
        .unwrap();
    for rate in [2, 4] {
        btc.config.burnchain.satoshis_per_byte = rate;
        let replacement = pending_submit(&mut btc, &key, &op)
            .expect("fee-only raise must replace identical payload");
        assert_ne!(id, replacement);
        let raw = pending_rpc(
            &config,
            "getrawtransaction",
            vec![replacement.to_hex().into(), true.into()],
        );
        assert_eq!(original["vin"][0]["txid"], raw["vin"][0]["txid"]);
        assert_eq!(original["vin"][0]["vout"], raw["vin"][0]["vout"]);
        let outs = original["vout"].as_array().unwrap().len();
        assert_eq!(
            &original["vout"].as_array().unwrap()[..outs - 1],
            &raw["vout"].as_array().unwrap()[..outs - 1],
            "only change output and witness may change"
        );
        let pool = pending_rpc(&config, "getrawmempool", vec![]);
        assert_eq!(pool, serde_json::json!([replacement.to_hex()]));
        let fee = pending_rpc(
            &config,
            "getmempoolentry",
            vec![replacement.to_hex().into()],
        )["fees"]["base"]
            .as_f64()
            .unwrap();
        assert!(fee > old_fee);
        assert_eq!(pending_rpc(&config, "getblockcount", vec![]), 102);
        println!(
            "PENDING_FEE_EVIDENCE rate={rate} old={} replacement={} fee_sats={}",
            id,
            replacement,
            (fee * 1e8).round()
        );
        old_fee = fee;
        id = replacement;
    }
    btc.config.burnchain.satoshis_per_byte = 1;
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([id.to_hex()])
    );
    btc.build_next_block(1);
    btc.config.burnchain.satoshis_per_byte = 6;
    assert!(matches!(
        pending_submit(&mut btc, &key, &op),
        Err(BurnchainControllerError::IdenticalOperation)
    ));
    assert_eq!(
        pending_rpc(&config, "getrawmempool", vec![]),
        serde_json::json!([])
    );
    bitcoind.stop_bitcoind().unwrap();
}

#[test]
#[ignore]
fn pending_fee_surcharge_coverage_and_fresh_target() {
    let (key, config, mut bitcoind, mut btc) = pending_fixture();
    btc.config.burnchain.block_commit_tx_estimated_size = 370;
    let mut op = utils::create_templated_commit_op();
    let first = pending_submit(&mut btc, &key, &op).unwrap();
    btc.config.burnchain.satoshis_per_byte = 2;
    let second = pending_submit(&mut btc, &key, &op).unwrap();
    assert_ne!(first, second);
    let fee_sats = |id: &Txid| -> u64 {
        (pending_rpc(&config, "getmempoolentry", vec![id.to_hex().into()])["fees"]["base"]
            .as_f64()
            .unwrap()
            * 1e8)
            .round() as u64
    };
    // Bitcoin's actual mempool fee, not the internal level, proves the surplus.
    assert_eq!(fee_sats(&second), 1111);
    for level in [3, 3, 2, 3] {
        btc.config.burnchain.satoshis_per_byte = level;
        assert!(
            matches!(
                pending_submit(&mut btc, &key, &op),
                Err(BurnchainControllerError::IdenticalOperation)
            ),
            "already-paid surcharge covers the fresh target; no extra RBF"
        );
        assert_eq!(
            pending_rpc(&config, "getrawmempool", vec![]),
            serde_json::json!([second.to_hex()])
        );
        assert_eq!(fee_sats(&second), 1111);
    }
    // A real payload change must still retarget, regardless of sufficient fees.
    op.burn_fee += 10;
    let retarget = pending_submit(&mut btc, &key, &op).unwrap();
    assert_ne!(retarget, second);
    assert!(fee_sats(&retarget) > 1110);
    btc.build_next_block(1);
    assert!(btc.is_transaction_confirmed(&retarget));
    op.burn_fee += 10;
    let fresh = pending_submit(&mut btc, &key, &op).unwrap();
    assert_eq!(get_satoshis_per_byte(&btc.config), 3);
    assert_eq!(
        fee_sats(&fresh),
        1110,
        "next fresh commit uses level 3, with no inherited surcharge"
    );
    println!("PENDING_COVERAGE_EVIDENCE pending_fee=1111 skipped_level=3 fresh_fee=1110 retarget={retarget}");
    bitcoind.stop_bitcoind().unwrap();
}
