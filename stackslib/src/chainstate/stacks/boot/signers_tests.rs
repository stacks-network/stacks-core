// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::tests::symbols_from_values;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, TupleData};
use clarity::vm::Value::Principal;
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{
    BurnchainHeaderHash, StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::PublicKey;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::coordinator::tests::{boot_nakamoto, make_token_transfer};
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::{TestSigners, TestStacker};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::pox_2_tests::with_clarity_db_ro;
use crate::chainstate::stacks::boot::pox_4_tests::{
    assert_latest_was_burn, get_last_block_sender_transactions, make_test_epochs_pox,
    prepare_pox4_test,
};
use crate::chainstate::stacks::boot::test::{
    instantiate_pox_peer_with_epoch, key_to_stacks_addr, make_pox_4_lockup, with_sortdb,
};
use crate::chainstate::stacks::boot::SIGNERS_NAME;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TenureChangeCause, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionVersion,
};
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::BITCOIN_REGTEST_FIRST_BLOCK_HASH;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::util_lib::boot::{boot_code_addr, boot_code_id, boot_code_test_addr};

#[test]
fn signers_get_config() {
    let (burnchain, mut peer, keys, latest_block, ..) = prepare_pox4_test(function_name!(), None);

    assert_eq!(
        readonly_call(
            &mut peer,
            &latest_block,
            "signers".into(),
            "stackerdb-get-config".into(),
            vec![],
        ),
        Value::okay(Value::Tuple(
            TupleData::from_data(vec![
                ("chunk-size".into(), Value::UInt(4096)),
                ("write-freq".into(), Value::UInt(0)),
                ("max-writes".into(), Value::UInt(4096)),
                ("max-neighbors".into(), Value::UInt(32)),
                (
                    "hint-replicas".into(),
                    Value::cons_list_unsanitized(vec![]).unwrap()
                )
            ])
            .unwrap()
        ))
        .unwrap()
    );
}

#[test]
fn signers_get_signer_keys_from_stackerdb() {
    let stacker_1 = TestStacker::from_seed(&[3, 4]);
    let stacker_2 = TestStacker::from_seed(&[5, 6]);

    let (mut peer, test_signers, latest_block_id) =
        prepare_signers_test(function_name!(), Some(vec![&stacker_1, &stacker_2]));

    let private_key = peer.config.private_key.clone();

    let mut expected_signers: Vec<_> =
        [&stacker_1.signer_private_key, &stacker_2.signer_private_key]
            .iter()
            .map(|sk| {
                let pk = Secp256k1PublicKey::from_private(sk);
                let pk_bytes = pk.to_bytes_compressed();
                let signer_addr = StacksAddress::p2pkh(false, &pk);
                let stackerdb_entry = TupleData::from_data(vec![
                    ("signer".into(), PrincipalData::from(signer_addr).into()),
                    ("num-slots".into(), Value::UInt(2)),
                ])
                .unwrap();
                (pk_bytes, stackerdb_entry)
            })
            .collect();
    // should be sorted by the pk bytes
    expected_signers.sort_by_key(|x| x.0.clone());
    let expected_stackerdb_slots = Value::cons_list_unsanitized(
        expected_signers
            .into_iter()
            .map(|(_pk, entry)| Value::from(entry))
            .collect(),
    )
    .unwrap();

    let signers = readonly_call(
        &mut peer,
        &latest_block_id,
        "signers".into(),
        "stackerdb-get-signer-slots".into(),
        vec![],
    )
    .expect_result_ok();

    assert_eq!(signers, expected_stackerdb_slots);
}

fn prepare_signers_test<'a>(
    test_name: &str,
    stackers: Option<Vec<&TestStacker>>,
) -> (TestPeer<'a>, TestSigners, StacksBlockId) {
    let mut test_signers = TestSigners::default();

    let mut peer = boot_nakamoto(test_name, vec![], &test_signers, stackers);

    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);

    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops);

    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();
    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx,
        &mut test_signers,
        |_miner, _chainstate, _sort_dbconn, _blocks| vec![],
    );
    let latest_block_id = blocks_and_sizes.last().unwrap().0.block_id();

    (peer, test_signers, latest_block_id)
}

fn advance_blocks(
    peer: &mut TestPeer,
    test_signers: &mut TestSigners,
    stacker_private_key: &StacksPrivateKey,
    num_blocks: u64,
) -> StacksBlockId {
    let current_height = peer.get_burnchain_view().unwrap().burn_block_height;

    //let key = peer.config.private_key;

    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);

    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops);

    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();
    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);
    let recipient_addr = boot_code_addr(false);
    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx.clone(),
        test_signers,
        |miner, chainstate, sortdb, blocks| {
            if blocks.len() < num_blocks as usize {
                let addr = key_to_stacks_addr(&stacker_private_key);
                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &stacker_private_key,
                    account.nonce,
                    1,
                    1,
                    &recipient_addr,
                );
                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );
    info!("tenure length {}", blocks_and_sizes.len());
    let latest_block_id = blocks_and_sizes.last().unwrap().0.block_id();
    latest_block_id
}

fn readonly_call(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    boot_contract: ContractName,
    function_name: ClarityName,
    args: Vec<Value>,
) -> Value {
    with_sortdb(peer, |chainstate, sortdb| {
        chainstate.with_read_only_clarity_tx(&sortdb.index_conn(), tip, |connection| {
            connection
                .with_readonly_clarity_env(
                    false,
                    0x80000000,
                    ClarityVersion::Clarity2,
                    PrincipalData::from(boot_code_addr(false)),
                    None,
                    LimitedCostTracker::new_free(),
                    |env| {
                        env.execute_contract_allow_private(
                            &boot_code_id(&boot_contract, false),
                            &function_name,
                            &symbols_from_values(args),
                            true,
                        )
                    },
                )
                .unwrap()
        })
    })
    .unwrap()
}
