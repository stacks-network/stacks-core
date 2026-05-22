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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::types::chainstate::StacksBlockId;
use clarity::vm::types::StacksAddressExtensions;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};

use super::{test_rpc, TestRPC};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::test::{
    key_to_stacks_addr, make_pox_4_lockup, make_signer_key_signature,
};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode,
    TransactionAuth, TransactionPayload, TransactionVersion,
};
use crate::net::api::getpoxinfo;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{HttpRequestContentsExtensions as _, StacksHttp, StacksHttpRequest};
use crate::net::test::TestEventObserver;
use crate::net::tests::{NakamotoBootPlan, NakamotoBootStep, NakamotoBootTenure};
use crate::net::{ProtocolFamily, TipRequest};
use crate::util_lib::signed_structured_data::pox4::Pox4SignatureTopic;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getpoxinfo(
        addr.into(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getpoxinfo::RPCPoxInfoRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    let request = StacksHttpRequest::new_getpoxinfo(addr.into(), TipRequest::UseLatestAnchoredTip);
    requests.push(request);

    // bad tip
    let request = StacksHttpRequest::new_getpoxinfo(
        addr.into(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    // this works
    let resp = response.decode_rpc_get_pox_info().unwrap();

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    // this fails with 404
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);
}

fn make_transfer_tx(
    key: &StacksPrivateKey,
    nonce: u64,
    recipient: &StacksAddress,
) -> StacksTransaction {
    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(key).unwrap(),
        TransactionPayload::TokenTransfer(
            recipient.to_account_principal(),
            1,
            TokenTransferMemo([0u8; 34]),
        ),
    );

    tx.chain_id = CHAIN_ID_TESTNET;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    tx.set_tx_fee(1);
    tx.auth.set_origin_nonce(nonce);

    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(key).unwrap();
    tx_signer.get_tx().unwrap()
}

fn make_padding_tenures(
    filler_keys: &[StacksPrivateKey],
    recipient: &StacksAddress,
    additional_tx: Option<StacksTransaction>,
) -> Vec<NakamotoBootTenure> {
    let mut extra_tenures = vec![];
    for (ix, key) in filler_keys.iter().enumerate() {
        let filler_tx = make_transfer_tx(key, 0, recipient);
        let txs = if ix == filler_keys.len() - 1 {
            let mut txs = vec![filler_tx];
            if let Some(tx) = additional_tx.clone() {
                txs.push(tx);
            }
            txs
        } else {
            vec![filler_tx]
        };
        extra_tenures.push(NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(txs),
        ]));
    }
    extra_tenures
}

fn with_test_stacker_amounts(boot_plan: NakamotoBootPlan) -> NakamotoBootPlan {
    // Use one consistent amount so stackers lock successfully and the test setup is stable.
    let test_stackers = boot_plan
        .test_stackers
        .iter()
        .cloned()
        .map(|mut stacker| {
            stacker.amount = 40_000_000_000_000_000;
            stacker
        })
        .collect();
    boot_plan.with_test_stackers(test_stackers)
}

fn decode_pox_info(
    response: crate::net::httpcore::StacksHttpResponse,
) -> getpoxinfo::RPCPoxInfoData {
    match response.clone().decode_rpc_get_pox_info() {
        Ok(info) => info,
        Err(e) => {
            let raw_response = String::from_utf8(response.try_serialize().unwrap_or_default())
                .unwrap_or_else(|_| "<non-utf8 response body>".to_string());
            panic!("failed to decode /v2/pox response: {e:?}\n{raw_response}");
        }
    }
}

#[test]
fn test_getpoxinfo_uses_persisted_threshold_after_additional_stack() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let request = StacksHttpRequest::new_getpoxinfo(addr.into(), TipRequest::UseLatestAnchoredTip);

    // Move into prepare phase for the next cycle, then submit one extra stack transaction.
    let filler_keys: Vec<_> = (0u8..8u8)
        .map(|ix| StacksPrivateKey::from_seed(&[0x70, ix]))
        .collect();
    let recipient_key = StacksPrivateKey::from_seed(b"pox-threshold-recipient");
    let recipient = key_to_stacks_addr(&recipient_key);

    let additional_stacker_key = StacksPrivateKey::from_seed(b"pox-threshold-extra-stacker");
    let additional_signer_key = StacksPrivateKey::from_seed(b"pox-threshold-extra-signer");
    let additional_signer_pub = StacksPublicKey::from_private(&additional_signer_key);
    let additional_stacker_addr = key_to_stacks_addr(&additional_stacker_key);
    let additional_pox_addr = PoxAddress::from_legacy(
        stacks_common::address::AddressHashMode::SerializeP2PKH,
        additional_stacker_addr.bytes().clone(),
    );

    // This transaction executes in reward cycle 5 in this boot-plan layout.
    let additional_amount = 500_000_000_000_000_000u128;
    let additional_auth_id = 777u128;
    let additional_sig = make_signer_key_signature(
        &additional_pox_addr,
        &additional_signer_key,
        5,
        &Pox4SignatureTopic::StackStx,
        1,
        additional_amount,
        additional_auth_id,
    );
    let additional_stack_tx = make_pox_4_lockup(
        &additional_stacker_key,
        0,
        additional_amount,
        &additional_pox_addr,
        1,
        &additional_signer_pub,
        59,
        Some(additional_sig),
        additional_amount,
        additional_auth_id,
    );

    let mut initial_balances = vec![(
        additional_stacker_addr.to_account_principal(),
        (additional_amount + 1_000_000) as u64,
    )];
    for key in filler_keys.iter() {
        initial_balances.push((key_to_stacks_addr(key).to_account_principal(), 1_000_000));
    }

    let baseline_test_name = format!("{}.baseline", function_name!());
    let baseline_pox = {
        let baseline_observer = TestEventObserver::new();
        let baseline_test = TestRPC::setup_nakamoto_with_boot_plan(
            &baseline_test_name,
            &baseline_observer,
            |boot_plan| {
                with_test_stacker_amounts(boot_plan)
                    .with_initial_balances(initial_balances.clone())
                    .with_boot_tenures(make_padding_tenures(&filler_keys, &recipient, None))
            },
        );
        let mut baseline_responses = baseline_test.run(vec![request.clone()]);
        decode_pox_info(baseline_responses.remove(0))
    };

    let additional_test_name = format!("{}.additional", function_name!());
    let additional_pox = {
        let additional_observer = TestEventObserver::new();
        let additional_test = TestRPC::setup_nakamoto_with_boot_plan(
            &additional_test_name,
            &additional_observer,
            |boot_plan| {
                with_test_stacker_amounts(boot_plan)
                    .with_initial_balances(initial_balances.clone())
                    .with_boot_tenures(make_padding_tenures(
                        &filler_keys,
                        &recipient,
                        Some(additional_stack_tx.clone()),
                    ))
            },
        );
        let mut additional_responses = additional_test.run(vec![request]);
        decode_pox_info(additional_responses.remove(0))
    };

    assert_eq!(baseline_pox.next_cycle.id, additional_pox.next_cycle.id);
    assert_eq!(
        baseline_pox.next_cycle.min_threshold_ustx,
        additional_pox.next_cycle.min_threshold_ustx
    );
    assert_eq!(
        additional_pox.next_cycle.stacked_ustx - baseline_pox.next_cycle.stacked_ustx,
        additional_amount as u64
    );

    let live_next_cycle_threshold = StacksChainState::get_threshold_from_participation(
        additional_pox.total_liquid_supply_ustx as u128,
        additional_pox.next_cycle.stacked_ustx as u128,
        additional_pox.reward_slots as u128,
    ) as u64;
    assert_ne!(
        additional_pox.next_cycle.min_threshold_ustx,
        live_next_cycle_threshold
    );
}
