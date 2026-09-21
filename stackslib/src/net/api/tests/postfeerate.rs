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

use clarity::codec::StacksMessageCodec;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::StacksAddressExtensions;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::Address;
use stacks_common::util::hash::to_hex;

use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::stacks::{TokenTransferMemo, TransactionPayload};
use crate::net::api::tests::TestRPC;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest};
use crate::net::test::RPCHandlerArgsType;
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let sender_addr =
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap();
    let tx_payload =
        TransactionPayload::new_contract_call(sender_addr, "hello-world", "add-unit", vec![])
            .unwrap();

    let request = StacksHttpRequest::new_post_fee_rate(
        addr.into(),
        postfeerate::FeeRateEstimateRequestBody {
            estimated_len: Some(123),
            transaction_payload: to_hex(&tx_payload.serialize_to_vec()),
        },
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = postfeerate::RPCPostFeeRateRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.estimated_len, Some(123));
    assert_eq!(handler.transaction_payload, Some(tx_payload));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.estimated_len.is_none());
    assert!(handler.transaction_payload.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let sender_addr =
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap();
    let tx_payload = TransactionPayload::new_contract_call(
        sender_addr.clone(),
        "hello-world",
        "add-unit",
        vec![],
    )
    .unwrap();

    // case 1: no fee estimates
    let mut requests = vec![];
    let request = StacksHttpRequest::new_post_fee_rate(
        addr.into(),
        postfeerate::FeeRateEstimateRequestBody {
            estimated_len: Some(123),
            transaction_payload: to_hex(&tx_payload.serialize_to_vec()),
        },
    );
    requests.push(request);

    let test_rpc = TestRPC::setup(function_name!());
    let mut responses = test_rpc.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    let body_json: serde_json::Value = body.try_into().unwrap();

    // get back a JSON string and a 400
    assert_eq!(preamble.status_code, 400);
    debug!("Response JSON no estimator: {}", &body_json);

    // case 2: no estimate available
    let mut requests = vec![];
    let request = StacksHttpRequest::new_post_fee_rate(
        addr.into(),
        postfeerate::FeeRateEstimateRequestBody {
            estimated_len: Some(123),
            transaction_payload: to_hex(&tx_payload.serialize_to_vec()),
        },
    );
    requests.push(request);

    let test_rpc = TestRPC::setup_with_rpc_args(
        function_name!(),
        Some(RPCHandlerArgsType::Null),
        Some(RPCHandlerArgsType::Null),
    );
    let mut responses = test_rpc.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    let body_json: serde_json::Value = body.try_into().unwrap();

    // get back a JSON object and a 400
    assert_eq!(preamble.status_code, 400);
    debug!("Response JSON no estimate fee: {}", &body_json);
    assert_eq!(
        body_json.get("reason").unwrap().as_str().unwrap(),
        "NoEstimateAvailable"
    );
    assert!(body_json.get("error").is_some());
    assert!(body_json.get("reason_data").is_some());

    // case 3: get estimates for transfer and contract-call payloads
    let transfer_payload = TransactionPayload::TokenTransfer(
        sender_addr.clone().to_account_principal(),
        1,
        TokenTransferMemo([0; 34]),
    );
    let transfer_request = StacksHttpRequest::new_post_fee_rate(
        addr.into(),
        postfeerate::FeeRateEstimateRequestBody {
            estimated_len: None,
            transaction_payload: to_hex(&transfer_payload.serialize_to_vec()),
        },
    );
    let contract_request = StacksHttpRequest::new_post_fee_rate(
        addr.into(),
        postfeerate::FeeRateEstimateRequestBody {
            estimated_len: None,
            transaction_payload: to_hex(&tx_payload.serialize_to_vec()),
        },
    );
    let estimated_len = 1550;
    let long_contract_request = StacksHttpRequest::new_post_fee_rate(
        addr.into(),
        postfeerate::FeeRateEstimateRequestBody {
            estimated_len: Some(estimated_len),
            transaction_payload: to_hex(&tx_payload.serialize_to_vec()),
        },
    );

    let test_rpc = TestRPC::setup_with_rpc_args(
        function_name!(),
        Some(RPCHandlerArgsType::FeeResponse),
        Some(RPCHandlerArgsType::FeeResponse),
    );
    let mut responses = test_rpc.run(vec![
        transfer_request,
        contract_request,
        long_contract_request,
    ]);

    let transfer_response = responses.remove(0).decode_fee_estimate().unwrap();
    assert_eq!(transfer_response.estimated_cost, ExecutionCost::ZERO);
    assert!(transfer_response.estimated_cost_scalar > 0);
    assert_eq!(transfer_response.estimations.len(), 3);
    assert!(transfer_response
        .estimations
        .iter()
        .all(|estimate| estimate.fee_rate > 0.0 && estimate.fee > 0));

    let contract_response = responses.remove(0).decode_fee_estimate().unwrap();
    assert!(contract_response.estimated_cost.runtime > 0);
    assert!(contract_response.estimated_cost.read_count > 0);
    assert!(contract_response.estimated_cost.read_length > 0);
    assert!(contract_response.estimated_cost.write_count > 0);
    assert!(contract_response.estimated_cost.write_length > 0);
    assert!(contract_response.estimated_cost_scalar > 0);
    assert_eq!(contract_response.estimations.len(), 3);

    let long_contract_response = responses.remove(0).decode_fee_estimate().unwrap();
    assert_eq!(
        long_contract_response.estimated_cost,
        contract_response.estimated_cost
    );
    assert!(long_contract_response.estimated_cost_scalar > contract_response.estimated_cost_scalar);
    assert_eq!(long_contract_response.estimations.len(), 3);

    let minimum_fee = estimated_len * MINIMUM_TX_FEE_RATE_PER_BYTE;
    for (base, with_length) in contract_response
        .estimations
        .iter()
        .zip(&long_contract_response.estimations)
    {
        assert!(with_length.fee >= base.fee);
        assert!(with_length.fee >= minimum_fee);
    }
}
