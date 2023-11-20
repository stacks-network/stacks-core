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

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName, Value};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world-unconfirmed".try_into().unwrap(),
        "test-map".into(),
        Value::UInt(13),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
        false,
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );
    assert_eq!(request.contents().get_with_proof(), false);

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getmapentry::RPCGetMapEntryRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // consumed path args and body
    assert_eq!(
        handler.contract_identifier,
        Some(
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world-unconfirmed"
            )
            .unwrap()
        )
    );
    assert_eq!(handler.map_name, Some("test-map".into()));
    assert_eq!(handler.key, Some(Value::UInt(13)));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.contract_identifier.is_none());
    assert!(handler.map_name.is_none());
    assert!(handler.key.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query existing
    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "test-map".try_into().unwrap(),
        Value::UInt(1),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query existing unconfirmed
    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world-unconfirmed".try_into().unwrap(),
        "test-map-unconfirmed".try_into().unwrap(),
        Value::Int(3),
        TipRequest::UseLatestUnconfirmedTip,
        true,
    );
    requests.push(request);

    // query non-existant map
    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "does-not-exist".try_into().unwrap(),
        Value::UInt(1),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query non-existant contract
    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "does-not-exist".try_into().unwrap(),
        "test-map".try_into().unwrap(),
        Value::UInt(1),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    // latest data
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_map_entry_response().unwrap();
    assert_eq!(resp.data, "0x0a0100000000000000000000000000000002");
    assert!(resp.marf_proof.is_some());

    // unconfirmed data
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_map_entry_response().unwrap();
    assert_eq!(resp.data, "0x0a0000000000000000000000000000000004");
    assert!(resp.marf_proof.is_some());

    // no such map (this just returns `none`)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_map_entry_response().unwrap();
    assert_eq!(resp.data, "0x09");
    assert_eq!(resp.marf_proof, Some("".to_string()));

    // no such contract (this just returns `none`)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_map_entry_response().unwrap();
    assert_eq!(resp.data, "0x09");
    assert_eq!(resp.marf_proof, Some("".to_string()));
}

/*
#[test]
#[ignore]
fn test_rpc_get_map_entry() {
    // Test v2/map_entry (aka GetMapEntry) endpoint.
    // In this test, we don't set any tip parameters, and we expect that querying for map data
    // against the canonical Stacks tip will succeed.
    test_rpc(
        function_name!(),
        40130,
        40131,
        50130,
        50131,
        true,
        |ref mut peer_client,
         ref mut convo_client,
         ref mut peer_server,
         ref mut convo_server| {
            let principal =
                StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                    .unwrap()
                    .to_account_principal();
            convo_client.new_getmapentry(
                StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                    .unwrap(),
                "hello-world".try_into().unwrap(),
                "unit-map".try_into().unwrap(),
                Value::Tuple(
                    TupleData::from_data(vec![("account".into(), Value::Principal(principal))])
                        .unwrap(),
                ),
                TipRequest::UseLatestAnchoredTip,
                false,
            )
        },
        |ref http_request,
         ref http_response,
         ref mut peer_client,
         ref mut peer_server,
         ref convo_client,
         ref convo_server| {
            let req_md = http_request.preamble().clone();
            match http_response {
                HttpResponseType::GetMapEntry(response_md, data) => {
                    assert_eq!(
                        Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                        Value::some(Value::Tuple(
                            TupleData::from_data(vec![("units".into(), Value::Int(123))])
                                .unwrap()
                        ))
                        .unwrap()
                    );
                    true
                }
                _ => {
                    error!("Invalid response; {:?}", &http_response);
                    false
                }
            }
        },
    );
}

#[test]
#[ignore]
fn test_rpc_get_map_entry_unconfirmed() {
    // Test v2/map_entry (aka GetMapEntry) endpoint.
    // In this test, we set `tip_req` to UseLatestUnconfirmedTip, and we expect that querying for map data
    // against the unconfirmed state will succeed.
    test_rpc(
        function_name!(),
        40140,
        40141,
        50140,
        50141,
        true,
        |ref mut peer_client,
         ref mut convo_client,
         ref mut peer_server,
         ref mut convo_server| {
            let unconfirmed_tip = peer_client
                .chainstate()
                .unconfirmed_state
                .as_ref()
                .unwrap()
                .unconfirmed_chain_tip
                .clone();
            let principal =
                StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                    .unwrap()
                    .to_account_principal();
            convo_client.new_getmapentry(
                StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                    .unwrap(),
                "hello-world".try_into().unwrap(),
                "unit-map".try_into().unwrap(),
                Value::Tuple(
                    TupleData::from_data(vec![("account".into(), Value::Principal(principal))])
                        .unwrap(),
                ),
                TipRequest::SpecificTip(unconfirmed_tip),
                false,
            )
        },
        |ref http_request,
         ref http_response,
         ref mut peer_client,
         ref mut peer_server,
         ref convo_client,
         ref convo_server| {
            let req_md = http_request.preamble().clone();
            match http_response {
                HttpResponseType::GetMapEntry(response_md, data) => {
                    assert_eq!(
                        Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                        Value::some(Value::Tuple(
                            TupleData::from_data(vec![("units".into(), Value::Int(1))])
                                .unwrap()
                        ))
                        .unwrap()
                    );
                    true
                }
                _ => {
                    error!("Invalid response; {:?}", &http_response);
                    false
                }
            }
        },
    );
}

#[test]
#[ignore]
fn test_rpc_get_map_entry_use_latest_tip() {
    test_rpc(
        function_name!(),
        40142,
        40143,
        50142,
        50143,
        true,
        |ref mut peer_client,
         ref mut convo_client,
         ref mut peer_server,
         ref mut convo_server| {
            let principal =
                StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                    .unwrap()
                    .to_account_principal();
            convo_client.new_getmapentry(
                StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                    .unwrap(),
                "hello-world".try_into().unwrap(),
                "unit-map".try_into().unwrap(),
                Value::Tuple(
                    TupleData::from_data(vec![("account".into(), Value::Principal(principal))])
                        .unwrap(),
                ),
                TipRequest::UseLatestAnchoredTip,
                false,
            )
        },
        |ref http_request,
         ref http_response,
         ref mut peer_client,
         ref mut peer_server,
         ref convo_client,
         ref convo_server| {
            let req_md = http_request.preamble().clone();
            match http_response {
                HttpResponseType::GetMapEntry(response_md, data) => {
                    assert_eq!(
                        Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                        Value::some(Value::Tuple(
                            TupleData::from_data(vec![("units".into(), Value::Int(1))])
                                .unwrap()
                        ))
                        .unwrap()
                    );
                    true
                }
                _ => {
                    error!("Invalid response; {:?}", &http_response);
                    false
                }
            }
        },
    );
}
*/
