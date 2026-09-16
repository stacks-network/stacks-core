// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions, TupleData};
use clarity::vm::{ClarityName, Value};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::Address;

use super::{bool_list_hex, test_rpc};
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{
    HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

fn new_getmapentry_request_with_hex_key(addr: SocketAddr, key: String) -> StacksHttpRequest {
    let contract_addr =
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap();
    StacksHttpRequest::new_for_peer(
        addr.into(),
        "POST".into(),
        format!("/v2/map_entry/{contract_addr}/flood/m"),
        HttpRequestContents::new().payload_json(serde_json::Value::String(key)),
    )
    .unwrap()
}

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world-unconfirmed".try_into().unwrap(),
        ClarityName::from_literal("test-map"),
        Value::UInt(13),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
        false,
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );
    assert!(!request.contents().get_with_proof());

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getmapentry::RPCGetMapEntryRequestHandler::new(
        ConnectionOptions::default().read_only_call_max_mem_bytes,
    );
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
    assert_eq!(
        handler.map_name,
        Some(ClarityName::from_literal("test-map"))
    );
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

/// Rejected by the body wire-size preflight, before JSON parsing.
#[test]
fn test_try_parse_request_rejects_oversized_key() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());
    // ~4 KiB hex body against a 1 KiB limit.
    let request = new_getmapentry_request_with_hex_key(addr, bool_list_hex(2048));
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getmapentry::RPCGetMapEntryRequestHandler::new(1024);

    let error = format!(
        "{:?}",
        http.handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap_err()
    );
    assert!(
        error.contains("exceeds parse memory limit"),
        "unexpected error: {error}"
    );
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

    // query existing with a tuple-typed key and without a MARF proof
    let account = StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
        .unwrap()
        .to_account_principal();
    let request = StacksHttpRequest::new_getmapentry(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "unit-map".try_into().unwrap(),
        Value::Tuple(
            TupleData::from_data(vec![(
                ClarityName::from_literal("account"),
                Value::Principal(account),
            )])
            .unwrap(),
        ),
        TipRequest::UseLatestAnchoredTip,
        false,
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    // latest data
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
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

    let resp = response.decode_map_entry_response().unwrap();
    assert_eq!(resp.data, "0x0a0000000000000000000000000000000004");
    assert!(resp.marf_proof.is_some());

    // no such map (this just returns `none`)
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
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

    let resp = response.decode_map_entry_response().unwrap();
    assert_eq!(resp.data, "0x09");
    assert_eq!(resp.marf_proof, Some("".to_string()));

    // tuple key, no proof
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_map_entry_response().unwrap();
    // `(some (tuple (units 123)))`, the value set for this principal at deploy time
    assert_eq!(
        resp.data,
        "0x0a0c0000000105756e697473000000000000000000000000000000007b"
    );
    // `with_proof = false`, so no MARF proof is returned
    assert_eq!(resp.marf_proof, None);
}
