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
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::ClarityName;
use rstest::rstest;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::Address;

use super::{bool_list_hex, test_rpc};
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

fn new_call_read_request_with_hex_args(
    addr: SocketAddr,
    arguments: Vec<String>,
) -> StacksHttpRequest {
    let contract_addr =
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap();
    StacksHttpRequest::new_for_peer(
        addr.into(),
        "POST".into(),
        format!("/v2/contracts/call-read/{contract_addr}/flood/f"),
        crate::net::http::HttpRequestContents::new().payload_json(
            serde_json::to_value(callreadonly::CallReadOnlyRequestBody {
                sender: contract_addr.to_account_principal().to_string(),
                sponsor: None,
                arguments,
            })
            .unwrap(),
        ),
    )
    .unwrap()
}

/// Preflight rejections only: the retention checkpoints need the tracking
/// allocator and are covered in `mem_abort`.
#[rstest]
// argument count * size_of::<Value>() exceeds the limit before any value is read.
#[case::argument_vector_reservation(vec!["03".into(); 1024], 16 * 1024, "exceeds parse memory limit")]
// the body's wire size alone exceeds the limit, before JSON parsing.
#[case::body_wire_size(vec![bool_list_hex(2048)], 1024, "exceeds parse memory limit")]
// the argument-count cap holds even with the byte budget disabled.
#[case::argument_count(
    vec!["03".into(); read_only_parse::MAX_READ_ONLY_CALL_ARGUMENTS + 1],
    0,
    "Too many argument values"
)]
fn test_try_parse_request_rejects_invalid_arguments(
    #[case] arguments: Vec<String>,
    #[case] read_only_call_max_mem_bytes: u64,
    #[case] expected_err: &str,
) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());
    let request = new_call_read_request_with_hex_args(addr, arguments);
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let conn_opts = ConnectionOptions::default();
    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        BLOCK_LIMIT_MAINNET_21,
        std::time::Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        read_only_call_max_mem_bytes,
    );

    let error = format!(
        "{:?}",
        http.handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap_err()
    );
    assert!(error.contains(expected_err), "unexpected error: {error}");
    assert!(handler.arguments.is_none());
}

#[test]
fn test_restart_clears_parse_retained_mem() {
    let conn_opts = ConnectionOptions::default();
    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        BLOCK_LIMIT_MAINNET_21,
        std::time::Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        conn_opts.read_only_call_max_mem_bytes,
    );
    handler.parse_retained_mem_bytes = 123;
    handler.restart();
    assert_eq!(handler.parse_retained_mem_bytes, 0);
}

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world-unconfirmed".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "ro-test".try_into().unwrap(),
        vec![],
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let conn_opts = ConnectionOptions::default();
    let mut handler = callreadonly::RPCCallReadOnlyRequestHandler::new(
        4096,
        BLOCK_LIMIT_MAINNET_21,
        std::time::Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        conn_opts.read_only_call_max_mem_bytes,
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
    assert_eq!(handler.function, Some(ClarityName::from_literal("ro-test")));
    assert_eq!(
        handler.sender,
        Some(PrincipalData::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap())
    );
    assert_eq!(handler.sponsor, None);
    assert_eq!(handler.arguments, Some(vec![]));

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    // restart clears the handler state
    handler.restart();
    assert!(handler.contract_identifier.is_none());
    assert!(handler.function.is_none());
    assert!(handler.sender.is_none());
    assert!(handler.sponsor.is_none());
    assert!(handler.arguments.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query confirmed tip
    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "ro-confirmed".try_into().unwrap(),
        vec![],
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query unconfirmed tip
    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world-unconfirmed".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "ro-test".try_into().unwrap(),
        vec![],
        TipRequest::UseLatestUnconfirmedTip,
    );
    requests.push(request);

    // query non-existent function
    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world-unconfirmed".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "does-not-exist".try_into().unwrap(),
        vec![],
        TipRequest::UseLatestUnconfirmedTip,
    );
    requests.push(request);

    // query non-existent contract
    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "does-not-exist".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "ro-test".try_into().unwrap(),
        vec![],
        TipRequest::UseLatestUnconfirmedTip,
    );
    requests.push(request);

    // query non-existent tip
    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "ro-confirmed".try_into().unwrap(),
        vec![],
        TipRequest::SpecificTip(StacksBlockId([0x11; 32])),
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    // confirmed tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_call_readonly_response().unwrap();

    assert!(resp.okay);
    assert!(resp.result.is_some());
    assert!(resp.cause.is_none());

    // u1
    assert_eq!(resp.result.unwrap(), "0x0100000000000000000000000000000001");

    // unconfirmed tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_call_readonly_response().unwrap();

    assert!(resp.okay);
    assert!(resp.result.is_some());
    assert!(resp.cause.is_none());

    // (ok 1)
    assert_eq!(
        resp.result.unwrap(),
        "0x070000000000000000000000000000000001"
    );

    // non-existent function
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_call_readonly_response().unwrap();

    assert!(!resp.okay);
    assert!(resp.result.is_none());
    assert!(resp.cause.is_some());

    assert!(resp.cause.unwrap().find("UndefinedFunction").is_some());

    // non-existent function
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_call_readonly_response().unwrap();

    assert!(!resp.okay);
    assert!(resp.result.is_none());
    assert!(resp.cause.is_some());

    assert!(resp.cause.unwrap().find("NoSuchContract").is_some());

    // non-existent tip
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, payload) = response.destruct();
    assert_eq!(preamble.status_code, 404);
}
