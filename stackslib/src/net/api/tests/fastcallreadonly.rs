// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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
use std::time::Duration;

use clarity::types::chainstate::StacksBlockId;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::ClarityName;
use rstest::rstest;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::Address;

use super::{bool_list_hex, test_rpc, test_rpc_with_config};
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

fn new_fast_call_read_request_with_hex_args(
    addr: SocketAddr,
    arguments: Vec<String>,
) -> StacksHttpRequest {
    let contract_addr =
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap();
    let mut request = StacksHttpRequest::new_for_peer(
        addr.into(),
        "POST".into(),
        format!("/v3/contracts/fast-call-read/{contract_addr}/flood/f"),
        crate::net::http::HttpRequestContents::new().payload_json(
            serde_json::to_value(callreadonly::CallReadOnlyRequestBody {
                sender: contract_addr.to_account_principal().to_string(),
                sponsor: None,
                arguments,
            })
            .unwrap(),
        ),
    )
    .unwrap();
    request.add_header("authorization".into(), "password".into());
    request
}

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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

    // add the authorization header
    request.add_header("authorization".into(), "password".into());

    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = fastcallreadonly::RPCFastCallReadOnlyRequestHandler::new(
        4096,
        Duration::from_secs(30),
        ConnectionOptions::default().read_only_call_max_mem_bytes,
        Some("password".into()),
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
        handler.call_read_only_handler.contract_identifier,
        Some(
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world-unconfirmed"
            )
            .unwrap()
        )
    );
    assert_eq!(
        handler.call_read_only_handler.function,
        Some(ClarityName::from_literal("ro-test"))
    );
    assert_eq!(
        handler.call_read_only_handler.sender,
        Some(PrincipalData::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap())
    );
    assert_eq!(handler.call_read_only_handler.sponsor, None);
    assert_eq!(handler.call_read_only_handler.arguments, Some(vec![]));

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    parsed_request.add_header("authorization".into(), "password".into());
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    // restart clears the handler state
    handler.restart();
    assert!(handler.call_read_only_handler.contract_identifier.is_none());
    assert!(handler.call_read_only_handler.function.is_none());
    assert!(handler.call_read_only_handler.sender.is_none());
    assert!(handler.call_read_only_handler.sponsor.is_none());
    assert!(handler.call_read_only_handler.arguments.is_none());
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
    vec!["03".into(); read_only::parse::MAX_READ_ONLY_CALL_ARGUMENTS + 1],
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
    let request = new_fast_call_read_request_with_hex_args(addr, arguments);
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let conn_opts = ConnectionOptions::default();
    let mut handler = fastcallreadonly::RPCFastCallReadOnlyRequestHandler::new(
        conn_opts.maximum_call_argument_size,
        Duration::from_secs(conn_opts.read_only_max_execution_time_secs),
        read_only_call_max_mem_bytes,
        Some("password".into()),
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
    assert!(handler.call_read_only_handler.arguments.is_none());
}

#[test]
fn test_restart_clears_parse_retained_mem() {
    let mut handler = fastcallreadonly::RPCFastCallReadOnlyRequestHandler::new(
        4096,
        Duration::from_secs(30),
        ConnectionOptions::default().read_only_call_max_mem_bytes,
        Some("password".into()),
    );
    handler.call_read_only_handler.parse_retained_mem_bytes = 123;
    handler.restart();
    assert_eq!(handler.call_read_only_handler.parse_retained_mem_bytes, 0);
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query confirmed tip
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "password".into());

    requests.push(request);

    // query unconfirmed tip
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "password".into());

    requests.push(request);

    // query non-existent function
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "password".into());

    requests.push(request);

    // query non-existent contract
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "password".into());

    requests.push(request);

    // query non-existent tip
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "password".into());

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

#[test]
fn test_try_make_response_free_cost_tracker() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query confirmed tip
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "password".into());

    requests.push(request);

    let mut responses = test_rpc_with_config(
        function_name!(),
        requests,
        |peer_1_config| {
            peer_1_config
                .connection_opts
                .read_only_max_execution_time_secs = 0
        },
        |peer_2_config| {
            peer_2_config
                .connection_opts
                .read_only_max_execution_time_secs = 0
        },
    );

    let response = responses.remove(0);
    let (preamble, contents) = response.destruct();

    assert_eq!(preamble.status_code, 400);

    let body: String = contents.try_into().unwrap();
    assert_eq!(body, "Execution resource budget exceeded");
}

#[test]
fn test_wrong_auth() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query confirmed tip
    let mut request = StacksHttpRequest::new_fastcallreadonlyfunction(
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
    request.add_header("authorization".into(), "wrong".into());

    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    let response = responses.remove(0);
    let (preamble, contents) = response.destruct();

    assert_eq!(preamble.status_code, 401);
}

#[test]
fn test_missing_auth() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query confirmed tip
    let request = StacksHttpRequest::new_fastcallreadonlyfunction(
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

    let mut responses = test_rpc(function_name!(), requests);

    let response = responses.remove(0);
    let (preamble, contents) = response.destruct();

    assert_eq!(preamble.status_code, 401);
}
