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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use clarity::types::chainstate::StacksBlockId;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::Address;

use super::{test_rpc, test_rpc_with_config};
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpRequestContentsExtensions as _, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

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
        Some("ro-test".into())
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

    // call function generating events
    let request = StacksHttpRequest::new_callreadonlyfunction(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        None,
        "printer".try_into().unwrap(),
        vec![],
        TipRequest::UseLatestAnchoredTip,
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

    // generated events
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_call_readonly_response().unwrap();

    assert!(resp.okay);
    assert!(resp.result.is_some());
    assert!(resp.cause.is_none());

    // Ok(u1)
    assert_eq!(
        resp.result.unwrap(),
        "0x070100000000000000000000000000000001"
    );

    let events = resp.events.unwrap();

    assert_eq!(events.len(), 7);
    assert_eq!(
        events[0].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[0].key, "print");
    assert_eq!(events[0].value, "0000000000000000000000000000000064"); // 100
    assert_eq!(
        events[1].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[1].key, "print");
    assert_eq!(events[1].value, "01000000000000000000000000000003e8"); // u1000
    assert_eq!(
        events[2].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[2].key, "print");
    assert_eq!(events[2].value, "0d0000000474657374"); // "test"
    assert_eq!(
        events[3].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[3].key, "print");
    assert_eq!(events[3].value, "03"); // true
    assert_eq!(
        events[4].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[4].key, "print");
    assert_eq!(events[4].value, "0d0000000578797a7a79"); // "xyzzy"
    assert_eq!(
        events[5].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[5].key, "print");
    assert_eq!(events[5].value, "0d0000000578797a7a77"); // "xyzzw"
    assert_eq!(
        events[6].sender,
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
    );
    assert_eq!(events[6].key, "print");
    assert_eq!(events[6].value, "0d0000000471757578"); // "quux"
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

    assert_eq!(preamble.status_code, 408);

    let body: String = contents.try_into().unwrap();
    assert_eq!(body, "ExecutionTime expired");
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
