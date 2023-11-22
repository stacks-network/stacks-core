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
use clarity::vm::{ClarityName, ContractName};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
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

    let request = StacksHttpRequest::new_getaccount(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        TipRequest::UseLatestAnchoredTip,
        false,
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getaccount::RPCGetAccountRequestHandler::new();
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

    // consumed path args
    assert_eq!(
        handler.account,
        Some(PrincipalData::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap())
    );

    assert_eq!(&preamble, request.preamble());

    // reset works
    handler.restart();
    assert!(handler.account.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query existing account
    let request = StacksHttpRequest::new_getaccount(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        TipRequest::UseLatestAnchoredTip,
        false,
    );
    requests.push(request);

    // query existing account with proof
    let request = StacksHttpRequest::new_getaccount(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query nonexistant
    let request = StacksHttpRequest::new_getaccount(
        addr.into(),
        StacksAddress::from_string("ST165ZBV86V4NJ0V73F52YZGBMJ0FZAQ1BM43C553")
            .unwrap()
            .to_account_principal(),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query existing account with unconfirmed state
    let request = StacksHttpRequest::new_getaccount(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
            .unwrap()
            .to_account_principal(),
        TipRequest::UseLatestUnconfirmedTip,
        true,
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_account_entry_response().unwrap();

    assert_eq!(resp.balance, "0x0000000000000000000000003b9aca00");
    assert_eq!(resp.locked, "0x00000000000000000000000000000000");
    assert_eq!(resp.nonce, 2);
    assert!(resp.balance_proof.is_none());
    assert!(resp.nonce_proof.is_none());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_account_entry_response().unwrap();

    assert_eq!(resp.balance, "0x0000000000000000000000003b9aca00");
    assert_eq!(resp.locked, "0x00000000000000000000000000000000");
    assert_eq!(resp.nonce, 2);
    assert!(resp.balance_proof.is_some());
    assert!(resp.nonce_proof.is_some());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_account_entry_response().unwrap();

    assert_eq!(resp.balance, "0x00000000000000000000000000000000");
    assert_eq!(resp.locked, "0x00000000000000000000000000000000");
    assert_eq!(resp.nonce, 0);
    assert_eq!(resp.balance_proof, Some("".to_string()));
    assert_eq!(resp.nonce_proof, Some("".to_string()));

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_account_entry_response().unwrap();

    assert_eq!(resp.balance, "0x0000000000000000000000003b9ac985");
    assert_eq!(resp.locked, "0x00000000000000000000000000000000");
    assert_eq!(resp.nonce, 4);
    assert!(resp.balance_proof.is_some());
    assert!(resp.nonce_proof.is_some());
}
