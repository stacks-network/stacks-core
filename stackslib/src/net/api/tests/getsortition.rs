// Copyright (C) 2024 Stacks Open Internet Foundation
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

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::types::chainstate::VRFSeed;
use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash};
use stacks_common::types::net::PeerHost;

use crate::net::api::getsortition::{GetSortitionHandler, QuerySpecifier, SortitionInfo};
use crate::net::api::tests::test_rpc;
use crate::net::connection::ConnectionOptions;
use crate::net::http::{
    Error as HttpError, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponsePayload, HttpVersion,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpPreamble, StacksHttpRequest};
use crate::net::Error as NetError;

fn make_preamble(query: &str) -> HttpRequestPreamble {
    HttpRequestPreamble {
        version: HttpVersion::Http11,
        verb: "GET".into(),
        path_and_query_str: format!("/v3/sortitions{query}"),
        host: PeerHost::DNS("localhost".into(), 0),
        content_type: None,
        content_length: Some(0),
        keep_alive: false,
        headers: BTreeMap::new(),
    }
}

#[test]
fn test_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());
    let mut handler = GetSortitionHandler::new();

    let tests = vec![
        (make_preamble(""), Ok(QuerySpecifier::Latest)),
        (
            make_preamble("/consensus/deadbeef00deadbeef01deadbeef02deadbeef03"),
            Ok(QuerySpecifier::ConsensusHash(
                ConsensusHash::from_hex("deadbeef00deadbeef01deadbeef02deadbeef03").unwrap(),
            )),
        ),
        (
            make_preamble("/burn/00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
            Ok(QuerySpecifier::BurnchainHeaderHash(
                BurnchainHeaderHash::from_hex(
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                )
                .unwrap(),
            )),
        ),
        (
            make_preamble("/burn_height/100"),
            Ok(QuerySpecifier::BlockHeight(100)),
        ),
        (
            make_preamble("/burn_height/a1be"),
            Err(HttpError::DecodeError("invalid digit found in string".into()).into()),
        ),
        (
            make_preamble("/burn/a1be0000"),
            Err(HttpError::DecodeError("bad length 8 for hex string".into()).into()),
        ),
        (
            make_preamble("/consensus/a1be0000"),
            Err(HttpError::DecodeError("bad length 8 for hex string".into()).into()),
        ),
        (
            make_preamble("/burn_height/20/consensus/deadbeef00deadbeef01deadbeef02deadbeef03"),
            Err(NetError::NotFoundError),
        ),
    ];

    for (inp, expected_result) in tests.into_iter() {
        handler.restart();
        let parsed_request = http.handle_try_parse_request(&mut handler, &inp, &[]);
        eprintln!("{}", &inp.path_and_query_str);
        eprintln!("{parsed_request:?}");
        match expected_result {
            Ok(query) => {
                assert!(parsed_request.is_ok());
                assert_eq!(&handler.query, &query);
            }
            Err(e) => {
                assert_eq!(e, parsed_request.unwrap_err());
            }
        }
    }
}

#[test]
fn response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);

    let request = StacksHttpRequest::new_for_peer(
        addr.into(),
        "GET".into(),
        "/v3/sortitions".into(),
        HttpRequestContents::new(),
    )
    .expect("FATAL: failed to construct request from infallible data");
    let mut responses = test_rpc(function_name!(), vec![request]);
    let HttpResponsePayload::JSON(response) =
        responses.pop().unwrap().get_http_payload_ok().unwrap()
    else {
        panic!("Expected JSON response");
    };

    info!("Response:\n{:#?}\n", response);

    let info_array = response.as_array().expect("Response should be array");
    assert_eq!(
        info_array.len(),
        1,
        "/v3/sortitions should return a single entry"
    );

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333);
    let request = StacksHttpRequest::new_for_peer(
        addr.into(),
        "GET".into(),
        "/v3/sortitions/latest_and_last".into(),
        HttpRequestContents::new(),
    )
    .expect("FATAL: failed to construct request from infallible data");
    let mut responses = test_rpc(function_name!(), vec![request]);
    let HttpResponsePayload::JSON(response) =
        responses.pop().unwrap().get_http_payload_ok().unwrap()
    else {
        panic!("Expected JSON response");
    };

    info!("Response:\n{:#?}\n", response);

    let info_array = response.as_array().expect("Response should be array");
    assert_eq!(
        info_array.len(),
        2,
        "/v3/sortitions/latest_and_last should return 2 entries"
    );
    let first_entry: SortitionInfo = serde_json::from_value(info_array[0].clone())
        .expect("Response array elements should parse to SortitionInfo");
    let second_entry: SortitionInfo = serde_json::from_value(info_array[1].clone())
        .expect("Response array elements should parse to SortitionInfo");
    assert!(first_entry.was_sortition);
    assert_eq!(
        first_entry.vrf_seed,
        Some(
            VRFSeed::from_hex("48b754acc291a5bfad1354ee19bbc471f14af2b21dc7eccc0f929bd16798defe")
                .unwrap()
        )
    );
    assert!(second_entry.was_sortition);
    assert_eq!(
        first_entry.last_sortition_ch.as_ref().unwrap(),
        &second_entry.consensus_hash,
    );
}
