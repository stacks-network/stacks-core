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

use clarity::types::net::PeerHost;
use rand::{thread_rng, RngCore};

use crate::net::api::getstxbtcratio;
use crate::net::api::tests::TestRPC;
use crate::net::connection::ConnectionOptions;
use crate::net::http::{Error as HttpError, HttpRequestPreamble, HttpVersion};
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest, TipRequest};
use crate::net::test::TestEventObserver;
use crate::net::Error as NetError;

fn make_preamble(query: &str) -> HttpRequestPreamble {
    HttpRequestPreamble {
        version: HttpVersion::Http11,
        verb: "GET".into(),
        path_and_query_str: format!("/v3/stx_btc_ratio{query}"),
        host: PeerHost::DNS("localhost".into(), 0),
        content_type: None,
        content_length: Some(0),
        keep_alive: false,
        headers: BTreeMap::new(),
        set_cookie: Vec::new(),
    }
}

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let http = StacksHttp::new(addr, &ConnectionOptions::default());
    let cycle_num = thread_rng().next_u32() as u64;

    let mut handler = getstxbtcratio::GetStxBtcRatioRequestHandler::new(Some("password".into()));
    let mut bad_content_length_preamble = make_preamble(&format!("/{cycle_num}"));
    bad_content_length_preamble.content_length = Some(1);

    let tests = vec![
        (make_preamble(&format!("/{cycle_num}")), Ok(Some(cycle_num))),
        (make_preamble("/foo"), Err(NetError::NotFoundError)),
        (
            bad_content_length_preamble,
            Err(
                HttpError::DecodeError("Invalid Http request: expected 0-length body".into())
                    .into(),
            ),
        ),
    ];

    for (inp, expected_result) in tests.into_iter() {
        handler.restart();
        let parsed_request = http.handle_try_parse_request(&mut handler, &inp, &[]);
        match expected_result {
            Ok(cycle) => {
                assert!(parsed_request.is_ok());
                assert_eq!(handler.reward_cycle, cycle);
            }
            Err(e) => {
                assert_eq!(e, parsed_request.unwrap_err());
            }
        }
    }
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let cycle_num = 5;
    let future_cycle = 1_000_000;
    let nakamoto_chain_tip = rpc_test.canonical_tip.clone();

    let mut req1 = StacksHttpRequest::new_get_stx_btc_ratio(
        addr.into(),
        cycle_num,
        TipRequest::SpecificTip(nakamoto_chain_tip.clone()),
    );
    req1.add_header("authorization".into(), "password".into());

    let mut req2 = StacksHttpRequest::new_get_stx_btc_ratio(
        addr.into(),
        future_cycle,
        TipRequest::SpecificTip(nakamoto_chain_tip),
    );
    req2.add_header("authorization".into(), "password".into());

    let requests = vec![req1, req2];

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    let ratio_response = response.decode_stx_btc_ratio().unwrap();
    assert_eq!(ratio_response.reward_cycle, cycle_num);
    assert!(ratio_response.tenure_count > 0);
    assert!(ratio_response.stx_earned_ustx > 0);
    assert!(ratio_response.btc_spent_sats > 0);
    assert!(ratio_response.stx_btc_ratio.is_some());
    assert!(ratio_response.smoothed_stx_btc_ratio.is_some());

    let response = responses.remove(0);
    let ratio_response = response.decode_stx_btc_ratio().unwrap();
    assert_eq!(ratio_response.reward_cycle, future_cycle);
    assert_eq!(ratio_response.tenure_count, 0);
    assert_eq!(ratio_response.stx_earned_ustx, 0);
    assert_eq!(ratio_response.btc_spent_sats, 0);
    assert_eq!(ratio_response.stx_btc_ratio, None);
    assert_eq!(ratio_response.smoothed_stx_btc_ratio, None);
}

#[test]
fn test_cold_cache_rejects_without_auth() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    // Request a cycle that hasn't been cached — no auth header.
    let future_cycle = 1_000_000;
    let nakamoto_chain_tip = rpc_test.canonical_tip.clone();

    let req = StacksHttpRequest::new_get_stx_btc_ratio(
        addr.into(),
        future_cycle,
        TipRequest::SpecificTip(nakamoto_chain_tip),
    );
    // Intentionally no auth header.

    let mut responses = rpc_test.run(vec![req]);
    let response = responses.remove(0);

    // Should get a 401 Unauthorized since the cache is cold and no auth was provided.
    let (preamble, _body) = response.destruct();
    assert_eq!(
        preamble.status_code, 401,
        "Cold cache without auth should return 401"
    );
}
