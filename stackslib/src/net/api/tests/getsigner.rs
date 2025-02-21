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

use clarity::types::chainstate::{StacksBlockId, StacksPrivateKey, StacksPublicKey};
use rand::{thread_rng, RngCore};
use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash};
use stacks_common::types::net::PeerHost;

use crate::net::api::getsigner::{self, GetSignerRequestHandler};
use crate::net::api::tests::{test_rpc, TestRPC};
use crate::net::connection::ConnectionOptions;
use crate::net::http::{Error as HttpError, HttpRequestPreamble, HttpVersion};
use crate::net::httpcore::{
    RPCRequestHandler, StacksHttp, StacksHttpPreamble, StacksHttpRequest, TipRequest,
};
use crate::net::test::TestEventObserver;
use crate::net::{Error as NetError, ProtocolFamily};

fn make_preamble(query: &str) -> HttpRequestPreamble {
    HttpRequestPreamble {
        version: HttpVersion::Http11,
        verb: "GET".into(),
        path_and_query_str: format!("/v3/signer{query}"),
        host: PeerHost::DNS("localhost".into(), 0),
        content_type: None,
        content_length: Some(0),
        keep_alive: false,
        headers: BTreeMap::new(),
    }
}

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());
    let private_key = StacksPrivateKey::random();
    let signer_pubkey = StacksPublicKey::from_private(&private_key);
    let signer_pubkey_hex = signer_pubkey.to_hex();
    let cycle_num = thread_rng().next_u32() as u64;

    let mut handler = getsigner::GetSignerRequestHandler::new();
    let mut bad_content_length_preamble =
        make_preamble(&format!("/{signer_pubkey_hex}/{cycle_num}"));
    bad_content_length_preamble.content_length = Some(1);
    let tests = vec![
        (
            make_preamble(&format!("/{signer_pubkey_hex}/{cycle_num}")),
            Ok((Some(signer_pubkey), Some(cycle_num))),
        ),
        (
            make_preamble(&format!("/foo/{cycle_num}")),
            Err(NetError::NotFoundError),
        ),
        (
            make_preamble(&format!("/{signer_pubkey_hex}/bar")),
            Err(NetError::NotFoundError),
        ),
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
            Ok((key, cycle)) => {
                assert!(parsed_request.is_ok());
                assert_eq!(handler.signer_pubkey, key);
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
    // Copy pasta of the test setup values
    let cycle_num = 5;
    let public_key = StacksPublicKey::from_hex(
        "0243311589af63c2adda04fcd7792c038a05c12a4fe40351b3eb1612ff6b2e5a0e",
    )
    .unwrap();

    let random_private_key = StacksPrivateKey::random();
    let random_public_key = StacksPublicKey::from_private(&random_private_key);

    let nakamoto_chain_tip = rpc_test.canonical_tip.clone();

    let mut requests = vec![];

    // Query existing signer
    let info = StacksHttpRequest::new_getsigner(
        addr.into(),
        &public_key,
        cycle_num,
        TipRequest::SpecificTip(nakamoto_chain_tip),
    );
    requests.push(info);

    // query random signer that doesn't exist
    let request = StacksHttpRequest::new_getsigner(
        addr.into(),
        &random_public_key,
        cycle_num,
        TipRequest::SpecificTip(nakamoto_chain_tip),
    );
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // Existing signer
    let response = responses.remove(0);
    info!("response: {:?}", &response);
    let signer_response = response.decode_signer().unwrap();
    assert_eq!(signer_response.blocks_signed, 20);

    // Signer doesn't exist so it should not have signed anything
    let response = responses.remove(0);
    info!("response: {:?}", &response);
    let signer_response = response.decode_signer().unwrap();
    assert_eq!(signer_response.blocks_signed, 0);
}
