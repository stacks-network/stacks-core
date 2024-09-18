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
    let private_key = StacksPrivateKey::new();
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
