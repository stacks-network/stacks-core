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

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, StacksHttp, StacksHttpRequest,
};

use stacks_common::types::net::PeerHost;

use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::Address;

use clarity::vm::types::PrincipalData;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::types::StacksAddressExtensions;
use clarity::vm::ClarityName;
use clarity::vm::ContractName;
use clarity::vm::Value;

use crate::net::api::*;
use crate::net::ProtocolFamily;
use crate::net::TipRequest;

use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::httpcore::RPCRequestHandler;

use crate::net::connection::ConnectionOptions;

use super::test_rpc;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getpoxinfo(
        addr.into(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getpoxinfo::RPCPoxInfoRequestHandler::new();
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

    assert_eq!(&preamble, request.preamble());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    let request = StacksHttpRequest::new_getpoxinfo(addr.into(), TipRequest::UseLatestAnchoredTip);
    requests.push(request);

    // bad tip
    let request = StacksHttpRequest::new_getpoxinfo(
        addr.into(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
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

    // this works
    let resp = response.decode_rpc_get_pox_info().unwrap();

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    // this fails with 404
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);
}

/*
#[test]
#[ignore]
fn test_rpc_getpoxinfo() {
    // Test v2/pox (aka GetPoxInfo) endpoint.
    // In this test, `tip_req` is set to UseLatestAnchoredTip.
    // Thus, the query for pox info will be against the canonical Stacks tip, which we expect to succeed.
    let pox_server_info = RefCell::new(None);
    test_rpc(
        function_name!(),
        40002,
        40003,
        50002,
        50003,
        true,
        |ref mut peer_client,
         ref mut convo_client,
         ref mut peer_server,
         ref mut convo_server| {
            let mut sortdb = peer_server.sortdb.as_mut().unwrap();
            let chainstate = &mut peer_server.stacks_node.as_mut().unwrap().chainstate;
            let stacks_block_id = {
                let tip = chainstate.get_stacks_chain_tip(sortdb).unwrap().unwrap();
                StacksBlockHeader::make_index_block_hash(
                    &tip.consensus_hash,
                    &tip.anchored_block_hash,
                )
            };
            let pox_info = RPCPoxInfoData::from_db(
                &mut sortdb,
                chainstate,
                &stacks_block_id,
                &peer_client.config.burnchain,
            )
            .unwrap();
            *pox_server_info.borrow_mut() = Some(pox_info);
            convo_client.new_getpoxinfo(TipRequest::UseLatestAnchoredTip)
        },
        |ref http_request,
         ref http_response,
         ref mut peer_client,
         ref mut peer_server,
         convo_client,
         convo_server| {
            let req_md = http_request.preamble().clone();
            match (*http_response).clone().decode_rpc_get_pox_info() {
                Ok(pox_data) => {
                    assert_eq!(Some(pox_data.clone()), *pox_server_info.borrow());
                    true
                }
                Err(e) => {
                    error!("Invalid response: {:?}", &e);
                    false
                }
            }
        },
    );
}

#[test]
#[ignore]
fn test_rpc_getpoxinfo_use_latest_tip() {
    // Test v2/pox (aka GetPoxInfo) endpoint.
    // In this test, we set `tip_req` to UseLatestUnconfirmedTip, and we expect that querying for pox
    // info against the unconfirmed state will succeed.
    let pox_server_info = RefCell::new(None);
    test_rpc(
        function_name!(),
        40004,
        40005,
        50004,
        50005,
        true,
        |ref mut peer_client,
         ref mut convo_client,
         ref mut peer_server,
         ref mut convo_server| {
            let mut sortdb = peer_server.sortdb.as_mut().unwrap();
            let chainstate = &mut peer_server.stacks_node.as_mut().unwrap().chainstate;
            let stacks_block_id = chainstate
                .unconfirmed_state
                .as_ref()
                .unwrap()
                .unconfirmed_chain_tip
                .clone();
            let pox_info = RPCPoxInfoData::from_db(
                &mut sortdb,
                chainstate,
                &stacks_block_id,
                &peer_client.config.burnchain,
            )
            .unwrap();
            *pox_server_info.borrow_mut() = Some(pox_info);
            convo_client.new_getpoxinfo(TipRequest::UseLatestUnconfirmedTip)
        },
        |ref http_request,
         ref http_response,
         ref mut peer_client,
         ref mut peer_server,
         ref convo_client,
         ref convo_server| {
            let req_md = http_request.preamble().clone();
            match (*http_response).clone().decode_rpc_get_pox_info() {
                Ok(pox_data) => {
                    assert_eq!(Some(pox_data.clone()), *pox_server_info.borrow());
                    true
                }
                Err(e) => {
                    error!("Invalid response: {:?}", &e);
                    false
                }
            }
        },
    );
}
*/
