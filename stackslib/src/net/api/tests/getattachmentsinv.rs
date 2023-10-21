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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName};
use serde_json;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::{test_rpc, TestRPC};
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::{Attachment, ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let mut pages = HashSet::new();
    for i in 0..10 {
        pages.insert(i);
    }

    let request =
        StacksHttpRequest::new_getattachmentsinv(addr.into(), StacksBlockId([0x11; 32]), pages);
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getattachmentsinv::RPCGetAttachmentsInvRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(handler.index_block_hash, Some(StacksBlockId([0x11; 32])));
    assert_eq!(
        handler.page_indexes,
        Some(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    );

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.index_block_hash.is_none());
    assert!(handler.page_indexes.is_none());
}

#[test]
fn test_try_make_response() {
    let attachment = Attachment {
        content: vec![0, 1, 2, 3, 4],
    };
    let attachment_hash = attachment.hash();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());
    let stacks_chain_tip = rpc_test.canonical_tip.clone();

    let mut requests = vec![];
    let mut pages = HashSet::new();
    pages.insert(1);

    // query existing attachment
    let request = StacksHttpRequest::new_getattachmentsinv(
        addr.into(),
        stacks_chain_tip.clone(),
        pages.clone(),
    );
    requests.push(request);

    // query non-existant block
    let request = StacksHttpRequest::new_getattachmentsinv(
        addr.into(),
        StacksBlockId([0x11; 32]),
        pages.clone(),
    );
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_atlas_attachments_inv_response().unwrap();

    // there should be a bit set in the inventory vector
    assert_eq!(resp.block_id, stacks_chain_tip);
    assert_eq!(resp.pages.len(), 1);
    assert_eq!(resp.pages[0].index, 1);
    assert!(resp.pages[0].inventory.iter().find(|&&x| x == 1).is_some());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );
    let resp = response.decode_atlas_attachments_inv_response().unwrap();

    // this is a HTTP 200, but no bits are set
    assert_eq!(resp.block_id, StacksBlockId([0x11; 32]));
    assert_eq!(resp.pages.len(), 1);
    assert_eq!(resp.pages[0].index, 1);
    assert!(resp.pages[0].inventory.iter().find(|&&x| x == 1).is_none());
}
