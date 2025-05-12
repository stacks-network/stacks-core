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

use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName};
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::TestRPC;
use crate::chainstate::stacks::db::blocks::test::*;
use crate::chainstate::stacks::db::test::instantiate_chainstate;
use crate::chainstate::stacks::db::{ExtendedStacksHeader, StacksChainState};
use crate::chainstate::stacks::{
    Error as chainstate_error, StacksBlock, StacksBlockHeader, StacksMicroblock,
};
use crate::net::api::getblock::StacksBlockStream;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::http::HttpChunkGenerator;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};
use crate::util_lib::db::DBConn;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getblock(addr.into(), StacksBlockId([0x11; 32]));
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getblock::RPCBlocksRequestHandler::new();
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
    assert_eq!(handler.block_id, Some(StacksBlockId([0x11; 32])));

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.block_id.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());
    let stacks_chain_tip = rpc_test.canonical_tip.clone();
    let consensus_hash = rpc_test.consensus_hash.clone();

    let mut requests = vec![];

    // query existing block
    let request = StacksHttpRequest::new_getblock(addr.into(), stacks_chain_tip.clone());
    requests.push(request);

    // query non-existant block
    let request = StacksHttpRequest::new_getblock(addr.into(), StacksBlockId([0x11; 32]));
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the block
    let response = responses.remove(0);
    let resp = response.decode_block().unwrap();

    assert_eq!(
        StacksBlockHeader::make_index_block_hash(&consensus_hash, &resp.block_hash()),
        stacks_chain_tip
    );

    // no block
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();

    assert_eq!(preamble.status_code, 404);
}

#[test]
fn test_stream_blocks() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let privk = StacksPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let block = make_16k_block(&privk);

    let consensus_hash = ConsensusHash([2u8; 20]);
    let parent_consensus_hash = ConsensusHash([1u8; 20]);
    let index_block_header =
        StacksBlockHeader::make_index_block_hash(&consensus_hash, &block.block_hash());

    // can't stream a non-existant block
    assert!(StacksBlockStream::new(&chainstate, &index_block_header).is_err());

    // store block to staging
    store_staging_block(
        &mut chainstate,
        &consensus_hash,
        &block,
        &parent_consensus_hash,
        1,
        2,
    );

    // should succeed now
    let mut stream = StacksBlockStream::new(&chainstate, &index_block_header).unwrap();

    // stream it back
    let mut all_block_bytes = vec![];
    loop {
        let mut next_bytes = stream.generate_next_chunk().unwrap();
        if next_bytes.is_empty() {
            break;
        }
        test_debug!(
            "Got {} more bytes from staging; add to {} total",
            next_bytes.len(),
            all_block_bytes.len()
        );
        all_block_bytes.append(&mut next_bytes);
    }

    // should decode back into the block
    let staging_block = StacksBlock::consensus_deserialize(&mut &all_block_bytes[..]).unwrap();
    assert_eq!(staging_block, block);

    // accept it
    set_block_processed(&mut chainstate, &consensus_hash, &block.block_hash(), true);

    // can still stream it
    let mut stream = StacksBlockStream::new(&chainstate, &index_block_header).unwrap();

    // stream from chunk store
    let mut all_block_bytes = vec![];
    loop {
        let mut next_bytes = stream.generate_next_chunk().unwrap();
        if next_bytes.is_empty() {
            break;
        }
        test_debug!(
            "Got {} more bytes from chunkstore; add to {} total",
            next_bytes.len(),
            all_block_bytes.len()
        );
        all_block_bytes.append(&mut next_bytes);
    }

    // should decode back into the block
    let staging_block = StacksBlock::consensus_deserialize(&mut &all_block_bytes[..]).unwrap();
    assert_eq!(staging_block, block);
}
