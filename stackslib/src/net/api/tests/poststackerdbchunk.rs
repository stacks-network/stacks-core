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
use clarity::vm::{ClarityName, ContractName, Value};
use libstackerdb::{SlotMetadata, StackerDBChunkData};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use super::TestRPC;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse(
            "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world-unconfirmed",
        )
        .unwrap(),
        0,
        1,
        MessageSignature::empty(),
        vec![0, 1, 2, 3, 4],
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = poststackerdbchunk::RPCPostStackerDBChunkRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(
        handler.contract_identifier,
        Some(
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world-unconfirmed"
            )
            .unwrap()
        )
    );
    assert_eq!(
        handler.chunk,
        Some(StackerDBChunkData {
            slot_id: 0,
            slot_version: 1,
            data: vec![0, 1, 2, 3, 4],
            sig: MessageSignature::empty()
        })
    );

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.contract_identifier.is_none());
    assert!(handler.chunk.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());
    let mut requests = vec![];

    // try to write a new chunk
    let data = "try make response".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 1, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world")
            .unwrap(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );
    requests.push(request);

    // try to overwrite a new chunk
    let data = "try make response 2".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 2, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world")
            .unwrap(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );
    requests.push(request);

    // try to overwrite a new chunk, with the same version (should fail)
    let data = "try make response 3".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 2, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world")
            .unwrap(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );
    requests.push(request);

    // try to write with the wrong key (should fail)
    let data = "try make response 4".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 3, data_hash);
    slot_metadata.sign(&rpc_test.privk2).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world")
            .unwrap(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );
    requests.push(request);

    // try to write to a bad slot (should fail)
    let data = "try make response 5".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(4093, 3, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world")
            .unwrap(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );
    requests.push(request);

    // try to write to a bad contract (should fail)
    let data = "try make response 6".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 3, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        QualifiedContractIdentifier::parse(
            "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.does-not-exist",
        )
        .unwrap(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stackerdb_chunk_ack().unwrap();
    assert_eq!(resp.accepted, true);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_id, 1);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_version, 1);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stackerdb_chunk_ack().unwrap();
    assert_eq!(resp.accepted, true);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_id, 1);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_version, 2);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stackerdb_chunk_ack().unwrap();
    assert_eq!(resp.accepted, false);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_id, 1);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_version, 2);
    assert!(resp.reason.is_some());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stackerdb_chunk_ack().unwrap();
    assert_eq!(resp.accepted, false);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_id, 1);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_version, 2);
    assert!(resp.reason.is_some());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stackerdb_chunk_ack().unwrap();
    assert_eq!(resp.accepted, false);
    assert!(resp.metadata.is_none());
    assert!(resp.reason.is_some());

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);
}
