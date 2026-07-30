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

use clarity::vm::types::QualifiedContractIdentifier;
use libstackerdb::{SlotMetadata, StackerDBChunkData};
use stacks_common::codec::MAX_MESSAGE_LEN;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use super::{TestRPC, TEST_CONTRACT_ID};
use crate::net::api::poststackerdbchunk::{
    RPCPostStackerDBChunkRequestHandler, StackerDBErrorCodes,
};
use crate::net::connection::ConnectionOptions;
use crate::net::http::Error as HttpError;
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpRequest};
use crate::net::{Error as NetError, ProtocolFamily};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr, &ConnectionOptions::default());

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
    let mut handler = RPCPostStackerDBChunkRequestHandler::new();
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
fn test_request_ok() {
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
        TEST_CONTRACT_ID.clone(),
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
        TEST_CONTRACT_ID.clone(),
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
    assert!(resp.accepted);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_id, 1);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_version, 1);

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_stackerdb_chunk_ack().unwrap();
    assert!(resp.accepted);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_id, 1);
    assert_eq!(resp.metadata.as_ref().unwrap().slot_version, 2);
}

/// Re-posting a slot version that is not newer than the stored one must be reported with the
/// `DataAlreadyExists` error code.
#[test]
fn test_request_fail_stale_chunk() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    // Write version 1 to slot 1 (owned by `privk1`), then re-post the same version so the
    // replica rejects it as stale.
    let data = "stale chunk".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 1, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let make_request = || {
        StacksHttpRequest::new_post_stackerdb_chunk(
            addr.into(),
            TEST_CONTRACT_ID.clone(),
            slot_metadata.slot_id,
            slot_metadata.slot_version,
            slot_metadata.signature.clone(),
            data.to_vec(),
        )
    };

    let mut responses = rpc_test.run(vec![make_request(), make_request()]);

    // First write is accepted.
    let accepted = responses.remove(0).decode_stackerdb_chunk_ack().unwrap();
    assert!(accepted.accepted);

    // Re-posting the same version is stale.
    let chunk_ack = responses.remove(0).decode_stackerdb_chunk_ack().unwrap();
    assert!(!chunk_ack.accepted);
    assert_eq!(
        chunk_ack.code,
        Some(StackerDBErrorCodes::DataAlreadyExists.code())
    );
    assert!(chunk_ack.reason.is_some());
    let metadata = chunk_ack.metadata.as_ref().unwrap();
    assert_eq!(metadata.slot_id, 1);
    assert_eq!(metadata.slot_version, 1);
}

/// A chunk addressed to a slot ID outside the replica's allocation must be reported with the
/// `NoSuchSlot` error code.
#[test]
fn test_request_fail_no_such_slot() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    // `TEST_CONTRACT` allocates far fewer than 4093 slots, so slot 4093 does not exist.
    let data = "no such slot".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(4093, 1, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        TEST_CONTRACT_ID.clone(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );

    let chunk_ack = rpc_test
        .run_one(request)
        .decode_stackerdb_chunk_ack()
        .unwrap();
    assert!(!chunk_ack.accepted);
    assert!(chunk_ack.metadata.is_none());
    assert_eq!(chunk_ack.code, Some(StackerDBErrorCodes::NoSuchSlot.code()));
    assert!(chunk_ack.reason.is_some());
}

/// A POST to a contract that is not a configured StackerDB must return HTTP 404, not a chunk ack.
#[test]
fn test_request_fail_no_such_contract() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    let data = "no such contract".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 1, data_hash);
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

    let (preamble, _body) = rpc_test.run_one(request).destruct();
    assert_eq!(preamble.status_code, 404);
}

/// A chunk that exceeds the replica's configured `chunk_size` must be reported with the
/// dedicated `ChunkTooBig` error code.
#[test]
fn test_request_fail_chunk_too_big() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    // The test StackerDB `TEST_CONTRACT` configures `chunk-size: u4096`.
    // Build a validly-signed chunk whose data exceeds that so the write is rejected as too big.
    let data = vec![0x01; 8192];
    let data_hash = Sha512Trunc256Sum::from_data(&data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 1, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        TEST_CONTRACT_ID.clone(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data,
    );

    let chunk_ack = rpc_test
        .run_one(request)
        .decode_stackerdb_chunk_ack()
        .unwrap();
    assert!(!chunk_ack.accepted);
    assert_eq!(
        chunk_ack.code,
        Some(StackerDBErrorCodes::ChunkTooBig.code())
    );
    assert!(chunk_ack.reason.is_some());
}

/// A chunk whose slot version exceeds the replica's configured `max_writes` must be reported
/// with the dedicated `TooManySlotWrites` error code.
#[test]
fn test_request_fail_too_many_slot_writes() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    // The test StackerDB `TEST_CONTRACT` configures `max-writes: u4096`. Slot 1 is a fresh
    // slot (server version 0) owned by `privk1`, so a validly-signed, small chunk at a version
    // just past `max_writes` clears the size, slot, signature, and staleness checks and is
    // rejected specifically for exceeding the write budget.
    let data = "too many slot writes".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 4097, data_hash);
    slot_metadata.sign(&rpc_test.privk1).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        TEST_CONTRACT_ID.clone(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );

    let chunk_ack = rpc_test
        .run_one(request)
        .decode_stackerdb_chunk_ack()
        .unwrap();
    assert!(!chunk_ack.accepted);
    assert_eq!(
        chunk_ack.code,
        Some(StackerDBErrorCodes::TooManySlotWrites.code())
    );
    assert!(chunk_ack.reason.is_some());
    // The ack still carries the current slot metadata so a client can learn the server's
    // version (actually unchanged)
    let metadata = chunk_ack.metadata.as_ref().unwrap();
    assert_eq!(metadata.slot_id, 1);
    assert_eq!(metadata.slot_version, 0);
}

/// A chunk validly signed by a key that does not own the slot must be reported with the
/// `BadSigner` error code.
#[test]
fn test_request_fail_bad_signer_slot() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    // Slot 1 is owned by `privk1`; signing with `privk2` yields a well-formed signature that
    // recovers to the wrong signer (distinct from the unverifiable-signature case).
    let data = "bad signer".as_bytes();
    let data_hash = Sha512Trunc256Sum::from_data(data);
    let mut slot_metadata = SlotMetadata::new_unsigned(1, 1, data_hash);
    slot_metadata.sign(&rpc_test.privk2).unwrap();

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        TEST_CONTRACT_ID.clone(),
        slot_metadata.slot_id,
        slot_metadata.slot_version,
        slot_metadata.signature.clone(),
        data.to_vec(),
    );

    let chunk_ack = rpc_test
        .run_one(request)
        .decode_stackerdb_chunk_ack()
        .unwrap();
    assert!(!chunk_ack.accepted);
    assert_eq!(chunk_ack.code, Some(StackerDBErrorCodes::BadSigner.code()));
    assert!(chunk_ack.reason.is_some());
}

/// A chunk whose signature cannot be recovered at all (malformed signature) is a bad *client*
/// request, not a server fault. It must be reported as a `BadSigner` ack
#[test]
fn test_request_fail_bad_signer_unverifiable_signature() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());

    // Slot 1 exists and is owned by `privk1`, and this small chunk clears the size and slot
    // checks. The signature's recovery-id byte is invalid, so signature *recovery* fails
    // (a `NetError::VerifyingError`).
    let data = "unverifiable signature".as_bytes();
    let unverifiable_sig = MessageSignature([0xff; 65]);

    let request = StacksHttpRequest::new_post_stackerdb_chunk(
        addr.into(),
        TEST_CONTRACT_ID.clone(),
        1,
        1,
        unverifiable_sig,
        data.to_vec(),
    );

    // A `NetError::VerifyingError` is mapped to `BadSigner`
    let chunk_ack = rpc_test
        .run_one(request)
        .decode_stackerdb_chunk_ack()
        .unwrap();
    assert!(!chunk_ack.accepted);
    assert_eq!(chunk_ack.code, Some(StackerDBErrorCodes::BadSigner.code()));
    assert!(chunk_ack.reason.is_some());
}
