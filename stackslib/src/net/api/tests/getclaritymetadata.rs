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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::vm::database::{ClaritySerializable, DataMapMetadata, DataVariableMetadata};
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions, TypeSignature};
use clarity::vm::{ClarityName, ContractName};
use serde_json::json;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::http::Error as HttpError;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::{Error as NetError, ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::9::contract-size".to_string(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getclaritymetadata::RPCGetClarityMetadataRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    // consumed path args
    assert_eq!(
        handler.clarity_metadata_key,
        Some("vm-metadata::9::contract-size".to_string())
    );
    assert_eq!(
        handler.contract_identifier,
        Some(
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
            )
            .unwrap()
        )
    );

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.clarity_metadata_key.is_none());
}

#[test]
fn test_try_parse_invalid_store_type() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::2::contract-size".to_string(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getclaritymetadata::RPCGetClarityMetadataRequestHandler::new();
    let parsed_request_err = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap_err();

    assert_eq!(
        parsed_request_err,
        HttpError::DecodeError("Invalid metadata type".to_string()).into()
    );
    handler.restart();
}

#[test]
fn test_try_parse_invalid_contract_metadata_var_name() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::9::contract-invalid-key".to_string(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getclaritymetadata::RPCGetClarityMetadataRequestHandler::new();
    let parsed_request_err = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap_err();

    assert_eq!(
        parsed_request_err,
        HttpError::DecodeError("Invalid metadata var name".to_string()).into()
    );
    handler.restart();
}

#[test]
fn test_try_parse_request_for_analysis() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "analysis".to_string(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
    );
    assert_eq!(
        request.contents().tip_request(),
        TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
    );
    let bytes = request.try_serialize().unwrap();

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getclaritymetadata::RPCGetClarityMetadataRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    // consumed path args
    assert_eq!(handler.clarity_metadata_key, Some("analysis".to_string()));
    assert_eq!(
        handler.contract_identifier,
        Some(
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world"
            )
            .unwrap()
        )
    );

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.clarity_metadata_key.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query invalid metadata key (wrong store type)
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::2::bar".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing contract size metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::9::contract-size".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing data map metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::5::test-map".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing data var metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::6::bar".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing data var metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::6::bar".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing data var metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::6::bar".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query undeclared var metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::6::non-existing-var".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query existing contract size metadata
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::9::contract-size".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    // query invalid metadata key (wrong store type)
    let request = StacksHttpRequest::new_getclaritymetadata(
        addr.into(),
        StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R").unwrap(),
        "hello-world".try_into().unwrap(),
        "vm-metadata::2::bar".to_string(),
        TipRequest::UseLatestAnchoredTip,
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    // unknwnon data var
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 400);

    // contract size metadata
    let response = responses.remove(0);
    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );
    let resp = response.decode_clarity_metadata_response().unwrap();
    assert_eq!(resp.data, "1432");

    // data map metadata
    let response = responses.remove(0);
    let resp = response.decode_clarity_metadata_response().unwrap();
    let expected = DataMapMetadata {
        key_type: TypeSignature::UIntType,
        value_type: TypeSignature::UIntType,
    };
    assert_eq!(resp.data, expected.serialize());

    // data var metadata
    let response = responses.remove(0);
    let resp = response.decode_clarity_metadata_response().unwrap();
    let expected = DataVariableMetadata {
        value_type: TypeSignature::IntType,
    };
    assert_eq!(resp.data, expected.serialize());

    // data var metadata
    let response = responses.remove(0);
    let resp = response.decode_clarity_metadata_response().unwrap();
    let expected = DataVariableMetadata {
        value_type: TypeSignature::IntType,
    };
    assert_eq!(resp.data, expected.serialize());

    // data var metadata
    let response = responses.remove(0);
    let resp = response.decode_clarity_metadata_response().unwrap();
    let expected = DataVariableMetadata {
        value_type: TypeSignature::IntType,
    };
    assert_eq!(resp.data, expected.serialize());

    // invalid metadata key
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);

    // contract size metadata
    let response = responses.remove(0);
    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );
    let resp = response.decode_clarity_metadata_response().unwrap();
    assert_eq!(resp.data, "1432");

    // unknwnon data var
    let response = responses.remove(0);
    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 400);
}
