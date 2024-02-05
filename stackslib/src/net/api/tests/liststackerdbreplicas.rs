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
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::types::Address;
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;

use super::test_rpc;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::{ProtocolFamily, TipRequest};

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    let contract_identifier = QualifiedContractIdentifier::parse(
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world-unconfirmed",
    )
    .unwrap();
    let request =
        StacksHttpRequest::new_list_stackerdb_replicas(addr.into(), contract_identifier.clone());
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = liststackerdbreplicas::RPCListStackerDBReplicasRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    assert_eq!(
        handler.contract_identifier,
        Some(contract_identifier.clone())
    );

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.contract_identifier.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    let contract_identifier =
        QualifiedContractIdentifier::parse("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world")
            .unwrap();
    let none_contract_identifier = QualifiedContractIdentifier::parse(
        "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.does-not-ext",
    )
    .unwrap();

    let request =
        StacksHttpRequest::new_list_stackerdb_replicas(addr.into(), contract_identifier.clone());
    requests.push(request);

    // no contract
    let request = StacksHttpRequest::new_list_stackerdb_replicas(
        addr.into(),
        none_contract_identifier.clone(),
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

    let resp = response.decode_stackerdb_replicas().unwrap();
    assert_eq!(resp.len(), 2);

    let naddr = resp.last().clone().unwrap();
    assert_eq!(naddr.addrbytes, PeerAddress::from_ipv4(127, 0, 0, 1));
    assert_eq!(
        naddr.public_key_hash,
        Hash160::from_hex("9b92533ccc243e25eb6197bd03c9164642c7c8a8").unwrap()
    );

    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );
    let resp = response.decode_stackerdb_replicas().unwrap();
    assert_eq!(resp.len(), 0);
}
