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
use serde_json;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
use crate::net::api::getinfo::RPCPeerInfoData;
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

    let request = StacksHttpRequest::new_getinfo(addr.into(), Some(123));

    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut parsed_request = http
        .try_parse_request(&parsed_preamble.expect_request(), &bytes[offset..])
        .unwrap();

    // parsed request consumes headers that would not be in a constructed reqeuest
    parsed_request.clear_headers();
    parsed_request.add_header(
        "X-Canonical-Stacks-Tip-Height".to_string(),
        "123".to_string(),
    );
    let (preamble, contents) = parsed_request.destruct();

    assert_eq!(&preamble, request.preamble());
}

#[test]
fn test_getinfo_compat() {
    let old_getinfo_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null}"#;
    let getinfo_no_pubkey_hash_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null,"node_public_key":"029b27d345e7bd2a6627262cefe6e97d9bc482f41ec32ec76a7bec391bb441798d"}"#;
    let getinfo_no_pubkey_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null,"node_public_key_hash":"046e6f832a83ff0da4a550907d3a44412cc1e4bf"}"#;
    let getinfo_full_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null,"node_public_key":"029b27d345e7bd2a6627262cefe6e97d9bc482f41ec32ec76a7bec391bb441798d","node_public_key_hash":"046e6f832a83ff0da4a550907d3a44412cc1e4bf"}"#;

    // they all parse
    for json_obj in &[
        &old_getinfo_json,
        &getinfo_no_pubkey_json,
        &getinfo_no_pubkey_hash_json,
        &getinfo_full_json,
    ] {
        let _v: RPCPeerInfoData = serde_json::from_str(json_obj).unwrap();
    }
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query existing account
    let request = StacksHttpRequest::new_getinfo(addr.into(), Some(123));
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
    let resp = response.decode_peer_info().unwrap();
}
