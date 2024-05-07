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
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::core::BLOCK_LIMIT_MAINNET_21;
use crate::net::api::getstxtransfercost::SINGLESIG_TX_TRANSFER_LEN;
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

    let request = StacksHttpRequest::new_get_stx_transfer_cost(addr.into());
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getstxtransfercost::RPCGetStxTransferCostRequestHandler::new();
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
    let request = StacksHttpRequest::new_get_stx_transfer_cost(addr.into());

    let mut responses = test_rpc(function_name!(), vec![request]);
    assert_eq!(responses.len(), 1);
    responses.reverse();

    let response = responses.pop().unwrap();
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let fee_rate = response.decode_stx_transfer_fee().unwrap();
    debug!("fee_rate = {:?}", &fee_rate);
    assert_eq!(fee_rate, MINIMUM_TX_FEE_RATE_PER_BYTE);
}
