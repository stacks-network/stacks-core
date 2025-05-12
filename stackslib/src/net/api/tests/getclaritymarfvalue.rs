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

use clarity::vm::database::{ClarityDeserializable, STXBalance};
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions, TypeSignature};
use clarity::vm::{ClarityName, ContractName, Value};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksAddress, TrieHash};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::test_rpc;
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

    let vm_key_epoch = TrieHash::from_key("vm-epoch::epoch-version");
    let vm_key_trip =
        TrieHash::from_key("vm::ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5.counter::1::count");
    let vm_key_quad =
        TrieHash::from_key("vm::ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5.counter::0::data::1234");
    let valid_keys = [vm_key_epoch, vm_key_trip, vm_key_quad];

    for key in valid_keys {
        let request = StacksHttpRequest::new_getclaritymarf(
            addr.into(),
            key,
            TipRequest::SpecificTip(StacksBlockId([0x22; 32])),
            true,
        );
        assert_eq!(
            request.contents().tip_request(),
            TipRequest::SpecificTip(StacksBlockId([0x22; 32]))
        );
        assert!(request.contents().get_with_proof());

        let bytes = request.try_serialize().unwrap();

        let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
        let mut handler = getclaritymarfvalue::RPCGetClarityMarfRequestHandler::new();
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
        assert_eq!(handler.marf_key_hash, Some(key.clone()));

        assert_eq!(&preamble, request.preamble());

        handler.restart();
        assert!(handler.marf_key_hash.is_none());
    }
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let mut requests = vec![];

    // query existing marf value
    let request = StacksHttpRequest::new_getclaritymarf(
        addr.into(),
        TrieHash::from_key("vm::ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world::1::bar"),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query existing unconfirmed
    let request = StacksHttpRequest::new_getclaritymarf(
        addr.into(),
        TrieHash::from_key("vm::ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world-unconfirmed::1::bar-unconfirmed"),
        TipRequest::UseLatestUnconfirmedTip,
        true,
    );
    requests.push(request);

    // query non-existant var
    let request = StacksHttpRequest::new_getclaritymarf(
        addr.into(),
        TrieHash::from_key(
            "vm::ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world::1::does-not-exist",
        ),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query non-existant contract
    let request = StacksHttpRequest::new_getclaritymarf(
        addr.into(),
        TrieHash::from_key("vm::ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.does-not-exist::1::bar"),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    // query vm-account balance
    let request = StacksHttpRequest::new_getclaritymarf(
        addr.into(),
        TrieHash::from_key("vm-account::ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R::19"),
        TipRequest::UseLatestAnchoredTip,
        true,
    );
    requests.push(request);

    let mut responses = test_rpc(function_name!(), requests);

    // existing data
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_clarity_marf_response().unwrap();
    assert_eq!(resp.data, "0x0000000000000000000000000000000000");
    assert!(resp.marf_proof.is_some());

    // unconfirmed data
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    assert_eq!(
        response.preamble().get_canonical_stacks_tip_height(),
        Some(1)
    );

    let resp = response.decode_clarity_marf_response().unwrap();
    assert_eq!(resp.data, "0x0100000000000000000000000000000001");
    assert!(resp.marf_proof.is_some());

    // no such var
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);

    // no such contract
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let (preamble, body) = response.destruct();
    assert_eq!(preamble.status_code, 404);

    // vm-account balance
    let response = responses.remove(0);
    debug!(
        "Response:\n{}\n",
        std::str::from_utf8(&response.try_serialize().unwrap()).unwrap()
    );

    let resp = response.decode_clarity_marf_response().unwrap();
    let balance = STXBalance::deserialize(&resp.data[2..]).unwrap();

    assert_eq!(balance.amount_unlocked(), 1_000_000_000);
    assert_eq!(balance.amount_locked(), 0);
}
