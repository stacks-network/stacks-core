// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::borrow::{Borrow, BorrowMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::thread::LocalKey;

use clarity::util::hash::hex_bytes;
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::Address;

use super::TestRPC;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::blocks::test::*;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::db::TRANSACTION_LOG;
use crate::chainstate::stacks::{
    Error as chainstate_error, StacksBlock, StacksBlockHeader, StacksMicroblock,
};
use crate::net::api::getblock_v3::NakamotoBlockStream;
use crate::net::api::*;
use crate::net::connection::ConnectionOptions;
use crate::net::http::HttpChunkGenerator;
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest,
};
use crate::net::test::TestEventObserver;
use crate::net::tests::inv::nakamoto::make_nakamoto_peer_from_invs;
use crate::net::{ProtocolFamily, TipRequest};
use crate::util_lib::db::DBConn;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());

    // NOTE: MARF enforces the height to be a u32 value
    let request = StacksHttpRequest::new_gettransaction(
        addr.into(),
        Txid::from_hex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF").unwrap(),
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = gettransaction::RPCGetTransactionRequestHandler::new();
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
        handler.txid,
        Some(
            Txid::from_hex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
                .unwrap()
        )
    );

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.txid.is_none());
}

struct TransactionLogState(bool);

impl TransactionLogState {
    fn new() -> Self {
        let current_value = TRANSACTION_LOG.with(|v| *v.borrow());
        TRANSACTION_LOG.with(|v| *v.borrow_mut() = true);
        Self { 0: current_value }
    }
}

impl Drop for TransactionLogState {
    fn drop(&mut self) {
        TRANSACTION_LOG.with(|v| *v.borrow_mut() = self.0);
    }
}

#[test]
fn test_try_make_response() {
    // TRANSACTION_LOG original value will be restored at the end of test
    let enable_transaction_log = TransactionLogState::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let test_observer = TestEventObserver::new();
    let rpc_test = TestRPC::setup_nakamoto(function_name!(), &test_observer);

    let consensus_hash = rpc_test.consensus_hash;
    let canonical_tip = rpc_test.canonical_tip;

    let peer = &rpc_test.peer_1;
    let sortdb = peer.sortdb.as_ref().unwrap();
    let tenure_blocks = rpc_test
        .peer_1
        .chainstate_ref()
        .nakamoto_blocks_db()
        .get_all_blocks_in_tenure(&consensus_hash, &canonical_tip)
        .unwrap();

    //let nakamoto_block_tip = NakamotoBlock::consensus_deserialize(&mut &block_data[..]).unwrap();

    let nakamoto_block_tip = tenure_blocks.last().unwrap();

    let tx = &nakamoto_block_tip.txs[0];

    let mut requests = vec![];

    // query the transaction
    let request = StacksHttpRequest::new_gettransaction(addr.into(), tx.txid());
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // check txid
    let response = responses.remove(0);
    let resp = response.decode_gettransaction().unwrap();

    let tx_bytes = hex_bytes(&resp.tx).unwrap();
    let stacks_transaction = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
    assert_eq!(stacks_transaction.txid(), tx.txid());
    assert_eq!(stacks_transaction.serialize_to_vec(), tx_bytes);

    // let response = responses.remove(0);
    //let (preamble, body) = response.destruct();

    //assert_eq!(preamble.status_code, 404);
}
