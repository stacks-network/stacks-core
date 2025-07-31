// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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

use std::io::{Read, Seek, SeekFrom};

use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::Value;
use regex::{Captures, Regex};
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::Txid;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::events::{
    StacksTransactionEvent, StacksTransactionReceipt, TransactionOrigin,
};
use crate::chainstate::stacks::{Error as ChainError, StacksTransaction};
use crate::net::http::{
    parse_bytes, Error, HttpChunkGenerator, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpRequest, StacksHttpResponse};
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoBlockSimulateRequestHandler {
    pub block_id: Option<StacksBlockId>,
}

impl RPCNakamotoBlockSimulateRequestHandler {
    pub fn new() -> Self {
        Self { block_id: None }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCSimulatedBlockTransaction {
    pub txid: Txid,
    pub tx_index: u32,
    pub data: Option<StacksTransaction>,
    pub hex: String,
    pub result: Value,
    pub stx_burned: u128,
    pub execution_cost: ExecutionCost,
    pub events: Vec<serde_json::Value>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCSimulatedBlock {
    pub block_id: StacksBlockId,
    pub block_hash: BlockHeaderHash,
    pub parent_block_id: StacksBlockId,
    pub consensus_hash: ConsensusHash,
    pub fees: u128,
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub state_index_root: TrieHash,
    pub timestamp: u64,
    pub miner_signature: MessageSignature,
    pub signer_signature: Vec<MessageSignature>,
    pub transactions: Vec<RPCSimulatedBlockTransaction>,
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoBlockSimulateRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/simulate/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/simulate/:block_id"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }

        let block_id_str = captures
            .name("block_id")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to block ID group".to_string())
            })?
            .as_str();

        let block_id = StacksBlockId::from_hex(block_id_str).map_err(|_| {
            Error::DecodeError("Invalid path: unparseable consensus hash".to_string())
        })?;
        self.block_id = Some(block_id);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoBlockSimulateRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_id = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_id = self
            .block_id
            .take()
            .ok_or(NetError::SendError("Missing `block_id`".into()))?;

        let simulated_block_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                let Some((tenure_id, parent_block_id)) = chainstate
                    .nakamoto_blocks_db()
                    .get_tenure_and_parent_block_id(&block_id)?
                else {
                    return Err(ChainError::NoSuchBlockError);
                };

                let staging_db_path = chainstate.get_nakamoto_staging_blocks_path()?;
                let db_conn =
                    StacksChainState::open_nakamoto_staging_blocks(&staging_db_path, false)?;
                let rowid = db_conn
                    .conn()
                    .get_nakamoto_block_rowid(&block_id)?
                    .ok_or(ChainError::NoSuchBlockError)?;

                let mut blob_fd = db_conn
                    .open_nakamoto_block(rowid, false)
                    .map_err(|e| {
                        let msg = format!("Failed to open Nakamoto block {}: {:?}", &block_id, &e);
                        warn!("{}", &msg);
                        msg
                    })
                    .unwrap();

                let block = NakamotoBlock::consensus_deserialize(&mut blob_fd)
                    .map_err(|e| {
                        let msg = format!("Failed to read Nakamoto block {}: {:?}", &block_id, &e);
                        warn!("{}", &msg);
                        msg
                    })
                    .unwrap();

                let burn_dbconn = match sortdb.index_handle_at_block(chainstate, &parent_block_id) {
                    Ok(burn_dbconn) => burn_dbconn,
                    Err(_) => return Err(ChainError::NoSuchBlockError),
                };

                let (block_fees, txs_receipts) = chainstate
                    .with_simulated_clarity_tx(
                        &burn_dbconn,
                        &parent_block_id,
                        &block_id,
                        |clarity_tx| {
                            //let mut clarity_tx = chainstate.block_begin(&burn_dbconn, parent_consensus_hash, parent_block, &block.header.consensus_hash, &block.header.block_hash());

                            let (block_fees, txs_receipts) =
                                match StacksChainState::process_block_transactions(
                                    clarity_tx,
                                    &block.txs,
                                    0,
                                    ASTRules::PrecheckSize,
                                ) {
                                    Err(e) => {
                                        let msg =
                                            format!("Invalid Stacks block {}: {:?}", &block_id, &e);
                                        warn!("{}", &msg);

                                        return Err(ChainError::InvalidStacksBlock(msg));
                                    }
                                    Ok((block_fees, _block_burns, txs_receipts)) => {
                                        (block_fees, txs_receipts)
                                    }
                                };
                            Ok((block_fees, txs_receipts))
                        },
                    )
                    .unwrap()
                    .unwrap();

                let block_hash = block.header.block_hash();

                let mut simulated_block = RPCSimulatedBlock {
                    block_id,
                    block_hash,
                    parent_block_id,
                    consensus_hash: tenure_id,
                    fees: block_fees,
                    tx_merkle_root: block.header.tx_merkle_root,
                    state_index_root: block.header.state_index_root,
                    timestamp: block.header.timestamp,
                    miner_signature: block.header.miner_signature,
                    signer_signature: block.header.signer_signature,
                    transactions: vec![],
                };
                for receipt in txs_receipts {
                    let events = receipt
                        .events
                        .iter()
                        .enumerate()
                        .map(|(event_index, event)| {
                            event
                                .json_serialize(event_index, &receipt.transaction.txid(), true)
                                .unwrap()
                        })
                        .collect();
                    let transaction_data = match &receipt.transaction {
                        TransactionOrigin::Stacks(stacks) => Some(stacks.clone()),
                        TransactionOrigin::Burn(_) => None,
                    };
                    let txid = receipt.transaction.txid();
                    let transaction = RPCSimulatedBlockTransaction {
                        txid,
                        tx_index: receipt.tx_index,
                        data: transaction_data,
                        hex: receipt.transaction.serialize_to_dbstring(),
                        result: receipt.result,
                        stx_burned: receipt.stx_burned,
                        execution_cost: receipt.execution_cost,
                        events,
                    };
                    simulated_block.transactions.push(transaction);
                }

                Ok(simulated_block)
            });

        // start loading up the block
        let simulated_block = match simulated_block_res {
            Ok(simulated_block) => simulated_block,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {:?}\n", &block_id)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!("Failed to load block {}: {:?}\n", &block_id, &e);
                warn!("{}", &msg);
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let body = HttpResponseContents::try_from_json(&simulated_block)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoBlockSimulateRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let bytes = parse_bytes(preamble, body, MAX_MESSAGE_LEN.into())?;
        Ok(HttpResponsePayload::Bytes(bytes))
    }
}
