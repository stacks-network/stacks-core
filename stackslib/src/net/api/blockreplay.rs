// Copyright (C) 2025 Stacks Open Internet Foundation
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

use clarity::vm::costs::ExecutionCost;
use clarity::vm::Value;
use regex::{Captures, Regex};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId, TrieHash};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use crate::chainstate::stacks::{Error as ChainError, StacksTransaction, TransactionPayload};
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{RPCRequestHandler, StacksHttpResponse};
use crate::net::{Error as NetError, StacksHttpRequest, StacksNodeState};

#[derive(Clone)]
pub struct RPCNakamotoBlockReplayRequestHandler {
    pub block_id: Option<StacksBlockId>,
    pub auth: Option<String>,
}

impl RPCNakamotoBlockReplayRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self {
            block_id: None,
            auth,
        }
    }

    pub fn block_replay(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
    ) -> Result<RPCReplayedBlock, ChainError> {
        let Some(block_id) = &self.block_id else {
            return Err(ChainError::InvalidStacksBlock("block_id is None".into()));
        };

        let Some((tenure_id, parent_block_id)) = chainstate
            .nakamoto_blocks_db()
            .get_tenure_and_parent_block_id(&block_id)?
        else {
            return Err(ChainError::NoSuchBlockError);
        };

        let staging_db_path = chainstate.get_nakamoto_staging_blocks_path()?;
        let db_conn = StacksChainState::open_nakamoto_staging_blocks(&staging_db_path, false)?;
        let rowid = db_conn
            .conn()
            .get_nakamoto_block_rowid(&block_id)?
            .ok_or(ChainError::NoSuchBlockError)?;

        let mut blob_fd = match db_conn.open_nakamoto_block(rowid, false).map_err(|e| {
            let msg = format!("Failed to open Nakamoto block {}: {:?}", &block_id, &e);
            warn!("{}", &msg);
            msg
        }) {
            Ok(blob_fd) => blob_fd,
            Err(e) => return Err(ChainError::InvalidStacksBlock(e)),
        };

        let block = match NakamotoBlock::consensus_deserialize(&mut blob_fd).map_err(|e| {
            let msg = format!("Failed to read Nakamoto block {}: {:?}", &block_id, &e);
            warn!("{}", &msg);
            msg
        }) {
            Ok(block) => block,
            Err(e) => return Err(ChainError::InvalidStacksBlock(e)),
        };

        let burn_dbconn = match sortdb.index_handle_at_block(chainstate, &parent_block_id) {
            Ok(burn_dbconn) => burn_dbconn,
            Err(_) => return Err(ChainError::NoSuchBlockError),
        };

        let tenure_change = block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::TenureChange(..)));
        let coinbase = block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::Coinbase(..)));
        let tenure_cause = tenure_change.and_then(|tx| match &tx.payload {
            TransactionPayload::TenureChange(tc) => Some(tc.cause),
            _ => None,
        });

        let parent_stacks_header_opt =
            match NakamotoChainState::get_block_header(chainstate.db(), &parent_block_id) {
                Ok(parent_stacks_header_opt) => parent_stacks_header_opt,
                Err(e) => return Err(e),
            };

        let Some(parent_stacks_header) = parent_stacks_header_opt else {
            return Err(ChainError::InvalidStacksBlock(
                "Invalid Parent Block".into(),
            ));
        };

        let mut builder = match NakamotoBlockBuilder::new(
            &parent_stacks_header,
            &block.header.consensus_hash,
            block.header.burn_spent,
            tenure_change,
            coinbase,
            block.header.pox_treatment.len(),
            None,
            None,
        ) {
            Ok(builder) => builder,
            Err(e) => return Err(e),
        };

        let mut miner_tenure_info =
            match builder.load_ephemeral_tenure_info(chainstate, &burn_dbconn, tenure_cause) {
                Ok(miner_tenure_info) => miner_tenure_info,
                Err(e) => return Err(e),
            };

        let burn_chain_height = miner_tenure_info.burn_tip_height;
        let mut tenure_tx = match builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info) {
            Ok(tenure_tx) => tenure_tx,
            Err(e) => return Err(e),
        };

        let mut block_fees: u128 = 0;
        let mut txs_receipts = vec![];

        for (i, tx) in block.txs.iter().enumerate() {
            let tx_len = tx.tx_len();

            let tx_result = builder.try_mine_tx_with_len(
                &mut tenure_tx,
                tx,
                tx_len,
                &BlockLimitFunction::NO_LIMIT_HIT,
                None,
            );
            let err = match tx_result {
                TransactionResult::Success(tx_result) => {
                    txs_receipts.push(tx_result.receipt);
                    Ok(())
                }
                _ => Err(format!("Problematic tx {i}")),
            };
            if let Err(reason) = err {
                let txid = tx.txid();
                return Err(ChainError::InvalidStacksTransaction(
                    format!("Unable to replay transaction {txid}: {reason}").into(),
                    false,
                ));
            }

            block_fees += tx.get_tx_fee() as u128;
        }

        let replayed_block = builder.mine_nakamoto_block(&mut tenure_tx, burn_chain_height);

        tenure_tx.rollback_block();

        let tx_merkle_root = block.header.tx_merkle_root.clone();

        let mut rpc_replayed_block =
            RPCReplayedBlock::from_block(block, block_fees, tenure_id, parent_block_id);

        for receipt in &txs_receipts {
            let transaction = RPCReplayedBlockTransaction::from_receipt(receipt);
            rpc_replayed_block.transactions.push(transaction);
        }

        rpc_replayed_block.valid_merkle_root =
            tx_merkle_root == replayed_block.header.tx_merkle_root;

        Ok(rpc_replayed_block)
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCReplayedBlockTransaction {
    /// transaction id
    pub txid: Txid,
    /// index of transaction in the block
    pub tx_index: u32,
    /// body (headers + payload) of transaction
    pub data: Option<StacksTransaction>,
    /// hex representation of the transaction body
    pub hex: String,
    /// result of transaction execution (clarity value)
    pub result: Value,
    /// amount of burned stx
    pub stx_burned: u128,
    /// execution cost infos
    pub execution_cost: ExecutionCost,
    /// generated events
    pub events: Vec<serde_json::Value>,
}

impl RPCReplayedBlockTransaction {
    pub fn from_receipt(receipt: &StacksTransactionReceipt) -> Self {
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

        Self {
            txid,
            tx_index: receipt.tx_index,
            data: transaction_data,
            hex: receipt.transaction.serialize_to_dbstring(),
            result: receipt.result.clone(),
            stx_burned: receipt.stx_burned,
            execution_cost: receipt.execution_cost.clone(),
            events,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct RPCReplayedBlock {
    /// block id (index_block_hash)
    pub block_id: StacksBlockId,
    /// block hash
    pub block_hash: BlockHeaderHash,
    /// height of the block
    pub block_height: u64,
    /// index_block_hash of the parent
    pub parent_block_id: StacksBlockId,
    /// consensus hash of the tenure containing the block
    pub consensus_hash: ConsensusHash,
    /// total fees for the transactions in the block
    pub fees: u128,
    /// merkle tree root hash of the included transactions
    pub tx_merkle_root: Sha512Trunc256Sum,
    /// state index of the MARF
    pub state_index_root: TrieHash,
    /// block timestamp
    pub timestamp: u64,
    /// signature of the miner
    pub miner_signature: MessageSignature,
    /// list of signers signatures
    pub signer_signature: Vec<MessageSignature>,
    /// the list of block transactions
    pub transactions: Vec<RPCReplayedBlockTransaction>,
    /// check if the computed merkle tree root hash matches the one from the original block
    pub valid_merkle_root: bool,
}

impl RPCReplayedBlock {
    pub fn from_block(
        block: NakamotoBlock,
        block_fees: u128,
        tenure_id: ConsensusHash,
        parent_block_id: StacksBlockId,
    ) -> Self {
        let block_id = block.block_id();
        let block_hash = block.header.block_hash();

        Self {
            block_id,
            block_hash,
            block_height: block.header.chain_length,
            parent_block_id,
            consensus_hash: tenure_id,
            fees: block_fees,
            tx_merkle_root: block.header.tx_merkle_root,
            state_index_root: block.header.state_index_root,
            timestamp: block.header.timestamp,
            miner_signature: block.header.miner_signature,
            signer_signature: block.header.signer_signature,
            transactions: vec![],
            valid_merkle_root: false,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCNakamotoBlockReplayRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/blocks/replay/(?P<block_id>[0-9a-f]{64})$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/blocks/replay/:block_id"
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
        // If no authorization is set, then the block replay endpoint is not enabled
        let Some(password) = &self.auth else {
            return Err(Error::Http(400, "Bad Request.".into()));
        };
        let Some(auth_header) = preamble.headers.get("authorization") else {
            return Err(Error::Http(401, "Unauthorized".into()));
        };
        if auth_header != password {
            return Err(Error::Http(401, "Unauthorized".into()));
        }
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

        let block_id = StacksBlockId::from_hex(block_id_str)
            .map_err(|_| Error::DecodeError("Invalid path: unparseable block id".to_string()))?;

        self.block_id = Some(block_id);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCNakamotoBlockReplayRequestHandler {
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
        let Some(block_id) = &self.block_id else {
            return Err(NetError::SendError("Missing `block_id`".into()));
        };

        let replayed_block_res =
            node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
                self.block_replay(sortdb, chainstate)
            });

        // start loading up the block
        let replayed_block = match replayed_block_res {
            Ok(replayed_block) => replayed_block,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("No such block {block_id}\n")),
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
        let body = HttpResponseContents::try_from_json(&replayed_block)?;
        Ok((preamble, body))
    }
}

impl StacksHttpRequest {
    /// Make a new block_replay request to this endpoint
    pub fn new_block_replay(host: PeerHost, block_id: &StacksBlockId) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            format!("/v3/blocks/replay/{block_id}"),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCNakamotoBlockReplayRequestHandler {
    /// Decode this response from a byte stream.  This is called by the client to decode this
    /// message
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let rpc_replayed_block: RPCReplayedBlock = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(rpc_replayed_block)?)
    }
}

impl StacksHttpResponse {
    pub fn decode_replayed_block(self) -> Result<RPCReplayedBlock, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let replayed_block: RPCReplayedBlock = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(replayed_block)
    }
}
