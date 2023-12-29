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

use std::io::{Read, Write};

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use regex::{Captures, Regex};
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN,
};
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksBlockId, StacksPublicKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::{hex_bytes, Hash160, Sha256Sum};
use stacks_common::util::retry::BoundReader;

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use crate::chainstate::stacks::{
    Error as ChainError, StacksBlock, StacksBlockHeader, StacksTransaction, TransactionPayload,
};
use crate::core::mempool::MemPoolDB;
use crate::cost_estimates::FeeRateEstimate;
use crate::net::http::{
    http_reason, parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::{
    Attachment, BlocksData, BlocksDatum, Error as NetError, StacksMessageType, StacksNodeState,
};
use crate::util_lib::db::Error as DBError;

/// This enum is used to supply a `reason_code` for validation
///  rejection responses. This is serialized as an enum with string
///  type (in jsonschema terminology).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidateRejectCode {
    BadBlockHash,
    BadTransaction,
    InvalidBlock,
    ChainstateError,
    UnknownParent,
}

/// A response for block proposal validation
///  that the stacks-node thinks should be rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockValidateReject {
    pub reason: String,
    pub reason_code: ValidateRejectCode,
}

/// A response for block proposal validation
///  that the stacks-node thinks is acceptable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockValidateOk {
    pub block: NakamotoBlock,
    pub cost: ExecutionCost,
    pub size: u64,
}

/// This enum is used for serializing the response to block
/// proposal validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "Result")]
pub enum BlockValidateResponse {
    Ok(BlockValidateOk),
    Reject(BlockValidateReject),
}

impl From<Result<BlockValidateOk, BlockValidateReject>> for BlockValidateResponse {
    fn from(value: Result<BlockValidateOk, BlockValidateReject>) -> Self {
        match value {
            Ok(o) => BlockValidateResponse::Ok(o),
            Err(e) => BlockValidateResponse::Reject(e),
        }
    }
}

impl From<ChainError> for BlockValidateReject {
    fn from(value: ChainError) -> Self {
        BlockValidateReject {
            reason: format!("Chainstate Error: {value}"),
            reason_code: ValidateRejectCode::ChainstateError,
        }
    }
}

impl From<DBError> for BlockValidateReject {
    fn from(value: DBError) -> Self {
        ChainError::from(value).into()
    }
}

/// Represents a block proposed to the `v2/block_proposal` endpoint for validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlockProposal {
    /// Proposed block
    pub block: NakamotoBlock,
    // tenure ID -- this is the index block hash of the start block of the last tenure (i.e.
    // the data we committed to in the block-commit).  If this is an epoch 2.x parent, then
    // this is just the index block hash of the parent Stacks block.
    pub tenure_start_block: StacksBlockId,
    /// Identifies which chain block is for (Mainnet, Testnet, etc.)
    pub chain_id: u32,
}

impl StacksMessageCodec for NakamotoBlockProposal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.block)?;
        write_next(fd, &self.tenure_start_block)?;
        write_next(fd, &self.chain_id)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            block: read_next(fd)?,
            tenure_start_block: read_next(fd)?,
            chain_id: read_next(fd)?,
        })
    }
}

impl NakamotoBlockProposal {
    /// Test this block proposal against the current chain state and
    /// either accept or reject the proposal
    ///
    /// This is done in 2 steps:
    /// - Static validation of the block, which checks the following:
    ///   - Block is well-formed
    ///   - Transactions are well-formed
    ///   - Miner signature is valid
    /// - Validation of transactions by executing them agains current chainstate.
    ///   This is resource intensive, and therefore done only if previous checks pass
    pub fn validate(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState, // not directly used; used as a handle to open other chainstates
    ) -> Result<BlockValidateOk, BlockValidateReject> {
        let ts_start = get_epoch_time_ms();
        // Measure time from start of function
        let time_elapsed = || get_epoch_time_ms().saturating_sub(ts_start);

        let mainnet = self.chain_id == CHAIN_ID_MAINNET;
        if self.chain_id != chainstate.chain_id || mainnet != chainstate.mainnet {
            return Err(BlockValidateReject {
                reason_code: ValidateRejectCode::InvalidBlock,
                reason: "Wrong netowrk/chain_id".into(),
            });
        }

        let burn_dbconn = sortdb.index_conn();
        let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn())?;
        let mut db_handle = sortdb.index_handle(&sort_tip);
        let expected_burn =
            NakamotoChainState::get_expected_burns(&mut db_handle, chainstate.db(), &self.block)?;

        // Static validation checks
        NakamotoChainState::validate_nakamoto_block_burnchain(
            &db_handle,
            expected_burn,
            &self.block,
            mainnet,
            self.chain_id,
        )?;

        // Validate block txs against chainstate
        let parent_stacks_header = NakamotoChainState::get_block_header(
            chainstate.db(),
            &self.block.header.parent_block_id,
        )?
        .ok_or_else(|| BlockValidateReject {
            reason_code: ValidateRejectCode::InvalidBlock,
            reason: "Invalid parent block".into(),
        })?;
        let tenure_change = self
            .block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::TenureChange(..)));
        let coinbase = self
            .block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::Coinbase(..)));
        let tenure_cause = tenure_change.and_then(|tx| match &tx.payload {
            TransactionPayload::TenureChange(tc) => Some(tc.cause),
            _ => None,
        });

        let mut builder = NakamotoBlockBuilder::new(
            &parent_stacks_header,
            &self.block.header.consensus_hash,
            self.block.header.burn_spent,
            tenure_change,
            coinbase,
        )?;

        let mut miner_tenure_info =
            builder.load_tenure_info(chainstate, &burn_dbconn, tenure_cause)?;
        let mut tenure_tx = builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info)?;

        for (i, tx) in self.block.txs.iter().enumerate() {
            let tx_len = tx.tx_len();
            let tx_result = builder.try_mine_tx_with_len(
                &mut tenure_tx,
                &tx,
                tx_len,
                &BlockLimitFunction::NO_LIMIT_HIT,
                ASTRules::PrecheckSize,
            );
            let err = match tx_result {
                TransactionResult::Success(_) => Ok(()),
                TransactionResult::Skipped(s) => Err(format!("tx {i} skipped: {}", s.error)),
                TransactionResult::ProcessingError(e) => {
                    Err(format!("Error processing tx {i}: {}", e.error))
                }
                TransactionResult::Problematic(p) => {
                    Err(format!("Problematic tx {i}: {}", p.error))
                }
            };
            if let Err(reason) = err {
                warn!(
                    "Rejected block proposal";
                    "reason" => %reason,
                    "tx" => ?tx,
                );
                return Err(BlockValidateReject {
                    reason,
                    reason_code: ValidateRejectCode::BadTransaction,
                });
            }
        }

        let mut block = builder.mine_nakamoto_block(&mut tenure_tx);
        let size = builder.get_bytes_so_far();
        let cost = builder.tenure_finish(tenure_tx);

        // Clone signatures from block proposal
        // These have already been validated by `validate_nakamoto_block_burnchain()``
        block.header.miner_signature = self.block.header.miner_signature.clone();
        block.header.signer_signature = self.block.header.signer_signature.clone();

        // Assuming `tx_nerkle_root` has been checked we don't need to hash the whole block
        let expected_block_header_hash = self.block.header.block_hash();
        let computed_block_header_hash = block.header.block_hash();

        if computed_block_header_hash != expected_block_header_hash {
            warn!(
                "Rejected block proposal";
                "reason" => "Block hash is not as expected",
                "expected_block_header_hash" => %expected_block_header_hash,
                "computed_block_header_hash" => %computed_block_header_hash,
                //"expected_block" => %serde_json::to_string(&serde_json::to_value(&self.block).unwrap()).unwrap(),
                //"computed_block" => %serde_json::to_string(&serde_json::to_value(&block).unwrap()).unwrap(),
            );
            return Err(BlockValidateReject {
                reason: "Block hash is not as expected".into(),
                reason_code: ValidateRejectCode::BadBlockHash,
            });
        }

        info!(
            "Participant: validated anchored block";
            "block_header_hash" => %computed_block_header_hash,
            "height" => block.header.chain_length,
            "tx_count" => block.txs.len(),
            "parent_stacks_block_id" => %block.header.parent_block_id,
            "block_size" => size,
            "execution_cost" => %cost,
            "validation_time_ms" => time_elapsed(),
            "tx_fees_microstacks" => block.txs.iter().fold(0, |agg: u64, tx| {
                agg.saturating_add(tx.get_tx_fee())
            })
        );

        Ok(BlockValidateOk { block, cost, size })
    }
}

#[derive(Clone, Default)]
pub struct RPCBlockProposalRequestHandler {
    pub block_proposal: Option<NakamotoBlockProposal>,
}

impl RPCBlockProposalRequestHandler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode a bare transaction from the body
    fn parse_octets(mut body: &[u8]) -> Result<NakamotoBlockProposal, Error> {
        NakamotoBlockProposal::consensus_deserialize(&mut body).map_err(|e| match e {
            CodecError::DeserializeError(msg) => {
                Error::DecodeError(format!("Failed to deserialize posted transaction: {msg}"))
            }
            _ => e.into(),
        })
    }

    /// Decode a JSON-encoded transaction
    fn parse_json(body: &[u8]) -> Result<NakamotoBlockProposal, Error> {
        serde_json::from_slice(body).map_err(|_| Error::DecodeError("Failed to parse body".into()))
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCBlockProposalRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/block_proposal$"#).unwrap()
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        // Only accept requests from localhost
        let is_loopback = match preamble.host {
            // Should never be DNS
            PeerHost::DNS(..) => false,
            PeerHost::IP(addr, ..) => addr.is_loopback(),
        };

        if !is_loopback {
            return Err(Error::Http(403, "Forbidden".into()));
        }

        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for PostBlock".to_string(),
            ));
        }

        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: BlockProposal body is too big".to_string(),
            ));
        }

        let block_proposal = match preamble.content_type {
            Some(HttpContentType::Bytes) => Self::parse_octets(body)?,
            Some(HttpContentType::JSON) => Self::parse_json(body)?,
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for transaction".to_string(),
                ))
            }
            _ => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for transaction; expected application/json or application/octet-stream".to_string(),
                ))
            }
        };

        self.block_proposal = Some(block_proposal);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCBlockProposalRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_proposal = None
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_proposal = self
            .block_proposal
            .take()
            .ok_or(NetError::SendError("`block_proposal` not set".into()))?;

        let res = node.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
            block_proposal.validate(sortdb, chainstate)
        });

        match res {
            Ok(ok) => {
                let mut preamble = HttpResponsePreamble::accepted_json(&preamble);
                preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
                let body = HttpResponseContents::try_from_json(&ok)?;
                Ok((preamble, body))
            }
            Err(err) => {
                let code = 400;
                let mut preamble = HttpResponsePreamble::error_json(code, http_reason(code));
                preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
                let body = HttpResponseContents::try_from_json(&err)?;
                Ok((preamble, body))
            }
        }
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCBlockProposalRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: BlockValidateResponse = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(response)
    }
}

impl StacksHttpRequest {
    /// Make a new post-block request
    #[cfg(test)]
    pub fn new_post_block_proposal(
        host: PeerHost,
        proposal: &NakamotoBlockProposal,
    ) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v2/block_proposal".into(),
            HttpRequestContents::new().payload_stacks(proposal),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_stacks_block_proposal_accepted(self) -> Result<BlockValidateResponse, NetError> {
        todo!()
    }
}
