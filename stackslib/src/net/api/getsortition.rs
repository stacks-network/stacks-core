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

use std::io::{Read, Seek, SeekFrom, Write};
use std::{fs, io};

use regex::{Captures, Regex};
use serde::de::Error as de_Error;
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksBlockId,
};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::{to_hex, Hash160};
use stacks_common::util::HexError;
use {serde, serde_json};

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NakamotoStagingBlocksConn};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::net::api::getblock_v3::NakamotoBlockStream;
use crate::net::api::{prefix_hex, prefix_opt_hex};
use crate::net::http::{
    parse_bytes, parse_json, Error, HttpBadRequest, HttpChunkGenerator, HttpContentType,
    HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp, StacksHttpRequest,
    StacksHttpResponse,
};
use crate::net::{Error as NetError, StacksNodeState, TipRequest, MAX_HEADERS};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Debug, Clone, PartialEq)]
pub enum QuerySpecifier {
    ConsensusHash(ConsensusHash),
    BurnchainHeaderHash(BurnchainHeaderHash),
    BlockHeight(u64),
    Latest,
}

pub static RPC_SORTITION_INFO_PATH: &str = "/v3/sortitions";
static PATH_REGEX: &str = "^/v3/sortitions(/(?P<key>[a-z_]{1,15})/(?P<value>[0-9a-f]{1,64}))?$";

/// Struct for sortition information returned via the GetSortition API call
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct SortitionInfo {
    /// The burnchain header hash of the block that triggered this event.
    #[serde(with = "prefix_hex")]
    pub burn_block_hash: BurnchainHeaderHash,
    /// The burn height of the block that triggered this event.
    pub burn_block_height: u64,
    /// This sortition ID of the block that triggered this event. This incorporates
    ///  PoX forking information and the burn block hash to obtain an identifier that is
    ///  unique across PoX forks and burnchain forks.
    #[serde(with = "prefix_hex")]
    pub sortition_id: SortitionId,
    /// The parent of this burn block's Sortition ID
    #[serde(with = "prefix_hex")]
    pub parent_sortition_id: SortitionId,
    /// The consensus hash of the block that triggered this event. This incorporates
    ///  PoX forking information and burn op information to obtain an identifier that is
    ///  unique across PoX forks and burnchain forks.
    #[serde(with = "prefix_hex")]
    pub consensus_hash: ConsensusHash,
    /// Boolean indicating whether or not there was a succesful sortition (i.e. a winning
    ///  block or miner was chosen).
    pub was_sortition: bool,
    /// If sortition occurred, and the miner's VRF key registration
    ///  associated a nakamoto mining pubkey with their commit, this
    ///  will contain the Hash160 of that mining key.
    #[serde(with = "prefix_opt_hex")]
    pub miner_pk_hash160: Option<Hash160>,
    /// If sortition occurred, this will be the consensus hash of the burn block corresponding
    /// to the winning block commit's parent block ptr. In 3.x, this is the consensus hash of
    /// the tenure that this new burn block's miner will be building off of.
    #[serde(with = "prefix_opt_hex")]
    pub stacks_parent_ch: Option<ConsensusHash>,
    /// If sortition occurred, this will be the consensus hash of the most recent sortition before
    ///  this one.
    #[serde(with = "prefix_opt_hex")]
    pub last_sortition_ch: Option<ConsensusHash>,
    #[serde(with = "prefix_opt_hex")]
    /// In Stacks 2.x, this is the winning block.
    /// In Stacks 3.x, this is the first block of the parent tenure.
    pub committed_block_hash: Option<BlockHeaderHash>,
}

impl TryFrom<(&str, &str)> for QuerySpecifier {
    type Error = Error;

    fn try_from(value: (&str, &str)) -> Result<Self, Self::Error> {
        let hex_str = if value.1.starts_with("0x") {
            &value.1[2..]
        } else {
            value.1
        };
        match value.0 {
            "consensus" => Ok(Self::ConsensusHash(
                ConsensusHash::from_hex(hex_str).map_err(|e| Error::DecodeError(e.to_string()))?,
            )),
            "burn" => Ok(Self::BurnchainHeaderHash(
                BurnchainHeaderHash::from_hex(hex_str)
                    .map_err(|e| Error::DecodeError(e.to_string()))?,
            )),
            "burn_height" => Ok(Self::BlockHeight(
                value
                    .1
                    .parse::<u64>()
                    .map_err(|e| Error::DecodeError(e.to_string()))?,
            )),
            other => Err(Error::DecodeError(format!("Unknown query param: {other}"))),
        }
    }
}

#[derive(Clone)]
pub struct GetSortitionHandler {
    pub query: QuerySpecifier,
}

impl GetSortitionHandler {
    pub fn new() -> Self {
        Self {
            query: QuerySpecifier::Latest,
        }
    }
}
/// Decode the HTTP request
impl HttpRequest for GetSortitionHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(PATH_REGEX).unwrap()
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

        let req_contents = HttpRequestContents::new().query_string(query);
        self.query = QuerySpecifier::Latest;
        if let (Some(key), Some(value)) = (captures.name("key"), captures.name("value")) {
            self.query = QuerySpecifier::try_from((key.as_str(), value.as_str()))?;
        }

        Ok(req_contents)
    }

    fn metrics_identifier(&self) -> &str {
        RPC_SORTITION_INFO_PATH
    }
}

impl RPCRequestHandler for GetSortitionHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.query = QuerySpecifier::Latest;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let result =
            node.with_node_state(|network, sortdb, _chainstate, _mempool, _rpc_args| {
                let query_result = match self.query {
                    QuerySpecifier::Latest => {
                        Ok(Some(network.burnchain_tip.clone()))
                    },
                    QuerySpecifier::ConsensusHash(ref consensus_hash) => {
                        SortitionDB::get_block_snapshot_consensus(sortdb.conn(), consensus_hash)
                    },
                    QuerySpecifier::BurnchainHeaderHash(ref burn_hash) => {
                        let handle = sortdb.index_handle_at_tip();
                        handle.get_block_snapshot(burn_hash)
                    },
                    QuerySpecifier::BlockHeight(burn_height) => {
                        let handle = sortdb.index_handle_at_tip();
                        handle.get_block_snapshot_by_height(burn_height)
                    },
                };
                let sortition_sn = query_result?
                    .ok_or_else(|| ChainError::NoSuchBlockError)?;

                let (miner_pk_hash160, stacks_parent_ch, committed_block_hash, last_sortition_ch) = if !sortition_sn.sortition {
                    (None, None, None, None)
                } else {
                    let block_commit = SortitionDB::get_block_commit(sortdb.conn(), &sortition_sn.winning_block_txid, &sortition_sn.sortition_id)?
                        .ok_or_else(|| {
                            error!(
                                "Failed to load block commit from Sortition DB for snapshot with a winning block txid";
                                "sortition_id" => %sortition_sn.sortition_id,
                                "txid" => %sortition_sn.winning_block_txid,
                            );
                            ChainError::NoSuchBlockError
                        })?;
                    let handle = sortdb.index_handle(&sortition_sn.sortition_id);
                    let stacks_parent_sn = handle.get_block_snapshot_by_height(block_commit.parent_block_ptr.into())?
                        .ok_or_else(|| {
                            warn!(
                                "Failed to load the snapshot of the winning block commits parent";
                                "sortition_id" => %sortition_sn.sortition_id,
                                "txid" => %sortition_sn.winning_block_txid,
                            );
                            ChainError::NoSuchBlockError
                        })?;

                    // try to figure out what the last snapshot in this fork was with a successful
                    //  sortition.
                    // optimization heuristic: short-circuit the load if its just `stacks_parent_sn`
                    let last_sortition_ch = if sortition_sn.num_sortitions == stacks_parent_sn.num_sortitions + 1 {
                        stacks_parent_sn.consensus_hash.clone()
                    } else {
                        // we actually need to perform the marf lookup
                        let last_sortition = handle.get_last_snapshot_with_sortition(stacks_parent_sn.block_height)?;
                        last_sortition.consensus_hash
                    };

                    (sortition_sn.miner_pk_hash.clone(), Some(stacks_parent_sn.consensus_hash), Some(block_commit.block_header_hash),
                     Some(last_sortition_ch))
                };

                Ok(SortitionInfo {
                    burn_block_hash: sortition_sn.burn_header_hash,
                    burn_block_height: sortition_sn.block_height,
                    sortition_id: sortition_sn.sortition_id,
                    parent_sortition_id: sortition_sn.parent_sortition_id,
                    consensus_hash: sortition_sn.consensus_hash,
                    was_sortition: sortition_sn.sortition,
                    miner_pk_hash160,
                    stacks_parent_ch,
                    last_sortition_ch,
                    committed_block_hash,
                })
            });

        let block = match result {
            Ok(block) => block,
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!("Could not find snapshot {:?}\n", &self.query)),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!("Failed to load snapshot for {:?}: {:?}\n", &self.query, &e);
                warn!("{msg}");
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let preamble = HttpResponsePreamble::ok_json(&preamble);
        let result = HttpResponseContents::try_from_json(&block)?;
        Ok((preamble, result))
    }
}

impl HttpResponse for GetSortitionHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let sortition_info: SortitionInfo = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(sortition_info)?)
    }
}
