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
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{to_hex, Hash160};
use stacks_common::util::HexError;
use {serde, serde_json};

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::BlockSnapshot;
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

pub static RPC_TENURE_FORKING_INFO_PATH: &str = "/v3/tenures/fork_info";

static DEPTH_LIMIT: usize = 10;

/// Struct for information about a tenure that is used to determine whether
///  or not the tenure should have been validly forked.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TenureForkingInfo {
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
    /// If the sortition occurred, and a block was mined during the tenure, this is the
    /// tenure's first block.
    #[serde(with = "prefix_opt_hex")]
    pub first_block_mined: Option<StacksBlockId>,
}

#[derive(Clone, Default)]
pub struct GetTenuresForkInfo {
    pub start_sortition: Option<ConsensusHash>,
    pub stop_sortition: Option<ConsensusHash>,
}

/// Decode the HTTP request
impl HttpRequest for GetTenuresForkInfo {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(&format!(
            r#"^{RPC_TENURE_FORKING_INFO_PATH}/(?P<start>[0-9a-f]{{40}})/(?P<stop>[0-9a-f]{{40}})$"#
        ))
        .unwrap()
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

        let start_str = captures
            .name("start")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to start_sortition group".to_string())
            })?
            .as_str();
        let stop_str = captures
            .name("stop")
            .ok_or_else(|| {
                Error::DecodeError("Failed to match path to stop_sortition group".to_string())
            })?
            .as_str();
        let start_sortition = ConsensusHash::from_hex(start_str).map_err(|_| {
            Error::DecodeError("Invalid path: unparseable consensus hash".to_string())
        })?;
        let stop_sortition = ConsensusHash::from_hex(stop_str).map_err(|_| {
            Error::DecodeError("Invalid path: unparseable consensus hash".to_string())
        })?;
        self.start_sortition = Some(start_sortition);
        self.stop_sortition = Some(stop_sortition);

        Ok(req_contents)
    }

    fn metrics_identifier(&self) -> &str {
        RPC_TENURE_FORKING_INFO_PATH
    }
}

impl TenureForkingInfo {
    fn from_snapshot(
        sn: &BlockSnapshot,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        tip_block_id: &StacksBlockId,
    ) -> Result<Self, ChainError> {
        let first_block_mined = if !sn.sortition {
            None
        } else {
            // is this a nakamoto sortition?
            let epoch = SortitionDB::get_stacks_epoch(sortdb.conn(), sn.block_height)?.ok_or_else(
                || {
                    warn!(
                        "Failed to lookup stacks epoch for processed snapshot height {}",
                        sn.block_height
                    );
                    ChainError::InvalidChainstateDB
                },
            )?;
            if epoch.epoch_id < StacksEpochId::Epoch30 {
                StacksChainState::get_stacks_block_header_info_by_consensus_hash(
                    chainstate.db(),
                    &sn.consensus_hash,
                )?
                .map(|header| header.index_block_hash())
            } else {
                NakamotoChainState::get_nakamoto_tenure_start_block_header(
                    &mut chainstate.index_conn(),
                    tip_block_id,
                    &sn.consensus_hash,
                )?
                .map(|header| header.index_block_hash())
            }
        };
        Ok(TenureForkingInfo {
            burn_block_hash: sn.burn_header_hash.clone(),
            burn_block_height: sn.block_height,
            sortition_id: sn.sortition_id.clone(),
            parent_sortition_id: sn.parent_sortition_id.clone(),
            consensus_hash: sn.consensus_hash.clone(),
            was_sortition: sn.sortition,
            first_block_mined,
        })
    }
}

impl RPCRequestHandler for GetTenuresForkInfo {
    /// Reset internal state
    fn restart(&mut self) {
        self.start_sortition = None;
        self.stop_sortition = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let result = node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
            let start_from = self
                .stop_sortition
                .clone()
                .ok_or_else(|| ChainError::NoSuchBlockError)?;
            let recurse_end = self
                .start_sortition
                .clone()
                .ok_or_else(|| ChainError::NoSuchBlockError)?;
            let recurse_end_snapshot =
                SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &recurse_end)?
                    .ok_or_else(|| ChainError::NoSuchBlockError)?;
            let height_bound = recurse_end_snapshot.block_height;

            let mut results = vec![];
            let mut cursor = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &start_from)?
                .ok_or_else(|| ChainError::NoSuchBlockError)?;
            results.push(TenureForkingInfo::from_snapshot(
                &cursor,
                sortdb,
                chainstate,
                &network.stacks_tip.block_id(),
            )?);
            let mut depth = 0;
            while depth < DEPTH_LIMIT && cursor.consensus_hash != recurse_end {
                if height_bound >= cursor.block_height {
                    return Err(ChainError::NotInSameFork);
                }
                cursor =
                    SortitionDB::get_block_snapshot(sortdb.conn(), &cursor.parent_sortition_id)?
                        .ok_or_else(|| ChainError::NoSuchBlockError)?;
                if cursor.sortition
                    || chainstate
                        .nakamoto_blocks_db()
                        .is_shadow_tenure(&cursor.consensus_hash)?
                {
                    results.push(TenureForkingInfo::from_snapshot(
                        &cursor,
                        sortdb,
                        chainstate,
                        &network.stacks_tip.block_id(),
                    )?);
                }
                if cursor.sortition {
                    // don't count shadow blocks towards the depth, since there can be a large
                    // swath of them.
                    depth += 1;
                }
            }

            Ok(results)
        });

        let tenures = match result {
            Ok(tenures) => tenures,
            Err(ChainError::NotInSameFork) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpBadRequest::new_json(serde_json::json!(
                        "Supplied start and end sortitions are not in the same sortition fork"
                    )),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
            Err(ChainError::NoSuchBlockError) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new(format!(
                        "Could not find snapshot {:?}\n",
                        &self.stop_sortition
                    )),
                )
                .try_into_contents()
                .map_err(NetError::from)
            }
            Err(e) => {
                // nope -- error trying to check
                let msg = format!(
                    "Failed to load snapshots for range ({:?}, {:?}]: {:?}\n",
                    &self.start_sortition, &self.stop_sortition, &e
                );
                warn!("{msg}");
                return StacksHttpResponse::new_error(&preamble, &HttpServerError::new(msg))
                    .try_into_contents()
                    .map_err(NetError::from);
            }
        };

        let resp_preamble = HttpResponsePreamble::from_http_request_preamble(
            &preamble,
            200,
            "OK",
            None,
            HttpContentType::JSON,
        );

        Ok((
            resp_preamble,
            HttpResponseContents::try_from_json(&tenures)?,
        ))
    }
}

impl HttpResponse for GetTenuresForkInfo {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let tenures_info: Vec<TenureForkingInfo> = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(tenures_info)?)
    }
}
