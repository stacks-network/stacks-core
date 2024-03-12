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

use clarity::vm::costs::ExecutionCost;
use stacks_common::codec::read_next;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};

use crate::burnchains::Txid;
use crate::chainstate::stacks::{StacksMicroblock, StacksTransaction};
use crate::core::mempool;
use crate::cost_estimates::FeeRateEstimate;
use crate::net::atlas::GetAttachmentResponse;
use crate::net::http::{
    Error, HttpRequest, HttpRequestContents, HttpRequestPreamble, HttpResponse,
    HttpResponseContents, HttpResponsePayload, HttpResponsePreamble,
};
use crate::net::httpcore::{StacksHttp, StacksHttpRequest, StacksHttpResponse};
use crate::net::Error as NetError;
use crate::stacks_common::codec::StacksMessageCodec;

pub mod callreadonly;
pub mod getaccount;
pub mod getattachment;
pub mod getattachmentsinv;
pub mod getblock;
pub mod getblock_v3;
pub mod getconstantval;
pub mod getcontractabi;
pub mod getcontractsrc;
pub mod getdatavar;
pub mod getheaders;
pub mod getinfo;
pub mod getistraitimplemented;
pub mod getmapentry;
pub mod getmicroblocks_confirmed;
pub mod getmicroblocks_indexed;
pub mod getmicroblocks_unconfirmed;
pub mod getneighbors;
pub mod getpoxinfo;
pub mod getstackerdbchunk;
pub mod getstackerdbmetadata;
pub mod getstackers;
pub mod getstxtransfercost;
pub mod gettenure;
pub mod gettenureinfo;
pub mod gettransaction_unconfirmed;
pub mod liststackerdbreplicas;
pub mod postblock;
pub mod postblock_proposal;
pub mod postfeerate;
pub mod postmempoolquery;
pub mod postmicroblock;
pub mod poststackerdbchunk;
pub mod posttransaction;

#[cfg(test)]
mod tests;

impl StacksHttp {
    /// Register all RPC methods.
    /// Put your new RPC method handlers here.
    pub fn register_rpc_methods(&mut self) {
        self.register_rpc_endpoint(callreadonly::RPCCallReadOnlyRequestHandler::new(
            self.maximum_call_argument_size,
            self.read_only_call_limit.clone(),
        ));
        self.register_rpc_endpoint(getaccount::RPCGetAccountRequestHandler::new());
        self.register_rpc_endpoint(getattachment::RPCGetAttachmentRequestHandler::new());
        self.register_rpc_endpoint(getattachmentsinv::RPCGetAttachmentsInvRequestHandler::new());
        self.register_rpc_endpoint(getblock::RPCBlocksRequestHandler::new());
        self.register_rpc_endpoint(getblock_v3::RPCNakamotoBlockRequestHandler::new());
        self.register_rpc_endpoint(getconstantval::RPCGetConstantValRequestHandler::new());
        self.register_rpc_endpoint(getcontractabi::RPCGetContractAbiRequestHandler::new());
        self.register_rpc_endpoint(getcontractsrc::RPCGetContractSrcRequestHandler::new());
        self.register_rpc_endpoint(getdatavar::RPCGetDataVarRequestHandler::new());
        self.register_rpc_endpoint(getheaders::RPCHeadersRequestHandler::new());
        self.register_rpc_endpoint(getinfo::RPCPeerInfoRequestHandler::new());
        self.register_rpc_endpoint(
            getistraitimplemented::RPCGetIsTraitImplementedRequestHandler::new(),
        );
        self.register_rpc_endpoint(getmapentry::RPCGetMapEntryRequestHandler::new());
        self.register_rpc_endpoint(
            getmicroblocks_confirmed::RPCMicroblocksConfirmedRequestHandler::new(),
        );
        self.register_rpc_endpoint(
            getmicroblocks_indexed::RPCMicroblocksIndexedRequestHandler::new(),
        );
        self.register_rpc_endpoint(
            getmicroblocks_unconfirmed::RPCMicroblocksUnconfirmedRequestHandler::new(),
        );
        self.register_rpc_endpoint(getneighbors::RPCNeighborsRequestHandler::new());
        self.register_rpc_endpoint(getstxtransfercost::RPCGetStxTransferCostRequestHandler::new());
        self.register_rpc_endpoint(getstackerdbchunk::RPCGetStackerDBChunkRequestHandler::new());
        self.register_rpc_endpoint(getpoxinfo::RPCPoxInfoRequestHandler::new());
        self.register_rpc_endpoint(
            getstackerdbmetadata::RPCGetStackerDBMetadataRequestHandler::new(),
        );
        self.register_rpc_endpoint(getstackers::GetStackersRequestHandler::default());
        self.register_rpc_endpoint(gettenure::RPCNakamotoTenureRequestHandler::new());
        self.register_rpc_endpoint(gettenureinfo::RPCNakamotoTenureInfoRequestHandler::new());
        self.register_rpc_endpoint(
            gettransaction_unconfirmed::RPCGetTransactionUnconfirmedRequestHandler::new(),
        );
        self.register_rpc_endpoint(
            liststackerdbreplicas::RPCListStackerDBReplicasRequestHandler::new(),
        );
        self.register_rpc_endpoint(postblock::RPCPostBlockRequestHandler::new());
        self.register_rpc_endpoint(postblock_proposal::RPCBlockProposalRequestHandler::new(
            self.block_proposal_token.clone(),
        ));
        self.register_rpc_endpoint(postfeerate::RPCPostFeeRateRequestHandler::new());
        self.register_rpc_endpoint(postmempoolquery::RPCMempoolQueryRequestHandler::new());
        self.register_rpc_endpoint(postmicroblock::RPCPostMicroblockRequestHandler::new());
        self.register_rpc_endpoint(poststackerdbchunk::RPCPostStackerDBChunkRequestHandler::new());
        self.register_rpc_endpoint(posttransaction::RPCPostTransactionRequestHandler::new());
        self.register_rpc_endpoint(getstackers::GetStackersRequestHandler::default());
    }
}

/// Helper conversion for NetError to Error
impl From<NetError> for Error {
    fn from(e: NetError) -> Error {
        match e {
            NetError::Http(e) => e,
            x => Error::AppError(format!("{x:?}")),
        }
    }
}
