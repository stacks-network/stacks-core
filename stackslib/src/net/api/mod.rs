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
use crate::net::http::Error;
use crate::net::httpcore::RPCRoutesBuilder;
use crate::net::Error as NetError;

pub mod blockreplay;
pub mod blocksimulate;
pub mod callreadonly;
pub mod fastcallreadonly;
pub mod get_tenure_tip_meta;
pub mod get_tenures_fork_info;
pub mod getaccount;
pub mod getattachment;
pub mod getattachmentsinv;
pub mod getblock;
pub mod getblock_v3;
pub mod getblockbyheight;
pub mod getclaritymarfvalue;
pub mod getclaritymetadata;
pub mod getconstantval;
pub mod getcontractabi;
pub mod getcontractsrc;
pub mod getdatavar;
pub mod getheaders;
pub mod gethealth;
pub mod getinfo;
pub mod getistraitimplemented;
pub mod getmapentry;
pub mod getmicroblocks_confirmed;
pub mod getmicroblocks_indexed;
pub mod getmicroblocks_unconfirmed;
pub mod getneighbors;
pub mod getpoxinfo;
pub mod getsigner;
pub mod getsortition;
pub mod getstackerdbchunk;
pub mod getstackerdbmetadata;
pub mod getstackers;
pub mod getstxtransfercost;
pub mod gettenure;
pub mod gettenureblocks;
pub mod gettenureblocksbyhash;
pub mod gettenureblocksbyheight;
pub mod gettenureinfo;
pub mod gettenuretip;
pub mod gettransaction;
pub mod gettransaction_unconfirmed;
pub mod liststackerdbreplicas;
pub mod postblock;
pub mod postblock_proposal;
#[warn(unused_imports)]
pub mod postblock_v3;
pub mod postfeerate;
pub mod postmempoolquery;
pub mod postmicroblock;
pub mod poststackerdbchunk;
pub mod posttransaction;
mod read_only;
pub mod txsimulate;

#[cfg(test)]
mod tests;

impl RPCRoutesBuilder {
    /// Register all RPC methods.
    /// Put your new RPC method handlers here.
    pub(crate) fn register_rpc_methods(&mut self) {
        self.register_rpc_endpoint(|http| {
            blockreplay::RPCNakamotoBlockReplayRequestHandler::new(http.auth_token.clone())
        });
        self.register_rpc_endpoint(|http| {
            blocksimulate::RPCNakamotoBlockSimulateRequestHandler::new(http.auth_token.clone())
        });
        self.register_rpc_endpoint(|http| {
            txsimulate::RPCTransactionSimulateRequestHandler::new(http.auth_token.clone())
        });
        self.register_rpc_endpoint(|http| {
            callreadonly::RPCCallReadOnlyRequestHandler::new(
                http.maximum_call_argument_size,
                http.read_only_call_limit.clone(),
                http.read_only_max_execution_time,
                http.read_only_call_max_mem_bytes,
            )
        });
        self.register_rpc_endpoint(|http| {
            fastcallreadonly::RPCFastCallReadOnlyRequestHandler::new(
                http.maximum_call_argument_size,
                http.read_only_max_execution_time,
                http.read_only_call_max_mem_bytes,
                http.auth_token.clone(),
            )
        });
        self.register_rpc_endpoint(|_| getaccount::RPCGetAccountRequestHandler::new());
        self.register_rpc_endpoint(|_| getattachment::RPCGetAttachmentRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            getattachmentsinv::RPCGetAttachmentsInvRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| getblock::RPCBlocksRequestHandler::new());
        self.register_rpc_endpoint(|_| getblock_v3::RPCNakamotoBlockRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            getblockbyheight::RPCNakamotoBlockByHeightRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| getclaritymarfvalue::RPCGetClarityMarfRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            getclaritymetadata::RPCGetClarityMetadataRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| getconstantval::RPCGetConstantValRequestHandler::new());
        self.register_rpc_endpoint(|_| getcontractabi::RPCGetContractAbiRequestHandler::new());
        self.register_rpc_endpoint(|_| getcontractsrc::RPCGetContractSrcRequestHandler::new());
        self.register_rpc_endpoint(|_| getdatavar::RPCGetDataVarRequestHandler::new());
        self.register_rpc_endpoint(|_| getheaders::RPCHeadersRequestHandler::new());
        self.register_rpc_endpoint(|_| getinfo::RPCPeerInfoRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            getistraitimplemented::RPCGetIsTraitImplementedRequestHandler::new()
        });
        self.register_rpc_endpoint(|http| {
            getmapentry::RPCGetMapEntryRequestHandler::new(http.read_only_call_max_mem_bytes)
        });
        self.register_rpc_endpoint(|_| {
            getmicroblocks_confirmed::RPCMicroblocksConfirmedRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| {
            getmicroblocks_indexed::RPCMicroblocksIndexedRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| {
            getmicroblocks_unconfirmed::RPCMicroblocksUnconfirmedRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| getneighbors::RPCNeighborsRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            getstxtransfercost::RPCGetStxTransferCostRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| {
            getstackerdbchunk::RPCGetStackerDBChunkRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| getpoxinfo::RPCPoxInfoRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            getstackerdbmetadata::RPCGetStackerDBMetadataRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| getstackers::GetStackersRequestHandler::default());
        self.register_rpc_endpoint(|_| getsortition::GetSortitionHandler::new());
        self.register_rpc_endpoint(|_| gettenure::RPCNakamotoTenureRequestHandler::new());
        self.register_rpc_endpoint(|_| gettenureinfo::RPCNakamotoTenureInfoRequestHandler::new());
        self.register_rpc_endpoint(|_| gettenuretip::RPCNakamotoTenureTipRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            get_tenure_tip_meta::NakamotoTenureTipMetadataRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| {
            gettenureblocks::RPCNakamotoTenureBlocksRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| {
            gettenureblocksbyhash::RPCNakamotoTenureBlocksByHashRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| {
            gettenureblocksbyheight::RPCNakamotoTenureBlocksByHeightRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| get_tenures_fork_info::GetTenuresForkInfo::default());
        self.register_rpc_endpoint(|_| {
            gettransaction_unconfirmed::RPCGetTransactionUnconfirmedRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| gettransaction::RPCGetTransactionRequestHandler::new());
        self.register_rpc_endpoint(|_| getsigner::GetSignerRequestHandler::default());
        self.register_rpc_endpoint(|_| gethealth::RPCGetHealthRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            liststackerdbreplicas::RPCListStackerDBReplicasRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| postblock::RPCPostBlockRequestHandler::new());
        self.register_rpc_endpoint(|http| {
            postblock_proposal::RPCBlockProposalRequestHandler::new(http.auth_token.clone())
        });
        self.register_rpc_endpoint(|http| {
            postblock_v3::RPCPostBlockRequestHandler::new(http.auth_token.clone())
        });
        self.register_rpc_endpoint(|_| postfeerate::RPCPostFeeRateRequestHandler::new());
        self.register_rpc_endpoint(|_| postmempoolquery::RPCMempoolQueryRequestHandler::new());
        self.register_rpc_endpoint(|_| postmicroblock::RPCPostMicroblockRequestHandler::new());
        self.register_rpc_endpoint(|_| {
            poststackerdbchunk::RPCPostStackerDBChunkRequestHandler::new()
        });
        self.register_rpc_endpoint(|_| posttransaction::RPCPostTransactionRequestHandler::new());
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
