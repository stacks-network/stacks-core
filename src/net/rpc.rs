/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::io;
use std::io::prelude::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::time::Instant;
use std::{convert::TryFrom, fmt};

use rand::prelude::*;
use rand::thread_rng;
use rusqlite::{DatabaseName, NO_PARAMS};

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Burnchain;
use crate::burnchains::BurnchainView;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::BurnchainOpsVec;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::burn::Opcodes;
use crate::chainstate::stacks::db::blocks::CheckError;
use crate::chainstate::stacks::db::{
    blocks::MINIMUM_TX_FEE_RATE_PER_BYTE, StacksChainState, StreamCursor,
};
use crate::chainstate::stacks::Error as chain_error;
use crate::chainstate::stacks::*;
use crate::clarity_vm::clarity::ClarityConnection;
use crate::codec::StacksMessageCodec;
use crate::core::mempool::*;
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::CostEstimator;
use crate::cost_estimates::FeeEstimator;
use crate::monitoring;
use crate::net::atlas::{AtlasDB, Attachment, MAX_ATTACHMENT_INV_PAGES_PER_REQUEST};
use crate::net::connection::ConnectionHttp;
use crate::net::connection::ConnectionOptions;
use crate::net::connection::ReplyHandleHttp;
use crate::net::db::PeerDB;
use crate::net::http::*;
use crate::net::p2p::PeerMap;
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::BlocksDatum;
use crate::net::Error as net_error;
use crate::net::HttpRequestMetadata;
use crate::net::HttpRequestType;
use crate::net::HttpResponseMetadata;
use crate::net::HttpResponseType;
use crate::net::MemPoolSyncData;
use crate::net::MicroblocksData;
use crate::net::NeighborAddress;
use crate::net::NeighborsData;
use crate::net::PeerAddress;
use crate::net::PeerHost;
use crate::net::ProtocolFamily;
use crate::net::RPCFeeEstimate;
use crate::net::RPCFeeEstimateResponse;
use crate::net::StacksHttp;
use crate::net::StacksHttpMessage;
use crate::net::StacksMessageType;
use crate::net::UnconfirmedTransactionResponse;
use crate::net::UnconfirmedTransactionStatus;
use crate::net::UrlString;
use crate::net::HTTP_REQUEST_ID_RESERVED;
use crate::net::MAX_HEADERS;
use crate::net::MAX_NEIGHBORS_DATA_LEN;
use crate::net::{
    AccountEntryResponse, AttachmentPage, CallReadOnlyResponse, ContractSrcResponse,
    DataVarResponse, GetAttachmentResponse, GetAttachmentsInvResponse, MapEntryResponse,
};
use crate::net::{BlocksData, GetIsTraitImplementedResponse};
use crate::net::{ClientError, TipRequest};
use crate::net::{
    RPCAffirmationData, RPCLastPoxAnchorData, RPCPeerInfoData, RPCPoxContractVersion,
    RPCPoxInfoData,
};
use crate::net::{RPCNeighbor, RPCNeighborsInfo};
use crate::util_lib::db::DBConn;
use crate::util_lib::db::Error as db_error;
use clarity::vm::database::clarity_store::make_contract_hash_key;
use clarity::vm::types::TraitIdentifier;
use clarity::vm::ClarityVersion;
use clarity::vm::{
    analysis::errors::CheckErrors,
    ast::ASTRules,
    costs::{ExecutionCost, LimitedCostTracker},
    database::{
        clarity_store::ContractCommitment, BurnStateDB, ClarityDatabase, ClaritySerializable,
        STXBalance, StoreType,
    },
    errors::Error as ClarityRuntimeError,
    errors::Error::Unchecked,
    errors::InterpreterError,
    types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData},
    ClarityName, ContractName, SymbolicExpression, Value,
};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::chainstate::stacks::boot::{POX_1_NAME, POX_2_NAME, POX_3_NAME};
use crate::chainstate::stacks::StacksBlockHeader;
use crate::clarity_vm::database::marf::MarfedKV;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress, StacksBlockId};
use stacks_common::types::StacksPublicKeyBuffer;

use crate::clarity_vm::clarity::Error as clarity_error;

use crate::{
    chainstate::burn::operations::leader_block_commit::OUTPUTS_PER_COMMIT, types, util,
    util::hash::Sha256Sum, version_string,
};

use crate::util_lib::boot::boot_code_id;

use super::{RPCPoxCurrentCycleInfo, RPCPoxNextCycleInfo};

pub const STREAM_CHUNK_SIZE: u64 = 4096;

#[derive(Default)]
pub struct RPCHandlerArgs<'a> {
    pub exit_at_block_height: Option<u64>,
    pub genesis_chainstate_hash: Sha256Sum,
    pub event_observer: Option<&'a dyn MemPoolEventDispatcher>,
    pub cost_estimator: Option<&'a dyn CostEstimator>,
    pub fee_estimator: Option<&'a dyn FeeEstimator>,
    pub cost_metric: Option<&'a dyn CostMetric>,
}

pub struct ConversationHttp {
    connection: ConnectionHttp,
    conn_id: usize,
    timeout: u64,
    peer_host: PeerHost,
    outbound_url: Option<UrlString>,
    peer_addr: SocketAddr,
    keep_alive: bool,
    total_request_count: u64,     // number of messages taken from the inbox
    total_reply_count: u64,       // number of messages responsed to
    last_request_timestamp: u64, // absolute timestamp of the last time we received at least 1 byte in a request
    last_response_timestamp: u64, // absolute timestamp of the last time we sent at least 1 byte in a response
    connection_time: u64,         // when this converation was instantiated

    canonical_stacks_tip_height: Option<u64>, // chain tip height of the peer's Stacks blockchain

    // ongoing block streams
    reply_streams: VecDeque<(
        ReplyHandleHttp,
        Option<(HttpChunkedTransferWriterState, StreamCursor)>,
        bool,
    )>,

    // our outstanding request/response to the remote peer, if any
    pending_request: Option<ReplyHandleHttp>,
    pending_response: Option<HttpResponseType>,
    pending_error_response: Option<HttpResponseType>,
}

impl fmt::Display for ConversationHttp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "http:id={},request={:?},peer={:?}",
            self.conn_id,
            self.pending_request.is_some(),
            &self.peer_addr
        )
    }
}

impl fmt::Debug for ConversationHttp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "http:id={},request={:?},peer={:?}",
            self.conn_id,
            self.pending_request.is_some(),
            &self.peer_addr
        )
    }
}

impl<'a> RPCHandlerArgs<'a> {
    pub fn get_estimators_ref(
        &self,
    ) -> Option<(&dyn CostEstimator, &dyn FeeEstimator, &dyn CostMetric)> {
        match (self.cost_estimator, self.fee_estimator, self.cost_metric) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }
}

impl RPCPeerInfoData {
    pub fn from_network(
        network: &PeerNetwork,
        chainstate: &StacksChainState,
        exit_at_block_height: Option<u64>,
        genesis_chainstate_hash: &Sha256Sum,
    ) -> RPCPeerInfoData {
        let server_version = version_string(
            "stacks-node",
            option_env!("STACKS_NODE_VERSION")
                .or(option_env!("CARGO_PKG_VERSION"))
                .unwrap_or("0.0.0.0"),
        );
        let (unconfirmed_tip, unconfirmed_seq) = match chainstate.unconfirmed_state {
            Some(ref unconfirmed) => {
                if unconfirmed.num_mined_txs() > 0 {
                    (
                        Some(unconfirmed.unconfirmed_chain_tip.clone()),
                        Some(unconfirmed.last_mblock_seq),
                    )
                } else {
                    (None, None)
                }
            }
            None => (None, None),
        };

        let public_key = StacksPublicKey::from_private(&network.local_peer.private_key);
        let public_key_buf = StacksPublicKeyBuffer::from_public_key(&public_key);
        let public_key_hash = Hash160::from_node_public_key(&public_key);

        RPCPeerInfoData {
            peer_version: network.burnchain.peer_version,
            pox_consensus: network.burnchain_tip.consensus_hash.clone(),
            burn_block_height: network.chain_view.burn_block_height,
            stable_pox_consensus: network.chain_view_stable_consensus_hash.clone(),
            stable_burn_block_height: network.chain_view.burn_stable_block_height,
            server_version,
            network_id: network.local_peer.network_id,
            parent_network_id: network.local_peer.parent_network_id,
            stacks_tip_height: network.burnchain_tip.canonical_stacks_tip_height,
            stacks_tip: network.burnchain_tip.canonical_stacks_tip_hash.clone(),
            stacks_tip_consensus_hash: network
                .burnchain_tip
                .canonical_stacks_tip_consensus_hash
                .clone(),
            unanchored_tip: unconfirmed_tip,
            unanchored_seq: unconfirmed_seq,
            exit_at_block_height: exit_at_block_height,
            genesis_chainstate_hash: genesis_chainstate_hash.clone(),
            node_public_key: Some(public_key_buf),
            node_public_key_hash: Some(public_key_hash),
            affirmations: Some(RPCAffirmationData {
                heaviest: network.heaviest_affirmation_map.clone(),
                stacks_tip: network.stacks_tip_affirmation_map.clone(),
                sortition_tip: network.sortition_tip_affirmation_map.clone(),
                tentative_best: network.tentative_best_affirmation_map.clone(),
            }),
            last_pox_anchor: Some(RPCLastPoxAnchorData {
                anchor_block_hash: network.last_anchor_block_hash.clone(),
                anchor_block_txid: network.last_anchor_block_txid.clone(),
            }),
        }
    }
}

impl RPCPoxInfoData {
    pub fn from_db(
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        burnchain: &Burnchain,
    ) -> Result<RPCPoxInfoData, net_error> {
        let mainnet = chainstate.mainnet;
        let chain_id = chainstate.chain_id;
        let current_burn_height =
            SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?.block_height;

        let pox_contract_name = burnchain
            .pox_constants
            .active_pox_contract(current_burn_height);

        let contract_identifier = boot_code_id(pox_contract_name, mainnet);
        let function = "get-pox-info";
        let cost_track = LimitedCostTracker::new_free();
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());

        debug!(
            "Active PoX contract is '{}' (current_burn_height = {}, v1_unlock_height = {}",
            &contract_identifier, current_burn_height, burnchain.pox_constants.v1_unlock_height
        );

        // Note: should always be 0 unless somehow configured to start later
        let pox_1_first_cycle = burnchain
            .block_height_to_reward_cycle(burnchain.first_block_height as u64)
            .ok_or(net_error::ChainstateError(
                "PoX-1 first reward cycle begins before first burn block height".to_string(),
            ))?;

        let pox_2_first_cycle = burnchain
            .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
            .ok_or(net_error::ChainstateError(
                "PoX-2 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let pox_3_first_cycle = burnchain
            .block_height_to_reward_cycle(burnchain.pox_constants.pox_3_activation_height as u64)
            .ok_or(net_error::ChainstateError(
                "PoX-3 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let data = chainstate
            .maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_readonly_clarity_env(
                    mainnet,
                    chain_id,
                    ClarityVersion::Clarity2,
                    sender,
                    None,
                    cost_track,
                    |env| env.execute_contract(&contract_identifier, function, &vec![], true),
                )
            })
            .map_err(|_| net_error::NotFoundError)?;

        let res = match data {
            Some(Ok(res)) => res.expect_result_ok().expect_tuple(),
            _ => return Err(net_error::DBError(db_error::NotFoundError)),
        };

        let first_burnchain_block_height = res
            .get("first-burnchain-block-height")
            .expect(&format!("FATAL: no 'first-burnchain-block-height'"))
            .to_owned()
            .expect_u128() as u64;

        let min_stacking_increment_ustx = res
            .get("min-amount-ustx")
            .expect(&format!("FATAL: no 'min-amount-ustx'"))
            .to_owned()
            .expect_u128() as u64;

        let prepare_cycle_length = res
            .get("prepare-cycle-length")
            .expect(&format!("FATAL: no 'prepare-cycle-length'"))
            .to_owned()
            .expect_u128() as u64;

        let rejection_fraction = res
            .get("rejection-fraction")
            .expect(&format!("FATAL: no 'rejection-fraction'"))
            .to_owned()
            .expect_u128() as u64;

        let reward_cycle_id = res
            .get("reward-cycle-id")
            .expect(&format!("FATAL: no 'reward-cycle-id'"))
            .to_owned()
            .expect_u128() as u64;

        let reward_cycle_length = res
            .get("reward-cycle-length")
            .expect(&format!("FATAL: no 'reward-cycle-length'"))
            .to_owned()
            .expect_u128() as u64;

        let current_rejection_votes = res
            .get("current-rejection-votes")
            .expect(&format!("FATAL: no 'current-rejection-votes'"))
            .to_owned()
            .expect_u128() as u64;

        let total_liquid_supply_ustx = res
            .get("total-liquid-supply-ustx")
            .expect(&format!("FATAL: no 'total-liquid-supply-ustx'"))
            .to_owned()
            .expect_u128() as u64;

        let total_required = (total_liquid_supply_ustx as u128 / 100)
            .checked_mul(rejection_fraction as u128)
            .ok_or_else(|| net_error::DBError(db_error::Overflow))?
            as u64;

        let rejection_votes_left_required = total_required.saturating_sub(current_rejection_votes);

        let burnchain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;

        let pox_consts = &burnchain.pox_constants;

        if prepare_cycle_length != pox_consts.prepare_length as u64 {
            error!(
                "PoX Constants in config mismatched with PoX contract constants: {} != {}",
                prepare_cycle_length, pox_consts.prepare_length
            );
            return Err(net_error::DBError(db_error::Corruption));
        }

        if reward_cycle_length != pox_consts.reward_cycle_length as u64 {
            error!(
                "PoX Constants in config mismatched with PoX contract constants: {} != {}",
                reward_cycle_length, pox_consts.reward_cycle_length
            );
            return Err(net_error::DBError(db_error::Corruption));
        }

        let effective_height = burnchain_tip.block_height - first_burnchain_block_height;
        let next_reward_cycle_in = reward_cycle_length - (effective_height % reward_cycle_length);

        let next_rewards_start = burnchain_tip.block_height + next_reward_cycle_in;
        let next_prepare_phase_start = next_rewards_start - prepare_cycle_length;

        let next_prepare_phase_in = i64::try_from(next_prepare_phase_start)
            .map_err(|_| net_error::ChainstateError("Burn block height overflowed i64".into()))?
            - i64::try_from(burnchain_tip.block_height).map_err(|_| {
                net_error::ChainstateError("Burn block height overflowed i64".into())
            })?;

        let cur_block_pox_contract = pox_consts.active_pox_contract(burnchain_tip.block_height);
        let cur_cycle_pox_contract =
            pox_consts.active_pox_contract(burnchain.reward_cycle_to_block_height(reward_cycle_id));
        let next_cycle_pox_contract = pox_consts
            .active_pox_contract(burnchain.reward_cycle_to_block_height(reward_cycle_id + 1));

        let cur_cycle_stacked_ustx = chainstate.get_total_ustx_stacked(
            &sortdb,
            tip,
            reward_cycle_id as u128,
            cur_cycle_pox_contract,
        )?;
        let next_cycle_stacked_ustx =
            // next_cycle_pox_contract might not be instantiated yet
            match chainstate.get_total_ustx_stacked(
                &sortdb,
                tip,
                reward_cycle_id as u128 + 1,
                next_cycle_pox_contract,
            ) {
                Ok(ustx) => ustx,
                Err(chain_error::ClarityError(_)) => {
                    // contract not instantiated yet
                    0
                }
                Err(e) => {
                    return Err(e.into());
                }
            };

        let reward_slots = pox_consts.reward_slots() as u64;

        let cur_cycle_threshold = StacksChainState::get_threshold_from_participation(
            total_liquid_supply_ustx as u128,
            cur_cycle_stacked_ustx,
            reward_slots as u128,
        ) as u64;

        let next_threshold = StacksChainState::get_threshold_from_participation(
            total_liquid_supply_ustx as u128,
            next_cycle_stacked_ustx,
            reward_slots as u128,
        ) as u64;

        let pox_activation_threshold_ustx = (total_liquid_supply_ustx as u128)
            .checked_mul(pox_consts.pox_participation_threshold_pct as u128)
            .map(|x| x / 100)
            .ok_or_else(|| net_error::DBError(db_error::Overflow))?
            as u64;

        let cur_cycle_pox_active = sortdb.is_pox_active(burnchain, &burnchain_tip)?;

        Ok(RPCPoxInfoData {
            contract_id: boot_code_id(cur_block_pox_contract, chainstate.mainnet).to_string(),
            pox_activation_threshold_ustx,
            first_burnchain_block_height,
            current_burnchain_block_height: burnchain_tip.block_height,
            prepare_phase_block_length: prepare_cycle_length,
            reward_phase_block_length: reward_cycle_length - prepare_cycle_length,
            reward_slots,
            rejection_fraction,
            total_liquid_supply_ustx,
            current_cycle: RPCPoxCurrentCycleInfo {
                id: reward_cycle_id,
                min_threshold_ustx: cur_cycle_threshold,
                stacked_ustx: cur_cycle_stacked_ustx as u64,
                is_pox_active: cur_cycle_pox_active,
            },
            next_cycle: RPCPoxNextCycleInfo {
                id: reward_cycle_id + 1,
                min_threshold_ustx: next_threshold,
                min_increment_ustx: min_stacking_increment_ustx,
                stacked_ustx: next_cycle_stacked_ustx as u64,
                prepare_phase_start_block_height: next_prepare_phase_start,
                blocks_until_prepare_phase: next_prepare_phase_in,
                reward_phase_start_block_height: next_rewards_start,
                blocks_until_reward_phase: next_reward_cycle_in,
                ustx_until_pox_rejection: rejection_votes_left_required,
            },
            min_amount_ustx: next_threshold,
            prepare_cycle_length,
            reward_cycle_id,
            reward_cycle_length,
            rejection_votes_left_required,
            next_reward_cycle_in,
            contract_versions: vec![
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_1_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain.first_block_height,
                    first_reward_cycle_id: pox_1_first_cycle,
                },
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_2_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain.pox_constants.v1_unlock_height
                        as u64,
                    first_reward_cycle_id: pox_2_first_cycle,
                },
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_3_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain
                        .pox_constants
                        .pox_3_activation_height
                        as u64,
                    first_reward_cycle_id: pox_3_first_cycle,
                },
            ],
        })
    }
}

impl RPCNeighborsInfo {
    /// Load neighbor address information from the peer network
    pub fn from_p2p(
        network_id: u32,
        network_epoch: u8,
        peers: &PeerMap,
        chain_view: &BurnchainView,
        peerdb: &PeerDB,
    ) -> Result<RPCNeighborsInfo, net_error> {
        let bootstrap_nodes =
            PeerDB::get_bootstrap_peers(peerdb.conn(), network_id).map_err(net_error::DBError)?;
        let bootstrap = bootstrap_nodes
            .into_iter()
            .map(|n| {
                RPCNeighbor::from_neighbor_key_and_pubkh(
                    n.addr.clone(),
                    Hash160::from_node_public_key(&n.public_key),
                    true,
                )
            })
            .collect();

        let neighbor_sample = PeerDB::get_random_neighbors(
            peerdb.conn(),
            network_id,
            network_epoch,
            MAX_NEIGHBORS_DATA_LEN,
            chain_view.burn_block_height,
            false,
        )
        .map_err(net_error::DBError)?;

        let sample: Vec<RPCNeighbor> = neighbor_sample
            .into_iter()
            .map(|n| {
                RPCNeighbor::from_neighbor_key_and_pubkh(
                    n.addr.clone(),
                    Hash160::from_node_public_key(&n.public_key),
                    true,
                )
            })
            .collect();

        let mut inbound = vec![];
        let mut outbound = vec![];
        for (_, convo) in peers.iter() {
            let nk = convo.to_neighbor_key();
            let naddr = convo.to_neighbor_address();
            if convo.is_outbound() {
                outbound.push(RPCNeighbor::from_neighbor_key_and_pubkh(
                    nk,
                    naddr.public_key_hash,
                    convo.is_authenticated(),
                ));
            } else {
                inbound.push(RPCNeighbor::from_neighbor_key_and_pubkh(
                    nk,
                    naddr.public_key_hash,
                    convo.is_authenticated(),
                ));
            }
        }

        Ok(RPCNeighborsInfo {
            bootstrap,
            sample,
            inbound,
            outbound,
        })
    }
}

impl ConversationHttp {
    pub fn new(
        peer_addr: SocketAddr,
        outbound_url: Option<UrlString>,
        peer_host: PeerHost,
        conn_opts: &ConnectionOptions,
        conn_id: usize,
    ) -> ConversationHttp {
        let mut stacks_http = StacksHttp::new(peer_addr.clone());
        stacks_http.maximum_call_argument_size = conn_opts.maximum_call_argument_size;
        ConversationHttp {
            connection: ConnectionHttp::new(stacks_http, conn_opts, None),
            conn_id: conn_id,
            timeout: conn_opts.timeout,
            reply_streams: VecDeque::new(),
            peer_addr: peer_addr,
            outbound_url: outbound_url,
            peer_host: peer_host,
            canonical_stacks_tip_height: None,
            pending_request: None,
            pending_response: None,
            pending_error_response: None,
            keep_alive: true,
            total_request_count: 0,
            total_reply_count: 0,
            last_request_timestamp: 0,
            last_response_timestamp: 0,
            connection_time: get_epoch_time_secs(),
        }
    }

    /// How many ongoing requests do we have on this conversation?
    pub fn num_pending_outbound(&self) -> usize {
        self.reply_streams.len()
    }

    /// What's our outbound URL?
    pub fn get_url(&self) -> Option<&UrlString> {
        self.outbound_url.as_ref()
    }

    /// What's our peer IP address?
    pub fn get_peer_addr(&self) -> &SocketAddr {
        &self.peer_addr
    }

    /// Is a request in-progress?
    pub fn is_request_inflight(&self) -> bool {
        self.pending_request.is_some()
    }

    /// Start a HTTP request from this peer, and expect a response.
    /// Returns the request handle; does not set the handle into this connection.
    fn start_request(&mut self, req: HttpRequestType) -> Result<ReplyHandleHttp, net_error> {
        test_debug!(
            "{:?},id={}: Start HTTP request {:?}",
            &self.peer_host,
            self.conn_id,
            &req
        );
        let mut handle = self.connection.make_request_handle(
            HTTP_REQUEST_ID_RESERVED,
            get_epoch_time_secs() + self.timeout,
            self.conn_id,
        )?;
        let stacks_msg = StacksHttpMessage::Request(req);
        self.connection.send_message(&mut handle, &stacks_msg)?;
        Ok(handle)
    }

    /// Start a HTTP request from this peer, and expect a response.
    /// Non-blocking.
    /// Only one request in-flight is allowed.
    pub fn send_request(&mut self, req: HttpRequestType) -> Result<(), net_error> {
        if self.is_request_inflight() {
            test_debug!(
                "{:?},id={}: Request in progress still",
                &self.peer_host,
                self.conn_id
            );
            return Err(net_error::InProgress);
        }
        if self.pending_error_response.is_some() {
            test_debug!(
                "{:?},id={}: Error response is inflight",
                &self.peer_host,
                self.conn_id
            );
            return Err(net_error::InProgress);
        }

        let handle = self.start_request(req)?;

        self.pending_request = Some(handle);
        self.pending_response = None;
        Ok(())
    }

    /// Send a HTTP error response.
    /// Discontinues and disables sending a non-error response
    pub fn reply_error<W: Write>(
        &mut self,
        fd: &mut W,
        res: HttpResponseType,
    ) -> Result<(), net_error> {
        if self.is_request_inflight() || self.pending_response.is_some() {
            test_debug!(
                "{:?},id={}: Request or response is already in progress",
                &self.peer_host,
                self.conn_id
            );
            return Err(net_error::InProgress);
        }
        if self.pending_error_response.is_some() {
            // error already in-flight
            return Ok(());
        }

        res.send(&mut self.connection.protocol, fd)?;

        let reply = self.connection.make_relay_handle(self.conn_id)?;

        self.pending_error_response = Some(res);
        self.reply_streams.push_back((reply, None, false));
        Ok(())
    }

    /// Handle a GET peer info.
    /// The response will be synchronously written to the given fd (so use a fd that can buffer!)
    fn handle_getinfo<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        network: &PeerNetwork,
        chainstate: &StacksChainState,
        handler_args: &RPCHandlerArgs,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let pi = RPCPeerInfoData::from_network(
            network,
            chainstate,
            handler_args.exit_at_block_height.clone(),
            &handler_args.genesis_chainstate_hash,
        );
        let response = HttpResponseType::PeerInfo(response_metadata, pi);
        response.send(http, fd)
    }

    fn response_get_burn_ops(
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        burn_block_height: u64,
        op_type: &Opcodes,
    ) -> Result<HttpResponseType, net_error> {
        let response_metadata = HttpResponseMetadata::from_http_request_type(req, None);
        let handle = sortdb.index_handle_at_tip();
        let burn_header_hash = match handle.get_block_snapshot_by_height(burn_block_height) {
            Ok(Some(snapshot)) => snapshot.burn_header_hash,
            _ => {
                return Ok(HttpResponseType::NotFound(
                    response_metadata,
                    format!("Could not find burn block at height {}", burn_block_height),
                ));
            }
        };

        let response = match op_type {
            Opcodes::PegIn => {
                SortitionDB::get_peg_in_ops(sortdb.conn(), &burn_header_hash).map(|ops| {
                    HttpResponseType::GetBurnchainOps(
                        response_metadata.clone(),
                        BurnchainOpsVec::PegIn(ops),
                    )
                })
            }
            _ => {
                return Ok(HttpResponseType::NotFound(
                    response_metadata,
                    format!(
                        "Burnchain operation {:?} is not supported by this endpoint",
                        op_type
                    ),
                ));
            }
        };

        response.or_else(|e| {
            Ok(HttpResponseType::NotFound(
                response_metadata,
                format!(
                    "Failure fetching {:?} operations from the sortition db: {}",
                    op_type, e
                ),
            ))
        })
    }

    /// Handle a GET for the burnchain operations at a particular
    /// burn block height
    fn handle_get_burn_ops<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        burn_block_height: u64,
        op_type: &Opcodes,
    ) -> Result<(), net_error> {
        let response = Self::response_get_burn_ops(req, sortdb, burn_block_height, op_type)?;

        response.send(http, fd)
    }

    /// Handle a GET pox info.
    /// The response will be synchronously written to the given fd (so use a fd that can buffer!)
    fn handle_getpoxinfo<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        burnchain: &Burnchain,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        match RPCPoxInfoData::from_db(sortdb, chainstate, tip, burnchain) {
            Ok(pi) => {
                let response = HttpResponseType::PoxInfo(response_metadata, pi);
                response.send(http, fd)
            }
            Err(net_error::NotFoundError) => {
                debug!("Chain tip not found during get PoX info: {:?}", req);
                let response = HttpResponseType::NotFound(
                    response_metadata,
                    "Failed to find chain tip".to_string(),
                );
                response.send(http, fd)
            }
            Err(e) => {
                warn!("Failed to get PoX info {:?}: {:?}", req, &e);
                let response = HttpResponseType::ServerError(
                    response_metadata,
                    "Failed to query peer info".to_string(),
                );
                response.send(http, fd)
            }
        }
    }

    fn handle_getattachmentsinv<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        atlasdb: &AtlasDB,
        index_block_hash: &StacksBlockId,
        pages_indexes: &HashSet<u32>,
        _options: &ConnectionOptions,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        // We are receiving a list of page indexes with a chain tip hash.
        // The amount of pages_indexes is capped by MAX_ATTACHMENT_INV_PAGES_PER_REQUEST (8)
        // Pages sizes are controlled by the constant ATTACHMENTS_INV_PAGE_SIZE (8), which
        // means that a `GET v2/attachments/inv` request can be requesting for a 64 bit vector
        // at once.
        // Since clients can be asking for non-consecutive pages indexes (1, 5_000, 10_000, ...),
        // we will be handling each page index separately.
        // We could also add the notion of "budget" so that a client could only get a limited number
        // of pages when they are spanning over many blocks.
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        if pages_indexes.len() > MAX_ATTACHMENT_INV_PAGES_PER_REQUEST {
            let msg = format!(
                "Number of attachment inv pages is limited by {} per request",
                MAX_ATTACHMENT_INV_PAGES_PER_REQUEST
            );
            warn!("{}", msg);
            let response = HttpResponseType::BadRequest(response_metadata, msg);
            response.send(http, fd)?;
            return Ok(());
        }
        if pages_indexes.len() == 0 {
            let msg = format!("Page indexes missing");
            warn!("{}", msg);
            let response = HttpResponseType::NotFound(response_metadata, msg.clone());
            response.send(http, fd)?;
            return Ok(());
        }

        let mut pages_indexes = pages_indexes.iter().map(|i| *i).collect::<Vec<u32>>();
        pages_indexes.sort();

        let mut pages = vec![];

        for page_index in pages_indexes.iter() {
            match atlasdb.get_attachments_available_at_page_index(*page_index, &index_block_hash) {
                Ok(inventory) => {
                    pages.push(AttachmentPage {
                        inventory,
                        index: *page_index,
                    });
                }
                Err(e) => {
                    let msg = format!("Unable to read Atlas DB - {}", e);
                    warn!("{}", msg);
                    let response = HttpResponseType::NotFound(response_metadata, msg);
                    return response.send(http, fd);
                }
            }
        }

        let content = GetAttachmentsInvResponse {
            block_id: index_block_hash.clone(),
            pages,
        };
        let response = HttpResponseType::GetAttachmentsInv(response_metadata, content);
        response.send(http, fd)
    }

    fn handle_getattachment<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        atlasdb: &mut AtlasDB,
        content_hash: Hash160,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        match atlasdb.find_attachment(&content_hash) {
            Ok(Some(attachment)) => {
                let content = GetAttachmentResponse { attachment };
                let response = HttpResponseType::GetAttachment(response_metadata, content);
                response.send(http, fd)
            }
            _ => {
                let msg = format!("Unable to find attachment");
                warn!("{}", msg);
                let response = HttpResponseType::NotFound(response_metadata, msg);
                response.send(http, fd)
            }
        }
    }

    /// Handle a GET neighbors
    /// The response will be synchronously written to the given fd (so use a fd that can buffer!)
    fn handle_getneighbors<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        network: &PeerNetwork,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let epoch = network.get_current_epoch();

        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let neighbor_data = RPCNeighborsInfo::from_p2p(
            network.local_peer.network_id,
            epoch.network_epoch,
            &network.peers,
            &network.chain_view,
            &network.peerdb,
        )?;
        let response = HttpResponseType::Neighbors(response_metadata, neighbor_data);
        response.send(http, fd)
    }

    /// Handle a not-found
    fn handle_notfound<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        response_metadata: HttpResponseMetadata,
        msg: String,
    ) -> Result<Option<StreamCursor>, net_error> {
        let response = HttpResponseType::NotFound(response_metadata, msg);
        return response.send(http, fd).and_then(|_| Ok(None));
    }

    /// Handle a server error
    fn handle_server_error<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        response_metadata: HttpResponseMetadata,
        msg: String,
    ) -> Result<Option<StreamCursor>, net_error> {
        // oops
        warn!("{}", &msg);
        let response = HttpResponseType::ServerError(response_metadata, msg);
        return response.send(http, fd).and_then(|_| Ok(None));
    }

    /// Handle a GET headers. Start streaming the reply.
    /// The response's preamble (but not the headers list) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a StreamCursor struct for the reward cycle we're sending, so we can continue to
    /// make progress sending it
    fn handle_getheaders<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        tip: &StacksBlockId,
        quantity: u64,
        chainstate: &StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<StreamCursor>, net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        if quantity > (MAX_HEADERS as u64) {
            // bad request
            let response = HttpResponseType::BadRequestJSON(
                response_metadata,
                serde_json::Value::String(format!(
                    "Invalid request: requested more than {} headers",
                    MAX_HEADERS
                )),
            );
            response.send(http, fd).and_then(|_| Ok(None))
        } else {
            let stream = match StreamCursor::new_headers(chainstate, tip, quantity as u32) {
                Ok(stream) => stream,
                Err(chain_error::NoSuchBlockError) => {
                    return ConversationHttp::handle_notfound(
                        http,
                        fd,
                        response_metadata,
                        format!("No such block {:?}", &tip),
                    );
                }
                Err(e) => {
                    // nope -- error trying to check
                    warn!("Failed to load block header {:?}: {:?}", req, &e);
                    let response = HttpResponseType::ServerError(
                        response_metadata,
                        format!("Failed to query block header {}", tip.to_hex()),
                    );
                    return response.send(http, fd).and_then(|_| Ok(None));
                }
            };
            let response = HttpResponseType::HeaderStream(response_metadata);
            response.send(http, fd).and_then(|_| Ok(Some(stream)))
        }
    }

    /// Handle a GET block.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a StreamCursor struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getblock<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        index_block_hash: &StacksBlockId,
        chainstate: &StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<StreamCursor>, net_error> {
        monitoring::increment_stx_blocks_served_counter();
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        // do we have this block?
        match StacksChainState::has_block_indexed(&chainstate.blocks_path, index_block_hash) {
            Ok(false) => {
                return ConversationHttp::handle_notfound(
                    http,
                    fd,
                    response_metadata,
                    format!("No such block {}", index_block_hash.to_hex()),
                );
            }
            Err(e) => {
                // nope -- error trying to check
                warn!("Failed to serve block {:?}: {:?}", req, &e);
                let response = HttpResponseType::ServerError(
                    response_metadata,
                    format!("Failed to query block {}", index_block_hash.to_hex()),
                );
                response.send(http, fd).and_then(|_| Ok(None))
            }
            Ok(true) => {
                // yup! start streaming it back
                let stream = StreamCursor::new_block(index_block_hash.clone());
                let response = HttpResponseType::BlockStream(response_metadata);
                response.send(http, fd).and_then(|_| Ok(Some(stream)))
            }
        }
    }

    /// Handle a GET confirmed microblock stream, by _anchor block hash_.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a StreamCursor struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getmicroblocks_confirmed<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        index_anchor_block_hash: &StacksBlockId,
        chainstate: &StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<StreamCursor>, net_error> {
        monitoring::increment_stx_confirmed_micro_blocks_served_counter();
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        match chainstate.has_processed_microblocks(index_anchor_block_hash) {
            Ok(true) => {}
            Ok(false) => {
                return ConversationHttp::handle_notfound(
                    http,
                    fd,
                    response_metadata,
                    format!(
                        "No such confirmed microblock stream for anchor block {}",
                        &index_anchor_block_hash
                    ),
                );
            }
            Err(e) => {
                return ConversationHttp::handle_server_error(
                    http,
                    fd,
                    response_metadata,
                    format!(
                        "Failed to query confirmed microblock stream {:?}: {:?}",
                        req, &e
                    ),
                );
            }
        }

        match chainstate.get_confirmed_microblock_index_hash(index_anchor_block_hash) {
            Err(e) => {
                return ConversationHttp::handle_server_error(
                    http,
                    fd,
                    response_metadata,
                    format!(
                        "Failed to serve confirmed microblock stream {:?}: {:?}",
                        req, &e
                    ),
                );
            }
            Ok(None) => {
                return ConversationHttp::handle_notfound(
                    http,
                    fd,
                    response_metadata,
                    format!(
                        "No such confirmed microblock stream for anchor block {}",
                        &index_anchor_block_hash
                    ),
                );
            }
            Ok(Some(tail_index_microblock_hash)) => {
                let (response, stream_opt) = match StreamCursor::new_microblock_confirmed(
                    chainstate,
                    tail_index_microblock_hash.clone(),
                ) {
                    Ok(stream) => (
                        HttpResponseType::MicroblockStream(response_metadata),
                        Some(stream),
                    ),
                    Err(chain_error::NoSuchBlockError) => (
                        HttpResponseType::NotFound(
                            response_metadata,
                            format!(
                                "No such confirmed microblock stream ending with {}",
                                tail_index_microblock_hash.to_hex()
                            ),
                        ),
                        None,
                    ),
                    Err(_e) => {
                        debug!(
                            "Failed to load confirmed microblock stream {}: {:?}",
                            &tail_index_microblock_hash, &_e
                        );
                        (
                            HttpResponseType::ServerError(
                                response_metadata,
                                format!(
                                    "Failed to query confirmed microblock stream {}",
                                    tail_index_microblock_hash.to_hex()
                                ),
                            ),
                            None,
                        )
                    }
                };
                response.send(http, fd).and_then(|_| Ok(stream_opt))
            }
        }
    }

    /// Handle a GET confirmed microblock stream, by last _index microblock hash_ in the stream.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a StreamCursor struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getmicroblocks_indexed<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        tail_index_microblock_hash: &StacksBlockId,
        chainstate: &StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<StreamCursor>, net_error> {
        monitoring::increment_stx_micro_blocks_served_counter();
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        // do we have this processed microblock stream?
        match StacksChainState::has_processed_microblocks_indexed(
            chainstate.db(),
            tail_index_microblock_hash,
        ) {
            Ok(false) => {
                // nope
                return ConversationHttp::handle_notfound(
                    http,
                    fd,
                    response_metadata,
                    format!(
                        "No such confirmed microblock stream ending with {}",
                        &tail_index_microblock_hash
                    ),
                );
            }
            Err(e) => {
                // nope
                return ConversationHttp::handle_server_error(
                    http,
                    fd,
                    response_metadata,
                    format!(
                        "Failed to serve confirmed microblock stream {:?}: {:?}",
                        req, &e
                    ),
                );
            }
            Ok(true) => {
                // yup! start streaming it back
                let (response, stream_opt) = match StreamCursor::new_microblock_confirmed(
                    chainstate,
                    tail_index_microblock_hash.clone(),
                ) {
                    Ok(stream) => (
                        HttpResponseType::MicroblockStream(response_metadata),
                        Some(stream),
                    ),
                    Err(chain_error::NoSuchBlockError) => (
                        HttpResponseType::NotFound(
                            response_metadata,
                            format!(
                                "No such confirmed microblock stream ending with {}",
                                tail_index_microblock_hash.to_hex()
                            ),
                        ),
                        None,
                    ),
                    Err(_e) => {
                        debug!(
                            "Failed to load confirmed indexed microblock stream {}: {:?}",
                            &tail_index_microblock_hash, &_e
                        );
                        (
                            HttpResponseType::ServerError(
                                response_metadata,
                                format!(
                                    "Failed to query confirmed microblock stream {}",
                                    tail_index_microblock_hash.to_hex()
                                ),
                            ),
                            None,
                        )
                    }
                };
                response.send(http, fd).and_then(|_| Ok(stream_opt))
            }
        }
    }

    /// Handle a GET token transfer cost.  Reply the entire response.
    /// TODO: accurately estimate the cost/length fee for token transfers, based on mempool
    /// pressure.
    fn handle_token_transfer_cost<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        // todo -- need to actually estimate the cost / length for token transfers
        //   right now, it just uses the minimum.
        let fee = MINIMUM_TX_FEE_RATE_PER_BYTE;
        let response = HttpResponseType::TokenTransferCost(response_metadata, fee);
        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET on an existing account, given the current chain tip.  Optionally supplies a
    /// MARF proof for each account detail loaded from the chain tip.
    fn handle_get_account_entry<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        account: &PrincipalData,
        with_proof: bool,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let response =
            match chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|clarity_db| {
                    let key = ClarityDatabase::make_key_for_account_balance(&account);
                    let burn_block_height = clarity_db.get_current_burnchain_block_height() as u64;
                    let v1_unlock_height = clarity_db.get_v1_unlock_height();
                    let v2_unlock_height = clarity_db.get_v2_unlock_height();
                    let (balance, balance_proof) = if with_proof {
                        clarity_db
                            .get_with_proof::<STXBalance>(&key)
                            .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                            .unwrap_or_else(|| (STXBalance::zero(), Some("".into())))
                    } else {
                        clarity_db
                            .get::<STXBalance>(&key)
                            .map(|a| (a, None))
                            .unwrap_or_else(|| (STXBalance::zero(), None))
                    };

                    let key = ClarityDatabase::make_key_for_account_nonce(&account);
                    let (nonce, nonce_proof) = if with_proof {
                        clarity_db
                            .get_with_proof(&key)
                            .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                            .unwrap_or_else(|| (0, Some("".into())))
                    } else {
                        clarity_db
                            .get(&key)
                            .map(|a| (a, None))
                            .unwrap_or_else(|| (0, None))
                    };

                    let unlocked = balance.get_available_balance_at_burn_block(
                        burn_block_height,
                        v1_unlock_height,
                        v2_unlock_height,
                    );
                    let (locked, unlock_height) = balance.get_locked_balance_at_burn_block(
                        burn_block_height,
                        v1_unlock_height,
                        v2_unlock_height,
                    );

                    let balance = format!("0x{}", to_hex(&unlocked.to_be_bytes()));
                    let locked = format!("0x{}", to_hex(&locked.to_be_bytes()));

                    AccountEntryResponse {
                        balance,
                        locked,
                        unlock_height,
                        nonce,
                        balance_proof,
                        nonce_proof,
                    }
                })
            }) {
                Ok(Some(data)) => HttpResponseType::GetAccount(response_metadata, data),
                Ok(None) | Err(_) => {
                    HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
                }
            };

        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET on a smart contract's data var, given the current chain tip.  Optionally
    /// supplies a MARF proof for the value.
    fn handle_get_data_var<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        var_name: &ClarityName,
        with_proof: bool,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let contract_identifier =
            QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let response =
            match chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|clarity_db| {
                    let key = ClarityDatabase::make_key_for_trip(
                        &contract_identifier,
                        StoreType::Variable,
                        var_name,
                    );

                    let (value_hex, marf_proof): (String, _) = if with_proof {
                        clarity_db
                            .get_with_proof(&key)
                            .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))?
                    } else {
                        clarity_db.get(&key).map(|a| (a, None))?
                    };

                    let data = format!("0x{}", value_hex);
                    Some(DataVarResponse { data, marf_proof })
                })
            }) {
                Ok(Some(Some(data))) => HttpResponseType::GetDataVar(response_metadata, data),
                Ok(Some(None)) => {
                    HttpResponseType::NotFound(response_metadata, "Data var not found".into())
                }
                Ok(None) | Err(_) => {
                    HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
                }
            };

        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET on a smart contract's data map, given the current chain tip.  Optionally
    /// supplies a MARF proof for the value.
    fn handle_get_map_entry<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        map_name: &ClarityName,
        key: &Value,
        with_proof: bool,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let contract_identifier =
            QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let response =
            match chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|clarity_db| {
                    let key = ClarityDatabase::make_key_for_data_map_entry(
                        &contract_identifier,
                        map_name,
                        key,
                    );
                    let (value_hex, marf_proof): (String, _) = if with_proof {
                        clarity_db
                            .get_with_proof(&key)
                            .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                            .unwrap_or_else(|| {
                                test_debug!("No value for '{}' in {}", &key, tip);
                                (Value::none().serialize_to_hex(), Some("".into()))
                            })
                    } else {
                        clarity_db.get(&key).map(|a| (a, None)).unwrap_or_else(|| {
                            test_debug!("No value for '{}' in {}", &key, tip);
                            (Value::none().serialize_to_hex(), None)
                        })
                    };

                    let data = format!("0x{}", value_hex);
                    MapEntryResponse { data, marf_proof }
                })
            }) {
                Ok(Some(data)) => HttpResponseType::GetMapEntry(response_metadata, data),
                Ok(None) | Err(_) => {
                    HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
                }
            };

        response.send(http, fd).map(|_| ())
    }

    /// Handle a POST to run a read-only function call with the given parameters on the given chain
    /// tip.  Returns the result of the function call.  Returns a CallReadOnlyResponse on success.
    fn handle_readonly_function_call<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function: &ClarityName,
        sender: &PrincipalData,
        sponsor: Option<&PrincipalData>,
        args: &[Value],
        options: &ConnectionOptions,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let contract_identifier =
            QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let args: Vec<_> = args
            .iter()
            .map(|x| SymbolicExpression::atom_value(x.clone()))
            .collect();
        let mainnet = chainstate.mainnet;
        let chain_id = chainstate.chain_id;
        let mut cost_limit = options.read_only_call_limit.clone();
        cost_limit.write_length = 0;
        cost_limit.write_count = 0;

        let data_opt_res =
            chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                let epoch = clarity_tx.get_epoch();
                let cost_track = clarity_tx
                    .with_clarity_db_readonly(|clarity_db| {
                        LimitedCostTracker::new_mid_block(
                            mainnet, chain_id, cost_limit, clarity_db, epoch,
                        )
                    })
                    .map_err(|_| {
                        ClarityRuntimeError::from(InterpreterError::CostContractLoadFailure)
                    })?;

                let clarity_version = clarity_tx
                    .with_analysis_db_readonly(|analysis_db| {
                        analysis_db.get_clarity_version(&contract_identifier)
                    })
                    .map_err(|_| {
                        ClarityRuntimeError::from(CheckErrors::NoSuchContract(format!(
                            "{}",
                            &contract_identifier
                        )))
                    })?;

                clarity_tx.with_readonly_clarity_env(
                    mainnet,
                    chain_id,
                    clarity_version,
                    sender.clone(),
                    sponsor.cloned(),
                    cost_track,
                    |env| {
                        // we want to execute any function as long as no actual writes are made as
                        // opposed to be limited to purely calling `define-read-only` functions,
                        // so use `read_only = false`.  This broadens the number of functions that
                        // can be called, and also circumvents limitations on `define-read-only`
                        // functions that can not use `contrac-call?`, even when calling other
                        // read-only functions
                        env.execute_contract(&contract_identifier, function.as_str(), &args, false)
                    },
                )
            });

        let response = match data_opt_res {
            Ok(Some(Ok(data))) => HttpResponseType::CallReadOnlyFunction(
                response_metadata,
                CallReadOnlyResponse {
                    okay: true,
                    result: Some(format!("0x{}", data.serialize_to_hex())),
                    cause: None,
                },
            ),
            Ok(Some(Err(e))) => match e {
                Unchecked(CheckErrors::CostBalanceExceeded(actual_cost, _))
                    if actual_cost.write_count > 0 =>
                {
                    HttpResponseType::CallReadOnlyFunction(
                        response_metadata,
                        CallReadOnlyResponse {
                            okay: false,
                            result: None,
                            cause: Some("NotReadOnly".to_string()),
                        },
                    )
                }
                _ => HttpResponseType::CallReadOnlyFunction(
                    response_metadata,
                    CallReadOnlyResponse {
                        okay: false,
                        result: None,
                        cause: Some(e.to_string()),
                    },
                ),
            },
            Ok(None) | Err(_) => {
                HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
            }
        };
        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET to fetch a contract's source code, given the chain tip.  Optionally returns a
    /// MARF proof as well.
    fn handle_get_contract_src<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        with_proof: bool,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let contract_identifier =
            QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let response =
            match chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|db| {
                    let source = db.get_contract_src(&contract_identifier)?;
                    let contract_commit_key = make_contract_hash_key(&contract_identifier);
                    let (contract_commit, proof) = if with_proof {
                        db.get_with_proof::<ContractCommitment>(&contract_commit_key)
                            .map(|(a, b)| (a, Some(format!("0x{}", to_hex(&b)))))
                            .expect("BUG: obtained source, but couldn't get contract commit")
                    } else {
                        db.get::<ContractCommitment>(&contract_commit_key)
                            .map(|a| (a, None))
                            .expect("BUG: obtained source, but couldn't get contract commit")
                    };

                    let publish_height = contract_commit.block_height;
                    Some(ContractSrcResponse {
                        source,
                        publish_height,
                        marf_proof: proof,
                    })
                })
            }) {
                Ok(Some(Some(data))) => HttpResponseType::GetContractSrc(response_metadata, data),
                Ok(Some(None)) => HttpResponseType::NotFound(
                    response_metadata,
                    "No contract source data found".into(),
                ),
                Ok(None) | Err(_) => {
                    HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
                }
            };

        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET to fetch whether or not a contract implements a certain trait
    fn handle_get_is_trait_implemented<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        trait_id: &TraitIdentifier,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let contract_identifier =
            QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let response =
            match chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|db| {
                    let analysis = db.load_contract_analysis(&contract_identifier)?;
                    if analysis.implemented_traits.contains(trait_id) {
                        Some(GetIsTraitImplementedResponse {
                            is_implemented: true,
                        })
                    } else {
                        let trait_defining_contract =
                            db.load_contract_analysis(&trait_id.contract_identifier)?;
                        let trait_definition =
                            trait_defining_contract.get_defined_trait(&trait_id.name)?;
                        let is_implemented = analysis
                            .check_trait_compliance(
                                &db.get_clarity_epoch_version(),
                                trait_id,
                                trait_definition,
                            )
                            .is_ok();
                        Some(GetIsTraitImplementedResponse { is_implemented })
                    }
                })
            }) {
                Ok(Some(Some(data))) => {
                    HttpResponseType::GetIsTraitImplemented(response_metadata, data)
                }
                Ok(Some(None)) => HttpResponseType::NotFound(
                    response_metadata,
                    "No contract analysis found or trait definition not found".into(),
                ),
                Ok(None) | Err(_) => {
                    HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
                }
            };

        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET to fetch a contract's analysis data, given the chain tip.  Note that this isn't
    /// something that's anchored to the blockchain, and can be different across different versions
    /// of Stacks -- callers must trust the Stacks node to return correct analysis data.
    /// Callers who don't trust the Stacks node should just fetch the contract source
    /// code and analyze it offline.
    fn handle_get_contract_abi<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let contract_identifier =
            QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let response =
            match chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                let epoch = clarity_tx.get_epoch();
                clarity_tx.with_analysis_db_readonly(|db| {
                    let contract = db.load_contract(&contract_identifier, &epoch)?;
                    contract.contract_interface
                })
            }) {
                Ok(Some(Some(data))) => HttpResponseType::GetContractABI(response_metadata, data),
                Ok(Some(None)) => HttpResponseType::NotFound(
                    response_metadata,
                    "No contract interface data found".into(),
                ),
                Ok(None) | Err(_) => {
                    HttpResponseType::NotFound(response_metadata, "Chain tip not found".into())
                }
            };

        response.send(http, fd).map(|_| ())
    }

    /// Handle a GET unconfirmed microblock stream.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a StreamCursor struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getmicroblocks_unconfirmed<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        index_anchor_block_hash: &StacksBlockId,
        min_seq: u16,
        chainstate: &StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<StreamCursor>, net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        // do we have this unconfirmed microblock stream?
        match chainstate.has_any_staging_microblock_indexed(index_anchor_block_hash, min_seq) {
            Ok(false) => {
                // nope
                let response = HttpResponseType::NotFound(
                    response_metadata,
                    format!(
                        "No such unconfirmed microblock stream for {} at or after {}",
                        index_anchor_block_hash.to_hex(),
                        min_seq
                    ),
                );
                response.send(http, fd).and_then(|_| Ok(None))
            }
            Err(e) => {
                // nope
                warn!(
                    "Failed to serve confirmed microblock stream {:?}: {:?}",
                    req, &e
                );
                let response = HttpResponseType::ServerError(
                    response_metadata,
                    format!(
                        "Failed to query unconfirmed microblock stream for {} at or after {}",
                        index_anchor_block_hash.to_hex(),
                        min_seq
                    ),
                );
                response.send(http, fd).and_then(|_| Ok(None))
            }
            Ok(true) => {
                // yup! start streaming it back
                let (response, stream_opt) = match StreamCursor::new_microblock_unconfirmed(
                    chainstate,
                    index_anchor_block_hash.clone(),
                    min_seq,
                ) {
                    Ok(stream) => (
                        HttpResponseType::MicroblockStream(response_metadata),
                        Some(stream),
                    ),
                    Err(chain_error::NoSuchBlockError) => (
                        HttpResponseType::NotFound(
                            response_metadata,
                            format!(
                                "No such unconfirmed microblock stream starting with {}",
                                index_anchor_block_hash.to_hex()
                            ),
                        ),
                        None,
                    ),
                    Err(_e) => {
                        debug!(
                            "Failed to load unconfirmed microblock stream {}: {:?}",
                            &index_anchor_block_hash, &_e
                        );
                        (
                            HttpResponseType::ServerError(
                                response_metadata,
                                format!(
                                    "Failed to query unconfirmed microblock stream {}",
                                    index_anchor_block_hash.to_hex()
                                ),
                            ),
                            None,
                        )
                    }
                };
                response.send(http, fd).and_then(|_| Ok(stream_opt))
            }
        }
    }

    /// Handle a GET unconfirmed transaction.
    /// The response will be synchronously written to the fd.
    fn handle_gettransaction_unconfirmed<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        chainstate: &StacksChainState,
        mempool: &MemPoolDB,
        txid: &Txid,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        // present in the unconfirmed state?
        if let Some(ref unconfirmed) = chainstate.unconfirmed_state.as_ref() {
            if let Some((transaction, mblock_hash, seq)) =
                unconfirmed.get_unconfirmed_transaction(txid)
            {
                let response = HttpResponseType::UnconfirmedTransaction(
                    response_metadata,
                    UnconfirmedTransactionResponse {
                        status: UnconfirmedTransactionStatus::Microblock {
                            block_hash: mblock_hash,
                            seq: seq,
                        },
                        tx: to_hex(&transaction.serialize_to_vec()),
                    },
                );
                return response.send(http, fd).map(|_| ());
            }
        }

        // present in the mempool?
        if let Some(txinfo) = MemPoolDB::get_tx(mempool.conn(), txid)? {
            let response = HttpResponseType::UnconfirmedTransaction(
                response_metadata,
                UnconfirmedTransactionResponse {
                    status: UnconfirmedTransactionStatus::Mempool,
                    tx: to_hex(&txinfo.tx.serialize_to_vec()),
                },
            );
            return response.send(http, fd).map(|_| ());
        }

        // not found
        let response = HttpResponseType::NotFound(
            response_metadata,
            format!("No such unconfirmed transaction {}", txid),
        );
        return response.send(http, fd).map(|_| ());
    }

    /// Load up the canonical Stacks chain tip.  Note that this is subject to both burn chain block
    /// Stacks block availability -- different nodes with different partial replicas of the Stacks chain state
    /// will return different values here.
    ///
    /// # Warn
    /// - There is a potential race condition. If this function is loading the latest unconfirmed
    /// tip, that tip may get invalidated by the time it is used in `maybe_read_only_clarity_tx`,
    /// which is used to load clarity state at a particular tip (which would lead to a 404 error).
    /// If this race condition occurs frequently, we can modify `maybe_read_only_clarity_tx` to
    /// re-load the unconfirmed chain tip. Refer to issue #2997.
    ///
    /// # Inputs
    /// - `tip_req` is given by the HTTP request as the optional query parameter for the chain tip
    /// hash.  It will be UseLatestAnchoredTip if there was no parameter given. If it is set to
    /// `latest`, the parameter will be set to UseLatestUnconfirmedTip.
    fn handle_load_stacks_chain_tip<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        tip_req: &TipRequest,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<StacksBlockId>, net_error> {
        match tip_req {
            TipRequest::UseLatestUnconfirmedTip => {
                let unconfirmed_chain_tip_opt = match &mut chainstate.unconfirmed_state {
                    Some(unconfirmed_state) => {
                        match unconfirmed_state.get_unconfirmed_state_if_exists() {
                            Ok(res) => res,
                            Err(msg) => {
                                let response_metadata =
                                    HttpResponseMetadata::from_http_request_type(
                                        req,
                                        Some(canonical_stacks_tip_height),
                                    );
                                let response = HttpResponseType::NotFound(response_metadata, msg);
                                return response.send(http, fd).and_then(|_| Ok(None));
                            }
                        }
                    }
                    None => None,
                };

                if let Some(unconfirmed_chain_tip) = unconfirmed_chain_tip_opt {
                    Ok(Some(unconfirmed_chain_tip))
                } else {
                    match chainstate.get_stacks_chain_tip(sortdb)? {
                        Some(tip) => Ok(Some(StacksBlockHeader::make_index_block_hash(
                            &tip.consensus_hash,
                            &tip.anchored_block_hash,
                        ))),
                        None => {
                            let response_metadata = HttpResponseMetadata::from_http_request_type(
                                req,
                                Some(canonical_stacks_tip_height),
                            );
                            warn!("Failed to load Stacks chain tip");
                            let response = HttpResponseType::NotFound(
                                response_metadata,
                                format!("Failed to load Stacks chain tip"),
                            );
                            response.send(http, fd).and_then(|_| Ok(None))
                        }
                    }
                }
            }
            TipRequest::SpecificTip(tip) => Ok(Some(*tip).clone()),
            TipRequest::UseLatestAnchoredTip => match chainstate.get_stacks_chain_tip(sortdb)? {
                Some(tip) => Ok(Some(StacksBlockHeader::make_index_block_hash(
                    &tip.consensus_hash,
                    &tip.anchored_block_hash,
                ))),
                None => {
                    let response_metadata = HttpResponseMetadata::from_http_request_type(
                        req,
                        Some(canonical_stacks_tip_height),
                    );
                    warn!("Failed to load Stacks chain tip");
                    let response = HttpResponseType::ServerError(
                        response_metadata,
                        format!("Failed to load Stacks chain tip"),
                    );
                    response.send(http, fd).and_then(|_| Ok(None))
                }
            },
        }
    }

    fn handle_load_stacks_chain_tip_hashes<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        tip: StacksBlockId,
        chainstate: &StacksChainState,
        canonical_stacks_tip_height: u64,
    ) -> Result<Option<(ConsensusHash, BlockHeaderHash)>, net_error> {
        match chainstate.get_block_header_hashes(&tip)? {
            Some((ch, bl)) => {
                return Ok(Some((ch, bl)));
            }
            None => {}
        }
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        warn!("Failed to load Stacks chain tip");
        let response = HttpResponseType::ServerError(
            response_metadata,
            format!("Failed to load Stacks chain tip"),
        );
        response.send(http, fd).and_then(|_| Ok(None))
    }

    fn handle_post_fee_rate_estimate<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        handler_args: &RPCHandlerArgs,
        sortdb: &SortitionDB,
        tx: &TransactionPayload,
        estimated_len: u64,
        canonical_stacks_tip_height: u64,
    ) -> Result<(), net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;
        let stacks_epoch = SortitionDB::get_stacks_epoch(sortdb.conn(), tip.block_height)?
                .ok_or_else(|| {
                    warn!(
                        "Failed to get fee rate estimate because could not load Stacks epoch for canonical burn height = {}",
                        tip.block_height
                    );
                    net_error::ChainstateError("Could not load Stacks epoch for canonical burn height".into())
                })?;
        if let Some((cost_estimator, fee_estimator, metric)) = handler_args.get_estimators_ref() {
            let estimated_cost = match cost_estimator.estimate_cost(tx, &stacks_epoch.epoch_id) {
                Ok(x) => x,
                Err(e) => {
                    debug!(
                        "Estimator RPC endpoint failed to estimate tx: {}",
                        tx.name()
                    );
                    return HttpResponseType::BadRequestJSON(response_metadata, e.into_json())
                        .send(http, fd);
                }
            };

            let scalar_cost =
                metric.from_cost_and_len(&estimated_cost, &stacks_epoch.block_limit, estimated_len);
            let fee_rates = match fee_estimator.get_rate_estimates() {
                Ok(x) => x,
                Err(e) => {
                    debug!(
                        "Estimator RPC endpoint failed to estimate fees for tx: {}",
                        tx.name()
                    );
                    return HttpResponseType::BadRequestJSON(response_metadata, e.into_json())
                        .send(http, fd);
                }
            };

            let mut estimations = RPCFeeEstimate::estimate_fees(scalar_cost, fee_rates).to_vec();

            let minimum_fee = estimated_len * MINIMUM_TX_FEE_RATE_PER_BYTE;

            for estimate in estimations.iter_mut() {
                if estimate.fee < minimum_fee {
                    estimate.fee = minimum_fee;
                }
            }

            let response = HttpResponseType::TransactionFeeEstimation(
                response_metadata,
                RPCFeeEstimateResponse {
                    estimated_cost,
                    estimations,
                    estimated_cost_scalar: scalar_cost,
                    cost_scalar_change_by_byte: metric.change_per_byte(),
                },
            );
            response.send(http, fd)
        } else {
            debug!("Fee and cost estimation not configured on this stacks node");
            let response = HttpResponseType::BadRequestJSON(
                response_metadata,
                json!({
                    "error": "Fee and Cost Estimation not configured on this Stacks node",
                    "reason": "CostEstimationDisabled",
                }),
            );
            response.send(http, fd)
        }
    }

    /// Handle a transaction.  Directly submit it to the mempool so the client can see any
    /// rejection reasons up-front (different from how the peer network handles it).  Indicate
    /// whether or not the transaction was accepted (and thus needs to be forwarded) in the return
    /// value.
    fn handle_post_transaction<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        consensus_hash: ConsensusHash,
        block_hash: BlockHeaderHash,
        mempool: &mut MemPoolDB,
        tx: StacksTransaction,
        atlasdb: &mut AtlasDB,
        attachment: Option<Attachment>,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
        canonical_stacks_tip_height: u64,
        ast_rules: ASTRules,
    ) -> Result<bool, net_error> {
        let txid = tx.txid();
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let (response, accepted) = if mempool.has_tx(&txid) {
            debug!("Mempool already has POSTed transaction {}", &txid);
            (
                HttpResponseType::TransactionID(response_metadata, txid),
                false,
            )
        } else {
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;
            let stacks_epoch = sortdb
                .index_conn()
                .get_stacks_epoch(tip.block_height as u32)
                .ok_or_else(|| {
                    warn!(
                        "Failed to store transaction because could not load Stacks epoch for canonical burn height = {}",
                        tip.block_height
                    );
                    net_error::ChainstateError("Could not load Stacks epoch for canonical burn height".into())
                })?;

            if Relayer::do_static_problematic_checks()
                && !Relayer::static_check_problematic_relayed_tx(
                    chainstate.mainnet,
                    stacks_epoch.epoch_id,
                    &tx,
                    ast_rules,
                )
                .is_ok()
            {
                debug!(
                    "Transaction {} is problematic in rules {:?}; will not store or relay",
                    &tx.txid(),
                    ast_rules
                );
                (
                    HttpResponseType::TransactionID(response_metadata, txid),
                    false,
                )
            } else {
                match mempool.submit(
                    chainstate,
                    sortdb,
                    &consensus_hash,
                    &block_hash,
                    &tx,
                    event_observer,
                    &stacks_epoch.block_limit,
                    &stacks_epoch.epoch_id,
                ) {
                    Ok(_) => {
                        debug!("Mempool accepted POSTed transaction {}", &txid);
                        (
                            HttpResponseType::TransactionID(response_metadata, txid),
                            true,
                        )
                    }
                    Err(e) => {
                        debug!("Mempool rejected POSTed transaction {}: {:?}", &txid, &e);
                        (
                            HttpResponseType::BadRequestJSON(response_metadata, e.into_json(&txid)),
                            false,
                        )
                    }
                }
            }
        };

        if let Some(ref attachment) = attachment {
            if let TransactionPayload::ContractCall(ref contract_call) = tx.payload {
                if atlasdb
                    .should_keep_attachment(&contract_call.to_clarity_contract_id(), &attachment)
                {
                    atlasdb
                        .insert_uninstantiated_attachment(attachment)
                        .map_err(|e| net_error::DBError(e))?;
                }
            }
        }

        response.send(http, fd).and_then(|_| Ok(accepted))
    }

    /// Handle a block.  Directly submit a Stacks block to this node's chain state.
    /// Indicate whether or not the block was accepted (i.e. it was new, and valid)
    fn handle_post_block<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block: &StacksBlock,
        canonical_stacks_tip_height: u64,
    ) -> Result<bool, net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        // is this a consensus hash we recognize?
        let (response, accepted) =
            match SortitionDB::get_sortition_id_by_consensus(&sortdb.conn(), consensus_hash) {
                Ok(Some(_)) => {
                    // we recognize this consensus hash
                    let ic = sortdb.index_conn();
                    match Relayer::process_new_anchored_block(
                        &ic,
                        chainstate,
                        consensus_hash,
                        block,
                        0,
                    ) {
                        Ok(true) => {
                            debug!(
                                "Accepted Stacks block {}/{}",
                                consensus_hash,
                                &block.block_hash()
                            );
                            (
                                HttpResponseType::StacksBlockAccepted(
                                    response_metadata,
                                    StacksBlockHeader::make_index_block_hash(
                                        consensus_hash,
                                        &block.block_hash(),
                                    ),
                                    true,
                                ),
                                true,
                            )
                        }
                        Ok(false) => {
                            debug!(
                                "Did not accept Stacks block {}/{}",
                                consensus_hash,
                                &block.block_hash()
                            );
                            (
                                HttpResponseType::StacksBlockAccepted(
                                    response_metadata,
                                    StacksBlockHeader::make_index_block_hash(
                                        consensus_hash,
                                        &block.block_hash(),
                                    ),
                                    false,
                                ),
                                false,
                            )
                        }
                        Err(e) => {
                            error!(
                                "Failed to process anchored block {}/{}: {:?}",
                                consensus_hash,
                                &block.block_hash(),
                                &e
                            );
                            (
                                HttpResponseType::ServerError(
                                    response_metadata,
                                    format!(
                                        "Failed to process anchored block {}/{}: {:?}",
                                        consensus_hash,
                                        &block.block_hash(),
                                        &e
                                    ),
                                ),
                                false,
                            )
                        }
                    }
                }
                Ok(None) => {
                    debug!(
                        "Unrecognized consensus hash {} for block {}",
                        consensus_hash,
                        &block.block_hash()
                    );
                    (
                        HttpResponseType::NotFound(
                            response_metadata,
                            format!("No such consensus hash '{}'", consensus_hash),
                        ),
                        false,
                    )
                }
                Err(e) => {
                    error!(
                        "Failed to query sortition ID by consensus '{}'",
                        consensus_hash
                    );
                    (
                        HttpResponseType::ServerError(
                            response_metadata,
                            format!(
                                "Failed to query sortition ID for consensus hash '{}': {:?}",
                                consensus_hash, &e
                            ),
                        ),
                        false,
                    )
                }
            };
        response.send(http, fd).and_then(|_| Ok(accepted))
    }

    /// Handle a microblock.  Directly submit it to the microblock store so the client can see any
    /// rejection reasons up-front (different from how the peer network handles it).  Indicate
    /// whether or not the microblock was accepted (and thus needs to be forwarded) in the return
    /// value.
    fn handle_post_microblock<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        microblock: &StacksMicroblock,
        canonical_stacks_tip_height: u64,
    ) -> Result<bool, net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));

        // make sure we can accept this
        let ch_sn = match SortitionDB::get_block_snapshot_consensus(sortdb.conn(), consensus_hash) {
            Ok(Some(sn)) => sn,
            Ok(None) => {
                let resp = HttpResponseType::NotFound(
                    response_metadata,
                    "No such consensus hash".to_string(),
                );
                return resp.send(http, fd).and_then(|_| Ok(false));
            }
            Err(e) => {
                let resp = HttpResponseType::BadRequestJSON(
                    response_metadata,
                    chain_error::DBError(e).into_json(),
                );
                return resp.send(http, fd).and_then(|_| Ok(false));
            }
        };

        let sort_handle = sortdb.index_handle(&ch_sn.sortition_id);
        let parent_block_snapshot =
            Relayer::get_parent_stacks_block_snapshot(&sort_handle, consensus_hash, block_hash)?;
        let ast_rules =
            SortitionDB::get_ast_rules(&sort_handle, parent_block_snapshot.block_height)?;
        let epoch_id =
            SortitionDB::get_stacks_epoch(&sort_handle, parent_block_snapshot.block_height)?
                .expect("FATAL: no epoch defined")
                .epoch_id;

        let (response, accepted) = if !Relayer::static_check_problematic_relayed_microblock(
            chainstate.mainnet,
            epoch_id,
            microblock,
            ast_rules,
        ) {
            info!("Microblock {} from {}/{} is problematic; will not store or relay it, nor its descendants", &microblock.block_hash(), consensus_hash, &block_hash);
            (
                // NOTE: txid is ignored in chainstate error .into_json()
                HttpResponseType::BadRequestJSON(
                    response_metadata,
                    chain_error::ProblematicTransaction(Txid([0u8; 32])).into_json(),
                ),
                false,
            )
        } else {
            match chainstate.preprocess_streamed_microblock(consensus_hash, block_hash, microblock)
            {
                Ok(accepted) => {
                    if accepted {
                        debug!(
                            "Accepted uploaded microblock {}/{}-{}",
                            &consensus_hash,
                            &block_hash,
                            &microblock.block_hash()
                        );
                    } else {
                        debug!(
                            "Did not accept microblock {}/{}-{}",
                            &consensus_hash,
                            &block_hash,
                            &microblock.block_hash()
                        );
                    }

                    (
                        HttpResponseType::MicroblockHash(
                            response_metadata,
                            microblock.block_hash(),
                        ),
                        accepted,
                    )
                }
                Err(e) => (
                    HttpResponseType::BadRequestJSON(response_metadata, e.into_json()),
                    false,
                ),
            }
        };

        response.send(http, fd).and_then(|_| Ok(accepted))
    }

    /// Handle a request for mempool transactions in bulk
    fn handle_mempool_query<W: Write>(
        http: &mut StacksHttp,
        fd: &mut W,
        req: &HttpRequestType,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        query: MemPoolSyncData,
        max_txs: u64,
        canonical_stacks_tip_height: u64,
        page_id: Option<Txid>,
    ) -> Result<StreamCursor, net_error> {
        let response_metadata =
            HttpResponseMetadata::from_http_request_type(req, Some(canonical_stacks_tip_height));
        let response = HttpResponseType::MemPoolTxStream(response_metadata);
        let height = chainstate
            .get_stacks_chain_tip(sortdb)?
            .map(|blk| blk.height)
            .unwrap_or(0);

        debug!(
            "Begin mempool query";
            "page_id" => %page_id.map(|txid| format!("{}", &txid)).unwrap_or("(none".to_string()),
            "block_height" => height,
            "max_txs" => max_txs
        );

        let stream = StreamCursor::new_tx_stream(query, max_txs, height, page_id);
        response.send(http, fd).and_then(|_| Ok(stream))
    }

    /// Handle an external HTTP request.
    /// Some requests, such as those for blocks, will create new reply streams.  This method adds
    /// those new streams into the `reply_streams` set.
    /// Returns a StacksMessageType option -- it's Some(...) if we need to forward a message to the
    /// peer network (like a transaction or a block or microblock)
    pub fn handle_request(
        &mut self,
        req: HttpRequestType,
        network: &mut PeerNetwork,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
        handler_opts: &RPCHandlerArgs,
    ) -> Result<Option<StacksMessageType>, net_error> {
        let mut reply = self.connection.make_relay_handle(self.conn_id)?;
        let keep_alive = req.metadata().keep_alive;
        let mut ret = None;

        let stream_opt = match req {
            HttpRequestType::GetInfo(ref _md) => {
                ConversationHttp::handle_getinfo(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    network,
                    chainstate,
                    handler_opts,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::GetPoxInfo(ref _md, ref tip_req) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_getpoxinfo(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        &network.burnchain,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::GetNeighbors(ref _md) => {
                ConversationHttp::handle_getneighbors(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    network,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::GetHeaders(ref _md, ref quantity, ref tip_req) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_getheaders(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        &tip,
                        *quantity,
                        chainstate,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?
                } else {
                    None
                }
            }
            HttpRequestType::GetBlock(ref _md, ref index_block_hash) => {
                ConversationHttp::handle_getblock(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    index_block_hash,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?
            }
            HttpRequestType::GetMicroblocksIndexed(ref _md, ref index_head_hash) => {
                ConversationHttp::handle_getmicroblocks_indexed(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    index_head_hash,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?
            }
            HttpRequestType::GetMicroblocksConfirmed(ref _md, ref anchor_index_block_hash) => {
                ConversationHttp::handle_getmicroblocks_confirmed(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    anchor_index_block_hash,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?
            }
            HttpRequestType::GetMicroblocksUnconfirmed(
                ref _md,
                ref index_anchor_block_hash,
                ref min_seq,
            ) => ConversationHttp::handle_getmicroblocks_unconfirmed(
                &mut self.connection.protocol,
                &mut reply,
                &req,
                index_anchor_block_hash,
                *min_seq,
                chainstate,
                network.burnchain_tip.canonical_stacks_tip_height,
            )?,
            HttpRequestType::GetTransactionUnconfirmed(ref _md, ref txid) => {
                ConversationHttp::handle_gettransaction_unconfirmed(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    chainstate,
                    mempool,
                    txid,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::GetAccount(ref _md, ref principal, ref tip_req, ref with_proof) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_get_account_entry(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        principal,
                        *with_proof,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::GetDataVar(
                ref _md,
                ref contract_addr,
                ref contract_name,
                ref var_name,
                ref tip_req,
                ref with_proof,
            ) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_get_data_var(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        contract_addr,
                        contract_name,
                        var_name,
                        *with_proof,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::GetMapEntry(
                ref _md,
                ref contract_addr,
                ref contract_name,
                ref map_name,
                ref key,
                ref tip_req,
                ref with_proof,
            ) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_get_map_entry(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        contract_addr,
                        contract_name,
                        map_name,
                        key,
                        *with_proof,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::GetTransferCost(ref _md) => {
                ConversationHttp::handle_token_transfer_cost(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::GetContractABI(
                ref _md,
                ref contract_addr,
                ref contract_name,
                ref tip_req,
            ) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_get_contract_abi(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        contract_addr,
                        contract_name,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::FeeRateEstimate(ref _md, ref tx, estimated_len) => {
                ConversationHttp::handle_post_fee_rate_estimate(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    handler_opts,
                    sortdb,
                    tx,
                    estimated_len,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::CallReadOnlyFunction(
                ref _md,
                ref ctrct_addr,
                ref ctrct_name,
                ref as_sender,
                ref as_sponsor,
                ref func_name,
                ref args,
                ref tip_req,
            ) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_readonly_function_call(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        ctrct_addr,
                        ctrct_name,
                        func_name,
                        as_sender,
                        as_sponsor.as_ref(),
                        args,
                        &self.connection.options,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::GetContractSrc(
                ref _md,
                ref contract_addr,
                ref contract_name,
                ref tip_req,
                ref with_proof,
            ) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_get_contract_src(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        contract_addr,
                        contract_name,
                        *with_proof,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::PostTransaction(ref _md, ref tx, ref attachment) => {
                match chainstate.get_stacks_chain_tip(sortdb)? {
                    Some(tip) => {
                        let accepted = ConversationHttp::handle_post_transaction(
                            &mut self.connection.protocol,
                            &mut reply,
                            &req,
                            chainstate,
                            sortdb,
                            tip.consensus_hash,
                            tip.anchored_block_hash,
                            mempool,
                            tx.clone(),
                            &mut network.atlasdb,
                            attachment.clone(),
                            handler_opts.event_observer.as_deref(),
                            network.burnchain_tip.canonical_stacks_tip_height,
                            network.ast_rules,
                        )?;
                        if accepted {
                            // forward to peer network
                            ret = Some(StacksMessageType::Transaction(tx.clone()));
                        }
                    }
                    None => {
                        let response_metadata = HttpResponseMetadata::from_http_request_type(
                            &req,
                            Some(network.burnchain_tip.canonical_stacks_tip_height),
                        );
                        warn!("Failed to load Stacks chain tip");
                        let response = HttpResponseType::ServerError(
                            response_metadata,
                            format!("Failed to load Stacks chain tip"),
                        );
                        response.send(&mut self.connection.protocol, &mut reply)?;
                    }
                }
                None
            }
            HttpRequestType::GetAttachment(ref _md, ref content_hash) => {
                ConversationHttp::handle_getattachment(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    &mut network.atlasdb,
                    content_hash.clone(),
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::GetAttachmentsInv(
                ref _md,
                ref index_block_hash,
                ref pages_indexes,
            ) => {
                ConversationHttp::handle_getattachmentsinv(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    &mut network.atlasdb,
                    &index_block_hash,
                    pages_indexes,
                    &self.connection.options,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                None
            }
            HttpRequestType::PostBlock(ref _md, ref consensus_hash, ref block) => {
                let accepted = ConversationHttp::handle_post_block(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    sortdb,
                    chainstate,
                    consensus_hash,
                    block,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )?;
                if accepted {
                    // inform the peer network so it can announce its presence
                    ret = Some(StacksMessageType::Blocks(BlocksData {
                        blocks: vec![BlocksDatum(consensus_hash.clone(), block.clone())],
                    }));
                }
                None
            }
            HttpRequestType::PostMicroblock(ref _md, ref mblock, ref tip_req) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    if let Some((consensus_hash, block_hash)) =
                        ConversationHttp::handle_load_stacks_chain_tip_hashes(
                            &mut self.connection.protocol,
                            &mut reply,
                            &req,
                            tip,
                            chainstate,
                            network.burnchain_tip.canonical_stacks_tip_height,
                        )?
                    {
                        let accepted = ConversationHttp::handle_post_microblock(
                            &mut self.connection.protocol,
                            &mut reply,
                            &req,
                            &consensus_hash,
                            &block_hash,
                            sortdb,
                            chainstate,
                            mblock,
                            network.burnchain_tip.canonical_stacks_tip_height,
                        )?;
                        if accepted {
                            // forward to peer network
                            let tip = StacksBlockHeader::make_index_block_hash(
                                &consensus_hash,
                                &block_hash,
                            );
                            ret = Some(StacksMessageType::Microblocks(MicroblocksData {
                                index_anchor_block: tip,
                                microblocks: vec![(*mblock).clone()],
                            }));
                        }
                    }
                }
                None
            }
            HttpRequestType::MemPoolQuery(ref _md, ref query, ref page_id_opt) => {
                Some(ConversationHttp::handle_mempool_query(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    sortdb,
                    chainstate,
                    query.clone(),
                    network.connection_opts.mempool_max_tx_query,
                    network.burnchain_tip.canonical_stacks_tip_height,
                    page_id_opt.clone(),
                )?)
            }
            HttpRequestType::OptionsPreflight(ref _md, ref _path) => {
                let response_metadata = HttpResponseMetadata::from_http_request_type(
                    &req,
                    Some(network.burnchain_tip.canonical_stacks_tip_height),
                );
                let response = HttpResponseType::OptionsPreflight(response_metadata);
                response
                    .send(&mut self.connection.protocol, &mut reply)
                    .map(|_| ())?;
                None
            }
            HttpRequestType::GetIsTraitImplemented(
                ref _md,
                ref contract_addr,
                ref contract_name,
                ref trait_id,
                ref tip_req,
            ) => {
                if let Some(tip) = ConversationHttp::handle_load_stacks_chain_tip(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    tip_req,
                    sortdb,
                    chainstate,
                    network.burnchain_tip.canonical_stacks_tip_height,
                )? {
                    ConversationHttp::handle_get_is_trait_implemented(
                        &mut self.connection.protocol,
                        &mut reply,
                        &req,
                        sortdb,
                        chainstate,
                        &tip,
                        contract_addr,
                        contract_name,
                        trait_id,
                        network.burnchain_tip.canonical_stacks_tip_height,
                    )?;
                }
                None
            }
            HttpRequestType::ClientError(ref _md, ref err) => {
                let response_metadata = HttpResponseMetadata::from_http_request_type(
                    &req,
                    Some(network.burnchain_tip.canonical_stacks_tip_height),
                );
                let response = match err {
                    ClientError::Message(s) => HttpResponseType::BadRequestJSON(
                        response_metadata,
                        serde_json::Value::String(s.to_string()),
                    ),
                    ClientError::NotFound(path) => {
                        HttpResponseType::NotFound(response_metadata, path.clone())
                    }
                };

                response
                    .send(&mut self.connection.protocol, &mut reply)
                    .map(|_| ())?;
                None
            }
            HttpRequestType::GetBurnOps {
                ref md,
                height,
                ref opcode,
            } => {
                Self::handle_get_burn_ops(
                    &mut self.connection.protocol,
                    &mut reply,
                    &req,
                    sortdb,
                    height,
                    opcode,
                )?;
                None
            }
        };

        match stream_opt {
            None => {
                self.reply_streams.push_back((reply, None, keep_alive));
            }
            Some(stream) => {
                self.reply_streams.push_back((
                    reply,
                    Some((
                        HttpChunkedTransferWriterState::new(STREAM_CHUNK_SIZE as usize),
                        stream,
                    )),
                    keep_alive,
                ));
            }
        }
        Ok(ret)
    }

    /// Make progress on outbound requests.
    fn send_outbound_responses(
        &mut self,
        mempool: &MemPoolDB,
        chainstate: &mut StacksChainState,
    ) -> Result<(), net_error> {
        // send out streamed responses in the order they were requested
        let mut drained_handle = false;
        let mut drained_stream = false;
        let mut broken = false;
        let mut do_keep_alive = true;

        test_debug!(
            "{:?}: {} HTTP replies pending",
            &self,
            self.reply_streams.len()
        );
        let _self_str = format!("{}", &self);

        match self.reply_streams.front_mut() {
            Some((ref mut reply, ref mut stream_opt, ref keep_alive)) => {
                do_keep_alive = *keep_alive;

                // if we're streaming, make some progress on the stream
                match stream_opt {
                    Some((ref mut http_chunk_state, ref mut stream)) => {
                        let mut encoder =
                            HttpChunkedTransferWriter::from_writer_state(reply, http_chunk_state);
                        match stream.stream_to(mempool, chainstate, &mut encoder, STREAM_CHUNK_SIZE)
                        {
                            Ok(nw) => {
                                test_debug!("{}: Streamed {} bytes", &_self_str, nw);
                                if nw == 0 {
                                    // EOF -- finish chunk and stop sending.
                                    if !encoder.corked() {
                                        encoder.flush().map_err(|e| {
                                            test_debug!(
                                                "{}: Write error on encoder flush: {:?}",
                                                &_self_str,
                                                &e
                                            );
                                            net_error::WriteError(e)
                                        })?;

                                        encoder.cork();

                                        test_debug!("{}: Stream indicates EOF", &_self_str);
                                    }

                                    // try moving some data to the connection only once we're done
                                    // streaming
                                    match reply.try_flush() {
                                        Ok(res) => {
                                            test_debug!(
                                                "{}: Streamed reply is drained?: {}",
                                                &_self_str,
                                                res
                                            );
                                            drained_handle = res;
                                        }
                                        Err(e) => {
                                            // dead
                                            warn!(
                                                "{}: Broken HTTP connection: {:?}",
                                                &_self_str, &e
                                            );
                                            broken = true;
                                        }
                                    }
                                    drained_stream = true;
                                }
                            }
                            Err(e) => {
                                // broken -- terminate the stream.
                                // For example, if we're streaming an unconfirmed block or
                                // microblock, the data can get moved to the chunk store out from
                                // under the stream.
                                warn!(
                                    "{}: Failed to send to HTTP connection: {:?}",
                                    &_self_str, &e
                                );
                                broken = true;
                            }
                        }
                    }
                    None => {
                        // not streamed; all data is buffered
                        drained_stream = true;

                        // try moving some data to the connection
                        match reply.try_flush() {
                            Ok(res) => {
                                test_debug!("{}: Reply is drained", &_self_str);
                                drained_handle = res;
                            }
                            Err(e) => {
                                // dead
                                warn!("{}: Broken HTTP connection: {:?}", &_self_str, &e);
                                broken = true;
                            }
                        }
                    }
                }
            }
            None => {}
        }

        if broken || (drained_handle && drained_stream) {
            // done with this stream
            test_debug!(
                "{:?}: done with stream (broken={}, drained_handle={}, drained_stream={})",
                &self,
                broken,
                drained_handle,
                drained_stream
            );
            self.total_reply_count += 1;
            self.reply_streams.pop_front();

            if !do_keep_alive {
                // encountered "Connection: close"
                self.keep_alive = false;
            }
        }
        Ok(())
    }

    pub fn try_send_recv_response(
        req: ReplyHandleHttp,
    ) -> Result<HttpResponseType, Result<ReplyHandleHttp, net_error>> {
        match req.try_send_recv() {
            Ok(message) => match message {
                StacksHttpMessage::Request(_) => {
                    warn!("Received response: not a HTTP response");
                    return Err(Err(net_error::InvalidMessage));
                }
                StacksHttpMessage::Response(http_response) => Ok(http_response),
            },
            Err(res) => Err(res),
        }
    }

    /// Make progress on our request/response
    fn recv_inbound_response(&mut self) -> Result<(), net_error> {
        // make progress on our pending request (if it exists).
        let inprogress = self.pending_request.is_some();
        let is_pending = self.pending_response.is_none();

        let pending_request = self.pending_request.take();
        let response = match pending_request {
            None => Ok(self.pending_response.take()),
            Some(req) => match ConversationHttp::try_send_recv_response(req) {
                Ok(response) => Ok(Some(response)),
                Err(res) => match res {
                    Ok(handle) => {
                        // try again
                        self.pending_request = Some(handle);
                        Ok(self.pending_response.take())
                    }
                    Err(e) => Err(e),
                },
            },
        }?;

        self.pending_response = response;

        if inprogress && self.pending_request.is_none() {
            test_debug!(
                "{:?},id={}: HTTP request finished",
                &self.peer_host,
                self.conn_id
            );
        }

        if is_pending && self.pending_response.is_some() {
            test_debug!(
                "{:?},id={}: HTTP response finished",
                &self.peer_host,
                self.conn_id
            );
        }

        Ok(())
    }

    /// Try to get our response
    pub fn try_get_response(&mut self) -> Option<HttpResponseType> {
        self.pending_response.take()
    }

    /// Make progress on in-flight messages.
    pub fn try_flush(
        &mut self,
        mempool: &MemPoolDB,
        chainstate: &mut StacksChainState,
    ) -> Result<(), net_error> {
        self.send_outbound_responses(mempool, chainstate)?;
        self.recv_inbound_response()?;
        Ok(())
    }

    /// Is the connection idle?
    pub fn is_idle(&self) -> bool {
        self.pending_response.is_none()
            && self.connection.inbox_len() == 0
            && self.connection.outbox_len() == 0
            && self.reply_streams.len() == 0
    }

    /// Is the conversation out of pending data?
    /// Don't consider it drained if we haven't received anything yet
    pub fn is_drained(&self) -> bool {
        ((self.total_request_count > 0 && self.total_reply_count > 0)
            || self.pending_error_response.is_some())
            && self.is_idle()
    }

    /// Should the connection be kept alive even if drained?
    pub fn is_keep_alive(&self) -> bool {
        self.keep_alive
    }

    /// When was the last time we got an inbound request?
    pub fn get_last_request_time(&self) -> u64 {
        self.last_request_timestamp
    }

    /// When was the last time we sent data as part of an outbound response?
    pub fn get_last_response_time(&self) -> u64 {
        self.last_response_timestamp
    }

    /// When was this converation conencted?
    pub fn get_connection_time(&self) -> u64 {
        self.connection_time
    }

    /// Make progress on in-flight requests and replies.
    /// Returns the list of transactions we'll need to forward to the peer network
    pub fn chat(
        &mut self,
        network: &mut PeerNetwork,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
        handler_args: &RPCHandlerArgs,
    ) -> Result<Vec<StacksMessageType>, net_error> {
        // if we have an in-flight error, then don't take any more requests.
        if self.pending_error_response.is_some() {
            return Ok(vec![]);
        }

        // handle in-bound HTTP request(s)
        let num_inbound = self.connection.inbox_len();
        let mut ret = vec![];
        test_debug!("{:?}: {} HTTP requests pending", &self, num_inbound);

        for _i in 0..num_inbound {
            let msg = match self.connection.next_inbox_message() {
                None => {
                    continue;
                }
                Some(m) => m,
            };

            match msg {
                StacksHttpMessage::Request(req) => {
                    // new request
                    self.total_request_count += 1;
                    self.last_request_timestamp = get_epoch_time_secs();
                    if req.metadata().canonical_stacks_tip_height.is_some() {
                        test_debug!(
                            "Request metadata: canonical stacks tip height is {:?}",
                            &req.metadata().canonical_stacks_tip_height
                        );
                        self.canonical_stacks_tip_height =
                            req.metadata().canonical_stacks_tip_height;
                    }
                    let start_time = Instant::now();
                    let path = req.get_path();
                    let msg_opt = monitoring::instrument_http_request_handler(req, |req| {
                        self.handle_request(req, network, sortdb, chainstate, mempool, handler_args)
                    })?;

                    debug!("Processed HTTPRequest"; "path" => %path, "processing_time_ms" => start_time.elapsed().as_millis(), "conn_id" => self.conn_id, "peer_addr" => &self.peer_addr);

                    if let Some(msg) = msg_opt {
                        ret.push(msg);
                    }
                }
                StacksHttpMessage::Response(resp) => {
                    // Is there someone else waiting for this message?  If so, pass it along.
                    // (this _should_ be our pending_request handle)
                    if resp.metadata().canonical_stacks_tip_height.is_some() {
                        test_debug!(
                            "Response metadata: canonical stacks tip height is {:?}",
                            &resp.metadata().canonical_stacks_tip_height
                        );
                        self.canonical_stacks_tip_height =
                            resp.metadata().canonical_stacks_tip_height;
                    }
                    match self
                        .connection
                        .fulfill_request(StacksHttpMessage::Response(resp))
                    {
                        None => {
                            test_debug!("{:?}: Fulfilled pending HTTP request", &self);
                        }
                        Some(_msg) => {
                            // unsolicited; discard
                            test_debug!("{:?}: Dropping unsolicited HTTP response", &self);
                        }
                    }
                }
            }
        }

        Ok(ret)
    }

    /// Remove all timed-out messages, and ding the remote peer as unhealthy
    pub fn clear_timeouts(&mut self) -> () {
        self.connection.drain_timeouts();
    }

    /// Load data into our HTTP connection
    pub fn recv<R: Read>(&mut self, r: &mut R) -> Result<usize, net_error> {
        let mut total_recv = 0;
        loop {
            let nrecv = match self.connection.recv_data(r) {
                Ok(nr) => nr,
                Err(e) => {
                    debug!("{:?}: failed to recv: {:?}", self, &e);
                    return Err(e);
                }
            };

            total_recv += nrecv;
            if nrecv > 0 {
                self.last_request_timestamp = get_epoch_time_secs();
            } else {
                break;
            }
        }
        monitoring::update_inbound_rpc_bandwidth(total_recv as i64);
        Ok(total_recv)
    }

    /// Write data out of our HTTP connection.  Write as much as we can
    pub fn send<W: Write>(
        &mut self,
        w: &mut W,
        mempool: &MemPoolDB,
        chainstate: &mut StacksChainState,
    ) -> Result<usize, net_error> {
        let mut total_sz = 0;
        loop {
            // prime the Write
            self.try_flush(mempool, chainstate)?;

            let sz = match self.connection.send_data(w) {
                Ok(sz) => sz,
                Err(e) => {
                    info!("{:?}: failed to send on HTTP conversation: {:?}", self, &e);
                    return Err(e);
                }
            };

            total_sz += sz;
            if sz > 0 {
                self.last_response_timestamp = get_epoch_time_secs();
            } else {
                break;
            }
        }
        monitoring::update_inbound_rpc_bandwidth(total_sz as i64);
        Ok(total_sz)
    }

    /// Make a new getinfo request to this endpoint
    pub fn new_getinfo(&self, stacks_height: Option<u64>) -> HttpRequestType {
        HttpRequestType::GetInfo(HttpRequestMetadata::from_host(
            self.peer_host.clone(),
            stacks_height,
        ))
    }

    /// Make a new getinfo request to this endpoint
    pub fn new_getpoxinfo(&self, tip_req: TipRequest) -> HttpRequestType {
        HttpRequestType::GetPoxInfo(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            tip_req,
        )
    }

    /// Make a new getneighbors request to this endpoint
    pub fn new_getneighbors(&self) -> HttpRequestType {
        HttpRequestType::GetNeighbors(HttpRequestMetadata::from_host(self.peer_host.clone(), None))
    }

    /// Make a new getheaders request to this endpoint
    pub fn new_getheaders(&self, quantity: u64, tip_req: TipRequest) -> HttpRequestType {
        HttpRequestType::GetHeaders(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            quantity,
            tip_req,
        )
    }

    /// Make a new getblock request to this endpoint
    pub fn new_getblock(&self, index_block_hash: StacksBlockId) -> HttpRequestType {
        HttpRequestType::GetBlock(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            index_block_hash,
        )
    }

    /// Make a new get-microblocks request to this endpoint
    pub fn new_getmicroblocks_indexed(
        &self,
        index_microblock_hash: StacksBlockId,
    ) -> HttpRequestType {
        HttpRequestType::GetMicroblocksIndexed(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            index_microblock_hash,
        )
    }

    /// Make a new get-microblocks-confirmed request to this endpoint
    pub fn new_getmicroblocks_confirmed(
        &self,
        index_anchor_block_hash: StacksBlockId,
    ) -> HttpRequestType {
        HttpRequestType::GetMicroblocksConfirmed(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            index_anchor_block_hash,
        )
    }

    /// Make a new get-microblocks request for unconfirmed microblocks
    pub fn new_getmicroblocks_unconfirmed(
        &self,
        anchored_index_block_hash: StacksBlockId,
        min_seq: u16,
    ) -> HttpRequestType {
        HttpRequestType::GetMicroblocksUnconfirmed(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            anchored_index_block_hash,
            min_seq,
        )
    }

    /// Make a new get-unconfirmed-tx request
    pub fn new_gettransaction_unconfirmed(&self, txid: Txid) -> HttpRequestType {
        HttpRequestType::GetTransactionUnconfirmed(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            txid,
        )
    }

    /// Make a new post-transaction request
    pub fn new_post_transaction(&self, tx: StacksTransaction) -> HttpRequestType {
        HttpRequestType::PostTransaction(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            tx,
            None,
        )
    }

    /// Make a new post-block request
    pub fn new_post_block(&self, ch: ConsensusHash, block: StacksBlock) -> HttpRequestType {
        HttpRequestType::PostBlock(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            ch,
            block,
        )
    }

    /// Make a new post-microblock request
    pub fn new_post_microblock(
        &self,
        mblock: StacksMicroblock,
        tip_req: TipRequest,
    ) -> HttpRequestType {
        HttpRequestType::PostMicroblock(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            mblock,
            tip_req,
        )
    }

    /// Make a new request for an account
    pub fn new_getaccount(
        &self,
        principal: PrincipalData,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> HttpRequestType {
        HttpRequestType::GetAccount(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            principal,
            tip_req,
            with_proof,
        )
    }

    /// Make a new request for a data var
    pub fn new_getdatavar(
        &self,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        var_name: ClarityName,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> HttpRequestType {
        HttpRequestType::GetDataVar(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            contract_addr,
            contract_name,
            var_name,
            tip_req,
            with_proof,
        )
    }

    /// Make a new request for a data map
    pub fn new_getmapentry(
        &self,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        map_name: ClarityName,
        key: Value,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> HttpRequestType {
        HttpRequestType::GetMapEntry(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            contract_addr,
            contract_name,
            map_name,
            key,
            tip_req,
            with_proof,
        )
    }

    /// Make a new request to get a contract's source
    pub fn new_getcontractsrc(
        &self,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        tip_req: TipRequest,
        with_proof: bool,
    ) -> HttpRequestType {
        HttpRequestType::GetContractSrc(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            contract_addr,
            contract_name,
            tip_req,
            with_proof,
        )
    }

    /// Make a new request to get a contract's ABI
    pub fn new_getcontractabi(
        &self,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        tip_req: TipRequest,
    ) -> HttpRequestType {
        HttpRequestType::GetContractABI(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            contract_addr,
            contract_name,
            tip_req,
        )
    }

    /// Make a new request to run a read-only function
    pub fn new_callreadonlyfunction(
        &self,
        contract_addr: StacksAddress,
        contract_name: ContractName,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        function_name: ClarityName,
        function_args: Vec<Value>,
        tip_req: TipRequest,
    ) -> HttpRequestType {
        HttpRequestType::CallReadOnlyFunction(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            contract_addr,
            contract_name,
            sender,
            sponsor,
            function_name,
            function_args,
            tip_req,
        )
    }

    /// Make a new request for attachment inventory page
    pub fn new_getattachmentsinv(
        &self,
        index_block_hash: StacksBlockId,
        pages_indexes: HashSet<u32>,
    ) -> HttpRequestType {
        HttpRequestType::GetAttachmentsInv(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            index_block_hash,
            pages_indexes,
        )
    }

    /// Make a new request for mempool contents
    pub fn new_mempool_query(
        &self,
        query: MemPoolSyncData,
        page_id_opt: Option<Txid>,
    ) -> HttpRequestType {
        HttpRequestType::MemPoolQuery(
            HttpRequestMetadata::from_host(self.peer_host.clone(), None),
            query,
            page_id_opt,
        )
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::convert::TryInto;
    use std::iter::FromIterator;

    use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
    use crate::burnchains::Burnchain;
    use crate::burnchains::BurnchainView;
    use crate::burnchains::*;
    use crate::chainstate::burn::ConsensusHash;
    use crate::chainstate::stacks::db::blocks::test::*;
    use crate::chainstate::stacks::db::StacksChainState;
    use crate::chainstate::stacks::db::StreamCursor;
    use crate::chainstate::stacks::miner::*;
    use crate::chainstate::stacks::test::*;
    use crate::chainstate::stacks::Error as chain_error;
    use crate::chainstate::stacks::*;
    use crate::net::codec::*;
    use crate::net::http::*;
    use crate::net::test::*;
    use crate::net::*;
    use clarity::vm::types::*;
    use stacks_common::address::*;
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::hash::hex_bytes;
    use stacks_common::util::pipe::*;

    use crate::chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    use crate::types::chainstate::BlockHeaderHash;
    use crate::types::chainstate::BurnchainHeaderHash;

    use crate::core::mempool::{BLOOM_COUNTER_ERROR_RATE, MAX_BLOOM_COUNTER_TXS};

    use super::*;

    const TEST_CONTRACT: &'static str = "
        (define-data-var bar int 0)
        (define-map unit-map { account: principal } { units: int })
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))
        (define-public (add-unit)
          (begin
            (map-set unit-map { account: tx-sender } { units: 1 } )
            (var-set bar 1)
            (ok 1)))
        (begin
          (map-set unit-map { account: 'ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R } { units: 123 }))";

    const TEST_CONTRACT_UNCONFIRMED: &'static str = "(define-read-only (ro-test) (ok 1))";

    fn convo_send_recv(
        sender: &mut ConversationHttp,
        sender_mempool: &MemPoolDB,
        sender_chainstate: &mut StacksChainState,
        receiver: &mut ConversationHttp,
        receiver_mempool: &MemPoolDB,
        receiver_chainstate: &mut StacksChainState,
    ) -> () {
        let (mut pipe_read, mut pipe_write) = Pipe::new();
        pipe_read.set_nonblocking(true);

        loop {
            let res = true;

            sender.try_flush(sender_mempool, sender_chainstate).unwrap();
            receiver
                .try_flush(sender_mempool, receiver_chainstate)
                .unwrap();

            pipe_write.try_flush().unwrap();

            let all_relays_flushed =
                receiver.num_pending_outbound() == 0 && sender.num_pending_outbound() == 0;

            let nw = sender
                .send(&mut pipe_write, sender_mempool, sender_chainstate)
                .unwrap();
            let nr = receiver.recv(&mut pipe_read).unwrap();

            test_debug!(
                "res = {}, all_relays_flushed = {} ({},{}), nr = {}, nw = {}",
                res,
                all_relays_flushed,
                receiver.num_pending_outbound(),
                sender.num_pending_outbound(),
                nr,
                nw
            );
            if res && all_relays_flushed && nr == 0 && nw == 0 {
                test_debug!("Breaking send_recv");
                break;
            }
        }
    }

    /// General testing function to test RPC calls.
    /// This function sets up two peers, a client and a server.
    /// It takes in a function of type F that generates the request to be sent to the server
    /// It takes in another function of type C that verifies that the result from
    /// the server is as expected.
    /// The parameter `include_microblocks` determines whether a microblock stream is mined or not.
    fn test_rpc<F, C>(
        test_name: &str,
        peer_1_p2p: u16,
        peer_1_http: u16,
        peer_2_p2p: u16,
        peer_2_http: u16,
        include_microblocks: bool,
        make_request: F,
        check_result: C,
    ) -> ()
    where
        F: FnOnce(
            &mut TestPeer,
            &mut ConversationHttp,
            &mut TestPeer,
            &mut ConversationHttp,
        ) -> HttpRequestType,
        C: FnOnce(
            &HttpRequestType,
            &HttpResponseType,
            &mut TestPeer,
            &mut TestPeer,
            &ConversationHttp,
            &ConversationHttp,
        ) -> bool,
    {
        let mut peer_1_config = TestPeerConfig::new(test_name, peer_1_p2p, peer_1_http);
        let mut peer_2_config = TestPeerConfig::new(test_name, peer_2_p2p, peer_2_http);

        let peer_1_indexer = BitcoinIndexer::new_unit_test(&peer_1_config.burnchain.working_dir);
        let peer_2_indexer = BitcoinIndexer::new_unit_test(&peer_2_config.burnchain.working_dir);

        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk1 = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk2 = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();
        let microblock_privkey = StacksPrivateKey::new();
        let microblock_pubkeyhash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));

        let addr1 = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk1)],
        )
        .unwrap();
        let addr2 = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk2)],
        )
        .unwrap();

        peer_1_config.initial_balances = vec![
            (addr1.to_account_principal(), 1000000000),
            (addr2.to_account_principal(), 1000000000),
        ];

        peer_2_config.initial_balances = vec![
            (addr1.to_account_principal(), 1000000000),
            (addr2.to_account_principal(), 1000000000),
        ];

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // mine one block with a contract in it
        // first the coinbase
        // make a coinbase for this miner
        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([0x00; 32]), None),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_coinbase_signed = tx_signer.get_tx().unwrap();

        // next the contract
        let contract = TEST_CONTRACT.clone();
        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_smart_contract(
                &format!("hello-world"),
                &contract.to_string(),
                None,
            )
            .unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.auth.set_origin_nonce(1);
        tx_contract.set_tx_fee(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_contract_signed = tx_signer.get_tx().unwrap();

        // update account and state in a microblock that will be unconfirmed
        let mut tx_cc = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_contract_call(addr1.clone(), "hello-world", "add-unit", vec![])
                .unwrap(),
        );

        tx_cc.chain_id = 0x80000000;
        tx_cc.auth.set_origin_nonce(2);
        tx_cc.set_tx_fee(123);

        let mut tx_signer = StacksTransactionSigner::new(&tx_cc);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_cc_signed = tx_signer.get_tx().unwrap();
        let tx_cc_len = {
            let mut bytes = vec![];
            tx_cc_signed.consensus_serialize(&mut bytes).unwrap();
            bytes.len() as u64
        };

        // make an unconfirmed contract
        let unconfirmed_contract = TEST_CONTRACT_UNCONFIRMED.clone();
        let mut tx_unconfirmed_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_smart_contract(
                &format!("hello-world-unconfirmed"),
                &unconfirmed_contract.to_string(),
                None,
            )
            .unwrap(),
        );

        tx_unconfirmed_contract.chain_id = 0x80000000;
        tx_unconfirmed_contract.auth.set_origin_nonce(3);
        tx_unconfirmed_contract.set_tx_fee(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_unconfirmed_contract);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_unconfirmed_contract_signed = tx_signer.get_tx().unwrap();
        let tx_unconfirmed_contract_len = {
            let mut bytes = vec![];
            tx_unconfirmed_contract_signed
                .consensus_serialize(&mut bytes)
                .unwrap();
            bytes.len() as u64
        };

        let tip =
            SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
                .unwrap();
        let mut anchor_cost = ExecutionCost::zero();
        let mut anchor_size = 0;

        // make a block and a microblock.
        // Put the coinbase and smart-contract in the anchored block.
        // Put the contract-call in the microblock
        let (burn_ops, stacks_block, microblocks) = peer_1.make_tenure(
            |ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, _| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                    &parent_tip,
                    vrf_proof,
                    tip.total_burn,
                    microblock_pubkeyhash,
                )
                .unwrap();
                let (anchored_block, anchored_block_size, anchored_block_cost) =
                    StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_conn(),
                        vec![tx_coinbase_signed.clone(), tx_contract_signed.clone()],
                    )
                    .unwrap();

                anchor_size = anchored_block_size;
                anchor_cost = anchored_block_cost;

                (anchored_block, vec![])
            },
        );

        let (_, _, consensus_hash) = peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &vec![]);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &vec![]);

        // begin microblock section
        if include_microblocks {
            // build 1-block microblock stream with the contract-call and the unconfirmed contract
            let microblock = {
                let sortdb = peer_1.sortdb.take().unwrap();
                Relayer::setup_unconfirmed_state(peer_1.chainstate(), &sortdb).unwrap();
                let mblock = {
                    let sort_iconn = sortdb.index_conn();
                    let mut microblock_builder = StacksMicroblockBuilder::new(
                        stacks_block.block_hash(),
                        consensus_hash.clone(),
                        peer_1.chainstate(),
                        &sort_iconn,
                        BlockBuilderSettings::max_value(),
                    )
                    .unwrap();
                    let microblock = microblock_builder
                        .mine_next_microblock_from_txs(
                            vec![
                                (tx_cc_signed, tx_cc_len),
                                (tx_unconfirmed_contract_signed, tx_unconfirmed_contract_len),
                            ],
                            &microblock_privkey,
                        )
                        .unwrap();
                    microblock
                };
                peer_1.sortdb = Some(sortdb);
                mblock
            };

            // store microblock stream
            peer_1
                .chainstate()
                .preprocess_streamed_microblock(
                    &consensus_hash,
                    &stacks_block.block_hash(),
                    &microblock,
                )
                .unwrap();
            peer_2
                .chainstate()
                .preprocess_streamed_microblock(
                    &consensus_hash,
                    &stacks_block.block_hash(),
                    &microblock,
                )
                .unwrap();

            // process microblock stream to generate unconfirmed state
            let canonical_tip = StacksBlockHeader::make_index_block_hash(
                &consensus_hash,
                &stacks_block.block_hash(),
            );
            let sortdb1 = peer_1.sortdb.take().unwrap();
            let sortdb2 = peer_2.sortdb.take().unwrap();
            peer_1
                .chainstate()
                .reload_unconfirmed_state(&sortdb1.index_conn(), canonical_tip.clone())
                .unwrap();
            peer_2
                .chainstate()
                .reload_unconfirmed_state(&sortdb2.index_conn(), canonical_tip.clone())
                .unwrap();
            peer_1.sortdb = Some(sortdb1);
            peer_2.sortdb = Some(sortdb2);
        }
        // end microblock section

        // stuff some transactions into peer_2's mempool
        // (relates to mempool query tests)
        let mut mempool = peer_2.mempool.take().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();
        for i in 0..10 {
            let pk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&StacksPrivateKey::new())],
            )
            .unwrap();
            let mut tx = StacksTransaction {
                version: TransactionVersion::Testnet,
                chain_id: 0x80000000,
                auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                anchor_mode: TransactionAnchorMode::Any,
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: vec![],
                payload: TransactionPayload::TokenTransfer(
                    addr.to_account_principal(),
                    123,
                    TokenTransferMemo([0u8; 34]),
                ),
            };
            tx.set_tx_fee(1000);
            tx.set_origin_nonce(0);

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let origin_addr = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let tx_fee = tx.get_tx_fee();

            // should succeed
            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                peer_1.chainstate(),
                &consensus_hash,
                &stacks_block.block_hash(),
                txid.clone(),
                tx_bytes,
                tx_fee,
                stacks_block.header.total_work.work,
                &origin_addr,
                origin_nonce,
                &sponsor_addr,
                sponsor_nonce,
                None,
            )
            .unwrap();
        }
        mempool_tx.commit().unwrap();
        peer_2.mempool.replace(mempool);

        let peer_1_sortdb = peer_1.sortdb.take().unwrap();
        let peer_1_stacks_node = peer_1.stacks_node.take().unwrap();
        let _ = peer_1
            .network
            .refresh_burnchain_view(
                &peer_1_indexer,
                &peer_1_sortdb,
                &peer_1_stacks_node.chainstate,
                false,
            )
            .unwrap();
        peer_1.sortdb = Some(peer_1_sortdb);
        peer_1.stacks_node = Some(peer_1_stacks_node);

        let peer_2_sortdb = peer_2.sortdb.take().unwrap();
        let peer_2_stacks_node = peer_2.stacks_node.take().unwrap();
        let _ = peer_2
            .network
            .refresh_burnchain_view(
                &peer_2_indexer,
                &peer_2_sortdb,
                &peer_2_stacks_node.chainstate,
                false,
            )
            .unwrap();
        peer_2.sortdb = Some(peer_2_sortdb);
        peer_2.stacks_node = Some(peer_2_stacks_node);

        let view_1 = peer_1.get_burnchain_view().unwrap();
        let view_2 = peer_2.get_burnchain_view().unwrap();

        let mut convo_1 = ConversationHttp::new(
            format!("127.0.0.1:{}", peer_1_http)
                .parse::<SocketAddr>()
                .unwrap(),
            Some(UrlString::try_from(format!("http://peer1.com")).unwrap()),
            peer_1.to_peer_host(),
            &peer_1.config.connection_opts,
            0,
        );

        let mut convo_2 = ConversationHttp::new(
            format!("127.0.0.1:{}", peer_2_http)
                .parse::<SocketAddr>()
                .unwrap(),
            Some(UrlString::try_from(format!("http://peer2.com")).unwrap()),
            peer_2.to_peer_host(),
            &peer_2.config.connection_opts,
            1,
        );

        let req = make_request(&mut peer_1, &mut convo_1, &mut peer_2, &mut convo_2);

        convo_1.send_request(req.clone()).unwrap();
        let mut peer_1_mempool = peer_1.mempool.take().unwrap();
        let peer_2_mempool = peer_2.mempool.take().unwrap();

        test_debug!("convo1 sends to convo2");
        convo_send_recv(
            &mut convo_1,
            &peer_1_mempool,
            peer_1.chainstate(),
            &mut convo_2,
            &peer_2_mempool,
            peer_2.chainstate(),
        );

        // hack around the borrow-checker
        let mut peer_1_sortdb = peer_1.sortdb.take().unwrap();
        let mut peer_1_stacks_node = peer_1.stacks_node.take().unwrap();

        Relayer::setup_unconfirmed_state(&mut peer_1_stacks_node.chainstate, &peer_1_sortdb)
            .unwrap();

        convo_1
            .chat(
                &mut peer_1.network,
                &mut peer_1_sortdb,
                &mut peer_1_stacks_node.chainstate,
                &mut peer_1_mempool,
                &RPCHandlerArgs::default(),
            )
            .unwrap();

        peer_1.sortdb = Some(peer_1_sortdb);
        peer_1.stacks_node = Some(peer_1_stacks_node);
        peer_1.mempool = Some(peer_1_mempool);
        peer_2.mempool = Some(peer_2_mempool);

        test_debug!("convo2 sends to convo1");

        // hack around the borrow-checker
        let mut peer_2_sortdb = peer_2.sortdb.take().unwrap();
        let mut peer_2_stacks_node = peer_2.stacks_node.take().unwrap();
        let mut peer_2_mempool = peer_2.mempool.take().unwrap();

        let _ = peer_2
            .network
            .refresh_burnchain_view(
                &peer_2_indexer,
                &peer_2_sortdb,
                &peer_2_stacks_node.chainstate,
                false,
            )
            .unwrap();

        Relayer::setup_unconfirmed_state(&mut peer_2_stacks_node.chainstate, &peer_2_sortdb)
            .unwrap();

        convo_2
            .chat(
                &mut peer_2.network,
                &mut peer_2_sortdb,
                &mut peer_2_stacks_node.chainstate,
                &mut peer_2_mempool,
                &RPCHandlerArgs::default(),
            )
            .unwrap();

        peer_2.sortdb = Some(peer_2_sortdb);
        peer_2.stacks_node = Some(peer_2_stacks_node);
        let mut peer_1_mempool = peer_1.mempool.take().unwrap();

        convo_send_recv(
            &mut convo_2,
            &peer_2_mempool,
            peer_2.chainstate(),
            &mut convo_1,
            &peer_1_mempool,
            peer_1.chainstate(),
        );

        test_debug!("flush convo1");

        // hack around the borrow-checker
        convo_send_recv(
            &mut convo_1,
            &peer_1_mempool,
            peer_1.chainstate(),
            &mut convo_2,
            &peer_2_mempool,
            peer_2.chainstate(),
        );

        peer_2.mempool = Some(peer_2_mempool);

        let mut peer_1_sortdb = peer_1.sortdb.take().unwrap();
        let mut peer_1_stacks_node = peer_1.stacks_node.take().unwrap();

        let _ = peer_1
            .network
            .refresh_burnchain_view(
                &peer_1_indexer,
                &peer_1_sortdb,
                &peer_1_stacks_node.chainstate,
                false,
            )
            .unwrap();

        Relayer::setup_unconfirmed_state(&mut peer_1_stacks_node.chainstate, &peer_1_sortdb)
            .unwrap();

        convo_1
            .chat(
                &mut peer_1.network,
                &mut peer_1_sortdb,
                &mut peer_1_stacks_node.chainstate,
                &mut peer_1_mempool,
                &RPCHandlerArgs::default(),
            )
            .unwrap();

        convo_1
            .try_flush(&peer_1_mempool, &mut peer_1_stacks_node.chainstate)
            .unwrap();

        peer_1.sortdb = Some(peer_1_sortdb);
        peer_1.stacks_node = Some(peer_1_stacks_node);
        peer_1.mempool = Some(peer_1_mempool);

        // should have gotten a reply
        let resp_opt = convo_1.try_get_response();
        assert!(resp_opt.is_some());

        let resp = resp_opt.unwrap();
        assert!(check_result(
            &req,
            &resp,
            &mut peer_1,
            &mut peer_2,
            &convo_1,
            &convo_2
        ));
    }

    /// This test tests two things:
    /// (1) the get info RPC call
    /// (2) whether the ConversationHttp object gets correctly updated with a peer's canonical
    /// stacks tip height, which is sent in HTTP headers as part of the request/response
    #[test]
    #[ignore]
    fn test_rpc_getinfo() {
        let peer_server_info = RefCell::new(None);
        let client_stacks_height = 17;
        test_rpc(
            function_name!(),
            40000,
            40001,
            50000,
            50001,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let peer_info = RPCPeerInfoData::from_network(
                    &peer_server.network,
                    &peer_server.stacks_node.as_ref().unwrap().chainstate,
                    None,
                    &Sha256Sum::zero(),
                );

                *peer_server_info.borrow_mut() = Some(peer_info);

                convo_client.new_getinfo(Some(client_stacks_height))
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                assert_eq!(convo_client.canonical_stacks_tip_height, Some(1));
                assert_eq!(
                    convo_server.canonical_stacks_tip_height,
                    Some(client_stacks_height)
                );
                match http_response {
                    HttpResponseType::PeerInfo(response_md, peer_data) => {
                        assert_eq!(Some((*peer_data).clone()), *peer_server_info.borrow());
                        assert!(peer_data.node_public_key.is_some());
                        assert!(peer_data.node_public_key_hash.is_some());
                        assert_eq!(
                            peer_data.node_public_key_hash,
                            Some(Hash160::from_node_public_key(
                                &peer_data
                                    .node_public_key
                                    .clone()
                                    .unwrap()
                                    .to_public_key()
                                    .unwrap()
                            ))
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_getpoxinfo() {
        // Test v2/pox (aka GetPoxInfo) endpoint.
        // In this test, `tip_req` is set to UseLatestAnchoredTip.
        // Thus, the query for pox info will be against the canonical Stacks tip, which we expect to succeed.
        let pox_server_info = RefCell::new(None);
        test_rpc(
            function_name!(),
            40002,
            40003,
            50002,
            50003,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let mut sortdb = peer_server.sortdb.as_mut().unwrap();
                let chainstate = &mut peer_server.stacks_node.as_mut().unwrap().chainstate;
                let stacks_block_id = {
                    let tip = chainstate.get_stacks_chain_tip(sortdb).unwrap().unwrap();
                    StacksBlockHeader::make_index_block_hash(
                        &tip.consensus_hash,
                        &tip.anchored_block_hash,
                    )
                };
                let pox_info = RPCPoxInfoData::from_db(
                    &mut sortdb,
                    chainstate,
                    &stacks_block_id,
                    &peer_client.config.burnchain,
                )
                .unwrap();
                *pox_server_info.borrow_mut() = Some(pox_info);
                convo_client.new_getpoxinfo(TipRequest::UseLatestAnchoredTip)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             convo_client,
             convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::PoxInfo(response_md, pox_data) => {
                        assert_eq!(Some((*pox_data).clone()), *pox_server_info.borrow());
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_getpoxinfo_use_latest_tip() {
        // Test v2/pox (aka GetPoxInfo) endpoint.
        // In this test, we set `tip_req` to UseLatestUnconfirmedTip, and we expect that querying for pox
        // info against the unconfirmed state will succeed.
        let pox_server_info = RefCell::new(None);
        test_rpc(
            function_name!(),
            40004,
            40005,
            50004,
            50005,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let mut sortdb = peer_server.sortdb.as_mut().unwrap();
                let chainstate = &mut peer_server.stacks_node.as_mut().unwrap().chainstate;
                let stacks_block_id = chainstate
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                let pox_info = RPCPoxInfoData::from_db(
                    &mut sortdb,
                    chainstate,
                    &stacks_block_id,
                    &peer_client.config.burnchain,
                )
                .unwrap();
                *pox_server_info.borrow_mut() = Some(pox_info);
                convo_client.new_getpoxinfo(TipRequest::UseLatestUnconfirmedTip)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::PoxInfo(response_md, pox_data) => {
                        assert_eq!(Some((*pox_data).clone()), *pox_server_info.borrow());
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_getneighbors() {
        test_rpc(
            function_name!(),
            40010,
            40011,
            50010,
            50011,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| { convo_client.new_getneighbors() },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::Neighbors(response_md, neighbor_info) => {
                        assert_eq!(neighbor_info.sample.len(), 1);
                        assert_eq!(neighbor_info.sample[0].port, peer_client.config.server_port); // we see ourselves as the neighbor
                        assert_eq!(neighbor_info.bootstrap.len(), 1);
                        assert_eq!(
                            neighbor_info.bootstrap[0].port,
                            peer_client.config.server_port
                        ); // we see ourselves as the bootstrap
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_getheaders() {
        let server_blocks_cell = RefCell::new(None);

        test_rpc(
            function_name!(),
            40012,
            40013,
            50012,
            50013,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                // have "server" peer store a few continuous block to staging
                let mut blocks: Vec<StacksBlock> = vec![];
                let mut index_block_hashes = vec![];
                for i in 0..25 {
                    let mut peer_server_block = make_codec_test_block(25);

                    peer_server_block.header.total_work.work = (i + 1) as u64;
                    peer_server_block.header.total_work.burn = (i + 1) as u64;
                    peer_server_block.header.parent_block = blocks
                        .last()
                        .map(|blk| blk.block_hash())
                        .unwrap_or(BlockHeaderHash([0u8; 32]));

                    let peer_server_consensus_hash = ConsensusHash([(i + 1) as u8; 20]);
                    let index_block_hash = StacksBlockHeader::make_index_block_hash(
                        &peer_server_consensus_hash,
                        &peer_server_block.block_hash(),
                    );

                    test_debug!("Store peer server index block {:?}", &index_block_hash);
                    store_staging_block(
                        peer_server.chainstate(),
                        &peer_server_consensus_hash,
                        &peer_server_block,
                        &ConsensusHash([i as u8; 20]),
                        456,
                        123,
                    );
                    set_block_processed(
                        peer_server.chainstate(),
                        &peer_server_consensus_hash,
                        &peer_server_block.block_hash(),
                        true,
                    );

                    index_block_hashes.push(index_block_hash);
                    blocks.push(peer_server_block);
                }

                let rev_blocks: Vec<_> = blocks.into_iter().rev().collect();
                let rev_ibhs: Vec<_> = index_block_hashes.into_iter().rev().collect();

                let tip = rev_ibhs[0].clone();
                *server_blocks_cell.borrow_mut() = Some((rev_blocks, rev_ibhs));

                // now ask for it
                convo_client.new_getheaders(25, TipRequest::SpecificTip(tip))
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::Headers(response_md, headers) => {
                        assert_eq!(headers.len(), 25);
                        let expected = server_blocks_cell.borrow().clone().unwrap();
                        for (i, h) in headers.iter().enumerate() {
                            assert_eq!(h.header, expected.0[i].header);
                            assert_eq!(h.consensus_hash, ConsensusHash([(25 - i) as u8; 20]));
                            if i + 1 < headers.len() {
                                assert_eq!(h.parent_block_id, expected.1[i + 1]);
                            }
                        }
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_unconfirmed_getblock() {
        let server_block_cell = RefCell::new(None);

        test_rpc(
            function_name!(),
            40020,
            40021,
            50020,
            50021,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                // have "server" peer store a block to staging
                let peer_server_block = make_codec_test_block(25);
                let peer_server_consensus_hash = ConsensusHash([0x02; 20]);
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &peer_server_consensus_hash,
                    &peer_server_block.block_hash(),
                );

                test_debug!("Store peer server index block {:?}", &index_block_hash);
                store_staging_block(
                    peer_server.chainstate(),
                    &peer_server_consensus_hash,
                    &peer_server_block,
                    &ConsensusHash([0x03; 20]),
                    456,
                    123,
                );

                *server_block_cell.borrow_mut() = Some(peer_server_block);

                // now ask for it
                convo_client.new_getblock(index_block_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::Block(response_md, block_info) => {
                        assert_eq!(
                            block_info.block_hash(),
                            (*server_block_cell.borrow()).as_ref().unwrap().block_hash()
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_confirmed_getblock() {
        let server_block_cell = RefCell::new(None);

        test_rpc(
            function_name!(),
            40030,
            40031,
            50030,
            50031,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                // have "server" peer store a block to staging
                let peer_server_block = make_codec_test_block(25);
                let peer_server_consensus_hash = ConsensusHash([0x02; 20]);
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &peer_server_consensus_hash,
                    &peer_server_block.block_hash(),
                );

                test_debug!("Store peer server index block {:?}", &index_block_hash);
                store_staging_block(
                    peer_server.chainstate(),
                    &peer_server_consensus_hash,
                    &peer_server_block,
                    &ConsensusHash([0x03; 20]),
                    456,
                    123,
                );
                set_block_processed(
                    peer_server.chainstate(),
                    &peer_server_consensus_hash,
                    &peer_server_block.block_hash(),
                    true,
                );

                *server_block_cell.borrow_mut() = Some(peer_server_block);

                // now ask for it
                convo_client.new_getblock(index_block_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::Block(response_md, block_info) => {
                        assert_eq!(
                            block_info.block_hash(),
                            (*server_block_cell.borrow()).as_ref().unwrap().block_hash()
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_indexed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc(
            function_name!(),
            40040,
            40041,
            50040,
            50041,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let privk = StacksPrivateKey::from_hex(
                    "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
                )
                .unwrap();

                let parent_block = make_codec_test_block(25);
                let parent_consensus_hash = ConsensusHash([0x02; 20]);
                let parent_index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &parent_consensus_hash,
                    &parent_block.block_hash(),
                );

                let mut mblocks = make_sample_microblock_stream(&privk, &parent_block.block_hash());
                mblocks.truncate(15);

                let mut child_block = make_codec_test_block(25);
                let child_consensus_hash = ConsensusHash([0x03; 20]);

                child_block.header.parent_block = parent_block.block_hash();
                child_block.header.parent_microblock =
                    mblocks.last().as_ref().unwrap().block_hash();
                child_block.header.parent_microblock_sequence =
                    mblocks.last().as_ref().unwrap().header.sequence;

                store_staging_block(
                    peer_server.chainstate(),
                    &parent_consensus_hash,
                    &parent_block,
                    &ConsensusHash([0x01; 20]),
                    456,
                    123,
                );
                set_block_processed(
                    peer_server.chainstate(),
                    &parent_consensus_hash,
                    &parent_block.block_hash(),
                    true,
                );

                store_staging_block(
                    peer_server.chainstate(),
                    &child_consensus_hash,
                    &child_block,
                    &parent_consensus_hash,
                    456,
                    123,
                );
                set_block_processed(
                    peer_server.chainstate(),
                    &child_consensus_hash,
                    &child_block.block_hash(),
                    true,
                );

                let index_microblock_hash = StacksBlockHeader::make_index_block_hash(
                    &parent_consensus_hash,
                    &mblocks.last().as_ref().unwrap().block_hash(),
                );

                for mblock in mblocks.iter() {
                    store_staging_microblock(
                        peer_server.chainstate(),
                        &parent_consensus_hash,
                        &parent_block.block_hash(),
                        &mblock,
                    );
                }

                set_microblocks_processed(
                    peer_server.chainstate(),
                    &child_consensus_hash,
                    &child_block.block_hash(),
                    &mblocks.last().as_ref().unwrap().block_hash(),
                );

                *server_microblocks_cell.borrow_mut() = mblocks;

                convo_client.new_getmicroblocks_indexed(index_microblock_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match (*http_response).clone() {
                    HttpResponseType::Microblocks(_, mut microblocks) => {
                        microblocks.reverse();
                        assert_eq!(microblocks.len(), (*server_microblocks_cell.borrow()).len());
                        assert_eq!(microblocks, *server_microblocks_cell.borrow());
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_confirmed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc(
            function_name!(),
            40042,
            40043,
            50042,
            50043,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let privk = StacksPrivateKey::from_hex(
                    "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
                )
                .unwrap();

                let parent_block = make_codec_test_block(25);
                let parent_consensus_hash = ConsensusHash([0x02; 20]);

                let mut mblocks = make_sample_microblock_stream(&privk, &parent_block.block_hash());
                mblocks.truncate(15);

                let mut child_block = make_codec_test_block(25);
                let child_consensus_hash = ConsensusHash([0x03; 20]);

                child_block.header.parent_block = parent_block.block_hash();
                child_block.header.parent_microblock =
                    mblocks.last().as_ref().unwrap().block_hash();
                child_block.header.parent_microblock_sequence =
                    mblocks.last().as_ref().unwrap().header.sequence;

                let child_index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &child_consensus_hash,
                    &child_block.block_hash(),
                );

                store_staging_block(
                    peer_server.chainstate(),
                    &parent_consensus_hash,
                    &parent_block,
                    &ConsensusHash([0x01; 20]),
                    456,
                    123,
                );
                set_block_processed(
                    peer_server.chainstate(),
                    &parent_consensus_hash,
                    &parent_block.block_hash(),
                    true,
                );

                store_staging_block(
                    peer_server.chainstate(),
                    &child_consensus_hash,
                    &child_block,
                    &parent_consensus_hash,
                    456,
                    123,
                );
                set_block_processed(
                    peer_server.chainstate(),
                    &child_consensus_hash,
                    &child_block.block_hash(),
                    true,
                );

                for mblock in mblocks.iter() {
                    store_staging_microblock(
                        peer_server.chainstate(),
                        &parent_consensus_hash,
                        &parent_block.block_hash(),
                        &mblock,
                    );
                }

                set_microblocks_processed(
                    peer_server.chainstate(),
                    &child_consensus_hash,
                    &child_block.block_hash(),
                    &mblocks.last().as_ref().unwrap().block_hash(),
                );

                *server_microblocks_cell.borrow_mut() = mblocks;

                convo_client.new_getmicroblocks_confirmed(child_index_block_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match (*http_response).clone() {
                    HttpResponseType::Microblocks(_, mut microblocks) => {
                        microblocks.reverse();
                        assert_eq!(microblocks.len(), (*server_microblocks_cell.borrow()).len());
                        assert_eq!(microblocks, *server_microblocks_cell.borrow());
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_unconfirmed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc(
            function_name!(),
            40050,
            40051,
            50050,
            50051,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let privk = StacksPrivateKey::from_hex(
                    "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
                )
                .unwrap();

                let consensus_hash = ConsensusHash([0x02; 20]);
                let anchored_block_hash = BlockHeaderHash([0x03; 32]);
                let index_block_hash =
                    StacksBlockHeader::make_index_block_hash(&consensus_hash, &anchored_block_hash);

                let mut mblocks = make_sample_microblock_stream(&privk, &anchored_block_hash);
                mblocks.truncate(15);

                for mblock in mblocks.iter() {
                    store_staging_microblock(
                        peer_server.chainstate(),
                        &consensus_hash,
                        &anchored_block_hash,
                        &mblock,
                    );
                }

                *server_microblocks_cell.borrow_mut() = mblocks;

                // start at seq 5
                convo_client.new_getmicroblocks_unconfirmed(index_block_hash, 5)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::Microblocks(response_md, microblocks) => {
                        assert_eq!(microblocks.len(), 10);
                        assert_eq!(
                            *microblocks,
                            (*server_microblocks_cell.borrow())[5..].to_vec()
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_unconfirmed_transaction() {
        let last_txid = RefCell::new(Txid([0u8; 32]));
        let last_mblock = RefCell::new(BlockHeaderHash([0u8; 32]));

        test_rpc(
            function_name!(),
            40052,
            40053,
            50052,
            50053,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let privk = StacksPrivateKey::from_hex(
                    "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
                )
                .unwrap();

                let sortdb = peer_server.sortdb.take().unwrap();
                Relayer::setup_unconfirmed_state(peer_server.chainstate(), &sortdb).unwrap();
                peer_server.sortdb = Some(sortdb);

                assert!(peer_server.chainstate().unconfirmed_state.is_some());
                let (txid, mblock_hash) = match peer_server.chainstate().unconfirmed_state {
                    Some(ref unconfirmed) => {
                        assert!(unconfirmed.mined_txs.len() > 0);
                        let mut txid = Txid([0u8; 32]);
                        let mut mblock_hash = BlockHeaderHash([0u8; 32]);
                        for (next_txid, (_, mbh, ..)) in unconfirmed.mined_txs.iter() {
                            txid = next_txid.clone();
                            mblock_hash = mbh.clone();
                            break;
                        }
                        (txid, mblock_hash)
                    }
                    None => {
                        panic!("No unconfirmed state");
                    }
                };

                *last_txid.borrow_mut() = txid.clone();
                *last_mblock.borrow_mut() = mblock_hash.clone();

                convo_client.new_gettransaction_unconfirmed(txid)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::UnconfirmedTransaction(response_md, unconfirmed_resp) => {
                        assert_eq!(
                            unconfirmed_resp.status,
                            UnconfirmedTransactionStatus::Microblock {
                                block_hash: (*last_mblock.borrow()).clone(),
                                seq: 0
                            }
                        );
                        let tx = StacksTransaction::consensus_deserialize(
                            &mut &hex_bytes(&unconfirmed_resp.tx).unwrap()[..],
                        )
                        .unwrap();
                        assert_eq!(tx.txid(), *last_txid.borrow());
                        true
                    }
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_missing_getblock() {
        test_rpc(
            function_name!(),
            40060,
            40061,
            50060,
            50061,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let peer_server_block_hash = BlockHeaderHash([0x04; 32]);
                let peer_server_consensus_hash = ConsensusHash([0x02; 20]);
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &peer_server_consensus_hash,
                    &peer_server_block_hash,
                );

                // now ask for it
                convo_client.new_getblock(index_block_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(response_md, msg) => true,
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_missing_index_getmicroblocks() {
        test_rpc(
            function_name!(),
            40070,
            40071,
            50070,
            50071,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let peer_server_block_hash = BlockHeaderHash([0x04; 32]);
                let peer_server_consensus_hash = ConsensusHash([0x02; 20]);
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &peer_server_consensus_hash,
                    &peer_server_block_hash,
                );

                // now ask for it
                convo_client.new_getmicroblocks_indexed(index_block_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(response_md, msg) => true,
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_missing_confirmed_getmicroblocks() {
        test_rpc(
            function_name!(),
            40072,
            40073,
            50072,
            50073,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let peer_server_block_hash = BlockHeaderHash([0x04; 32]);
                let peer_server_consensus_hash = ConsensusHash([0x02; 20]);
                let index_block_hash = StacksBlockHeader::make_index_block_hash(
                    &peer_server_consensus_hash,
                    &peer_server_block_hash,
                );

                // now ask for it
                convo_client.new_getmicroblocks_confirmed(index_block_hash)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(response_md, msg) => true,
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_missing_unconfirmed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc(
            function_name!(),
            40080,
            40081,
            50080,
            50081,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let privk = StacksPrivateKey::from_hex(
                    "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
                )
                .unwrap();

                let consensus_hash = ConsensusHash([0x02; 20]);
                let anchored_block_hash = BlockHeaderHash([0x03; 32]);
                let index_block_hash =
                    StacksBlockHeader::make_index_block_hash(&consensus_hash, &anchored_block_hash);

                let mut mblocks = make_sample_microblock_stream(&privk, &anchored_block_hash);
                mblocks.truncate(15);

                for mblock in mblocks.iter() {
                    store_staging_microblock(
                        peer_server.chainstate(),
                        &consensus_hash,
                        &anchored_block_hash,
                        &mblock,
                    );
                }

                *server_microblocks_cell.borrow_mut() = mblocks;

                // start at seq 16 (which doesn't exist)
                convo_client.new_getmicroblocks_unconfirmed(index_block_hash, 16)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(response_md, msg) => true,
                    _ => {
                        error!("Invalid response: {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_src() {
        // Test v2/contracts/source (aka GetContractSrc) endpoint.
        // In this test, we don't set any tip parameters, and allow the endpoint to execute against
        // the canonical Stacks tip.
        // The contract source we are querying for exists in the anchored state, so we expect the
        // query to succeed.
        test_rpc(
            function_name!(),
            40090,
            40091,
            50090,
            50091,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getcontractsrc(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetContractSrc(response_md, data) => {
                        assert_eq!(data.source, TEST_CONTRACT);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_src_unconfirmed_with_canonical_tip() {
        // Test v2/contracts/source (aka GetContractSrc) endpoint.
        // In this test, we don't set any tip parameters, and allow the endpoint to execute against
        // the canonical Stacks tip.
        // The contract source we are querying for only exists in the unconfirmed state, so we
        // expect the query to fail.
        test_rpc(
            function_name!(),
            40100,
            40101,
            50100,
            50101,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getcontractsrc(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(_, error_str) => {
                        assert_eq!(error_str, "No contract source data found");
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_src_with_unconfirmed_tip() {
        // Test v2/contracts/source (aka GetContractSrc) endpoint.
        // In this test, we set `tip_req` to be the unconfirmed chain tip.
        // The contract source we are querying for exists in the unconfirmed state, so we expect
        // the query to succeed.
        test_rpc(
            function_name!(),
            40102,
            40103,
            50102,
            50103,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let unconfirmed_tip = peer_client
                    .chainstate()
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                convo_client.new_getcontractsrc(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    TipRequest::SpecificTip(unconfirmed_tip),
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetContractSrc(response_md, data) => {
                        assert_eq!(data.source, TEST_CONTRACT_UNCONFIRMED);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_src_use_latest_tip() {
        // Test v2/contracts/source (aka GetContractSrc) endpoint.
        // In this test, we set `tip_req` to UseLatestUnconfirmedTip.
        // The contract source we are querying for exists in the unconfirmed state, so we expect
        // the query to succeed.
        test_rpc(
            function_name!(),
            40104,
            40105,
            50104,
            50105,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getcontractsrc(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetContractSrc(response_md, data) => {
                        assert_eq!(data.source, TEST_CONTRACT_UNCONFIRMED);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_account() {
        test_rpc(
            function_name!(),
            40110,
            40111,
            50110,
            50111,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getaccount(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetAccount(response_md, data) => {
                        assert_eq!(data.nonce, 2);
                        let balance = u128::from_str_radix(&data.balance[2..], 16).unwrap();
                        assert_eq!(balance, 1000000000);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    /// In this test, the query parameter `tip_req` is set to UseLatestUnconfirmedTip, and so we expect the
    /// tip used for the query to be the latest microblock.
    /// We check that the account state matches the state in the most recent microblock.
    #[test]
    #[ignore]
    fn test_rpc_get_account_use_latest_tip() {
        test_rpc(
            function_name!(),
            40112,
            40113,
            50112,
            50113,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getaccount(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetAccount(response_md, data) => {
                        assert_eq!(data.nonce, 4);
                        let balance = u128::from_str_radix(&data.balance[2..], 16).unwrap();
                        assert_eq!(balance, 999999877);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    /// In this test, the query parameter `tip_req` is set to UseLatestUnconfirmedTip, but we did not generate
    /// microblocks in the rpc test. Thus, we expect the tip used for the query to be the previous
    /// anchor block (which is the latest tip).
    /// We check that the account state matches the state in the previous anchor block.
    #[test]
    #[ignore]
    fn test_rpc_get_account_use_latest_tip_no_microblocks() {
        test_rpc(
            function_name!(),
            40114,
            40115,
            50114,
            50115,
            false,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getaccount(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetAccount(response_md, data) => {
                        assert_eq!(data.nonce, 2);
                        let balance = u128::from_str_radix(&data.balance[2..], 16).unwrap();
                        assert_eq!(balance, 1000000000);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_account_unconfirmed() {
        test_rpc(
            function_name!(),
            40120,
            40121,
            50120,
            50121,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let unconfirmed_tip = peer_client
                    .chainstate()
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                convo_client.new_getaccount(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    TipRequest::SpecificTip(unconfirmed_tip),
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetAccount(response_md, data) => {
                        assert_eq!(data.nonce, 4);
                        let balance = u128::from_str_radix(&data.balance[2..], 16).unwrap();
                        assert_eq!(balance, 1000000000 - 123);
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_data_var() {
        test_rpc(
            function_name!(),
            40122,
            40123,
            50122,
            50123,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getdatavar(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    "bar".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetDataVar(response_md, data) => {
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                            Value::Int(0)
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_data_var_unconfirmed() {
        test_rpc(
            function_name!(),
            40124,
            40125,
            50124,
            50125,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let unconfirmed_tip = peer_client
                    .chainstate()
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                convo_client.new_getdatavar(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    "bar".try_into().unwrap(),
                    TipRequest::SpecificTip(unconfirmed_tip),
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetDataVar(response_md, data) => {
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                            Value::Int(1)
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_data_var_nonexistant() {
        test_rpc(
            function_name!(),
            40125,
            40126,
            50125,
            50126,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getdatavar(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    "bar-nonexistant".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(_, msg) => {
                        assert_eq!(msg, "Data var not found");
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_map_entry() {
        // Test v2/map_entry (aka GetMapEntry) endpoint.
        // In this test, we don't set any tip parameters, and we expect that querying for map data
        // against the canonical Stacks tip will succeed.
        test_rpc(
            function_name!(),
            40130,
            40131,
            50130,
            50131,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let principal =
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal();
                convo_client.new_getmapentry(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    "unit-map".try_into().unwrap(),
                    Value::Tuple(
                        TupleData::from_data(vec![("account".into(), Value::Principal(principal))])
                            .unwrap(),
                    ),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetMapEntry(response_md, data) => {
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                            Value::some(Value::Tuple(
                                TupleData::from_data(vec![("units".into(), Value::Int(123))])
                                    .unwrap()
                            ))
                            .unwrap()
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_map_entry_unconfirmed() {
        // Test v2/map_entry (aka GetMapEntry) endpoint.
        // In this test, we set `tip_req` to UseLatestUnconfirmedTip, and we expect that querying for map data
        // against the unconfirmed state will succeed.
        test_rpc(
            function_name!(),
            40140,
            40141,
            50140,
            50141,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let unconfirmed_tip = peer_client
                    .chainstate()
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                let principal =
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal();
                convo_client.new_getmapentry(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    "unit-map".try_into().unwrap(),
                    Value::Tuple(
                        TupleData::from_data(vec![("account".into(), Value::Principal(principal))])
                            .unwrap(),
                    ),
                    TipRequest::SpecificTip(unconfirmed_tip),
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetMapEntry(response_md, data) => {
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                            Value::some(Value::Tuple(
                                TupleData::from_data(vec![("units".into(), Value::Int(1))])
                                    .unwrap()
                            ))
                            .unwrap()
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_map_entry_use_latest_tip() {
        test_rpc(
            function_name!(),
            40142,
            40143,
            50142,
            50143,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let principal =
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal();
                convo_client.new_getmapentry(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world".try_into().unwrap(),
                    "unit-map".try_into().unwrap(),
                    Value::Tuple(
                        TupleData::from_data(vec![("account".into(), Value::Principal(principal))])
                            .unwrap(),
                    ),
                    TipRequest::UseLatestAnchoredTip,
                    false,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetMapEntry(response_md, data) => {
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.data).unwrap(),
                            Value::some(Value::Tuple(
                                TupleData::from_data(vec![("units".into(), Value::Int(1))])
                                    .unwrap()
                            ))
                            .unwrap()
                        );
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_abi() {
        // Test /v2/contracts/interface (aka GetContractABI) endpoint.
        // In this test, we don't set any tip parameters, and we expect that querying
        // against the canonical Stacks tip will succeed.
        test_rpc(
            function_name!(),
            40150,
            40151,
            50150,
            50151,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getcontractabi(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::NotFound(..) => {
                        // not confirmed yet
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_abi_unconfirmed() {
        // Test /v2/contracts/interface (aka GetContractABI) endpoint.
        // In this test, we set `tip_req` to UseLatestUnconfirmedTip, and we expect that querying
        // against the unconfirmed state will succeed.
        test_rpc(
            function_name!(),
            40152,
            40153,
            50152,
            50153,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let unconfirmed_tip = peer_client
                    .chainstate()
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                convo_client.new_getcontractabi(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    TipRequest::SpecificTip(unconfirmed_tip),
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetContractABI(response_md, data) => true,
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_get_contract_abi_use_latest_tip() {
        test_rpc(
            function_name!(),
            40154,
            40155,
            50154,
            50155,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_getcontractabi(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    TipRequest::UseLatestAnchoredTip,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::GetContractABI(response_md, data) => true,
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_call_read_only() {
        // Test /v2/contracts/call-read (aka CallReadOnlyFunction) endpoint.
        // In this test, we don't set any tip parameters, and we expect that querying
        // against the canonical Stacks tip will succeed.
        test_rpc(
            function_name!(),
            40170,
            40171,
            50170,
            50171,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_callreadonlyfunction(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    None,
                    "ro-test".try_into().unwrap(),
                    vec![],
                    TipRequest::UseLatestAnchoredTip,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::CallReadOnlyFunction(response_md, data) => {
                        assert!(data.cause.is_some());
                        assert!(data.cause.clone().unwrap().find("NoSuchContract").is_some());
                        assert!(!data.okay);
                        assert!(data.result.is_none());
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_call_read_only_use_latest_tip() {
        // Test /v2/contracts/call-read (aka CallReadOnlyFunction) endpoint.
        // In this test, we set `tip_req` to UseLatestUnconfirmedTip, and we expect that querying
        // against the unconfirmed state will succeed.
        test_rpc(
            function_name!(),
            40172,
            40173,
            50172,
            50173,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_callreadonlyfunction(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    None,
                    "ro-test".try_into().unwrap(),
                    vec![],
                    TipRequest::UseLatestAnchoredTip,
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::CallReadOnlyFunction(response_md, data) => {
                        assert!(data.okay);
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.result.clone().unwrap())
                                .unwrap(),
                            Value::okay(Value::Int(1)).unwrap()
                        );
                        assert!(data.cause.is_none());
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_call_read_only_unconfirmed() {
        test_rpc(
            function_name!(),
            40180,
            40181,
            50180,
            50181,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let unconfirmed_tip = peer_client
                    .chainstate()
                    .unconfirmed_state
                    .as_ref()
                    .unwrap()
                    .unconfirmed_chain_tip
                    .clone();
                convo_client.new_callreadonlyfunction(
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap(),
                    "hello-world-unconfirmed".try_into().unwrap(),
                    StacksAddress::from_string("ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R")
                        .unwrap()
                        .to_account_principal(),
                    None,
                    "ro-test".try_into().unwrap(),
                    vec![],
                    TipRequest::SpecificTip(unconfirmed_tip),
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                match http_response {
                    HttpResponseType::CallReadOnlyFunction(response_md, data) => {
                        assert!(data.okay);
                        assert_eq!(
                            Value::try_deserialize_hex_untyped(&data.result.clone().unwrap())
                                .unwrap(),
                            Value::okay(Value::Int(1)).unwrap()
                        );
                        assert!(data.cause.is_none());
                        true
                    }
                    _ => {
                        error!("Invalid response; {:?}", &http_response);
                        false
                    }
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_getattachmentsinv_limit_reached() {
        test_rpc(
            function_name!(),
            40190,
            40191,
            50190,
            50191,
            true,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                let pages_indexes = HashSet::from_iter(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
                convo_client.new_getattachmentsinv(StacksBlockId([0x00; 32]), pages_indexes)
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                println!("{:?}", http_response);
                match http_response {
                    HttpResponseType::BadRequest(_, msg) => {
                        assert_eq!(
                            msg,
                            "Number of attachment inv pages is limited by 8 per request"
                        );
                        true
                    }
                    _ => false,
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_mempool_query_txtags() {
        test_rpc(
            function_name!(),
            40813,
            40814,
            50813,
            50814,
            false,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                convo_client.new_mempool_query(
                    MemPoolSyncData::TxTags([0u8; 32], vec![]),
                    Some(Txid([0u8; 32])),
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                println!("{:?}", http_response);
                match http_response {
                    HttpResponseType::MemPoolTxs(_, _, txs) => {
                        // got everything
                        assert_eq!(txs.len(), 10);
                        true
                    }
                    _ => false,
                }
            },
        );
    }

    #[test]
    #[ignore]
    fn test_rpc_mempool_query_bloom() {
        test_rpc(
            function_name!(),
            40815,
            40816,
            50815,
            50816,
            false,
            |ref mut peer_client,
             ref mut convo_client,
             ref mut peer_server,
             ref mut convo_server| {
                // empty bloom filter
                convo_client.new_mempool_query(
                    MemPoolSyncData::BloomFilter(BloomFilter::new(
                        BLOOM_COUNTER_ERROR_RATE,
                        MAX_BLOOM_COUNTER_TXS,
                        BloomNodeHasher::new(&[0u8; 32]),
                    )),
                    Some(Txid([0u8; 32])),
                )
            },
            |ref http_request,
             ref http_response,
             ref mut peer_client,
             ref mut peer_server,
             ref convo_client,
             ref convo_server| {
                let req_md = http_request.metadata().clone();
                println!("{:?}", http_response);
                match http_response {
                    HttpResponseType::MemPoolTxs(_, _, txs) => {
                        // got everything
                        assert_eq!(txs.len(), 10);
                        true
                    }
                    _ => false,
                }
            },
        );
    }

    #[test]
    fn test_getinfo_compat() {
        let old_getinfo_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null}"#;
        let getinfo_no_pubkey_hash_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null,"node_public_key":"029b27d345e7bd2a6627262cefe6e97d9bc482f41ec32ec76a7bec391bb441798d"}"#;
        let getinfo_no_pubkey_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null,"node_public_key_hash":"046e6f832a83ff0da4a550907d3a44412cc1e4bf"}"#;
        let getinfo_full_json = r#"{"peer_version":402653189,"pox_consensus":"b712eb731b613eebae814a8f416c5c15bc8391ec","burn_block_height":727631,"stable_pox_consensus":"53b5ed79842080500d7d83daa36aa1069dedf983","stable_burn_block_height":727624,"server_version":"stacks-node 0.0.1 (feat/faster-inv-generation:68f33190a, release build, linux [x86_64])","network_id":1,"parent_network_id":3652501241,"stacks_tip_height":52537,"stacks_tip":"b3183f2ac588e12319ff0fde78f97e62c92a218d87828c35710c29aaf7adbedc","stacks_tip_consensus_hash":"b712eb731b613eebae814a8f416c5c15bc8391ec","genesis_chainstate_hash":"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b","unanchored_tip":"e76f68d607480e9984b4062b2691fb60a88423177898f5780b40ace17ae8982a","unanchored_seq":0,"exit_at_block_height":null,"node_public_key":"029b27d345e7bd2a6627262cefe6e97d9bc482f41ec32ec76a7bec391bb441798d","node_public_key_hash":"046e6f832a83ff0da4a550907d3a44412cc1e4bf"}"#;

        // they all parse
        for json_obj in &[
            &old_getinfo_json,
            &getinfo_no_pubkey_json,
            &getinfo_no_pubkey_hash_json,
            &getinfo_full_json,
        ] {
            let _v: RPCPeerInfoData = serde_json::from_str(json_obj).unwrap();
        }
    }
}
