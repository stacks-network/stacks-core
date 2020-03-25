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

use std::io::prelude::*;
use std::io;
use std::io::{Read, Write, Seek, SeekFrom};
use std::fmt;

use std::collections::HashMap;
use std::collections::VecDeque;
use net::Error as net_error;
use net::http::*;
use net::ProtocolFamily;
use net::StacksMessageCodec;
use net::MAX_NEIGHBORS_DATA_LEN;
use net::StacksHttpMessage;
use net::HttpRequestType;
use net::HttpResponseType;
use net::HttpRequestMetadata;
use net::HttpResponseMetadata;
use net::{MapEntryResponse, AccountEntryResponse};
use net::PeerAddress;
use net::PeerInfoData;
use net::NeighborAddress;
use net::NeighborsData;
use net::StacksHttp;
use net::PeerHost;
use net::HTTP_REQUEST_ID_RESERVED;
use net::connection::ConnectionHttp;
use net::connection::ReplyHandleHttp;
use net::connection::ConnectionOptions;
use net::db::PeerDB;

use burnchains::Burnchain;
use burnchains::BurnchainView;
use burnchains::BurnchainHeaderHash;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::db::{
    StacksChainState,
    BlockStreamData,
    blocks::MINIMUM_TX_FEE_RATE_PER_BYTE};
use chainstate::stacks::Error as chain_error;
use chainstate::stacks::*;
use burnchains::*;

use rusqlite::{DatabaseName, NO_PARAMS};

use util::db::Error as db_error;
use util::db::DBConn;
use util::get_epoch_time_secs;
use util::hash::to_hex;

use vm::{
    clarity::ClarityConnection,
    ClarityName,
    ContractName,
    Value,
    types::{ PrincipalData,
             QualifiedContractIdentifier },
    database::{ ClarityDatabase,
                ClaritySerializable },
};

use rand::prelude::*;
use rand::thread_rng;

pub const STREAM_CHUNK_SIZE : u64 = 4096;

pub struct ConversationHttp {
    network_id: u32,
    connection: ConnectionHttp,
    conn_id: usize,
    timeout: u64,
    peer_host: PeerHost,
    burnchain: Burnchain,
    keep_alive: bool,
    total_request_count: u64,       // number of messages taken from the inbox
    total_reply_count: u64,         // number of messages responsed to
    last_request_timestamp: u64,    // absolute timestamp of last inbound request, in seconds
    last_response_timestamp: u64,   // absolute timestamp of the last time we sent at least 1 byte in response
    connection_time: u64,           // when this converation was instantiated

    // ongoing block streams
    reply_streams: VecDeque<(ReplyHandleHttp, Option<(HttpChunkedTransferWriterState, BlockStreamData)>, bool)>,
    
    // our outstanding request/response to the remote peer, if any
    pending_request: Option<ReplyHandleHttp>,
    pending_response: Option<HttpResponseType>,
}

impl fmt::Display for ConversationHttp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "http:id={},request={:?}", self.conn_id, self.pending_request.is_some())
    }
}

impl fmt::Debug for ConversationHttp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "http:id={},request={:?}", self.conn_id, self.pending_request.is_some())
    }
}

impl PeerInfoData {
    pub fn from_db(burnchain: &Burnchain, burndb: &mut BurnDB, peerdb: &mut PeerDB) -> Result<PeerInfoData, net_error> {
        let burnchain_tip = BurnDB::get_canonical_burn_chain_tip(burndb.conn()).map_err(net_error::DBError)?;
        let local_peer = PeerDB::get_local_peer(peerdb.conn()).map_err(net_error::DBError)?;
        let stable_burnchain_tip = {
            let mut tx = burndb.tx_begin().map_err(net_error::DBError)?;
            let stable_height = 
                if burnchain_tip.block_height < burnchain.stable_confirmations as u64 {
                    0
                }
                else {
                    burnchain_tip.block_height - (burnchain.stable_confirmations as u64)
                };

            BurnDB::get_block_snapshot_in_fork(&mut tx, stable_height, &burnchain_tip.burn_header_hash)
                .map_err(net_error::DBError)?
                .ok_or(net_error::DBError(db_error::NotFoundError))?
        };

        Ok(PeerInfoData {
            peer_version: burnchain.peer_version,
            burn_consensus: burnchain_tip.consensus_hash,
            burn_block_height: burnchain_tip.block_height,
            stable_burn_consensus: stable_burnchain_tip.consensus_hash,
            stable_burn_block_height: stable_burnchain_tip.block_height,
            server_version: "TODO".to_string(),
            network_id: local_peer.network_id,
            parent_network_id: local_peer.parent_network_id,
        })
    }
}

impl ConversationHttp {
    pub fn new(network_id: u32, burnchain: &Burnchain, peer_host: PeerHost, conn_opts: &ConnectionOptions, conn_id: usize) -> ConversationHttp {
        ConversationHttp {
            network_id: network_id,
            connection: ConnectionHttp::new(StacksHttp::new(), conn_opts, None),
            conn_id: conn_id,
            timeout: conn_opts.timeout,
            reply_streams: VecDeque::new(),
            peer_host: peer_host,
            burnchain: burnchain.clone(),
            pending_request: None,
            pending_response: None,
            keep_alive: true,
            total_request_count: 0,
            total_reply_count: 0,
            last_request_timestamp: 0,
            last_response_timestamp: 0,
            connection_time: get_epoch_time_secs()
        }
    }

    /// How many ongoing requests do we have on this conversation?
    pub fn num_pending_outbound(&self) -> usize {
        self.reply_streams.len()
    }

    /// Start a HTTP request from this peer, and expect a response.
    /// Non-blocking.
    /// Only one request in-flight is allowed.
    pub fn send_request(&mut self, req: HttpRequestType) -> Result<(), net_error> {
        if self.pending_request.is_some() {
            return Err(net_error::InProgress);
        }
        
        let mut handle = self.connection.make_request_handle(HTTP_REQUEST_ID_RESERVED, self.timeout)?;
        let stacks_msg = StacksHttpMessage::Request(req);
        self.connection.send_message(&mut handle, &stacks_msg)?;
        
        self.pending_request = Some(handle);
        self.pending_response = None;
        Ok(())
    }

    /// Handle a GET peer info.
    /// The response will be synchronously written to the given fd (so use a fd that can buffer!)
    fn handle_getinfo<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType, burnchain: &Burnchain, burndb: &mut BurnDB, peerdb: &mut PeerDB) -> Result<(), net_error> {
        let response_metadata = HttpResponseMetadata::from(req);

        match PeerInfoData::from_db(burnchain, burndb, peerdb) {
            Ok(pi) => {
                let response = HttpResponseType::PeerInfo(response_metadata, pi);
                response.send(http, fd)
            }
            Err(e) => {
                warn!("Failed to get peer info {:?}: {:?}", req, &e);
                let response = HttpResponseType::ServerError(response_metadata, "Failed to query peer info".to_string());
                response.send(http, fd)
            }
        }
    }

    /// Handle a GET neighbors
    /// The response will be synchronously written to the given fd (so use a fd that can buffer!)
    fn handle_getneighbors<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType, network_id: u32, chain_view: &BurnchainView, peerdb: &mut PeerDB) -> Result<(), net_error> {
        let response_metadata = HttpResponseMetadata::from(req);
        
        // get neighbors at random as long as they're fresh
        let neighbors = PeerDB::get_random_neighbors(peerdb.conn(), network_id, MAX_NEIGHBORS_DATA_LEN, chain_view.burn_block_height, false)
            .map_err(net_error::DBError)?;

        let neighbor_addrs : Vec<NeighborAddress> = neighbors
            .iter()
            .map(|n| NeighborAddress::from_neighbor(n))
            .collect();

        let neighbor_data = NeighborsData { neighbors: neighbor_addrs };
        let response = HttpResponseType::Neighbors(response_metadata, neighbor_data);
        response.send(http, fd)
    }

    /// Handle a GET block.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a BlockStreamData struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getblock<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType, index_block_hash: &BlockHeaderHash, chainstate: &mut StacksChainState) -> Result<Option<BlockStreamData>, net_error> {
        let response_metadata = HttpResponseMetadata::from(req);

        // do we have this block?
        match StacksChainState::has_block_indexed(&chainstate.blocks_path, index_block_hash) {
            Ok(false) => {
                // nope -- not confirmed
                let response = HttpResponseType::NotFound(response_metadata, format!("No such block {}", index_block_hash.to_hex()));
                response.send(http, fd).and_then(|_| Ok(None))
            },
            Err(e) => {
                // nope -- error trying to check
                warn!("Failed to serve block {:?}: {:?}", req, &e);
                let response = HttpResponseType::ServerError(response_metadata, format!("Failed to query block {}", index_block_hash.to_hex()));
                response.send(http, fd).and_then(|_| Ok(None))
            },
            Ok(true) => {
                // yup! start streaming it back
                let stream = BlockStreamData::new_block(index_block_hash.clone());
                let response = HttpResponseType::BlockStream(response_metadata);
                response.send(http, fd).and_then(|_| Ok(Some(stream)))
            }
        }
    }
    
    /// Handle a GET confirmed microblock stream.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a BlockStreamData struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getmicroblocks<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType, index_microblock_hash: &BlockHeaderHash, chainstate: &mut StacksChainState) -> Result<Option<BlockStreamData>, net_error> {
        let response_metadata = HttpResponseMetadata::from(req);

        // do we have this confirmed microblock stream?
        match chainstate.has_confirmed_microblocks_indexed(index_microblock_hash) {
            Ok(false) => {
                // nope
                let response = HttpResponseType::NotFound(response_metadata, format!("No such confirmed microblock stream {}", index_microblock_hash.to_hex()));
                response.send(http, fd).and_then(|_| Ok(None))
            },
            Err(e) => {
                // nope
                warn!("Failed to serve confirmed microblock stream {:?}: {:?}", req, &e);
                let response = HttpResponseType::ServerError(response_metadata, format!("Failed to query confirmed microblock stream {}", index_microblock_hash.to_hex()));
                response.send(http, fd).and_then(|_| Ok(None))
            },
            Ok(true) => {
                // yup! start streaming it back
                let stream = BlockStreamData::new_microblock_confirmed(index_microblock_hash.clone());
                let response = HttpResponseType::MicroblockStream(response_metadata);
                response.send(http, fd).and_then(|_| Ok(Some(stream)))
            }
        }
    }

    fn handle_token_transfer_cost<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType) -> Result<(), net_error> {
        let response_metadata = HttpResponseMetadata::from(req);

        // todo -- need to actually estimate the cost / length for token transfers
        //   right now, it just uses the minimum.
        let fee = MINIMUM_TX_FEE_RATE_PER_BYTE;
        let response = HttpResponseType::TokenTransferCost(response_metadata, fee);
        response.send(http, fd).map(|_| ())
    }

    fn handle_get_account_entry<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType,
                                          chainstate: &mut StacksChainState, cur_burn: &BurnchainHeaderHash, cur_block: &BlockHeaderHash,
                                          account: &PrincipalData) -> Result<(), net_error> {
        let response_metadata = HttpResponseMetadata::from(req);

        let data = chainstate.with_read_only_clarity_tx(cur_burn, cur_block, |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|clarity_db| {
                let key = ClarityDatabase::make_key_for_account_balance(&account);
                let (balance, bal_proof) = clarity_db.get_with_proof(&key)?;
                let key = ClarityDatabase::make_key_for_account_nonce(&account);
                let (nonce, nonce_proof) = clarity_db.get_with_proof(&key)?;

                Some(AccountEntryResponse {
                    balance, nonce, balance_proof: bal_proof.to_hex(), nonce_proof: nonce_proof.to_hex() })
            })
        }).unwrap_or_else(|| AccountEntryResponse { balance: 0, nonce: 0, balance_proof: "".into(), nonce_proof: "".into() });

        let response = HttpResponseType::GetAccount(
            response_metadata, data);

        response.send(http, fd).map(|_| ())
    }

    fn handle_get_map_entry<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType,
                                      chainstate: &mut StacksChainState, cur_burn: &BurnchainHeaderHash, cur_block: &BlockHeaderHash,
                                      contract_addr: &StacksAddress, contract_name: &ContractName, map_name: &ClarityName, key: &Value) -> Result<(), net_error> {
        let response_metadata = HttpResponseMetadata::from(req);
        let contract_identifier = QualifiedContractIdentifier::new(contract_addr.clone().into(), contract_name.clone());

        let data = chainstate.with_read_only_clarity_tx(cur_burn, cur_block, |clarity_tx| {
            clarity_tx.with_clarity_db_readonly(|clarity_db| {
                let key = ClarityDatabase::make_key_for_data_map_entry(&contract_identifier, map_name, key);
                let (value, proof) = clarity_db.get_with_proof::<Value>(&key)?;
                let data = value.serialize();
                Some(MapEntryResponse { data, marf_proof: proof.to_hex() })
            })
        });

        let response = HttpResponseType::GetMapEntry(
            response_metadata, data);

        response.send(http, fd).map(|_| ())
    }

    
    /// Handle a GET unconfirmed microblock stream.  Start streaming the reply.
    /// The response's preamble (but not the block data) will be synchronously written to the fd
    /// (so use a fd that can buffer!)
    /// Return a BlockStreamData struct for the block that we're sending, so we can continue to
    /// make progress sending it.
    fn handle_getmicroblocks_unconfirmed<W: Write>(http: &mut StacksHttp, fd: &mut W, req: &HttpRequestType, index_anchor_block_hash: &BlockHeaderHash, min_seq: u16, chainstate: &mut StacksChainState) -> Result<Option<BlockStreamData>, net_error> {
        let response_metadata = HttpResponseMetadata::from(req);

        // do we have this unconfirmed microblock stream?
        match chainstate.has_any_staging_microblock_indexed(index_anchor_block_hash, min_seq) {
            Ok(false) => {
                // nope
                let response = HttpResponseType::NotFound(response_metadata, format!("No such unconfirmed microblock stream for {} at or after {}", index_anchor_block_hash.to_hex(), min_seq));
                response.send(http, fd).and_then(|_| Ok(None))
            },
            Err(e) => {
                // nope
                warn!("Failed to serve confirmed microblock stream {:?}: {:?}", req, &e);
                let response = HttpResponseType::ServerError(response_metadata, format!("Failed to query unconfirmed microblock stream for {} at or after {}", index_anchor_block_hash.to_hex(), min_seq));
                response.send(http, fd).and_then(|_| Ok(None))
            },
            Ok(true) => {
                // yup! start streaming it back
                let stream = BlockStreamData::new_microblock_unconfirmed(index_anchor_block_hash.clone(), min_seq);
                let response = HttpResponseType::MicroblockStream(response_metadata);
                response.send(http, fd).and_then(|_| Ok(Some(stream)))
            }
        }
    }

    /// Handle an external HTTP request.
    /// Some requests, such as those for blocks, will create new reply streams.  This method adds
    /// those new streams into the `reply_streams` set.
    pub fn handle_request(&mut self, req: HttpRequestType, chain_view: &BurnchainView, burndb: &mut BurnDB, peerdb: &mut PeerDB,
                          chainstate: &mut StacksChainState, burn_block: &BurnchainHeaderHash, block: &BlockHeaderHash) -> Result<(), net_error> {
        let mut reply = self.connection.make_relay_handle()?;
        let keep_alive = req.metadata().keep_alive;
        let stream_opt = match req {
            HttpRequestType::GetInfo(ref _md) => {
                ConversationHttp::handle_getinfo(&mut self.connection.protocol, &mut reply, &req, &self.burnchain, burndb, peerdb)?;
                None
            },
            HttpRequestType::GetNeighbors(ref _md) => {
                ConversationHttp::handle_getneighbors(&mut self.connection.protocol, &mut reply, &req, self.network_id, chain_view, peerdb)?;
                None
            },
            HttpRequestType::GetBlock(ref _md, ref index_block_hash) => {
                ConversationHttp::handle_getblock(&mut self.connection.protocol, &mut reply, &req, index_block_hash, chainstate)?
            },
            HttpRequestType::GetMicroblocks(ref _md, ref index_head_hash) => {
                ConversationHttp::handle_getmicroblocks(&mut self.connection.protocol, &mut reply, &req, index_head_hash, chainstate)?
            },
            HttpRequestType::GetMicroblocksUnconfirmed(ref _md, ref index_anchor_block_hash, ref min_seq) => {
                ConversationHttp::handle_getmicroblocks_unconfirmed(&mut self.connection.protocol, &mut reply, &req, index_anchor_block_hash, *min_seq, chainstate)?
            },
            HttpRequestType::GetAccount(ref _md, ref principal) => {
                ConversationHttp::handle_get_account_entry(&mut self.connection.protocol, &mut reply, &req, chainstate, burn_block, block, principal)?;
                None
            },
            HttpRequestType::GetMapEntry(ref _md, ref contract_addr, ref contract_name, ref map_name, ref key) => {
                ConversationHttp::handle_get_map_entry(&mut self.connection.protocol, &mut reply, &req, chainstate, burn_block, block,
                                                       contract_addr, contract_name, map_name, key)?;
                None
            },
            HttpRequestType::GetTransferCost(ref _md) => {
                ConversationHttp::handle_token_transfer_cost(&mut self.connection.protocol, &mut reply, &req)?;
                None
            },
            HttpRequestType::PostTransaction(_md, _tx) => {
                panic!("Not implemented");
            }
        };

        match stream_opt {
            None => {
                self.reply_streams.push_back((reply, None, keep_alive));
            },
            Some(stream) => {
                self.reply_streams.push_back((reply, Some((HttpChunkedTransferWriterState::new(STREAM_CHUNK_SIZE as usize), stream)), keep_alive));
            }
        }
        Ok(())
    }

    /// Make progress on outbound requests.
    /// Return true if the connection should be kept alive after all messages are drained.
    /// If we process a request with "Connection: close", then return false (indicating that the
    /// connection should be severed once the conversation is drained)
    fn send_outbound_responses(&mut self, chainstate: &mut StacksChainState) -> Result<(), net_error> {
        // send out streamed responses in the order they were requested 
        let mut drained_handle = false;
        let mut drained_stream = false;
        let mut broken = false;
        let mut do_keep_alive = true;
        
        test_debug!("{:?}: {} HTTP replies pending", &self, self.reply_streams.len());
        match self.reply_streams.front_mut() {
            Some((ref mut reply, ref mut stream_opt, ref keep_alive)) => {
                do_keep_alive = *keep_alive;

                // if we're streaming, make some progress on the stream
                match stream_opt {
                    Some((ref mut http_chunk_state, ref mut stream)) => {
                        let mut encoder = HttpChunkedTransferWriter::from_writer_state(reply, http_chunk_state);
                        match stream.stream_to(chainstate, &mut encoder, STREAM_CHUNK_SIZE) {
                            Ok(nw) => {
                                test_debug!("streamed {} bytes", nw);
                                if nw == 0 {
                                    // EOF -- finish chunk and stop sending.
                                    if !encoder.corked() {
                                        encoder.flush()
                                            .map_err(|e| {
                                                test_debug!("Write error on encoder flush: {:?}", &e);
                                                net_error::WriteError(e)
                                            })?;

                                        encoder.cork();
                                    
                                        test_debug!("stream indicates EOF");
                                    }

                                    // try moving some data to the connection only once we're done
                                    // streaming
                                    match reply.try_flush() {
                                        Ok(res) => {
                                            test_debug!("Streamed reply is drained");
                                            drained_handle = res;
                                        },
                                        Err(e) => {
                                            // dead
                                            warn!("Broken HTTP connection: {:?}", &e);
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
                                warn!("Failed to send to HTTP connection: {:?}", &e);
                                broken = true;
                            }
                        }
                    },
                    None => {
                        // not streamed; all data is bufferred
                        drained_stream = true;

                        // try moving some data to the connection
                        match reply.try_flush() {
                            Ok(res) => {
                                test_debug!("Reply is drained");
                                drained_handle = res;
                            },
                            Err(e) => {
                                // dead
                                warn!("Broken HTTP connection: {:?}", &e);
                                broken = true;
                            }
                        }
                    }
                }
            },
            None => {}
        }

        if broken || (drained_handle && drained_stream) {
            // done with this stream
            test_debug!("{:?}: done with stream", &self);
            self.total_reply_count += 1;
            self.reply_streams.pop_front();

            if !do_keep_alive {
                // encountered "Connection: close"
                self.keep_alive = false;
            }
        }

        Ok(())
    }

    /// Make progress on our request/response
    fn recv_inbound_response(&mut self) -> Result<(), net_error> {
        // make progress on our pending request (if it exists).
        let pending_request = self.pending_request.take();
        let response = match pending_request {
            None => Ok(self.pending_response.take()),
            Some(req) => {
                match req.try_send_recv() {
                    Ok(message) => match message {
                        StacksHttpMessage::Request(_) => {
                            warn!("Received response: not an HTTP response");
                            return Err(net_error::InvalidMessage);
                        },
                        StacksHttpMessage::Response(http_response) => {
                            Ok(Some(http_response))
                        }
                    },
                    Err(res) => match res {
                        Ok(handle) => {
                            // try again
                            self.pending_request = Some(handle);
                            Ok(self.pending_response.take())
                        },
                        Err(e) => Err(e)
                    }
                }
            }
        }?;

        self.pending_response = response;
        Ok(())
    }

    /// Try to get our response
    pub fn try_get_response(&mut self) -> Option<HttpResponseType> {
        self.pending_response.take()
    }

    /// Make progress on in-flight messages.
    pub fn try_flush(&mut self, chainstate: &mut StacksChainState) -> Result<(), net_error> {
        self.send_outbound_responses(chainstate)?;
        self.recv_inbound_response()?;
        Ok(())
    }

    /// Is the connection idle?
    pub fn is_idle(&self) -> bool {
        self.pending_response.is_none() && self.connection.inbox_len() == 0 && self.connection.outbox_len() == 0 && self.reply_streams.len() == 0
    }

    /// Is the conversation out of pending data?
    /// Don't consider it drained if we haven't received anything yet
    pub fn is_drained(&self) -> bool {
        self.total_request_count > 0 && self.total_reply_count > 0 && self.is_idle()
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
    /// Returns the list of unhandled inbound requests
    pub fn chat(&mut self, chain_view: &BurnchainView, burndb: &mut BurnDB, peerdb: &mut PeerDB,
                chainstate: &mut StacksChainState, burn_block: &BurnchainHeaderHash, block: &BlockHeaderHash) -> Result<(), net_error> {
        // handle in-bound HTTP request(s)
        let num_inbound = self.connection.inbox_len();
        test_debug!("{:?}: {} HTTP requests pending", &self, num_inbound);

        for _i in 0..num_inbound {
            let msg = match self.connection.next_inbox_message() {
                None => {
                    continue;
                },
                Some(m) => m
            };
 
            match msg {
                StacksHttpMessage::Request(req) => {
                    // new request
                    self.total_request_count += 1;
                    self.last_request_timestamp = get_epoch_time_secs();
                    self.handle_request(req, chain_view, burndb, peerdb, chainstate, burn_block, block)?;
                },
                StacksHttpMessage::Response(resp) => {
                    // Is there someone else waiting for this message?  If so, pass it along.
                    // (this _should_ be our pending_request handle)
                    match self.connection.fulfill_request(StacksHttpMessage::Response(resp)) {
                        None => {
                            test_debug!("{:?}: Fulfilled pending HTTP request", &self);
                        },
                        Some(_msg) => {
                            // unsolicited; discard
                            test_debug!("{:?}: Dropping unsolicited HTTP response", &self);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Remove all timed-out messages, and ding the remote peer as unhealthy
    pub fn clear_timeouts(&mut self) -> () {
        self.connection.drain_timeouts();
    }

    /// Load data into our HTTP connection
    pub fn recv<R: Read>(&mut self, r: &mut R) -> Result<usize, net_error> {
        self.connection.recv_data(r)
    }

    /// Write data out of our HTTP connection 
    pub fn send<W: Write>(&mut self, w: &mut W) -> Result<usize, net_error> {
        let sz = self.connection.send_data(w)?;
        if sz > 0 {
            self.last_response_timestamp = get_epoch_time_secs();
        }
        Ok(sz)
    }

    /// Make a new getinfo request to this endpoint
    pub fn new_getinfo(&self) -> HttpRequestType {
        HttpRequestType::GetInfo(HttpRequestMetadata::from_host(self.peer_host.clone()))
    }
    
    /// Make a new getneighbors request to this endpoint
    pub fn new_getneighbors(&self) -> HttpRequestType {
        HttpRequestType::GetNeighbors(HttpRequestMetadata::from_host(self.peer_host.clone()))
    }
    
    /// Make a new getblock request to this endpoint
    pub fn new_getblock(&self, index_block_hash: BlockHeaderHash) -> HttpRequestType {
        HttpRequestType::GetBlock(HttpRequestMetadata::from_host(self.peer_host.clone()), index_block_hash)
    }
    
    /// Make a new get-microblocks request to this endpoint
    pub fn new_getmicroblocks(&self, index_microblock_hash: BlockHeaderHash) -> HttpRequestType {
        HttpRequestType::GetMicroblocks(HttpRequestMetadata::from_host(self.peer_host.clone()), index_microblock_hash)
    }

    /// Make a new get-microblocks request for unconfirmed microblocks
    pub fn new_getmicroblocks_unconfirmed(&self, anchored_index_block_hash: BlockHeaderHash, min_seq: u16) -> HttpRequestType {
        HttpRequestType::GetMicroblocksUnconfirmed(HttpRequestMetadata::from_host(self.peer_host.clone()), anchored_index_block_hash, min_seq)
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use super::*;
    use net::*;
    use net::codec::*;
    use net::test::*;
    use net::http::*;
    
    use burnchains::Burnchain;
    use burnchains::BurnchainView;
    use burnchains::BurnchainHeaderHash;

    use chainstate::burn::db::burndb::BurnDB;
    use chainstate::burn::BlockHeaderHash;
    use chainstate::stacks::test::*;
    use chainstate::stacks::db::StacksChainState;
    use chainstate::stacks::db::BlockStreamData;
    use chainstate::stacks::db::blocks::test::*;
    use chainstate::stacks::Error as chain_error;
    use chainstate::stacks::*;
    use burnchains::*;
   
    use util::pipe::*;
    use util::get_epoch_time_secs;

    fn convo_send_recv(sender: &mut ConversationHttp, sender_chainstate: &mut StacksChainState, receiver: &mut ConversationHttp, receiver_chainstate: &mut StacksChainState) -> () {
        let (mut pipe_read, mut pipe_write) = Pipe::new();
        pipe_read.set_nonblocking(true);

        loop {
            let res = true;
           
            sender.try_flush(sender_chainstate).unwrap();
            receiver.try_flush(receiver_chainstate).unwrap();

            let all_relays_flushed = receiver.num_pending_outbound() == 0 && sender.num_pending_outbound() == 0;
            
            let nw = sender.send(&mut pipe_write).unwrap();
            let nr = receiver.recv(&mut pipe_read).unwrap();

            test_debug!("res = {}, all_relays_flushed = {} ({},{}), nr = {}, nw = {}", res, all_relays_flushed, receiver.num_pending_outbound(), sender.num_pending_outbound(), nr, nw);
            if res && all_relays_flushed && nr == 0 && nw == 0 {
                test_debug!("Breaking send_recv");
                break;
            }
        }
    }

    fn test_rpc<F, C>(test_name: &str, peer_1_p2p: u16, peer_1_http: u16, peer_2_p2p: u16, peer_2_http: u16, make_request: F, check_result: C) -> ()
    where
        F: FnOnce(&mut TestPeer, &mut ConversationHttp, &mut TestPeer, &mut ConversationHttp) -> HttpRequestType,
        C: FnOnce(&HttpRequestType, &HttpResponseType, &mut TestPeer, &mut TestPeer) -> bool
    {
        let mut peer_1_config = TestPeerConfig::new(test_name, peer_1_p2p, peer_1_http);
        let mut peer_2_config = TestPeerConfig::new(test_name, peer_2_p2p, peer_2_http);

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let view_1 = peer_1.get_burnchain_view().unwrap();
        let view_2 = peer_2.get_burnchain_view().unwrap();

        let mut convo_1 = ConversationHttp::new(peer_1.config.network_id, &peer_1.config.burnchain, peer_1.to_peer_host(), &peer_1.config.connection_opts, 0);
        let mut convo_2 = ConversationHttp::new(peer_2.config.network_id, &peer_2.config.burnchain, peer_2.to_peer_host(), &peer_2.config.connection_opts, 1);

        let req = make_request(&mut peer_1, &mut convo_1, &mut peer_2, &mut convo_2);

        convo_1.send_request(req.clone()).unwrap();

        test_debug!("convo1 sends to convo2");
        convo_send_recv(&mut convo_1, peer_1.chainstate.as_mut().unwrap(), &mut convo_2, peer_2.chainstate.as_mut().unwrap());
        convo_1.chat(&view_1, peer_1.burndb.as_mut().unwrap(), &mut peer_1.network.peerdb, peer_1.chainstate.as_mut().unwrap()).unwrap();
        
        test_debug!("convo2 sends to convo1");
        convo_2.chat(&view_2, peer_2.burndb.as_mut().unwrap(), &mut peer_2.network.peerdb, peer_2.chainstate.as_mut().unwrap()).unwrap();
        convo_send_recv(&mut convo_2, peer_2.chainstate.as_mut().unwrap(), &mut convo_1, peer_1.chainstate.as_mut().unwrap());
      
        test_debug!("flush convo1");
        convo_send_recv(&mut convo_1, peer_1.chainstate.as_mut().unwrap(), &mut convo_2, peer_2.chainstate.as_mut().unwrap());
        convo_1.chat(&view_1, peer_1.burndb.as_mut().unwrap(), &mut peer_1.network.peerdb, peer_1.chainstate.as_mut().unwrap()).unwrap();

        convo_1.try_flush(peer_1.chainstate.as_mut().unwrap()).unwrap();

        // should have gotten a reply
        let resp_opt = convo_1.try_get_response();
        assert!(resp_opt.is_some());

        let resp = resp_opt.unwrap();
        assert!(check_result(&req, &resp, &mut peer_1, &mut peer_2));
    }

    #[test]
    fn test_rpc_getinfo() {
        let peer_server_info = RefCell::new(None);
        test_rpc("test_rpc_getinfo", 40000, 40001, 50000, 50001,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     let peer_info = PeerInfoData::from_db(&peer_server.config.burnchain, peer_server.burndb.as_mut().unwrap(), &mut peer_server.network.peerdb).unwrap();
                     *peer_server_info.borrow_mut() = Some(peer_info);
                     
                     convo_client.new_getinfo()
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                     let req_md = http_request.metadata().clone();
                     match http_response {
                        HttpResponseType::PeerInfo(response_md, peer_data) => {
                            assert_eq!(Some((*peer_data).clone()), *peer_server_info.borrow());
                            true
                        },
                        _ => {
                            error!("Invalid response: {:?}", &http_response);
                            false
                        }
                    }
                 });
    }

    #[test]
    fn test_rpc_getneighbors() {
        test_rpc("test_rpc_getneighbors", 40010, 40011, 50010, 50011,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     convo_client.new_getneighbors()
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                     let req_md = http_request.metadata().clone();
                     match http_response {
                        HttpResponseType::Neighbors(response_md, neighbor_info) => {
                            assert_eq!(neighbor_info.neighbors.len(), 1);
                            assert_eq!(neighbor_info.neighbors[0].port, peer_client.config.server_port);     // we see ourselves as the neighbor
                            true
                        },
                        _ => {
                            error!("Invalid response: {:?}", &http_response);
                            false
                        }
                     }
                 });
    }
    
    #[test]
    fn test_rpc_unconfirmed_getblock() {
        let server_block_cell = RefCell::new(None);

        test_rpc("test_rpc_unconfirmed_getblock", 40020, 40021, 50020, 50021,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     // have "server" peer store a block to staging
                     let peer_server_block = make_codec_test_block(25);
                     let peer_server_burn_block_hash = BurnchainHeaderHash([0x02; 32]);
                     let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                     test_debug!("Store peer server index block {:?}", &index_block_hash);
                     store_staging_block(peer_server.chainstate.as_mut().unwrap(), &peer_server_burn_block_hash, get_epoch_time_secs(), &peer_server_block, &BurnchainHeaderHash([0x03; 32]), 456, 123);

                     *server_block_cell.borrow_mut() = Some(peer_server_block);

                     // now ask for it
                     convo_client.new_getblock(index_block_hash)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                     
                     let req_md = http_request.metadata().clone();
                     match http_response {
                        HttpResponseType::Block(response_md, block_info) => {
                           assert_eq!(block_info.block_hash(), (*server_block_cell.borrow()).as_ref().unwrap().block_hash());
                           true
                        },
                        _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                        }
                    }
                });
    }
    
    #[test]
    fn test_rpc_confirmed_getblock() {
        let server_block_cell = RefCell::new(None);

        test_rpc("test_rpc_confirmed_getblock", 40030, 40031, 50030, 50031,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     // have "server" peer store a block to staging
                     let peer_server_block = make_codec_test_block(25);
                     let peer_server_burn_block_hash = BurnchainHeaderHash([0x02; 32]);
                     let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block.block_hash());

                     test_debug!("Store peer server index block {:?}", &index_block_hash);
                     store_staging_block(peer_server.chainstate.as_mut().unwrap(), &peer_server_burn_block_hash, get_epoch_time_secs(), &peer_server_block, &BurnchainHeaderHash([0x03; 32]), 456, 123);
                     set_block_processed(peer_server.chainstate.as_mut().unwrap(), &peer_server_burn_block_hash, &peer_server_block.block_hash(), true);

                     *server_block_cell.borrow_mut() = Some(peer_server_block);

                     // now ask for it
                     convo_client.new_getblock(index_block_hash)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                    let req_md = http_request.metadata().clone();
                    match http_response {
                       HttpResponseType::Block(response_md, block_info) => {
                           assert_eq!(block_info.block_hash(), (*server_block_cell.borrow()).as_ref().unwrap().block_hash());
                           true
                       },
                       _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                       }
                    }
                });
    }
    
    #[test]
    fn test_rpc_confirmed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc("test_rpc_confirmed_microblocks", 40040, 40041, 50040, 50041,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();

                     let burn_header_hash = BurnchainHeaderHash([0x02; 32]);
                     let anchored_block_hash = BlockHeaderHash([0x03; 32]);

                     let mut mblocks = make_sample_microblock_stream(&privk, &anchored_block_hash);
                     mblocks.truncate(15);
                     
                     let index_microblock_hash = StacksBlockHeader::make_index_block_hash(&burn_header_hash, &mblocks[0].block_hash());

                     for mblock in mblocks.iter() {
                         store_staging_microblock(peer_server.chainstate.as_mut().unwrap(), &burn_header_hash, &anchored_block_hash, &mblock);
                     }

                     set_microblocks_confirmed(peer_server.chainstate.as_mut().unwrap(), &burn_header_hash, &anchored_block_hash, mblocks.last().unwrap().header.sequence);

                     *server_microblocks_cell.borrow_mut() = mblocks;

                     convo_client.new_getmicroblocks(index_microblock_hash)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                    let req_md = http_request.metadata().clone();
                    match http_response {
                        HttpResponseType::Microblocks(response_md, microblocks) => {
                            assert_eq!(microblocks.len(), (*server_microblocks_cell.borrow()).len());
                            assert_eq!(*microblocks, *server_microblocks_cell.borrow());
                            true
                        },
                        _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                       }
                    }
                });
    }
    
    #[test]
    fn test_rpc_unconfirmed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc("test_rpc_unconfirmed_microblocks", 40050, 40051, 50050, 50051,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();

                     let burn_header_hash = BurnchainHeaderHash([0x02; 32]);
                     let anchored_block_hash = BlockHeaderHash([0x03; 32]);
                     let index_block_hash = StacksBlockHeader::make_index_block_hash(&burn_header_hash, &anchored_block_hash);

                     let mut mblocks = make_sample_microblock_stream(&privk, &anchored_block_hash);
                     mblocks.truncate(15);
                     
                     for mblock in mblocks.iter() {
                         store_staging_microblock(peer_server.chainstate.as_mut().unwrap(), &burn_header_hash, &anchored_block_hash, &mblock);
                     }

                     *server_microblocks_cell.borrow_mut() = mblocks;

                     // start at seq 5
                     convo_client.new_getmicroblocks_unconfirmed(index_block_hash, 5)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                    let req_md = http_request.metadata().clone();
                    match http_response {
                        HttpResponseType::Microblocks(response_md, microblocks) => {
                            assert_eq!(microblocks.len(), 10);
                            assert_eq!(*microblocks, (*server_microblocks_cell.borrow())[5..].to_vec());
                            true
                        },
                        _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                       }
                    }
                });
    }

    #[test]
    fn test_rpc_missing_getblock() {
        test_rpc("test_rpc_missing_getblock", 40060, 40061, 50060, 50061,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     let peer_server_block_hash = BlockHeaderHash([0x04; 32]);
                     let peer_server_burn_block_hash = BurnchainHeaderHash([0x02; 32]);
                     let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block_hash);

                     // now ask for it
                     convo_client.new_getblock(index_block_hash)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                     let req_md = http_request.metadata().clone();
                     match http_response {
                        HttpResponseType::NotFound(response_md, msg) => true,
                        _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                        }
                    }
                });
    }
    
    #[test]
    fn test_rpc_missing_getmicroblocks() {
        test_rpc("test_rpc_missing_getmicroblocks", 40070, 40071, 50070, 50071,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     let peer_server_block_hash = BlockHeaderHash([0x04; 32]);
                     let peer_server_burn_block_hash = BurnchainHeaderHash([0x02; 32]);
                     let index_block_hash = StacksBlockHeader::make_index_block_hash(&peer_server_burn_block_hash, &peer_server_block_hash);

                     // now ask for it
                     convo_client.new_getmicroblocks(index_block_hash)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                     let req_md = http_request.metadata().clone();
                     match http_response {
                        HttpResponseType::NotFound(response_md, msg) => true,
                        _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                        }
                    }
                });
    }
    
    #[test]
    fn test_rpc_missing_unconfirmed_microblocks() {
        let server_microblocks_cell = RefCell::new(vec![]);

        test_rpc("test_rpc_missing_unconfirmed_microblocks", 40080, 40081, 50080, 50081,
                 |ref mut peer_client, ref mut convo_client, ref mut peer_server, ref mut convo_server| {
                     let privk = StacksPrivateKey::from_hex("eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01").unwrap();

                     let burn_header_hash = BurnchainHeaderHash([0x02; 32]);
                     let anchored_block_hash = BlockHeaderHash([0x03; 32]);
                     let index_block_hash = StacksBlockHeader::make_index_block_hash(&burn_header_hash, &anchored_block_hash);

                     let mut mblocks = make_sample_microblock_stream(&privk, &anchored_block_hash);
                     mblocks.truncate(15);
                     
                     for mblock in mblocks.iter() {
                         store_staging_microblock(peer_server.chainstate.as_mut().unwrap(), &burn_header_hash, &anchored_block_hash, &mblock);
                     }

                     *server_microblocks_cell.borrow_mut() = mblocks;

                     // start at seq 16 (which doesn't exist)
                     convo_client.new_getmicroblocks_unconfirmed(index_block_hash, 16)
                 },
                 |ref http_request, ref http_response, ref mut peer_client, ref mut peer_server| {
                    let req_md = http_request.metadata().clone();
                    match http_response {
                        HttpResponseType::NotFound(response_md, msg) => true,
                        _ => {
                           error!("Invalid response: {:?}", &http_response);
                           false
                       }
                    }
                });
    }
}

