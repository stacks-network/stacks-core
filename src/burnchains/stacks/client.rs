// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

// This module is concerned with the implementation of the BitcoinIndexer
// structure and its methods and traits.

use std::cmp;
use std::collections::HashMap;
use std::convert::From;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::io;
use std::io::Read;
use std::net::Shutdown;
use std::net::ToSocketAddrs;

use chainstate::stacks::db::StacksAccount;
use chainstate::stacks::StacksBlock;

use vm::ast::build_ast;
use vm::costs::ExecutionCost;
use vm::database::clarity_store::make_contract_hash_key;
use vm::database::clarity_store::ContractCommitment;
use vm::database::ClarityDatabase;
use vm::database::ClaritySerializable;
use vm::database::STXBalance;
use vm::database::StoreType;
use vm::representations::ContractName;
use vm::representations::UrlString;
use vm::types::signatures::TypeSignature;
use vm::types::QualifiedContractIdentifier;
use vm::types::Value;
use vm::types::{PrincipalData, StandardPrincipalData};

use core::*;

use codec::StacksMessageCodec;

use net::atlas::Attachment;
use net::AccountEntryResponse;
use net::ContractSrcResponse;
use net::DataVarResponse;
use net::Error as net_error;
use net::ExtendedStacksHeader;
use net::HttpRequestMetadata;
use net::HttpRequestType;
use net::HttpResponseMetadata;
use net::HttpResponseType;
use net::HttpVersion;
use net::MapEntryResponse;
use net::PeerHost;
use net::ProtocolFamily;
use net::RPCPeerInfoData;
use net::StacksHttp;
use net::StacksHttpMessage;
use net::StacksHttpPreamble;
use net::MAX_HEADERS;

use util::boot::boot_code_addr;
use util::get_epoch_time_secs;
use util::hash::hex_bytes;
use util::hash::Sha512Trunc256Sum;
use util::sleep_ms;
use util::strings::StacksString;

use burnchains::stacks::AppChainClient;
use burnchains::stacks::Error;
use burnchains::stacks::MiningContractBlock;
use burnchains::stacks::MiningContractTransaction;
use burnchains::Error as burnchain_error;
use burnchains::MagicBytes;

use burnchains::BurnchainBlock;
use burnchains::BurnchainRecipient;
use burnchains::IndexerError as indexer_error;
use burnchains::Txid;

use burnchains::stacks::db::LightClientDB;
use burnchains::stacks::AppChainConfig;

use chainstate::stacks::index::node::TriePath;
use chainstate::stacks::StacksTransaction;

use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, MARFValue, StacksAddress, StacksBlockHeader,
    StacksBlockId, StacksWorkScore,
};
use crate::types::proof::{TrieHash, TrieMerkleProof};

use std::time::Duration;

use std::net::TcpStream;

/// Maximum length of an HTTP payload from a remote node (4MB).
const MAX_BODY_LEN: u64 = 4 * 1024 * 1024;

/// Name of the data map that stores the appchain's burn operations within the mining contract.
const DATA_MAP_APPCHAIN_NAME: &str = "appchain";

/// Name of the data var that contains the appchain schema version
const DATA_VAR_APPCHAIN_VERSION: &str = "appchain-version";

/// Name of the data var that encodes the appchain configuration (see below)
const DATA_VAR_APPCHAIN_CONFIG: &str = "appchain-config";

lazy_static! {
    /// Type signature of an entry within the appchain data map
    static ref DATA_MAP_APPCHAIN_TYPE : TypeSignature = TypeSignature::parse_type_repr(
        &build_ast(&QualifiedContractIdentifier::transient(), "(optional (list 128 { sender: principal, chained?: bool, data: (buff 80), burnt: uint, transferred: uint, recipients: (list 2 principal) }))", &mut ())
            .unwrap()
            .expressions
            .pop()
            .unwrap(),
        &mut ()
    ).unwrap();

    /// Type signature of an entry within the appchain-version data var
    static ref DATA_VAR_APPCHAIN_VERSION_TYPE : TypeSignature = TypeSignature::parse_type_repr(
        &build_ast(&QualifiedContractIdentifier::transient(), "uint", &mut ())
            .unwrap()
            .expressions
            .pop()
            .unwrap(),
        &mut ()
    ).unwrap();

    /// Type signature of the appchain-config data var.  Field are:
    /// * start-height: the first block on the host chain when the appchain kicks off
    /// * chain-id: a 32-bit chain ID that will go into the appchain's transactions, to make them
    /// valid only on that appchain
    /// * boot-nodes: a list of existing appchain nodes that other appchain nodes can boot off of.
    /// Specifically:
    ///    * public-key: the compressed secp256k1 peer public key
    ///    * host: the IPv4 or IPv6 address of the remote peer
    ///    * port: the p2p port of the remote peer
    ///    * data-host: the IPv4 or IPv6 address of the remote peer
    ///    * data-port: the RPC port of the remote peer
    /// * pox: the PoxConstants structure for this node
    ///     fields are 1-to-1 with the PoxConstants structure (see that struct for field meanings)
    /// * block-limit: the ExecutionCost structure for all blocks on this node
    ///     fields are 1-to-1 with the ExecutionCost structure (see that struct for field meanings)
    /// * initial-balances: a list of initial token allocations.  Addresses must all be standard
    /// principals.
    /// * boot-code: a list of names of additional contracts that will be instantiated in the
    /// appchain boot code.  If the code bodies are not provided locally, they will be downloaded
    /// from one of the nodes given in boot-nodes
    static ref DATA_VAR_APPCHAIN_CONFIG_TYPE : TypeSignature = TypeSignature::parse_type_repr(
        &build_ast(&QualifiedContractIdentifier::transient(), r#"{
                start-height: uint,
                chain-id: uint,
                boot-nodes: (list 16 { public-key: (buff 33), host: (buff 16), port: (buff 2), data-host: (buff 16), data-port: (buff 2) }),
                pox: {
                    reward-cycle-length: uint,
                    prepare-length: uint,
                    anchor-threshold: uint,
                    pox-rejection-fraction: uint,
                    pox-participation-threshold-pct: uint,
                    sunset-start: uint,
                    sunset-end: uint
                },
                block-limit: {
                    write-length: uint,
                    write-count: uint,
                    read-length: uint,
                    read-count: uint,
                    runtime: uint
                },
                initial-balances: (list 128 { recipient: principal, amount: uint }),
                boot-code: (list 128 (string-ascii 128)),
            }"#, &mut ())
            .unwrap()
            .expressions
            .pop()
            .unwrap(),
        &mut ()
    ).unwrap();
}

impl AppChainClient {
    /// Instantiate a new appchain client
    pub fn new(
        mainnet: bool,
        headers_path: &str,
        parent_chain_id: u32,
        parent_chain_peer: (&str, u16),
        contract_id: QualifiedContractIdentifier,
        magic: MagicBytes,
        genesis_hash: TrieHash,
        tip: Option<StacksBlockId>,
    ) -> AppChainClient {
        AppChainClient {
            mainnet: mainnet,
            chain_id: 0, // not known yet
            parent_chain_id: parent_chain_id,
            headers_path: headers_path.to_string(),
            peer: (parent_chain_peer.0.to_string(), parent_chain_peer.1),
            connect_timeout: 5_000,
            duration_timeout: 60_000,
            refresh_peerinfo_deadline: 0,
            refresh_peerinfo_interval: 10,
            contract_id: contract_id,
            root_to_block: HashMap::new(),
            tip: tip,
            magic_bytes: magic,
            config: None,
            session: None,
            genesis_hash,
            boot_code: HashMap::new(),
        }
    }

    /// Make a safe copy of the AppChainClient struct, without duplicating any session state (such
    /// as a TCP stream).
    pub fn cloned(&self) -> AppChainClient {
        AppChainClient {
            mainnet: self.mainnet,
            chain_id: self.chain_id,
            parent_chain_id: self.parent_chain_id,
            headers_path: self.headers_path.clone(),
            peer: self.peer.clone(),
            connect_timeout: self.connect_timeout,
            duration_timeout: self.duration_timeout,
            refresh_peerinfo_deadline: self.refresh_peerinfo_deadline,
            refresh_peerinfo_interval: self.refresh_peerinfo_interval,
            contract_id: self.contract_id.clone(),
            root_to_block: self.root_to_block.clone(),
            tip: self.tip.clone(),
            magic_bytes: self.magic_bytes.clone(),
            config: self.config.clone(),
            session: None,
            genesis_hash: self.genesis_hash.clone(),
            boot_code: self.boot_code.clone(),
        }
    }

    /// Helper method to get a ref to the remote host chain peer.
    pub fn remote_peer(&self) -> (&str, u16) {
        (&self.peer.0, self.peer.1)
    }

    /// Connect to a given peer using our connection settings.
    /// Uses ToSocketAddrs impl of (&str, u16) to perform DNS resolution if need be.
    /// Returns the new TCP stream on success
    pub fn connect(&self, peer: (&str, u16)) -> Result<TcpStream, Error> {
        for addr in peer
            .to_socket_addrs()
            .map_err(|e| Error::ToSocketError(e))?
        {
            let stream = match TcpStream::connect_timeout(
                &addr,
                Duration::from_millis(self.connect_timeout),
            ) {
                Ok(s) => s,
                Err(e) => {
                    info!("Failed to connect to {:?}: {:?}", &addr, &e);
                    continue;
                }
            };

            stream
                .set_read_timeout(Some(Duration::from_millis(self.duration_timeout)))
                .map_err(Error::ConnectError)?;

            stream
                .set_write_timeout(Some(Duration::from_millis(self.duration_timeout)))
                .map_err(Error::ConnectError)?;

            stream.set_nodelay(true).map_err(Error::ConnectError)?;

            test_debug!(
                "New socket connected to {}:{}: {:?}",
                &peer.0,
                peer.1,
                &stream
            );
            return Ok(stream);
        }
        return Err(Error::NotConnected);
    }

    /// Synchronous HTTP request.
    /// Returns the HttpResponseType on success.
    fn request(socket: &mut TcpStream, req: HttpRequestType) -> Result<HttpResponseType, Error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let mut http = StacksHttp::new(peer);
        req.send(&mut http, socket)?;

        http.reset();
        http.begin_request(HttpVersion::Http11, req.request_path());

        let preamble = StacksHttpPreamble::consensus_deserialize(socket).map_err(|_| {
            Error::NetError(net_error::DeserializeError(
                "Failed to parse HTTP preamble".to_string(),
            ))
        })?;

        let is_chunked = match preamble {
            StacksHttpPreamble::Response(ref resp) => resp.is_chunked(),
            _ => {
                return Err(Error::NetError(net_error::DeserializeError(
                    "Invalid HTTP message: did not get a Response preamble".to_string(),
                )));
            }
        };

        http.set_preamble(&preamble)?;

        if is_chunked {
            match http.stream_payload(&preamble, socket) {
                Ok((Some((message, _)), _)) => match message {
                    StacksHttpMessage::Response(resp) => Ok(resp),
                    _ => Err(Error::NetError(net_error::InvalidMessage)),
                },
                Ok((None, _)) => Err(Error::NetError(net_error::UnderflowError(
                    "Not enough bytes to form a streamed HTTP response".to_string(),
                ))),
                Err(e) => Err(Error::NetError(e)),
            }
        } else {
            let msg_len =
                http.payload_len(&preamble)
                    .ok_or(Error::NetError(net_error::DeserializeError(
                        "Invalid HTTP message: no content-length given".to_string(),
                    )))? as u64;

            if msg_len > MAX_BODY_LEN {
                return Err(Error::NetError(net_error::OverflowError(
                    "Invalid HTTP message: content-length too big".to_string(),
                )));
            }

            let mut message_bytes = Vec::with_capacity(msg_len as usize);
            socket
                .read_exact(&mut message_bytes)
                .map_err(Error::ConnectError)?;

            let (message, _) = http
                .read_payload(&preamble, &mut message_bytes)
                .map_err(Error::NetError)?;

            match message {
                StacksHttpMessage::Response(resp) => Ok(resp),
                _ => Err(Error::NetError(net_error::InvalidMessage)),
            }
        }
    }

    /// Helper method to convert an HttpResponseType for a 4xx or 5xx error into a burnchain_error.
    /// Returns the HttpResponseType itself it it's *not* an error.
    fn handle_http_error(resp: HttpResponseType) -> Result<HttpResponseType, burnchain_error> {
        match resp {
            HttpResponseType::BadRequest(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(400, msg)),
            )),
            HttpResponseType::BadRequestJSON(_md, msg_json) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(400, format!("{}", &msg_json))),
            )),
            HttpResponseType::Unauthorized(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(401, msg)),
            )),
            HttpResponseType::PaymentRequired(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(402, msg)),
            )),
            HttpResponseType::Forbidden(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(403, msg)),
            )),
            HttpResponseType::NotFound(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(404, msg)),
            )),
            HttpResponseType::ServerError(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(500, msg)),
            )),
            HttpResponseType::ServiceUnavailable(_md, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(503, msg)),
            )),
            HttpResponseType::Error(_md, code, msg) => Err(burnchain_error::Indexer(
                indexer_error::Stacks(Error::HttpError(code, msg)),
            )),
            x => Ok(x),
        }
    }

    /// Download a given number of ancestor headers from a given tip.  If the tip is None, then the
    /// latest host chain's tip will be used.  The num_headers argument is the number of ancestors
    /// of tip (including tip) to request.
    ///
    /// Does not rely on any internal session state -- all I/O happens through the given TCP
    /// socket.
    ///
    /// Returns the list of ExtendedStacksHeader instances for the ancestor headers on success.
    pub fn download_headers(
        socket: &mut TcpStream,
        num_headers: u64,
        tip: Option<StacksBlockId>,
    ) -> Result<Vec<ExtendedStacksHeader>, burnchain_error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::GetHeaders(
            HttpRequestMetadata::from_host(PeerHost::from_socketaddr(&peer)),
            num_headers,
            tip,
        );

        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::Headers(_md, headers) = resp {
            Ok(headers)
        } else {
            error!(
                "Invalid response from Stacks node for GetHeaders: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Run a given method `cls` on batches of headers, downloaded in reverse order starting with
    /// the latest on the host chain.  The session argument is a cls-specific type and value to
    /// represent context to be maintained across invocations.  If `cls` returns Ok(false), the
    /// walk stops early.  Similarly, if it errors out, the Err(...) will be returned on the spot.
    ///
    /// The initial_header_request argument is a hint as to the number of headers to go and get on
    /// the first walk.  By default, the node tries to get the maximal amount allowed by the
    /// protocol.  However, because this method is often used to synchronize headers with the host
    /// chain and to find reorgs, it's often only necessary to check the last few headers or so.
    pub fn walk_headers<F, R>(
        socket: &mut TcpStream,
        initial_header_request: u64,
        session: &mut R,
        mut cls: F,
    ) -> Result<(), burnchain_error>
    where
        F: FnMut(&mut R, Vec<ExtendedStacksHeader>) -> Result<bool, burnchain_error>,
    {
        let mut last_tip = None;
        let mut num_headers = initial_header_request;
        loop {
            debug!("Get {} headers tipped at {:?}", num_headers, last_tip);
            let next_headers = AppChainClient::download_headers(socket, num_headers, last_tip)?;
            debug!(
                "Got {} (out of {}) headers tipped at {:?}",
                next_headers.len(),
                num_headers,
                last_tip
            );

            last_tip = match next_headers.last() {
                Some(last_header) => Some(last_header.parent_block_id.clone()),
                None => {
                    break;
                }
            };

            let should_continue = cls(session, next_headers)?;
            if !should_continue {
                break;
            }

            num_headers = MAX_HEADERS as u64;
        }
        Ok(())
    }

    /// Download /v2/info via the given socket
    pub fn download_getinfo(socket: &mut TcpStream) -> Result<RPCPeerInfoData, burnchain_error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::GetInfo(HttpRequestMetadata::from_host(
            PeerHost::from_socketaddr(&peer),
        ));
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        match resp {
            HttpResponseType::PeerInfo(_, peer_info) => Ok(peer_info),
            _ => {
                error!("Invalid response from Stacks node for GetInfo: {:?}", &resp);
                return Err(burnchain_error::Indexer(indexer_error::Stacks(
                    Error::NetError(net_error::InvalidMessage),
                )));
            }
        }
    }

    /// Connect to a remote peer and get its peer info, and set the internal tip member to point to
    /// the remote chain tip.  remote_peer should refer to the host chain, and should have the
    /// given expected_network_id.
    ///
    /// Return the new socket and the RPCPeerInfoData returned on success.
    pub fn try_open_session(
        &mut self,
        remote_peer: (&str, u16),
        expected_network_id: u32,
    ) -> Result<(TcpStream, RPCPeerInfoData), Error> {
        debug!(
            "Try to connect to chain peer {}:{}...",
            remote_peer.0, remote_peer.1
        );
        let mut socket = match self.connect(remote_peer) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Failed to connect to Stacks peer {}:{} ({:?})",
                    &remote_peer.0, remote_peer.1, &e
                );
                return Err(e);
            }
        };

        // we start at the highest tip and work our way back to genesis
        let peer_info = match AppChainClient::download_getinfo(&mut socket) {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    "Failed to get peer info from Stacks peer {}:{} ({:?})",
                    &remote_peer.0, remote_peer.1, &e
                );
                match e {
                    burnchain_error::Indexer(indexer_error::Stacks(e)) => {
                        return Err(e);
                    }
                    _ => {
                        return Err(Error::NotConnected);
                    }
                }
            }
        };

        if peer_info.network_id != expected_network_id {
            // likely a config error
            error!("Remote Stacks peer {}:{} reports chain ID {} (expected {}). Please update your node's config and try again.", &remote_peer.0, &remote_peer.1, peer_info.network_id, expected_network_id);
            return Err(Error::BadPeer);
        }

        self.tip = Some(StacksBlockHeader::make_index_block_hash(
            &peer_info.stacks_tip_consensus_hash,
            &peer_info.stacks_tip,
        ));
        Ok((socket, peer_info))
    }

    /// Connect to the remote peer and get its peer info.
    /// Block until we can do this.
    ///
    /// Used for booting up the node initially, where blocking forever is the preferred thing to
    /// do.
    ///
    /// Returns the new TCP stream and the /v2/info data.
    pub fn begin_session(&mut self) -> (TcpStream, RPCPeerInfoData) {
        let mut connect_timeout = 1;
        loop {
            let remote_peer = self.peer.clone();
            let (socket, peer_info) = match self
                .try_open_session((&remote_peer.0, remote_peer.1), self.parent_chain_id)
            {
                Ok(s) => s,
                Err(Error::BadPeer) => {
                    panic!("Peer {}:{} reports a bad chain ID. This is likely a configuration error. Please update your node and try again", &self.peer.0, self.peer.1);
                }
                Err(e) => {
                    warn!(
                        "Failed to open session to Stacks peer {}:{} ({:?}), trying again in {} ms",
                        &self.peer.0, self.peer.1, &e, &connect_timeout
                    );
                    sleep_ms(connect_timeout);
                    connect_timeout = cmp::max(600, connect_timeout * 2);
                    continue;
                }
            };

            return (socket, peer_info);
        }
    }

    /// Do something via `todo` with a the internal session state -- i.e. the cached /v2/info and
    /// TCP socket to the remote host chain peer.  If the cached /v2/info is stale, or the socket
    /// is broken, then the session will be re-instantiated.
    pub fn with_session<F, R>(&mut self, todo: F) -> Result<R, burnchain_error>
    where
        F: FnOnce(
            &mut AppChainClient,
            &mut TcpStream,
            &RPCPeerInfoData,
        ) -> Result<R, burnchain_error>,
    {
        let mut clear = false;
        if let Some((tcp_socket, rpc_peerinfo)) = self.session.as_mut() {
            // periodically refresh the peerinfo
            if self.refresh_peerinfo_deadline < get_epoch_time_secs() {
                debug!("Refresh peerinfo");
                match AppChainClient::download_getinfo(tcp_socket) {
                    Ok(new_peerinfo) => {
                        *rpc_peerinfo = new_peerinfo;
                    }
                    Err(e) => {
                        debug!("Refresh peerinfo failed: {:?}", &e);
                        let _ = tcp_socket.shutdown(Shutdown::Both);
                        clear = true;
                    }
                }
            }
        }

        if clear {
            // force refresh
            self.session = None;
        }

        if self.session.is_none() {
            // start up a session
            let session = self.begin_session();
            self.session = Some(session);
            self.refresh_peerinfo_deadline = get_epoch_time_secs() + self.refresh_peerinfo_interval;
        }

        if let Some((mut tcp_socket, rpc_peerinfo)) = self.session.take() {
            let result = todo(self, &mut tcp_socket, &rpc_peerinfo);
            if result.is_ok() {
                self.session = Some((tcp_socket, rpc_peerinfo));
            }
            result
        } else {
            unreachable!()
        }
    }

    /// Synchronize all host chain headers and store them to the headers DB.  Returns the highest
    /// header and lowest header downloaded.
    ///
    /// Internally, this will also update the root_to_block map for authenticating MARF proofs.
    pub fn sync_all_headers(
        &mut self,
        socket: &mut TcpStream,
    ) -> Result<(Option<ExtendedStacksHeader>, Option<ExtendedStacksHeader>), burnchain_error> {
        debug!(
            "Sync all headers with parent Stacks chain {}:{}",
            &self.peer.0, self.peer.1
        );
        let mut highest_header_downloaded: Option<ExtendedStacksHeader> = None;
        let mut lowest_header_downloaded: Option<ExtendedStacksHeader> = None;

        let mut light_client = LightClientDB::new(&self.headers_path, true)?;

        AppChainClient::walk_headers(socket, 6, self, |client, reverse_headers| {
            let start_height = if let Some(earliest_header) = reverse_headers.last() {
                earliest_header.header.total_work.work.saturating_sub(1)
            } else {
                // no more headers
                debug!(
                    "Received empty header list from {}:{}",
                    &client.peer.0, client.peer.1
                );
                return Ok(false);
            };

            if let Some(highest_header) = reverse_headers.first() {
                let cur_highest_header_height = highest_header_downloaded
                    .as_ref()
                    .map(|hdr| hdr.header.total_work.work)
                    .unwrap_or(0);

                if highest_header.header.total_work.work > cur_highest_header_height {
                    highest_header_downloaded = Some(highest_header.clone());
                }
            }

            lowest_header_downloaded = reverse_headers.last().cloned();

            let mut more = true;
            if let Some(lowest_header) = reverse_headers.last() {
                // stop if we have them all
                if let Some(ehdr) =
                    light_client.read_block_header(lowest_header.header.total_work.work)?
                {
                    if *lowest_header == ehdr {
                        debug!("Sync'ed Stacks headers down to known header at height {} ({}), so will stop sync'ing", ehdr.header.block_hash(), ehdr.header.total_work.work);
                        more = false;
                    }
                }
            }

            let headers = reverse_headers.into_iter().rev().collect();
            light_client.insert_block_headers(start_height, headers)?;

            if start_height == 0 {
                // no more headers.
                debug!(
                    "Reached header height 0; no more headers to ask for from {}:{}",
                    &client.peer.0, client.peer.1
                );
                return Ok(false);
            }

            // more
            Ok(more)
        })?;

        if let Some(lowest_header_downloaded) = lowest_header_downloaded.as_ref() {
            debug!(
                "Sync'ed down to header at height {}",
                lowest_header_downloaded.header.total_work.work
            );
            let root_to_block =
                light_client.load_root_to_block(lowest_header_downloaded.header.total_work.work)?;
            self.root_to_block.extend(root_to_block.into_iter());
        }

        Ok((highest_header_downloaded, lowest_header_downloaded))
    }

    /// Find the lowest header at which we need to go and re-download and re-process blocks in the
    /// event of a host chain reorg.  Returns a height higher than any known height if no reorg is
    /// necessary.
    pub fn find_reorg_height(
        &mut self,
        socket: &mut TcpStream,
        peer_info: &RPCPeerInfoData,
    ) -> Result<u64, burnchain_error> {
        let tip = StacksBlockHeader::make_index_block_hash(
            &peer_info.stacks_tip_consensus_hash,
            &peer_info.stacks_tip,
        );
        let light_client = LightClientDB::new(&self.headers_path, false)?;
        let highest_header_height = light_client.get_highest_header_height()?;
        let mut diverged_height = highest_header_height + 1;

        if self.tip == Some(tip) {
            return Ok(diverged_height);
        }

        // tip changed. Most likely, this means the chain advanced, but either way, sync headers
        // until we find the highest common ancestor and return *its* height.
        AppChainClient::walk_headers(socket, 6, self, |_client, reverse_headers| {
            for ehdr in reverse_headers {
                // if we have this header, then we're done
                match light_client.read_block_header(ehdr.header.total_work.work)? {
                    Some(our_ehdr) => {
                        if our_ehdr != ehdr {
                            // divergence
                            debug!(
                                "Stacks parent reorg detected: {:?} != {:?}",
                                &our_ehdr, &ehdr
                            );
                            diverged_height = ehdr.header.total_work.work;
                            return Ok(false);
                        }
                    }
                    None => {
                        // we don't have this header!
                        debug!(
                            "Stacks parent reorg detected: no header at height {}",
                            ehdr.header.total_work.work
                        );
                        diverged_height = ehdr.header.total_work.work;
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })?;

        Ok(diverged_height)
    }

    /// Given the cached host chain tip, find both its id-block-hash and associated state root hash
    /// from the MARF.  Errors out if there is no cached tip.
    fn get_marf_tip(&self) -> Result<(StacksBlockId, TrieHash), burnchain_error> {
        let (tip, marf_tip) = if let Some(tip) = self.tip.as_ref() {
            // find the associated MARF state root for this tip
            let light_client = LightClientDB::new(&self.headers_path, false)?;
            if let Some(marf_tip) = light_client.load_state_root_hash(tip)? {
                (tip.clone(), marf_tip.clone())
            } else {
                test_debug!("No state index root for {}", &tip);
                return Err(burnchain_error::MissingHeaders);
            }
        } else {
            test_debug!("No chain tip loaded yet");
            return Err(burnchain_error::MissingHeaders);
        };

        Ok((tip, marf_tip))
    }

    /// Given a MARF key/value pair, a MARF merkle proof, the MARF root <--> Stacks block mapping
    /// obtained from the host chain's headers, and the current MARF tip, verify that the given
    /// value is set in the MARF as of the MARF tip.
    ///
    /// Errors out on verification failure.
    fn authenticate_string(
        marf_tip: &TrieHash,
        marf_key: String,
        serialized_value: String,
        marf_proof_opt: Option<String>,
        root_to_block: &HashMap<TrieHash, StacksBlockId>,
    ) -> Result<(), burnchain_error> {
        if let Some(serialized_proof_hex_string) = marf_proof_opt {
            // NOTE: truncate the 0x at the beginning!
            // NOTE: some older versions of the software don't have a leading 0x
            let serialized_proof = hex_bytes(
                serialized_proof_hex_string
                    .strip_prefix("0x")
                    .unwrap_or(&serialized_proof_hex_string),
            )
            .map_err(|_| {
                warn!("MARF proof is not a hex string");
                burnchain_error::BurnchainPeerBroken
            })?;

            let marf_proof =
                TrieMerkleProof::<StacksBlockId>::consensus_deserialize(&mut &serialized_proof[..])
                    .map_err(|_| {
                        warn!("MARF proof could not be decoded");
                        burnchain_error::Indexer(indexer_error::Stacks(Error::NetError(
                            net_error::DeserializeError(
                                "Failed to decode MARF proof for data var".to_string(),
                            ),
                        )))
                    })?;

            let marf_path = TriePath::from_key(&marf_key);
            let marf_value = MARFValue::from_value(&serialized_value);
            if !marf_proof.verify(&marf_path, &marf_value, &marf_tip, root_to_block) {
                warn!("Failed to verify MARF proof");
                return Err(burnchain_error::BurnchainPeerBroken);
            }
            Ok(())
        } else {
            warn!("MARF proof not given by remote burnchain peer");
            Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )))
        }
    }

    /// Wrapper around authenticate_string().
    /// Verify that a key/value pair is present in the MARF via an inner call to
    /// authenticate_string, and expect that the value is a hex string.  Returns the byte
    /// representation if the proof is given and is valid, and the value is a hex string.
    fn authenticate_bytes(
        marf_tip: &TrieHash,
        marf_key: String,
        serialized_value: String,
        marf_proof_opt: Option<String>,
        root_to_block: &HashMap<TrieHash, StacksBlockId>,
    ) -> Result<Vec<u8>, burnchain_error> {
        AppChainClient::authenticate_string(
            marf_tip,
            marf_key,
            serialized_value.clone(),
            marf_proof_opt,
            root_to_block,
        )?;

        let bin = hex_bytes(&serialized_value).map_err(|_| {
            warn!("MARF value is not a hex string");
            burnchain_error::BurnchainPeerBroken
        })?;

        Ok(bin)
    }

    /// Wrapper around authenticate_bytes().
    /// Verify that the given key/value pair is present in the MARF, and also that it decodes to a
    /// Clarity value.  Return the Clarity value if so.
    fn authenticate_value(
        &self,
        marf_tip: &TrieHash,
        marf_key: String,
        marf_value: String,
        marf_proof_opt: Option<String>,
        data_type: &TypeSignature,
    ) -> Result<Value, burnchain_error> {
        let serialized_value = marf_value
            .strip_prefix("0x")
            .ok_or_else(|| {
                warn!("MARF value does not begin with 0x");
                burnchain_error::BurnchainPeerBroken
            })?
            .to_string();
        let value_bin = AppChainClient::authenticate_bytes(
            marf_tip,
            marf_key,
            serialized_value,
            marf_proof_opt,
            &self.root_to_block,
        )?;
        let value =
            Value::deserialize_read(&mut &value_bin[..], Some(&data_type)).map_err(|e| {
                Error::NetError(net_error::DeserializeError(format!(
                    "Failed to parse value: {:?}",
                    &e
                )))
            })?;

        Ok(value)
    }

    /// Wrapper around authenticate_value().
    /// Verify that a given data var is present in the MARF, and if so, return its Clarity value.
    fn authenticate_data_var(
        &self,
        marf_tip: &TrieHash,
        data_var_name: &str,
        data_var: DataVarResponse,
        data_type: &TypeSignature,
    ) -> Result<Value, burnchain_error> {
        let marf_key = ClarityDatabase::make_key_for_trip(
            &self.contract_id,
            StoreType::Variable,
            data_var_name,
        );
        self.authenticate_value(
            marf_tip,
            marf_key,
            data_var.data,
            data_var.marf_proof,
            data_type,
        )
    }

    /// Wrapper around authenticate_value().
    /// Verify that a given data map entry's value is present in the MARF, given its key.
    /// If so, return its Clarity value.
    fn authenticate_data_map_entry(
        &self,
        marf_tip: &TrieHash,
        data_map_entry_name: &str,
        data_map_entry_key: &Value,
        map_entry: MapEntryResponse,
        data_value_type: &TypeSignature,
    ) -> Result<Value, burnchain_error> {
        if let Some(ref serialized_proof_hex_string) = map_entry.marf_proof.as_ref() {
            // if this data entry doesn't exist, then bail out
            if serialized_proof_hex_string.len() == 0
                && map_entry.data == format!("0x{}", &Value::none().serialize())
            {
                return Err(burnchain_error::NoDataReturned);
            }
        }

        let marf_key = ClarityDatabase::make_key_for_data_map_entry(
            &self.contract_id,
            data_map_entry_name,
            &data_map_entry_key,
        );
        self.authenticate_value(
            marf_tip,
            marf_key,
            map_entry.data,
            map_entry.marf_proof,
            data_value_type,
        )
    }

    /// Wrapper around authenticate_bytes().
    /// Verify that a given smart contract source is present in the MARF, given its address.
    /// If so, return its StacksString representation.
    fn authenticate_contract_src(
        marf_tip: &TrieHash,
        contract_address: &StacksAddress,
        contract_name: &ContractName,
        src_response: ContractSrcResponse,
        root_to_block: &HashMap<TrieHash, StacksBlockId>,
    ) -> Result<StacksString, burnchain_error> {
        let marf_key = make_contract_hash_key(&QualifiedContractIdentifier {
            issuer: StandardPrincipalData(
                contract_address.version,
                contract_address.clone().bytes.0,
            ),
            name: contract_name.clone(),
        });
        let marf_value = {
            let cc = ContractCommitment {
                hash: Sha512Trunc256Sum::from_data(src_response.source.as_bytes()),
                block_height: src_response.publish_height,
            };
            cc.serialize()
        };

        let _ = AppChainClient::authenticate_bytes(
            marf_tip,
            marf_key,
            marf_value,
            src_response.marf_proof,
            root_to_block,
        )?;
        let code = StacksString::from_string(&src_response.source).ok_or(Error::NetError(
            net_error::DeserializeError("Failed to parse code to StacksString".to_string()),
        ))?;

        Ok(code)
    }

    /// Decode a literal u128 represented as a 16-byte big-endian hex string
    fn decode_u128(value: &str) -> Result<u128, burnchain_error> {
        let bytes = hex_bytes(value.strip_prefix("0x").ok_or_else(|| {
            warn!("MARF u128 value does not begin with 0x");
            burnchain_error::BurnchainPeerBroken
        })?)
        .map_err(|_| {
            warn!("MARF u128 value is not a hex string");
            burnchain_error::BurnchainPeerBroken
        })?;

        if bytes.len() != 16 {
            warn!("Invalid balance value: not 16-byte hex string");
            return Err(burnchain_error::BurnchainPeerBroken);
        }

        let mut bytes_16 = [0u8; 16];
        bytes_16.copy_from_slice(&bytes[0..16]);
        Ok(u128::from_be_bytes(bytes_16))
    }

    /// Authenticate a Stacks account.  Verify both the MARF proofs of its nonce as well as its
    /// balance.  Return the StacksAccount on success.
    fn authenticate_account(
        &self,
        marf_tip: &TrieHash,
        address: StacksAddress,
        account_response: AccountEntryResponse,
    ) -> Result<StacksAccount, burnchain_error> {
        let account_principal = address.to_account_principal();

        // no proof means the account isn't realized
        if let Some(proof) = account_response.balance_proof.as_ref() {
            if proof.len() == 0 {
                return Ok(StacksAccount::empty(address.to_account_principal()));
            }
        } else {
            warn!("MARF proof not given by remote burnchain peer");
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }

        if let Some(proof) = account_response.nonce_proof.as_ref() {
            if proof.len() == 0 {
                return Ok(StacksAccount::empty(address.to_account_principal()));
            }
        } else {
            warn!("MARF proof not given by remote burnchain peer");
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }

        let marf_balance_key = ClarityDatabase::make_key_for_account_balance(&account_principal);
        let marf_nonce_key = ClarityDatabase::make_key_for_account_nonce(&account_principal);

        let balance = STXBalance {
            amount_unlocked: AppChainClient::decode_u128(&account_response.balance)?,
            amount_locked: AppChainClient::decode_u128(&account_response.locked)?,
            unlock_height: account_response.unlock_height,
        };

        let marf_balance_value = balance.serialize();
        let marf_nonce_value = account_response.nonce.serialize();

        let _ = AppChainClient::authenticate_bytes(
            marf_tip,
            marf_balance_key,
            marf_balance_value,
            account_response.balance_proof,
            &self.root_to_block,
        )
        .map_err(|e| {
            warn!("MARF failed to authenticate balance for {}", &address);
            e
        })?;

        AppChainClient::authenticate_string(
            marf_tip,
            marf_nonce_key,
            marf_nonce_value,
            account_response.nonce_proof,
            &self.root_to_block,
        )
        .map_err(|e| {
            warn!("MARF failed to authenticate balance for {}", &address);
            e
        })?;

        Ok(StacksAccount {
            principal: address.to_account_principal(),
            nonce: account_response.nonce,
            stx_balance: balance,
        })
    }

    /// Helper method to make an HTTP request for a data map entry.
    /// Errors out of the given socket is not connected.
    fn make_map_entry_request(
        &self,
        socket: &TcpStream,
        map_name: &str,
        map_key: Value,
        tip: StacksBlockId,
    ) -> Result<HttpRequestType, Error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::GetMapEntry(
            HttpRequestMetadata::from_host(PeerHost::from_socketaddr(&peer)),
            self.contract_id.clone().issuer.into(),
            self.contract_id.clone().name.clone(),
            map_name.into(),
            map_key,
            Some(tip),
            true,
        );
        Ok(req)
    }

    /// Helper method to make an HTTP request for a data var.
    /// Errors out of the given socket is not connected.
    fn make_data_var_request(
        &self,
        socket: &TcpStream,
        var_name: &str,
        tip: StacksBlockId,
    ) -> Result<HttpRequestType, Error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::GetDataVar(
            HttpRequestMetadata::from_host(PeerHost::from_socketaddr(&peer)),
            self.contract_id.clone().issuer.into(),
            self.contract_id.clone().name.clone(),
            var_name.into(),
            Some(tip),
            true,
        );
        Ok(req)
    }

    /// Helper method to make an HTTP request for a smart contract.
    /// Errors out of the given socket is not connected.
    fn make_contract_src_request(
        socket: &TcpStream,
        contract_address: StacksAddress,
        contract_name: ContractName,
        tip: StacksBlockId,
    ) -> Result<HttpRequestType, Error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::GetContractSrc(
            HttpRequestMetadata::from_host(PeerHost::from_socketaddr(&peer)),
            contract_address,
            contract_name,
            Some(tip),
            true,
        );
        Ok(req)
    }

    /// Helper method to make an HTTP request for a Stacks account.
    /// Errors out of the given socket is not connected.
    fn make_account_request(
        socket: &TcpStream,
        address: StacksAddress,
        tip: StacksBlockId,
    ) -> Result<HttpRequestType, Error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::GetAccount(
            HttpRequestMetadata::from_host(PeerHost::from_socketaddr(&peer)),
            address.to_account_principal(),
            Some(tip),
            true,
        );
        Ok(req)
    }

    /// Helper method to make a POST-transaction request.
    /// Errors out of the given socket is not connected.
    fn make_post_transaction_request(
        socket: &TcpStream,
        tx: StacksTransaction,
        attachment: Option<Attachment>,
    ) -> Result<HttpRequestType, Error> {
        let peer = socket.peer_addr().map_err(Error::RequestError)?;
        let req = HttpRequestType::PostTransaction(
            HttpRequestMetadata::from_host(PeerHost::from_socketaddr(&peer)),
            tx,
            attachment,
        );
        Ok(req)
    }

    /// Send a transaction via the given socket.
    pub fn send_transaction(
        socket: &mut TcpStream,
        tx: StacksTransaction,
        attachment: Option<Attachment>,
    ) -> Result<(), burnchain_error> {
        let expected_txid = tx.txid();

        debug!("Sending Stacks transaction {:?}", &tx);

        let req = AppChainClient::make_post_transaction_request(socket, tx, attachment)?;
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::TransactionID(_, txid) = resp {
            if txid != expected_txid {
                error!(
                    "Invalid response from Stacks node for PostTransaction: got {}, expected {}",
                    &txid, &expected_txid
                );
                return Err(burnchain_error::BurnchainPeerBroken);
            }
            Ok(())
        } else {
            error!(
                "Invalid response from Stacks node for PostTransaction: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Download and authenticate a Stacks account
    pub fn download_account(
        &mut self,
        address: StacksAddress,
        socket: &mut TcpStream,
    ) -> Result<StacksAccount, burnchain_error> {
        let (tip, marf_tip) = self.get_marf_tip()?;
        let req = AppChainClient::make_account_request(socket, address, tip.clone())?;
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::GetAccount(_, account_response) = resp {
            self.authenticate_account(&marf_tip, address, account_response)
        } else {
            error!(
                "Invalid response from Stacks node for GetAccount: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Download and authenticate the appchain config version data var.
    pub fn download_appchain_version(
        &mut self,
        socket: &mut TcpStream,
    ) -> Result<u128, burnchain_error> {
        let (tip, marf_tip) = self.get_marf_tip()?;
        let req = self.make_data_var_request(socket, DATA_VAR_APPCHAIN_VERSION, tip.clone())?;
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::GetDataVar(_md, data_var) = resp {
            let value = self.authenticate_data_var(
                &marf_tip,
                DATA_VAR_APPCHAIN_VERSION,
                data_var,
                &DATA_VAR_APPCHAIN_VERSION_TYPE,
            )?;
            let appchain_version = value
                .checked_u128()
                .ok_or(burnchain_error::UnsupportedBurnchain)?;

            // loaded!
            Ok(appchain_version)
        } else {
            error!(
                "Invalid response from Stacks node for GetMapEntry: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Download and authenticate the appchain config data var.  If successful, store a copy of it
    /// internally, as well as remember the chain ID so that a subsequent request to a peer
    /// appchain node will succeed.
    pub fn download_config(
        &mut self,
        socket: &mut TcpStream,
        appchain_version: u128,
        appchain_genesis_hash: TrieHash,
    ) -> Result<AppChainConfig, burnchain_error> {
        let (tip, marf_tip) = self.get_marf_tip()?;
        let req = self.make_data_var_request(socket, DATA_VAR_APPCHAIN_CONFIG, tip.clone())?;
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::GetDataVar(_md, data_var) = resp {
            let value = self.authenticate_data_var(
                &marf_tip,
                DATA_VAR_APPCHAIN_CONFIG,
                data_var,
                &DATA_VAR_APPCHAIN_CONFIG_TYPE,
            )?;
            let mut appchain_config = AppChainConfig::from_value(
                self.mainnet,
                self.parent_chain_id,
                self.contract_id.clone(),
                appchain_version,
                appchain_genesis_hash,
                value,
            )
            .ok_or(burnchain_error::UnsupportedBurnchain)?;

            // find the associated burnchain block
            let light_client = LightClientDB::new(&self.headers_path, false)?;
            let start_header = light_client
                .read_block_header(appchain_config.start_block())?
                .ok_or_else(|| {
                    error!(
                        "No parent Stacks header at height {}",
                        appchain_config.start_block()
                    );
                    burnchain_error::MissingHeaders
                })?;

            appchain_config.set_first_block_hash(BurnchainHeaderHash(
                StacksBlockHeader::make_index_block_hash(
                    &start_header.consensus_hash,
                    &start_header.header.block_hash(),
                )
                .0,
            ));

            // loaded!
            self.chain_id = appchain_config.chain_id();
            self.config = Some(appchain_config.clone());
            Ok(appchain_config)
        } else {
            error!(
                "Invalid response from Stacks node for GetMapEntry: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Download and authenticate a smart contract from the boot address in the boot block of a
    /// remote Stacks node.  The given genesis_hash value would be given via the appchain-config
    /// data var.
    pub fn download_boot_contract(
        socket: &mut TcpStream,
        mainnet: bool,
        contract_name: &ContractName,
        genesis_hash: &TrieHash,
    ) -> Result<StacksString, burnchain_error> {
        let mut genesis_root_to_block = HashMap::new();
        let genesis_tip = StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        );
        genesis_root_to_block.insert(genesis_hash.clone(), genesis_tip.clone());

        let req = AppChainClient::make_contract_src_request(
            socket,
            boot_code_addr(mainnet),
            contract_name.clone(),
            genesis_tip,
        )?;
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::GetContractSrc(_md, src_response) = resp {
            let code = AppChainClient::authenticate_contract_src(
                &genesis_hash,
                &boot_code_addr(mainnet),
                &contract_name,
                src_response,
                &genesis_root_to_block,
            )?;
            Ok(code)
        } else {
            error!(
                "Invalid response from Stacks node for GetContractSrc: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Download a "block" via the given socket, given its header.
    /// The app chain client must already have performed a header sync and booted up.
    /// The "block" in this case is really the list of entries in the appchains data map on the
    /// host chain's mining contract that were inserted at the height of this header.  These
    /// entries will be authenticated via the host chain's MARF and assembled into a
    /// MiningContractBlock on success.
    ///
    /// Blocks *must* be downloaded in ascending order.  To enforce commit chaining (a
    /// discount-mining countermeasure), the code keeps track of the last transaction each "miner"
    /// sent, and pairs that up with extracted transactions in this "block".  Since this
    /// last-transaction table is built up incrementally this way by this method, the blocks must
    /// be fetched in order.  Since this method is called by the burnchain indexer (which does
    /// this), this should work out.
    pub fn download_block(
        &mut self,
        socket: &mut TcpStream,
        header: &ExtendedStacksHeader,
    ) -> Result<MiningContractBlock, burnchain_error> {
        let (tip, marf_tip) = self.get_marf_tip()?;
        let req = self.make_map_entry_request(
            socket,
            DATA_MAP_APPCHAIN_NAME,
            Value::UInt(header.header.total_work.work as u128),
            tip.clone(),
        )?;
        let resp = AppChainClient::request(socket, req)?;
        let resp = AppChainClient::handle_http_error(resp)?;
        if let HttpResponseType::GetMapEntry(_md, map_entry) = resp {
            let value = match self.authenticate_data_map_entry(
                &marf_tip,
                DATA_MAP_APPCHAIN_NAME,
                &Value::UInt(header.header.total_work.work as u128),
                map_entry,
                &DATA_MAP_APPCHAIN_TYPE,
            ) {
                Ok(value) => value,
                Err(burnchain_error::NoDataReturned) => {
                    // no map entry for this block
                    warn!(
                        "No block data for appchain block height {}",
                        header.header.total_work.work
                    );
                    return Ok(MiningContractBlock {
                        header: header.clone(),
                        txs: vec![],
                    });
                }
                Err(e) => {
                    return Err(e);
                }
            };

            let mut light_client = LightClientDB::new(&self.headers_path, true)?;

            // transaction last sent by standard address, used for prestx in the same block as
            // stackstx and transferstx.
            let mut last_sent: HashMap<StacksAddress, Txid> = HashMap::new();

            let txs = value
                .expect_optional() // NOTE: we typechecked already above in Value::deserialize_read()
                .map(|value| {
                    value
                        .expect_list() // NOTE: we typechecked already above in Value::deserialize_read()
                        .into_iter()
                        .enumerate()
                        .filter_map(|(vtxindex, tx_value)| {
                            let components = tx_value.clone().checked_tuple()?;

                            // data must be well-formed
                            let data = components.get("data").ok()?.clone().checked_buff(80)?;
                            if data.len() < 3 {
                                debug!("Transaction data is too short in {:?}", &tx_value);
                                return None;
                            }
                            if &data[0..2] != self.magic_bytes.as_bytes() {
                                debug!(
                                    "Transaction data does not start with magic bytes: {:?}",
                                    &tx_value
                                );
                                return None;
                            }

                            // find the txid this principal last sent so we can handle
                            // prestx-dependent operations
                            let sender =
                                components.get("sender").ok()?.clone().checked_principal()?;
                            let last_txid_opt = if let PrincipalData::Standard(ref data) = &sender {
                                let addr = StacksAddress::from(data.clone());
                                match last_sent.get(&addr) {
                                    Some(last_txid) => Some(last_txid.clone()),
                                    None => LightClientDB::get_last_sender_txid(
                                        light_client.conn(),
                                        &StacksAddress::from(data.clone()),
                                        header.header.total_work.work,
                                        vtxindex as u64,
                                    )
                                    .expect("BUG: failed to query last sender txid"),
                                }
                            } else {
                                // contracts aren't supported for prestx
                                None
                            };

                            let tx_opt = if let Some(last_txid) = last_txid_opt {
                                debug!("Last txid from {} is {}", &sender.to_string(), &last_txid);
                                MiningContractTransaction::from_value(
                                    tx_value,
                                    self.mainnet,
                                    header.header.total_work.work as u32,
                                    vtxindex as u32,
                                    last_txid,
                                )
                            } else {
                                // generate a determinstic fake txid that won't match any txid in
                                // the burnchain DB.
                                debug!("No last txid from {}, so mocking it", &sender.to_string());
                                MiningContractTransaction::from_value_mock_txid(
                                    tx_value.clone(),
                                    self.mainnet,
                                    header.header.total_work.work as u32,
                                    vtxindex as u32,
                                )
                            };

                            if let Some(tx) = tx_opt.as_ref() {
                                if let PrincipalData::Standard(ref data) = &sender {
                                    last_sent.insert(StacksAddress::from(data.clone()), tx.txid());
                                }
                            }

                            tx_opt
                        })
                        .collect()
                })
                .unwrap_or(vec![]);

            // record each miner's txid from this block, so that in subsequent blocks, we can find
            // the miner's prior txid.
            {
                let mut dbtx = light_client.tx_begin()?;
                for tx in txs.iter() {
                    if let PrincipalData::Standard(ref data) = &tx.sender {
                        LightClientDB::insert_sender_txid(
                            &mut dbtx,
                            &StacksAddress::from(data.clone()),
                            &tx.txid(),
                            header.header.total_work.work,
                            tx.vtxindex().into(),
                        )?;
                    }
                }
                dbtx.commit()?;
            }

            debug!(
                "Downloaded appchain block {} from {}: {} txs",
                header.header.total_work.work,
                &self.contract_id,
                txs.len()
            );
            Ok(MiningContractBlock {
                header: header.clone(),
                txs: txs,
            })
        } else {
            error!(
                "Invalid response from Stacks node for GetMapEntry: {:?}",
                &resp
            );
            return Err(burnchain_error::Indexer(indexer_error::Stacks(
                Error::NetError(net_error::InvalidMessage),
            )));
        }
    }

    /// Get the boot code for this appchain, once the client has been booted up.  This method only
    /// returns if it can match all of its appchain-config's boot-code contract names to code
    /// bodies.  It returns None if at least one is missing.
    pub fn get_boot_code(&self) -> Option<Vec<(ContractName, StacksString)>> {
        if let Some(config) = self.config.as_ref() {
            let mut ret = vec![];
            let boot_contracts = config.boot_code_contract_names();
            for boot_contract in boot_contracts {
                if let Some(contract) = self.boot_code.get(&boot_contract) {
                    ret.push((boot_contract.clone(), contract.clone()));
                } else {
                    return None;
                }
            }
            Some(ret)
        } else {
            None
        }
    }

    /// Top-level appchain client instantiation logic.  Given a HashMap of available boot code
    /// (which does not need to be complete), this method will go and set up a burnchain working
    /// directory, download all host chain headers, and download the appchain configuration and
    /// boot code.  If it succeeds, it returns the host chain's chain tip's extended Stacks header.
    ///
    /// This method is idempotent.  Keep calling it until it succeeds.
    pub fn bootup(
        &mut self,
        available_boot_code: &HashMap<ContractName, StacksString>,
    ) -> Result<ExtendedStacksHeader, burnchain_error> {
        let (mut socket, _) = self.begin_session();
        self.sync_all_headers(&mut socket)?;
        self.refresh_root_to_block_map()?;
        if self.config.is_none() {
            debug!("Downloading appchain config version");
            let appchain_version = self.download_appchain_version(&mut socket)?;

            debug!("Downloading appchain config (version {})", appchain_version);
            let config =
                self.download_config(&mut socket, appchain_version, self.genesis_hash.clone())?;

            debug!("Downloading appchain boot code");
            for contract_name in config.boot_code_contract_names().into_iter() {
                if self.boot_code.contains_key(&contract_name) {
                    debug!("Already have appchain boot code {}", &contract_name);
                    continue;
                }
                if let Some(src) = available_boot_code.get(&contract_name) {
                    debug!(
                        "Appchain boot code for {} available locally",
                        &contract_name
                    );
                    self.boot_code.insert(contract_name, src.clone());
                } else {
                    let mut found = false;
                    for ((_pubkey, _p2p_boot_peer), data_boot_peer) in
                        config.boot_nodes().into_iter()
                    {
                        // talk to a bootstrap peer and get *its* contracts
                        let (host, port) = data_boot_peer.to_host_port();
                        let (mut socket, _) =
                            match self.try_open_session((host.as_str(), port), self.chain_id) {
                                Ok(x) => x,
                                Err(e) => {
                                    warn!(
                                        "Failed to open session to bootstrap peer {}:{}: {:?}",
                                        &host, port, &e
                                    );
                                    continue;
                                }
                            };

                        debug!(
                            "Downloading boot code {}.{} from {}",
                            &boot_code_addr(self.mainnet),
                            &contract_name,
                            &data_boot_peer
                        );
                        let boot_code = match AppChainClient::download_boot_contract(
                            &mut socket,
                            self.mainnet,
                            &contract_name,
                            &config.genesis_hash(),
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(
                                    "Failed to download boot code for .{} from {}:{}: {:?}",
                                    &contract_name, &host, port, &e
                                );
                                continue;
                            }
                        };

                        self.boot_code.insert(contract_name.clone(), boot_code);

                        info!(
                            "Obtained boot code for {}.{} from {}",
                            &boot_code_addr(self.mainnet),
                            &contract_name,
                            &data_boot_peer
                        );
                        found = true;
                        break;
                    }
                    if !found {
                        error!("Failed to download boot code for .{}", &contract_name);

                        // make this idempotent
                        self.config = None;
                        return Err(burnchain_error::NoDataReturned);
                    }
                }
            }
        }

        // returns the highest header
        let light_client = LightClientDB::new(&self.headers_path, false)?;
        let highest_header_height = light_client.get_highest_header_height()?;
        let highest_header = light_client
            .read_block_header(highest_header_height)?
            .ok_or(burnchain_error::MissingHeaders)?;

        Ok(highest_header)
    }

    /// Load the MARF root hash <--> stacks block id map from the headers DB.
    /// Used by clients that don't sync the chain, but read from an existing header db
    pub fn refresh_root_to_block_map(&mut self) -> Result<(), burnchain_error> {
        let light_client = LightClientDB::new(&self.headers_path, false)?;
        let root_to_block = light_client.load_root_to_block(0)?;
        self.root_to_block.extend(root_to_block.into_iter());
        debug!("Root-to-block map has {} entries", self.root_to_block.len());
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use std::collections::HashMap;
    use std::error;
    use std::fmt;
    use std::io;
    use std::io::Read;
    use std::net::ToSocketAddrs;

    use chainstate::stacks::StacksBlock;
    use vm::ast::build_ast;
    use vm::database::ClarityDatabase;
    use vm::representations::UrlString;
    use vm::types::signatures::TypeSignature;
    use vm::types::QualifiedContractIdentifier;
    use vm::types::Value;

    use codec::StacksMessageCodec;

    use address::*;

    use chainstate::stacks::address::*;
    use net::test::*;
    use net::Error as net_error;
    use net::*;

    use chainstate::coordinator::tests::get_chainstate_path_str;
    use chainstate::stacks::db::*;
    use chainstate::stacks::Error as chainstate_error;
    use chainstate::stacks::*;

    use burnchains::stacks::AppChainClient;
    use burnchains::stacks::Error;
    use burnchains::stacks::MiningContractBlock;
    use burnchains::stacks::MiningContractTransaction;
    use burnchains::Address;
    use burnchains::Burnchain;
    use burnchains::Error as burnchain_error;
    use burnchains::PoxConstants;

    use burnchains::indexer::BurnchainBlockParser;
    use burnchains::indexer::BurnchainIndexer;
    use burnchains::BurnchainBlock;
    use burnchains::BurnchainBlockHeader;
    use burnchains::BurnchainRecipient;
    use burnchains::BurnchainSigner;
    use burnchains::BurnchainTransaction;
    use burnchains::ConsensusHash;
    use burnchains::IndexerError as indexer_error;

    use chainstate::burn::operations::leader_block_commit::*;
    use chainstate::burn::operations::*;

    use chainstate::stacks::boot::BOOT_CODE_COSTS;
    use chainstate::stacks::index::node::TriePath;

    use crate::types::chainstate::{
        BlockHeaderHash, MARFValue, StacksBlockHeader, StacksBlockId, StacksWorkScore,
    };
    use crate::types::proof::{TrieHash, TrieMerkleProof};

    use std::time::Duration;

    use std::net::TcpStream;

    use chainstate::burn::db::sortdb::*;
    use chainstate::stacks::db::test::*;
    use chainstate::stacks::events::*;
    use util::hash::*;
    use util::strings::*;
    use util::vrf::*;

    use vm::costs::ExecutionCost;
    use vm::database::NULL_BURN_STATE_DB;
    use vm::ContractName;

    use types::chainstate::*;

    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::thread;

    use std::fs;

    const APPCHAIN_MINING_CONTRACT: &str = r#"
(define-data-var appchain-version uint u1)

(define-map appchain
    ;; parent stacks chain block height
    uint
    ;; list of burnchain operations at that height
    (list 128 {
        ;; miner
        sender: principal,
        ;; is this operation chained to the last one?  Only applies to block-commits
        chained?: bool,
        ;; burnchain op payload (serialized)
        data: (buff 80),
        ;; amount of parent tokens destroyed
        burnt: uint,
        ;; total amount of tokens transferred
        transferred: uint,
        ;; PoX recipients on parent chain
        recipients: (list 2 principal)
    })
)
(define-data-var appchain-config
    {
        chain-id: uint,
        start-height: uint,
        boot-nodes: (list 16 { public-key: (buff 33), host: (buff 16), port: (buff 2), data-host: (buff 16), data-port: (buff 2) }),
        pox: {
            reward-cycle-length: uint,
            prepare-length: uint,
            anchor-threshold: uint,
            pox-rejection-fraction: uint,
            pox-participation-threshold-pct: uint,
            sunset-start: uint,
            sunset-end: uint
        },
        block-limit: {
            write-length: uint,
            write-count: uint,
            read-length: uint,
            read-count: uint,
            runtime: uint
        },
        initial-balances: (list 128 { recipient: principal, amount: uint }),
        boot-code: (list 128 (string-ascii 128)),
    }
    {
        chain-id: u2147483650,   ;; 0x80000002
        start-height: (+ u5 block-height),
        boot-nodes: (list
            {
                ;; private key: 9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001
                public-key: 0x038cc1dc238b5b6f8d0a8b38baf5c52280396f8a209cc4de33caff2daefe756c23, 
                ;; 127.0.0.1:8000
                host: 0x00000000000000000000ffff7f000001,
                port: 0x1f40,
                ;; 127.0.0.1:8001
                data-host: 0x00000000000000000000ffff7f000001,
                data-port: 0x1f41
            }
        ),
        pox: {
            reward-cycle-length: u5,
            prepare-length: u3,
            anchor-threshold: u2,
            pox-rejection-fraction: u25,
            pox-participation-threshold-pct: u5,
            sunset-start: u18446744073709551615,
            sunset-end: u18446744073709551615
        },
        block-limit: {
            write-length: u15000000,
            write-count: u7750,
            read-length: u100000000,
            read-count: u7750,
            runtime: u5000000000
        },
        initial-balances: (list
            {
                ;; private key: 3bfbeabafb8c6708ac85e66feaf76074a827e74f3e81678600153d94b5bd1a2b01
                recipient: 'ST3N0JG3EE5Z2R3HN7WAEFM0HRGHHMCD4E170C0T1,
                amount: u1000000
            }
        ),
        boot-code: (list
            "hello-world"
        ),
    }
)

(define-map last-mined-heights
    ;; sender
    principal
    ;; height at which a block-commit was last sent
    uint
)

(define-private (add-nonmining-block-op (payload (buff 80)) (recipients (list 2 principal)))
    (let (
       (op-list (default-to (list ) (map-get? appchain block-height)))
    )
       (map-set appchain block-height 
           (unwrap-panic
               (as-max-len? (append op-list {
                   sender: tx-sender,
                   chained?: true,
                   data: payload,
                   burnt: u0,
                   transferred: u0,
                   recipients: recipients
               })
               u128)
           )
       )
       (ok true)
    )
)

(define-public (register-vrf-key (key-op (buff 80)))
    (add-nonmining-block-op key-op (list ))
)

(define-public (register-vrf-key-as-contract (key-op (buff 80)))
   (as-contract (register-vrf-key key-op))
)

(define-private (send-to-recipient (recipient principal) (amount uint))
    (begin
        (unwrap-panic
            (if (not (is-eq tx-sender recipient))
                (stx-transfer? amount tx-sender recipient)
                (ok true)
            )
        )
        amount
    )
)

(define-public (mine-block (block-op (buff 80)) (to-burn uint) (recipients (list 2 principal)) (recipient-amount uint))
    (let (
        (op-list (default-to (list ) (map-get? appchain block-height)))
        ;; pessimistic take: consider block-commits chained only if the miner mined in the last block
        (chained? (is-eq block-height (+ u1 (default-to u0 (map-get? last-mined-heights tx-sender)))))
    )
        (asserts! (> (len recipients) u0)
            (err u0))   ;; no recipients

        (asserts! (> recipient-amount u0)
            (err u3))   ;; amount to send is non-positive

        (asserts! (>= (stx-get-balance tx-sender) (+ to-burn (* (len recipients) recipient-amount)))
            (err u1))   ;; insufficient balance

        (if (> to-burn u0)
            (unwrap-panic (stx-burn? to-burn tx-sender))
            true
        )

        (fold send-to-recipient recipients recipient-amount)

        (map-set appchain block-height
            (unwrap-panic
                (as-max-len? (append op-list {
                    sender: tx-sender,
                    chained?: chained?,
                    data: block-op,
                    burnt: to-burn,
                    transferred: (* (len recipients) recipient-amount),
                    recipients: recipients
                })
                u128)
            )
        )
        (map-set last-mined-heights tx-sender block-height)
        (ok true)
    )
)

(define-public (mine-block-as-contract (block-op (buff 80)) (to-burn uint) (recipients (list 2 principal)) (recipient-amount uint))
    (begin
        (unwrap-panic (stx-transfer? (+ to-burn (* (len recipients) recipient-amount)) tx-sender (as-contract tx-sender)))
        (as-contract (mine-block block-op to-burn recipients recipient-amount))
    )
)

(define-public (prestx (payload (buff 80)))
    (add-nonmining-block-op payload (list ))
)

(define-public (prestx-as-contract (payload (buff 80)))
    (as-contract (prestx payload))
)

(define-public (stack-appchain-stx (stack-payload (buff 80)) (pox-addr principal))
    (add-nonmining-block-op stack-payload (list pox-addr))
)

(define-public (stack-appchain-stx-as-contract (stack-payload (buff 80)) (pox-addr principal))
    (as-contract (stack-appchain-stx stack-payload pox-addr))
)

(define-public (transfer-appchain-stx (transfer-payload (buff 80)) (recipient principal))
    (add-nonmining-block-op transfer-payload (list recipient))
)

(define-public (transfer-appchain-stx-as-contract (transfer-payload (buff 80)) (recipient principal))
    (as-contract (transfer-appchain-stx transfer-payload recipient))
)
"#;

    const HELLO_WORLD_CONTRACT: &str = r#"
(print "Hello appchains!")
"#;

    /// Set up the host chain.  Make a test peer and mine a few blocks.  Instantiate the mining
    /// contract by sending it as a smart contract transaction and mining it.
    fn setup_parent_chain<'a>(
        test_name: &str,
        parent_p2p: u16,
        parent_http: u16,
        mining_contract_name: &str,
        mining_contract_body: &str,
    ) -> TestPeer<'a> {
        let mut parent_config = TestPeerConfig::new(test_name, parent_p2p, parent_http);

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

        parent_config.initial_balances = vec![
            (addr1.to_account_principal(), 1000000000),
            (addr2.to_account_principal(), 1000000000),
        ];

        let mut parent = TestPeer::new(parent_config);

        // mine one block with the app chain mining contract in it
        // first the coinbase
        // make a coinbase for this miner
        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([0x00; 32])),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_coinbase_signed = tx_signer.get_tx().unwrap();

        // next the contract
        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_smart_contract(mining_contract_name, mining_contract_body)
                .unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.auth.set_origin_nonce(1);
        tx_contract.set_tx_fee(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_contract_signed = tx_signer.get_tx().unwrap();

        let tip =
            SortitionDB::get_canonical_burn_chain_tip(&parent.sortdb.as_ref().unwrap().conn())
                .unwrap();

        let mut anchor_cost = ExecutionCost::zero();
        let mut anchor_size = 0;

        // make the block
        let (burn_ops, stacks_block, microblocks) = parent.make_tenure(
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

        let (_, _, consensus_hash) = parent.next_burnchain_block(burn_ops.clone());
        parent.process_stacks_epoch_at_tip(&stacks_block, &vec![]);

        parent
    }

    pub fn next_parent_block(peer: &mut TestPeer, txs: Vec<StacksTransaction>) {
        let microblock_privkey = StacksPrivateKey::new();
        let microblock_pubkeyhash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
        let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
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
                        txs.clone(),
                    )
                    .unwrap();

                (anchored_block, vec![])
            },
        );

        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &vec![]);
    }

    pub fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(sk)],
        )
        .unwrap()
    }

    /// Make a coinbase transaction for the host chain's miner
    fn make_parent_coinbase(privk: &StacksPrivateKey, nonce: u64) -> StacksTransaction {
        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(privk).unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([0x00; 32])),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        tx_signer.sign_origin(privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Make a coinbase transaction for an appchain
    fn make_appchain_coinbase(
        appchain_client: &AppChainClient,
        privk: &StacksPrivateKey,
        nonce: u64,
    ) -> StacksTransaction {
        let mut tx_coinbase = StacksTransaction::new(
            if appchain_client.mainnet {
                TransactionVersion::Mainnet
            } else {
                TransactionVersion::Testnet
            },
            TransactionAuth::from_p2pkh(privk).unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([0x00; 32])),
        );
        tx_coinbase.chain_id = appchain_client.config.as_ref().unwrap().chain_id();
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        tx_signer.sign_origin(privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Make a VRF key-register transaction for the app chain. This is a contract-call into
    /// register-vrf-key on the host chain's mining contract.
    fn make_appchain_vrf_key_tx(
        appchain_client: &AppChainClient,
        privk: &StacksPrivateKey,
        pubk: &VRFPublicKey,
        nonce: u64,
        as_contract: bool,
    ) -> StacksTransaction {
        let leader_key_op = LeaderKeyRegisterOp {
            public_key: pubk.clone(),
            memo: vec![],
            address: to_addr(privk),
            consensus_hash: ConsensusHash([0x01; 20]),

            // ignored
            vtxindex: 0,
            txid: Txid([0x00; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = appchain_client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            leader_key_op
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk).unwrap(),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: appchain_client.contract_id.issuer.clone().into(),
                contract_name: appchain_client.contract_id.name.clone(),
                function_name: if as_contract {
                    "register-vrf-key-as-contract".into()
                } else {
                    "register-vrf-key".into()
                },
                function_args: vec![Value::buff_from(op_bytes).unwrap()],
            }),
        );

        tx.chain_id = 0x80000000;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Make a block-commit transaction for the app chain.  This is a contract-call to mine-block
    /// on the host chain's mining contract
    fn make_appchain_block_commit_tx(
        appchain_client: &AppChainClient,
        privk: &StacksPrivateKey,
        block_hash: BlockHeaderHash,
        parent: (u32, u16),
        key: (u32, u16),
        burn: u64,
        recipients: Vec<StacksAddress>,
        payout: u64,
        nonce: u64,
        as_contract: bool,
    ) -> StacksTransaction {
        let block_commit_op = LeaderBlockCommitOp {
            block_header_hash: block_hash,
            burn_fee: payout,
            sunset_burn: burn,
            parent_block_ptr: parent.0,
            parent_vtxindex: parent.1,
            key_block_ptr: key.0,
            key_vtxindex: key.1,

            // mocked
            new_seed: VRFSeed([0x1; 32]),
            memo: vec![0x80],

            // ignored
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner {
                public_keys: vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
                num_sigs: 1,
                hash_mode: AddressHashMode::SerializeP2PKH,
            },

            // filled in late
            commit_outs: vec![],
            txid: Txid([0x00; 32]),
            vtxindex: 444,
            block_height: 125,
            burn_parent_modulus: (124 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = appchain_client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            block_commit_op
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk).unwrap(),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: appchain_client.contract_id.issuer.clone().into(),
                contract_name: appchain_client.contract_id.name.clone(),
                function_name: if as_contract {
                    "mine-block-as-contract".into()
                } else {
                    "mine-block".into()
                },
                function_args: vec![
                    Value::buff_from(op_bytes).unwrap(),
                    Value::UInt(burn as u128),
                    Value::list_from(
                        recipients
                            .into_iter()
                            .map(|addr| Value::Principal(addr.into()))
                            .collect(),
                    )
                    .unwrap(),
                    Value::UInt(payout as u128),
                ],
            }),
        );

        tx.chain_id = 0x80000000;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Make a prestx transaction for the app chain.  This is a contract-call to the prestx
    /// function in the host chain's mining contract
    fn make_appchain_prestx(
        appchain_client: &AppChainClient,
        privk: &StacksPrivateKey,
        nonce: u64,
        as_contract: bool,
    ) -> StacksTransaction {
        let prestx = PreStxOp {
            // all of this is filled in by the parser
            output: StacksAddress::burn_address(false),
            txid: Txid([0x00; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = appchain_client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            prestx
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk).unwrap(),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: appchain_client.contract_id.issuer.clone().into(),
                contract_name: appchain_client.contract_id.name.clone(),
                function_name: if as_contract {
                    "prestx-as-contract".into()
                } else {
                    "prestx".into()
                },
                function_args: vec![Value::buff_from(op_bytes).unwrap()],
            }),
        );

        tx.chain_id = 0x80000000;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Make a stackstx transaction for hte app chain. This is a contract-call to the
    /// stack-appchain-stx function in the host chain's mining contract.
    fn make_appchain_stack_stx(
        appchain_client: &AppChainClient,
        privk: &StacksPrivateKey,
        amount: u128,
        reward_cycles: u8,
        reward_addr: StacksAddress,
        nonce: u64,
        as_contract: bool,
    ) -> StacksTransaction {
        let stack_stx_op = StackStxOp {
            stacked_ustx: amount,
            num_cycles: reward_cycles,
            reward_addr: reward_addr,
            // to be filled in
            sender: StacksAddress::burn_address(false),
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = appchain_client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            stack_stx_op
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk).unwrap(),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: appchain_client.contract_id.issuer.clone().into(),
                contract_name: appchain_client.contract_id.name.clone(),
                function_name: if as_contract {
                    "stack-appchain-stx-as-contract".into()
                } else {
                    "stack-appchain-stx".into()
                },
                function_args: vec![
                    Value::buff_from(op_bytes).unwrap(),
                    Value::Principal(reward_addr.into()),
                ],
            }),
        );

        tx.chain_id = 0x80000000;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Make a transferstx transaction for the app chain.  This is a contract-call to the host
    /// chain's mining contract's transfer-appchain-stx method
    fn make_appchain_transfer_stx(
        appchain_client: &AppChainClient,
        privk: &StacksPrivateKey,
        amount: u128,
        memo: Vec<u8>,
        recipient_addr: StacksAddress,
        nonce: u64,
        as_contract: bool,
    ) -> StacksTransaction {
        let stx_transfer_op = TransferStxOp {
            transfered_ustx: amount,
            memo: memo,
            // to be filled in
            sender: StacksAddress::burn_address(false),
            recipient: StacksAddress::burn_address(false),
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        };

        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = appchain_client.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            stx_transfer_op
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
            buffer
        };

        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk).unwrap(),
            TransactionPayload::ContractCall(TransactionContractCall {
                address: appchain_client.contract_id.issuer.clone().into(),
                contract_name: appchain_client.contract_id.name.clone(),
                function_name: if as_contract {
                    "transfer-appchain-stx-as-contract".into()
                } else {
                    "transfer-appchain-stx".into()
                },
                function_args: vec![
                    Value::buff_from(op_bytes).unwrap(),
                    Value::Principal(recipient_addr.into()),
                ],
            }),
        );

        tx.chain_id = 0x80000000;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.auth.set_origin_nonce(nonce);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(&privk).unwrap();
        tx_signer.get_tx().unwrap()
    }

    /// Commands to send to the host chain thread
    #[derive(Clone, Debug, PartialEq)]
    enum ParentChainCommand {
        Exit,
        MineBlock(Vec<StacksTransaction>),
    }

    /// Results of commands from the host chain thread
    enum ParentChainResult {
        Done,
    }

    /// Threaded runloop for the host chain
    fn run_parent_chain(
        mut parent_peer: TestPeer<'static>,
    ) -> (
        thread::JoinHandle<()>,
        SyncSender<ParentChainCommand>,
        Receiver<ParentChainResult>,
    ) {
        let (cmd_in, cmd_out) = sync_channel(1);
        let (result_in, result_out) = sync_channel(1);

        let handle = thread::spawn(move || loop {
            match cmd_out.try_recv() {
                Ok(ParentChainCommand::Exit) => {
                    break;
                }
                Ok(ParentChainCommand::MineBlock(txs)) => {
                    next_parent_block(&mut parent_peer, txs);
                    result_in.send(ParentChainResult::Done).unwrap();
                }
                _ => {}
            }

            let _ = parent_peer.step();
        });

        (handle, cmd_in, result_out)
    }

    /// Verify that an app chain can boot up from the host chain by downloading headers and
    /// configuration data and authenticating it against the MARF roots in the headers
    #[test]
    fn test_appchain_setup() {
        let test_name = "test_appchain_setup";
        let parent_peer = setup_parent_chain(
            test_name,
            7000,
            7001,
            "appchain-mvp",
            APPCHAIN_MINING_CONTRACT,
        );

        let appchain_working_dir = format!("/tmp/{}-appchain", test_name);
        if fs::metadata(&appchain_working_dir).is_ok() {
            fs::remove_dir_all(&appchain_working_dir).unwrap();
        }

        let parent_working_dir = parent_peer.config.burnchain.working_dir.clone();
        let parent_chainstate_dir = parent_peer.chainstate_path.clone();

        let appchain_headers_bootup =
            format!("{}/appchain-boot-headers.sqlite", &parent_working_dir);

        let (parent_thread, parent_cmds, parent_results) = run_parent_chain(parent_peer);

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();

        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk_contract = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        // mine a few blocks
        let mut nonce = 0;

        for i in 0..10 {
            let coinbase_tx = make_parent_coinbase(&privk, nonce);
            parent_cmds
                .send(ParentChainCommand::MineBlock(vec![coinbase_tx]))
                .unwrap();
            let _ = parent_results.recv().unwrap();
            eprintln!("Mined block {}", i);

            nonce += 1;
        }

        let genesis_hash =
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap();
        let mut appchain_client = AppChainClient::new(
            false,
            &appchain_headers_bootup,
            0x80000000,
            ("localhost", 7001),
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.appchain-mvp",
            )
            .unwrap(),
            MagicBytes([97, 112]),
            genesis_hash,
            None,
        );

        let mut bootcode = HashMap::new();
        bootcode.insert(
            ContractName::try_from("hello-world").unwrap(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        );
        appchain_client.bootup(&bootcode).unwrap();

        eprintln!("conf = {:?}", &appchain_client.config);

        let config = if let AppChainConfig::V1(config) = appchain_client.config.clone().unwrap() {
            config
        } else {
            panic!("Not a v1 appchain config");
        };

        assert_eq!(config.mainnet, false);
        assert_eq!(config.start_block, 6);
        assert_eq!(config.chain_id, 0x80000002);
        assert_eq!(
            config.pox_constants,
            PoxConstants::new(5, 3, 2, 25, 5, u64::max_value(), u64::max_value())
        );
        assert_eq!(
            config.boot_nodes,
            vec![(
                (
                    StacksPublicKey::from_private(&privk_contract),
                    PeerHost::IP(PeerAddress::from_ipv4(127, 0, 0, 1), 8000)
                ),
                PeerHost::IP(PeerAddress::from_ipv4(127, 0, 0, 1), 8001)
            )]
        );
        assert_eq!(
            config.boot_code_contract_names,
            vec![ContractName::try_from("hello-world").unwrap()]
        );
        assert_eq!(
            config.genesis_hash,
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap()
        );
        assert_eq!(
            config.block_limit,
            ExecutionCost {
                read_length: 100_000_000,
                read_count: 7_750,
                write_length: 15_000_000,
                write_count: 7_750,
                runtime: 5_000_000_000
            }
        );

        let burnchain =
            Burnchain::new_appchain(&AppChainConfig::V1(config.clone()), &appchain_working_dir)
                .unwrap();

        // got filled in
        assert_ne!(burnchain.first_block_hash, BurnchainHeaderHash([0x00; 32]));

        let mut appchain_boot_data = ChainStateBootData::new_appchain(
            false,
            &burnchain,
            config.initial_balances.clone(),
            vec![(
                "hello-world".into(),
                StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
            )],
            config.genesis_hash.clone(),
        );

        let (mut appchain_chainstate, receipts) = StacksChainState::open_and_exec(
            false,
            config.chain_id,
            &appchain_working_dir,
            Some(&mut appchain_boot_data),
            config.block_limit.clone(),
        )
        .unwrap();

        // hello-world ran
        eprintln!("receipts.last() = {:?}", receipts.last());

        let hello_world_event = receipts
            .last()
            .clone()
            .unwrap()
            .events
            .first()
            .clone()
            .unwrap();
        if let StacksTransactionEvent::SmartContractEvent(data) = hello_world_event {
            assert_eq!(
                data.key,
                (
                    QualifiedContractIdentifier::parse("ST000000000000000000002AMW42H.hello-world")
                        .unwrap(),
                    "print".to_string()
                )
            );
            assert_eq!(data.value.clone().expect_ascii(), "Hello appchains!");
        } else {
            panic!("Last event is not from hello-world");
        }

        let (mut socket, _) = appchain_client.begin_session();

        // miner account checks out
        let miner_account = appchain_client
            .download_account(to_addr(&privk), &mut socket)
            .unwrap();
        eprintln!("miner account: {:?}", &miner_account);
        assert_eq!(miner_account.nonce, nonce);
        assert_eq!(miner_account.stx_balance.amount_unlocked, 26200000000);
        assert_eq!(miner_account.stx_balance.amount_locked, 0);
        assert_eq!(miner_account.stx_balance.unlock_height, 0);

        // ask initial app peer
        let initial_recipient = {
            let tip = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            let account = appchain_chainstate
                .with_read_only_clarity_tx(&NULL_BURN_STATE_DB, &tip, |clarity_conn| {
                    StacksChainState::get_account(
                        clarity_conn,
                        &StacksAddress::from_string("ST3N0JG3EE5Z2R3HN7WAEFM0HRGHHMCD4E170C0T1")
                            .unwrap()
                            .to_account_principal(),
                    )
                })
                .unwrap();
            account
        };

        eprintln!("initial recipient account: {:?}", &initial_recipient);
        assert_eq!(initial_recipient.nonce, 0);
        assert_eq!(initial_recipient.stx_balance.amount_unlocked, 1000000);
        assert_eq!(initial_recipient.stx_balance.amount_locked, 0);
        assert_eq!(initial_recipient.stx_balance.unlock_height, 0);

        // miner can send a transaction via the client to the parent chain
        let mut tx_stx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk).unwrap(),
            TransactionPayload::TokenTransfer(
                to_addr(&privk_contract).to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        tx_stx.chain_id = 0x80000000;
        tx_stx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_stx.auth.set_origin_nonce(nonce);
        tx_stx.set_tx_fee(200);

        let mut tx_signer = StacksTransactionSigner::new(&tx_stx);
        tx_signer.sign_origin(&privk).unwrap();
        let tx = tx_signer.get_tx().unwrap();

        let res = AppChainClient::send_transaction(&mut socket, tx.clone(), None);
        eprintln!("Send {}: {:?}", tx.txid(), &res);
        assert!(res.is_ok());

        // should show up in parent chain mempool
        let parent_mempool = MemPoolDB::open_test(false, 0x80000000, &parent_chainstate_dir).unwrap();
        let txinfo = MemPoolDB::get_tx(parent_mempool.conn(), &tx.txid()).unwrap();
        assert!(txinfo.is_some());

        parent_cmds.send(ParentChainCommand::Exit).unwrap();
        parent_thread.join().unwrap();
    }

    /// Verify that we can download and authenticate boot code
    #[test]
    fn test_appchain_download_boot_code() {
        // test downloading the app chain smart contract instead from the running parent node,
        // since it exercises the "juicy" code path

        let test_name = "test_appchain_download_boot_code";
        let parent_peer = setup_parent_chain(
            test_name,
            7100,
            7011,
            "appchain-mvp",
            APPCHAIN_MINING_CONTRACT,
        );

        let appchain_working_dir = format!("/tmp/{}-appchain", test_name);
        if fs::metadata(&appchain_working_dir).is_ok() {
            fs::remove_dir_all(&appchain_working_dir).unwrap();
        }

        let appchain_headers_bootup = format!(
            "{}/appchain-boot-headers.sqlite",
            &parent_peer.config.burnchain.working_dir
        );
        let parent_chainstate_path = parent_peer.chainstate_path.clone();

        let (parent_thread, parent_cmds, parent_results) = run_parent_chain(parent_peer);

        // get a boot contract from the *parent* chain,
        // without needing to sync headers or fetch config state or anything like that
        let genesis_hash =
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap();
        let mut appchain_client = AppChainClient::new(
            false,
            &appchain_headers_bootup,
            0x80000000,
            ("localhost", 7011),
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.appchain-mvp",
            )
            .unwrap(),
            MagicBytes([97, 112]),
            genesis_hash,
            None,
        );
        let (mut socket, peer_info) = appchain_client
            .try_open_session(("localhost", 7011), 0x80000000)
            .unwrap();
        let parent_chain_genesis_hash = {
            let (mut chainstate, _) =
                StacksChainState::open(false, 0x80000000, &parent_chainstate_path).unwrap();
            chainstate.get_genesis_state_index_root()
        };

        eprintln!("genesis chain hash: {}", &parent_chain_genesis_hash);

        let boot_code = AppChainClient::download_boot_contract(
            &mut socket,
            false,
            &"costs".try_into().unwrap(),
            &parent_chain_genesis_hash,
        )
        .unwrap();
        assert_eq!(boot_code, StacksString::from_str(BOOT_CODE_COSTS).unwrap());
    }

    /// Verify that the app chain can send VRF registration transactions that will get picked up
    /// and processed when downloading and processing blocks.
    #[test]
    fn test_appchain_vrf_register() {
        let test_name = "test_appchain_vrf_register";
        let parent_peer = setup_parent_chain(
            test_name,
            7002,
            7003,
            "appchain-mvp",
            APPCHAIN_MINING_CONTRACT,
        );

        let appchain_working_dir = format!("/tmp/{}-appchain", test_name);
        if fs::metadata(&appchain_working_dir).is_ok() {
            fs::remove_dir_all(&appchain_working_dir).unwrap();
        }

        let appchain_headers_bootup = format!(
            "{}/appchain-boot-headers.sqlite",
            &parent_peer.config.burnchain.working_dir
        );

        let (parent_thread, parent_cmds, parent_results) = run_parent_chain(parent_peer);

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();

        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk_contract = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        // mine a few blocks
        let mut nonce = 0;

        for i in 0..10 {
            let coinbase_tx = make_parent_coinbase(&privk, nonce);
            parent_cmds
                .send(ParentChainCommand::MineBlock(vec![coinbase_tx]))
                .unwrap();
            let _ = parent_results.recv().unwrap();
            eprintln!("Mined block {}", i);

            nonce += 1;
        }

        let genesis_hash =
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap();
        let mut appchain_client = AppChainClient::new(
            false,
            &appchain_headers_bootup,
            0x80000000,
            ("localhost", 7003),
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.appchain-mvp",
            )
            .unwrap(),
            MagicBytes([97, 112]),
            genesis_hash,
            None,
        );

        let mut bootcode = HashMap::new();
        bootcode.insert(
            ContractName::try_from("hello-world").unwrap(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        );
        appchain_client.bootup(&bootcode).unwrap();

        let vrf_pk = VRFPrivateKey::new();
        let vrf_public_key = VRFPublicKey::from_private(&vrf_pk);

        // make a block with a VRF register
        let coinbase_tx = make_parent_coinbase(&privk, nonce);
        let vrf_key_tx =
            make_appchain_vrf_key_tx(&appchain_client, &privk, &vrf_public_key, nonce + 1, false);
        let vrf_key_tx_contract =
            make_appchain_vrf_key_tx(&appchain_client, &privk, &vrf_public_key, nonce + 2, true);

        parent_cmds
            .send(ParentChainCommand::MineBlock(vec![
                coinbase_tx,
                vrf_key_tx,
                vrf_key_tx_contract,
            ]))
            .unwrap();
        let _ = parent_results.recv().unwrap();

        eprintln!("Mined block");

        let (mut socket, peer_info) = appchain_client.begin_session();

        // query that block!
        appchain_client.sync_all_headers(&mut socket).unwrap();
        let light_client = LightClientDB::new(&appchain_client.headers_path, false).unwrap();
        let highest_header_height = light_client.get_highest_header_height().unwrap();
        assert_eq!(highest_header_height, 12);

        let mining_hdr = light_client
            .read_block_header(highest_header_height)
            .unwrap()
            .unwrap();

        let blk = appchain_client
            .download_block(&mut socket, &mining_hdr)
            .unwrap();

        eprintln!("Downloaded block: {:?}", &blk);

        assert_eq!(blk.txs.len(), 2);

        let burnchain_blk = appchain_client.parse(&blk).unwrap();

        // first tx: vrf key register from standard principal
        let op = LeaderKeyRegisterOp::from_tx(
            &burnchain_blk.header(),
            &BurnchainTransaction::Stacks(blk.txs[0].clone()),
        )
        .unwrap();

        eprintln!("Parsed block op: {:?}", &op);

        assert_eq!(op.public_key, vrf_public_key);
        assert_eq!(op.address, to_addr(&privk));
        assert_eq!(op.consensus_hash, ConsensusHash([0x01; 20]));

        // second tx: vrf key register from contract
        let op = LeaderKeyRegisterOp::from_tx(
            &burnchain_blk.header(),
            &BurnchainTransaction::Stacks(blk.txs[1].clone()),
        )
        .unwrap();

        eprintln!("Parsed block op: {:?}", &op);

        assert_eq!(op.public_key, vrf_public_key);
        assert_eq!(op.address, to_addr(&privk_contract)); // limitation: this is always a standard principal, even if a contract sent it
        assert_eq!(op.consensus_hash, ConsensusHash([0x01; 20]));

        eprintln!("Test finished!");

        parent_cmds.send(ParentChainCommand::Exit).unwrap();
        parent_thread.join().unwrap();
    }

    /// Verify that the appchain can send block-commit transactions to the host chain's mining
    /// contract, and that the appchain client can download and authenticate them via
    /// download_block()
    #[test]
    fn test_appchain_block_commit() {
        let test_name = "test_appchain_block_commit";
        let parent_peer = setup_parent_chain(
            test_name,
            7004,
            7005,
            "appchain-mvp",
            APPCHAIN_MINING_CONTRACT,
        );

        let appchain_working_dir = format!("/tmp/{}-appchain", test_name);
        if fs::metadata(&appchain_working_dir).is_ok() {
            fs::remove_dir_all(&appchain_working_dir).unwrap();
        }

        let appchain_headers_bootup = format!(
            "{}/appchain-boot-headers.sqlite",
            &parent_peer.config.burnchain.working_dir
        );

        let (parent_thread, parent_cmds, parent_results) = run_parent_chain(parent_peer);

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();

        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk_contract = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        // mine a few blocks
        let mut nonce = 0;

        for i in 0..10 {
            let coinbase_tx = make_parent_coinbase(&privk, nonce);
            parent_cmds
                .send(ParentChainCommand::MineBlock(vec![coinbase_tx]))
                .unwrap();
            let _ = parent_results.recv().unwrap();
            eprintln!("Mined block {}", i);

            nonce += 1;
        }

        let genesis_hash =
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap();
        let mut appchain_client = AppChainClient::new(
            false,
            &appchain_headers_bootup,
            0x80000000,
            ("localhost", 7005),
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.appchain-mvp",
            )
            .unwrap(),
            MagicBytes([97, 112]),
            genesis_hash,
            None,
        );

        let mut bootcode = HashMap::new();
        bootcode.insert(
            ContractName::try_from("hello-world").unwrap(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        );
        appchain_client.bootup(&bootcode).unwrap();

        let burnchain = Burnchain::new_appchain(
            &appchain_client.config.clone().unwrap(),
            &appchain_working_dir,
        )
        .unwrap();

        // make a block with block commits
        let coinbase_tx = make_parent_coinbase(&privk, nonce);
        let block_commit_tx = make_appchain_block_commit_tx(
            &appchain_client,
            &privk,
            BlockHeaderHash([0x22; 32]),
            (0, 0),
            (1, 2),
            1000,
            vec![to_addr(&privk), to_addr(&privk_contract)],
            2000,
            nonce + 1,
            false,
        );
        let block_commit_tx_contract = make_appchain_block_commit_tx(
            &appchain_client,
            &privk,
            BlockHeaderHash([0x33; 32]),
            (0, 0),
            (1, 3),
            2000,
            vec![to_addr(&privk_contract), to_addr(&privk)],
            4000,
            nonce + 2,
            true,
        );

        parent_cmds
            .send(ParentChainCommand::MineBlock(vec![
                coinbase_tx,
                block_commit_tx,
                block_commit_tx_contract,
            ]))
            .unwrap();
        let _ = parent_results.recv().unwrap();

        eprintln!("Mined block");

        let (mut socket, peer_info) = appchain_client.begin_session();

        // query that block!
        appchain_client.sync_all_headers(&mut socket).unwrap();
        let light_client = LightClientDB::new(&appchain_client.headers_path, false).unwrap();
        let highest_header_height = light_client.get_highest_header_height().unwrap();
        assert_eq!(highest_header_height, 12);

        let mining_hdr = light_client
            .read_block_header(highest_header_height)
            .unwrap()
            .unwrap();

        let blk = appchain_client
            .download_block(&mut socket, &mining_hdr)
            .unwrap();

        eprintln!("Downloaded block: {:?}", &blk);

        assert_eq!(blk.txs.len(), 2);

        let burnchain_blk = appchain_client.parse(&blk).unwrap();

        // first tx: block-commit from standard principal
        let op = LeaderBlockCommitOp::from_tx(
            &burnchain,
            &burnchain_blk.header(),
            &BurnchainTransaction::Stacks(blk.txs[0].clone()),
        )
        .unwrap();

        eprintln!("Parsed block op: {:?}", &op);

        assert_eq!(op.block_header_hash, BlockHeaderHash([0x22; 32]));
        assert_eq!(op.burn_fee, 4000);
        assert_eq!(op.sunset_burn, 1000);
        assert_eq!(
            op.commit_outs,
            vec![to_addr(&privk), to_addr(&privk_contract)]
        );

        // second tx: block-commit from contract
        let op = LeaderBlockCommitOp::from_tx(
            &burnchain,
            &burnchain_blk.header(),
            &BurnchainTransaction::Stacks(blk.txs[1].clone()),
        )
        .unwrap();

        eprintln!("Parsed block op: {:?}", &op);

        assert_eq!(op.block_header_hash, BlockHeaderHash([0x33; 32]));
        assert_eq!(op.burn_fee, 8000);
        assert_eq!(op.sunset_burn, 2000);
        assert_eq!(
            op.commit_outs,
            vec![to_addr(&privk_contract), to_addr(&privk)]
        );
    }

    /// Verify that an appchain can fully sync state from the host chain's mining contract --
    /// including downloading and processing all of its burnchain "blocks" and storing the
    /// burnchain operations.
    #[test]
    fn test_appchain_sync() {
        let test_name = "test_appchain_sync";
        let parent_peer = setup_parent_chain(
            test_name,
            7008,
            7009,
            "appchain-mvp",
            APPCHAIN_MINING_CONTRACT,
        );

        let appchain_working_dir = format!("/tmp/{}-appchain", test_name);
        if fs::metadata(&appchain_working_dir).is_ok() {
            fs::remove_dir_all(&appchain_working_dir).unwrap();
        }

        let appchain_headers_bootup = format!(
            "{}/appchain-boot-headers.sqlite",
            &parent_peer.config.burnchain.working_dir
        );

        let (parent_thread, parent_cmds, parent_results) = run_parent_chain(parent_peer);

        let genesis_hash =
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap();
        let mut appchain_client = AppChainClient::new(
            false,
            &appchain_headers_bootup,
            0x80000000,
            ("localhost", 7009),
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.appchain-mvp",
            )
            .unwrap(),
            MagicBytes([97, 112]),
            genesis_hash,
            None,
        );

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();

        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk_contract = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        let mut nonce = 0;

        for i in 0..10 {
            let coinbase_tx = make_parent_coinbase(&privk, nonce);
            parent_cmds
                .send(ParentChainCommand::MineBlock(vec![coinbase_tx]))
                .unwrap();
            let _ = parent_results.recv().unwrap();
            eprintln!("Mined block {}", i);

            nonce += 1;
        }

        let vrf_pk = VRFPrivateKey::new();
        let vrf_public_key = VRFPublicKey::from_private(&vrf_pk);

        let vrf_pk_contract = VRFPrivateKey::new();
        let vrf_public_key_contract = VRFPublicKey::from_private(&vrf_pk);

        // make a block with a VRF register
        let coinbase_tx = make_parent_coinbase(&privk, nonce);
        let vrf_key_tx =
            make_appchain_vrf_key_tx(&appchain_client, &privk, &vrf_public_key, nonce + 1, false);
        let vrf_key_tx_contract = make_appchain_vrf_key_tx(
            &appchain_client,
            &privk,
            &vrf_public_key_contract,
            nonce + 2,
            true,
        );

        parent_cmds
            .send(ParentChainCommand::MineBlock(vec![
                coinbase_tx,
                vrf_key_tx,
                vrf_key_tx_contract,
            ]))
            .unwrap();
        let _ = parent_results.recv().unwrap();

        eprintln!("Registered VRF keys");

        // make a block with a VRF register
        let coinbase_tx = make_parent_coinbase(&privk, nonce + 3);
        let block_commit_tx = make_appchain_block_commit_tx(
            &appchain_client,
            &privk,
            BlockHeaderHash([0x22; 32]),
            (0, 0),
            (2, 1),
            1000,
            vec![to_addr(&privk), to_addr(&privk_contract)],
            2000,
            nonce + 4,
            false,
        );
        let block_commit_tx_contract = make_appchain_block_commit_tx(
            &appchain_client,
            &privk,
            BlockHeaderHash([0x33; 32]),
            (0, 0),
            (2, 2),
            2000,
            vec![to_addr(&privk_contract), to_addr(&privk)],
            4000,
            nonce + 5,
            true,
        );

        parent_cmds
            .send(ParentChainCommand::MineBlock(vec![
                coinbase_tx,
                block_commit_tx,
                block_commit_tx_contract,
            ]))
            .unwrap();
        let _ = parent_results.recv().unwrap();

        eprintln!("Mined block");

        let mut bootcode = HashMap::new();
        bootcode.insert(
            ContractName::try_from("hello-world").unwrap(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        );
        appchain_client.bootup(&bootcode).unwrap();

        let mut burnchain = Burnchain::new_appchain(
            &appchain_client.config.clone().unwrap(),
            &appchain_working_dir,
        )
        .unwrap();
        let last_header = burnchain
            .sync_with_indexer(&mut appchain_client, None, None, None, None)
            .unwrap();

        eprintln!("Last header: {:?}", &last_header);

        // got 13 headers
        assert_eq!(last_header.block_height, 13);
        assert_eq!(last_header.num_txs, 2);

        // got all headers
        let hdrs = appchain_client.read_headers(0, 13).unwrap();
        assert_eq!(hdrs.len(), 13);

        // burnchain DB got all the ops we sent
        let (_, burnchain_db) = burnchain
            .connect_db(
                false,
                appchain_client.config.as_ref().unwrap().start_block_hash(),
                0,
            )
            .unwrap();

        let canonical_chain_tip = burnchain_db.get_canonical_chain_tip().unwrap();
        assert_eq!(canonical_chain_tip, last_header);

        let vrf_block_header = appchain_client.read_headers(12, 13).unwrap().pop().unwrap();
        let block_commit_header = appchain_client.read_headers(13, 14).unwrap().pop().unwrap();

        let vrf_ops = burnchain_db
            .get_burnchain_block(&BurnchainHeaderHash(
                StacksBlockHeader::make_index_block_hash(
                    &vrf_block_header.consensus_hash,
                    &vrf_block_header.header.block_hash(),
                )
                .0,
            ))
            .unwrap();
        assert_eq!(vrf_ops.ops.len(), 2);

        for (op, (expected_pubkey, privk_used)) in vrf_ops.ops.iter().zip(
            [
                (&vrf_public_key, &privk),
                (&vrf_public_key_contract, &privk_contract),
            ]
            .iter(),
        ) {
            if let BlockstackOperationType::LeaderKeyRegister(ref opdata) = op {
                assert_eq!(opdata.public_key, **expected_pubkey);
                assert_eq!(opdata.address, to_addr(privk_used));
                assert_eq!(opdata.consensus_hash, ConsensusHash([0x01; 20]));
            } else {
                panic!("Not a leader key op");
            }
        }

        let block_commit_ops = burnchain_db
            .get_burnchain_block(&BurnchainHeaderHash(
                StacksBlockHeader::make_index_block_hash(
                    &block_commit_header.consensus_hash,
                    &block_commit_header.header.block_hash(),
                )
                .0,
            ))
            .unwrap();
        for (
            op,
            (expected_block_header_hash, expected_burn_fee, expected_sunset_burn, expected_outs),
        ) in block_commit_ops.ops.iter().zip(
            [
                (
                    BlockHeaderHash([0x22; 32]),
                    4000,
                    1000,
                    vec![to_addr(&privk), to_addr(&privk_contract)],
                ),
                (
                    BlockHeaderHash([0x33; 32]),
                    8000,
                    2000,
                    vec![to_addr(&privk_contract), to_addr(&privk)],
                ),
            ]
            .iter(),
        ) {
            if let BlockstackOperationType::LeaderBlockCommit(ref opdata) = op {
                assert_eq!(opdata.block_header_hash, *expected_block_header_hash);
                assert_eq!(opdata.burn_fee, *expected_burn_fee);
                assert_eq!(opdata.sunset_burn, *expected_sunset_burn);
                assert_eq!(opdata.commit_outs, *expected_outs)
            } else {
                panic!("Not a block commit op");
            }
        }
    }

    /// Veirfy that the prestx, stackstx, and transferstx transactions all work correctly.  This
    /// verifies that stackstx and transferstx consume exactly one prior prestx.
    #[test]
    fn test_appchain_sync_prestx_stack_and_transfer() {
        let test_name = "test_appchain_sync_prestx_stack_and_transfer";
        let parent_peer = setup_parent_chain(
            test_name,
            7006,
            7007,
            "appchain-mvp",
            APPCHAIN_MINING_CONTRACT,
        );

        let appchain_working_dir = format!("/tmp/{}-appchain", test_name);
        if fs::metadata(&appchain_working_dir).is_ok() {
            fs::remove_dir_all(&appchain_working_dir).unwrap();
        }

        let appchain_headers_bootup = format!(
            "{}/appchain-boot-headers.sqlite",
            &parent_peer.config.burnchain.working_dir
        );

        let (parent_thread, parent_cmds, parent_results) = run_parent_chain(parent_peer);

        let genesis_hash =
            TrieHash::from_hex("83dfd47a1b9c7350b31738dba6454390c68b36f81ae5cc4fa8a8a68ba2344df9")
                .unwrap();
        let mut appchain_client = AppChainClient::new(
            false,
            &appchain_headers_bootup,
            0x80000000,
            ("localhost", 7007),
            QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.appchain-mvp",
            )
            .unwrap(),
            MagicBytes([97, 112]),
            genesis_hash,
            None,
        );

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();

        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk_contract = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        let mut nonce = 0;

        for i in 0..10 {
            let coinbase_tx = make_parent_coinbase(&privk, nonce);
            parent_cmds
                .send(ParentChainCommand::MineBlock(vec![coinbase_tx]))
                .unwrap();
            let _ = parent_results.recv().unwrap();
            eprintln!("Mined block {}", i);

            nonce += 1;
        }

        let coinbase_tx = make_parent_coinbase(&privk, nonce);
        let prestx = make_appchain_prestx(&appchain_client, &privk, nonce + 1, false);
        let prestx_contract = make_appchain_prestx(&appchain_client, &privk, nonce + 2, true);

        let stack_stx = make_appchain_stack_stx(
            &appchain_client,
            &privk,
            12345,
            6,
            to_addr(&privk_contract),
            nonce + 3,
            false,
        );
        let stack_stx_contract = make_appchain_stack_stx(
            &appchain_client,
            &privk,
            22345,
            7,
            to_addr(&privk),
            nonce + 4,
            true,
        );

        let prestx_2 = make_appchain_prestx(&appchain_client, &privk, nonce + 5, false);
        let prestx_contract_2 = make_appchain_prestx(&appchain_client, &privk, nonce + 6, true);

        let transfer_stx = make_appchain_transfer_stx(
            &appchain_client,
            &privk,
            12346,
            vec![0x06, 0x07, 0x08],
            to_addr(&privk_contract),
            nonce + 7,
            false,
        );
        let transfer_stx_contract = make_appchain_transfer_stx(
            &appchain_client,
            &privk,
            22346,
            vec![0x06, 0x07, 0x08],
            to_addr(&privk),
            nonce + 8,
            true,
        );

        // will both fail due to a lack of a prestx
        let transfer_stx_2 = make_appchain_transfer_stx(
            &appchain_client,
            &privk,
            12347,
            vec![0x06, 0x07, 0x08],
            to_addr(&privk_contract),
            nonce + 9,
            false,
        );
        let transfer_stx_contract_2 = make_appchain_transfer_stx(
            &appchain_client,
            &privk,
            22347,
            vec![0x06, 0x07, 0x08],
            to_addr(&privk),
            nonce + 10,
            true,
        );

        parent_cmds
            .send(ParentChainCommand::MineBlock(vec![
                coinbase_tx,
                prestx,
                prestx_contract,
                stack_stx,
                stack_stx_contract,
                prestx_2,
                prestx_contract_2,
                transfer_stx,
                transfer_stx_contract,
                transfer_stx_2,
                transfer_stx_contract_2,
            ]))
            .unwrap();
        let _ = parent_results.recv().unwrap();

        eprintln!("Mined block");

        let mut bootcode = HashMap::new();
        bootcode.insert(
            ContractName::try_from("hello-world").unwrap(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        );
        appchain_client.bootup(&bootcode).unwrap();

        let mut burnchain = Burnchain::new_appchain(
            &appchain_client.config.clone().unwrap(),
            &appchain_working_dir,
        )
        .unwrap();
        let last_header = burnchain
            .sync_with_indexer(&mut appchain_client, None, None, None, None)
            .unwrap();

        eprintln!("Last header: {:?}", &last_header);

        // everything should have been accepted
        let (_, burnchain_db) = burnchain
            .connect_db(
                false,
                appchain_client.config.as_ref().unwrap().start_block_hash(),
                0,
            )
            .unwrap();
        let block_ops = burnchain_db
            .get_burnchain_block(&last_header.block_hash)
            .unwrap();

        eprintln!("Successful block ops:");
        for (i, block_op) in block_ops.ops.iter().enumerate() {
            eprintln!("block op: {:?}", &block_op);
        }

        // all prestx succeed, but only the standard principal stack-stx and stx-transfer succeed
        // (and the third such operation fails for want of a prestx)
        assert_eq!(block_ops.ops.len(), 6);

        for (i, block_op) in block_ops.ops.iter().enumerate() {
            if i == 0 {
                if let BlockstackOperationType::PreStx(ref data) = block_op {
                    assert_eq!(data.output, to_addr(&privk));
                } else {
                    panic!("Op 0 is not a prestx");
                }
            }
            if i == 1 {
                if let BlockstackOperationType::PreStx(ref data) = block_op {
                    assert_eq!(data.output, to_addr(&privk_contract));
                } else {
                    panic!("Op 1 is not a prestx");
                }
            }
            if i == 2 {
                if let BlockstackOperationType::StackStx(ref data) = block_op {
                    assert_eq!(data.sender, to_addr(&privk));
                    assert_eq!(data.reward_addr, to_addr(&privk_contract));
                    assert_eq!(data.stacked_ustx, 12345);
                    assert_eq!(data.num_cycles, 6);
                } else {
                    panic!("Op 2 is not a stackstx");
                }
            }
            if i == 3 {
                if let BlockstackOperationType::PreStx(ref data) = block_op {
                    assert_eq!(data.output, to_addr(&privk));
                } else {
                    panic!("Op 3 is not a prestx");
                }
            }
            if i == 4 {
                if let BlockstackOperationType::PreStx(ref data) = block_op {
                    assert_eq!(data.output, to_addr(&privk_contract));
                } else {
                    panic!("Op 4 is not a prestx");
                }
            }
            if i == 5 {
                if let BlockstackOperationType::TransferStx(ref data) = block_op {
                    assert_eq!(data.sender, to_addr(&privk));
                    assert_eq!(data.recipient, to_addr(&privk_contract));
                    assert_eq!(data.transfered_ustx, 12346);
                    assert_eq!(data.memo, vec![0x06, 0x07, 0x08]);
                } else {
                    panic!("Op 5 is not a transferstx");
                }
            }
        }
    }
}
