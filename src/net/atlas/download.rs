use super::{AttachmentInstance, AtlasDB};
use net::Error as net_error;
use net::dns::*;
use net::p2p::PeerNetwork;
use net::{HttpRequestType, HttpResponseType, PeerHost, HttpRequestMetadata, Requestable};
use net::{GetAttachmentResponse, GetAttachmentsInvResponse};
use net::server::HttpPeer;
use net::connection::ConnectionOptions;
use net::NeighborKey;
use vm::types::QualifiedContractIdentifier;
use vm::representations::UrlString;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::{StacksBlockId, StacksBlockHeader};
use chainstate::burn::{ConsensusHash, BlockHeaderHash};
use util::{get_epoch_time_ms, get_epoch_time_secs};
use util::strings;
use util::hash::{Hash160, MerkleHashFunc};

use std::fmt;
use std::cmp::Ordering;
use std::net::{IpAddr, SocketAddr};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::collections::hash_map::Entry;
use std::hash::{Hash, Hasher};

#[derive(Debug)]
pub struct AttachmentsDownloader {
    priority_queue: BinaryHeap<AttachmentsBatch>,
    ongoing_batch: Option<AttachmentsBatchStateMachine>,
    processed_batches: Vec<AttachmentsBatch>
}

impl AttachmentsDownloader {

    pub fn new() -> AttachmentsDownloader {
        AttachmentsDownloader {
            priority_queue: BinaryHeap::new(),
            ongoing_batch: None,
            processed_batches: vec![]
        }
    }

    pub fn run(&mut self, 
               dns_client: &mut DNSClient, 
               chainstate: &mut StacksChainState, 
               network: &mut PeerNetwork) -> Result<Vec<AttachmentInstance>, net_error> 
    {    
        let mut resolved_attachments = vec![];        

        let ongoing_fsm = match self.ongoing_batch.take() {
            Some(batch) => batch,
            None => match self.priority_queue.pop() {
                Some(attachments_batch) => {
                    // Build a brand new set of peer
                    let mut peers = HashMap::new();
                    for peer in network.get_outbound_sync_peers() {
                        if let Some(peer_url) = network.get_data_url(&peer) {
                            peers.insert(peer.clone(), peer_url);
                        }
                    }
                    let ctx = AttachmentsBatchStateContext::new(
                        attachments_batch, 
                        peers,
                        &network.connection_opts);
                    AttachmentsBatchStateMachine::new(ctx)
                }
                None => {
                    // Nothing to do!
                    return Ok(vec![])
                }
            }
        };

        let mut progress = AttachmentsBatchStateMachine::try_proceed(
            ongoing_fsm,
            dns_client, 
            network,
            chainstate);
        
        match progress {
            AttachmentsBatchStateMachine::Done(ref mut context) => {
                for (_, response) in context.attachments.drain() {
                    let attachment = response.attachment;
                    let mut attachments_instances = network.atlasdb.find_all_attachment_instances(&attachment.hash)
                        .map_err(|e| net_error::DBError(e))?;
                    network.atlasdb.insert_new_attachment(&attachment.hash, &attachment.content, true)
                        .map_err(|e| net_error::DBError(e))?;
                    resolved_attachments.append(&mut attachments_instances);
                }
    
                // At the end of the process, the batch should be simplified if did not succeed.
                // Priority queue: combination of retry count and block height.
            }
            next_state => {
                self.ongoing_batch = Some(next_state);
            }
        };

        Ok(resolved_attachments)
    }


    pub fn enqueue_new_attachments(&mut self, new_attachments: &mut HashSet<AttachmentInstance>, atlasdb: &mut AtlasDB) -> Result<Vec<AttachmentInstance>, net_error> 
    {
        if new_attachments.is_empty() {
            return Ok(vec![])
        }        

        let mut resolved_attachments = vec![];        
        let mut attachments_batch = AttachmentsBatch::new();
        for attachment in new_attachments.drain() {
            // Are we dealing with an empty hash - allowed for undoing onchain binding
            if attachment.content_hash == Hash160::empty() {
                // todo(ludo) insert or update ?
                atlasdb.insert_new_attachment_instance(&attachment, true)
                    .map_err(|e| net_error::DBError(e))?;
                debug!("Atlas: inserting and pairing new attachment instance with empty hash");
                resolved_attachments.push(attachment);
                continue;
            }
            
            // Do we already have a matching validated attachment
            if let Ok(Some(_entry)) = atlasdb.find_attachment(&attachment.content_hash) {
                atlasdb.insert_new_attachment_instance(&attachment, true)
                    .map_err(|e| net_error::DBError(e))?;
                debug!("Atlas: inserting and pairing new attachment instance to existing attachment");
                resolved_attachments.push(attachment);
                continue;
            }

            // Do we already have a matching inboxed attachment
            if let Ok(Some(_entry)) = atlasdb.find_inboxed_attachment(&attachment.content_hash) {
                atlasdb.import_attachment_from_inbox(&attachment.content_hash)
                    .map_err(|e| net_error::DBError(e))?;
                atlasdb.insert_new_attachment_instance(&attachment, true)
                    .map_err(|e| net_error::DBError(e))?;
                debug!("Atlas: inserting and pairing new attachment instance to inboxed attachment, now validated");
                resolved_attachments.push(attachment);
                continue;
            }

            // This attachment in refering to an unknown attachment. 
            // Let's append it to the batch being constructed in this routine.
            attachments_batch.track_attachment_instance(&attachment);
            atlasdb.insert_new_attachment_instance(&attachment, false)
                .map_err(|e| net_error::DBError(e))?;
        }

        if !attachments_batch.attachments_instances.is_empty() {
            self.priority_queue.push(attachments_batch);
        }

        Ok(resolved_attachments)
    }
}

#[derive(Debug)]
struct AttachmentsBatchStateContext {
    pub attachments_batch: AttachmentsBatch,
    pub peers: HashMap<NeighborKey, UrlString>,
    pub connection_options: ConnectionOptions,
    pub dns_lookups: HashMap<UrlString, Option<Vec<SocketAddr>>>,
    pub inventories: HashMap<AttachmentsInventoryRequest, HashMap<UrlString, GetAttachmentsInvResponse>>,
    pub attachments: HashMap<AttachmentRequest, GetAttachmentResponse>
}

impl AttachmentsBatchStateContext {

    pub fn new(attachments_batch: AttachmentsBatch, peers: HashMap<NeighborKey, UrlString>, connection_options: &ConnectionOptions) -> AttachmentsBatchStateContext {
        AttachmentsBatchStateContext {
            attachments_batch,
            peers,
            connection_options: connection_options.clone(),
            dns_lookups: HashMap::new(),
            inventories: HashMap::new(),
            attachments: HashMap::new(),
        }
    }

    pub fn get_peers_urls(&self) -> Vec<UrlString> {
        self.peers.values().map(|e| e.clone()).collect()
    }

    pub fn get_prioritized_attachments_inventory_requests(&self) -> BinaryHeap<AttachmentsInventoryRequest> {
        let mut queue = BinaryHeap::new();
        for (contract_id, _) in self.attachments_batch.attachments_instances.iter() {
            for (_, peer_url) in self.peers.iter() {
                let request = AttachmentsInventoryRequest {
                    url: peer_url.clone(),
                    contract_id: contract_id.clone(),
                    pages: self.attachments_batch.get_missing_pages_for_contract_id(contract_id),
                    block_height: self.attachments_batch.block_height,    
                    consensus_hash: self.attachments_batch.consensus_hash,
                    block_header_hash: self.attachments_batch.block_header_hash,            
                };
                queue.push(request);
            }
        }
        queue
    }

    pub fn get_prioritized_attachments_requests(&self) -> BinaryHeap<AttachmentRequest> {
        let mut queue = BinaryHeap::new();
        for (inventory_request, peers_responses) in self.inventories.iter() {
            let missing_attachments = match self.attachments_batch.attachments_instances.get(&inventory_request.contract_id) {
                None => continue,
                Some(missing_attachments) => missing_attachments,
            };
            for ((page_index, position_in_page), content_hash) in missing_attachments.iter() {
                let mut urls = vec![];

                for (peer_url, response) in peers_responses.iter() {

                    let index = response.pages
                        .iter()
                        .position(|page| page.index == *page_index);
                    
                    let has_attachment = match index {
                        Some(index) => match response.pages[index].inventory.get(*position_in_page as usize) {
                            Some(result) if *result == 1 => true,
                            _ => false
                        }
                        None => false,
                    };

                    if !has_attachment {
                        info!("Atlas: peer does not have attachment ({}, {}) in its inventory {:?}", page_index, position_in_page, response.pages);
                        continue;
                    }

                    urls.push(peer_url.clone());
                }

                if urls.len() > 0 {
                    let request = AttachmentRequest {
                        urls,
                        content_hash: content_hash.clone()
                    };
                    queue.push(request);    
                } else {
                    warn!("Atlas: -"); // todo(ludo)
                }
            }
        }
        queue
    }

    pub fn extend_with_dns_lookups(mut self, results: &mut BatchedDNSLookupsResults) -> AttachmentsBatchStateContext {
        for (k, v) in results.dns_lookups.drain() {
            self.dns_lookups.insert(k, v);
        }
        self
    }

    pub fn extend_with_inventories(mut self, results: &mut BatchedRequestsResult<AttachmentsInventoryRequest>) -> AttachmentsBatchStateContext {
        for (k, mut v) in results.succeeded.drain() {
            let mut responses = HashMap::new();
            for (url, response) in v.drain() {
                if let Some(HttpResponseType::GetAttachmentsInv(_, response)) = response {
                    responses.insert(url, response);
                }
            }
            self.inventories.insert(k, responses);
        }
        self
    }

    pub fn extend_with_attachments(mut self, results: &mut BatchedRequestsResult<AttachmentRequest>) -> AttachmentsBatchStateContext {
        for (k, mut v) in results.succeeded.drain() {
            for (_, response) in v.drain() {
                if let Some(HttpResponseType::GetAttachment(_, response)) = response {
                    self.attachments.insert(k, response);
                    break;
                }
            }
        }
        self
    }
}

#[derive(Debug)]
enum AttachmentsBatchStateMachine {
    Initialized(AttachmentsBatchStateContext),
    DNSLookup((BatchedDNSLookupsState, AttachmentsBatchStateContext)),
    DownloadingAttachmentsInv((BatchedRequestsState<AttachmentsInventoryRequest>, AttachmentsBatchStateContext)),
    DownloadingAttachment((BatchedRequestsState<AttachmentRequest>, AttachmentsBatchStateContext)),
    Done(AttachmentsBatchStateContext), // At the end of the process, the batch should be simplified if did not succeed
}

impl AttachmentsBatchStateMachine {

    pub fn new(ctx: AttachmentsBatchStateContext) -> AttachmentsBatchStateMachine {
        AttachmentsBatchStateMachine::Initialized(ctx)
    }

    fn try_proceed(fsm: AttachmentsBatchStateMachine, dns_client: &mut DNSClient, network: &mut PeerNetwork, chainstate: &mut StacksChainState) -> AttachmentsBatchStateMachine {
        match fsm {
            AttachmentsBatchStateMachine::Initialized(context) => {
                let sub_state = BatchedDNSLookupsState::new(context.get_peers_urls());
                AttachmentsBatchStateMachine::DNSLookup((sub_state, context))
            }
            AttachmentsBatchStateMachine::DNSLookup((dns_lookup_state, context)) => {
                match BatchedDNSLookupsState::try_proceed(dns_lookup_state, dns_client, &context.connection_options) {
                    BatchedDNSLookupsState::Done(ref mut results) => {
                        let context = context.extend_with_dns_lookups(results);
                        let sub_state = {
                            let requests_queue = context.get_prioritized_attachments_inventory_requests();
                            BatchedRequestsState::Initialized(requests_queue)
                        };
                        AttachmentsBatchStateMachine::DownloadingAttachmentsInv((sub_state, context))
                    }
                    state => {
                        AttachmentsBatchStateMachine::DNSLookup((state, context))
                    }
                }
            }
            AttachmentsBatchStateMachine::DownloadingAttachmentsInv((attachments_invs_requests, context)) => {
                match BatchedRequestsState::try_proceed(attachments_invs_requests, &context.dns_lookups, network, chainstate) {
                    BatchedRequestsState::Done(ref mut results) => {
                        let context = context.extend_with_inventories(results);
                        let sub_state = {
                            let requests_queue = context.get_prioritized_attachments_requests();
                            BatchedRequestsState::Initialized(requests_queue)
                        };
                        AttachmentsBatchStateMachine::DownloadingAttachment((sub_state, context))
                    }
                    state => {
                        AttachmentsBatchStateMachine::DownloadingAttachmentsInv((state, context))
                    }
                }
            }
            AttachmentsBatchStateMachine::DownloadingAttachment((attachments_requests, context)) => {
                match BatchedRequestsState::try_proceed(attachments_requests, &context.dns_lookups, network, chainstate) {
                    BatchedRequestsState::Done(ref mut results) => {
                        let context = context.extend_with_attachments(results);
                        AttachmentsBatchStateMachine::Done(context)
                    }
                    state => {
                        AttachmentsBatchStateMachine::DownloadingAttachment((state, context))
                    }
                }
            }
            AttachmentsBatchStateMachine::Done(context) => {
                // At the end of the process, the batch should be simplified if did not succeed
                // priority queue: combination of retry count and block height.
                unimplemented!()
            }
        }
    }
}

#[derive(Debug)]
enum BatchedDNSLookupsState {
    Initialized(Vec<UrlString>),
    Resolving(BatchedDNSLookupsResults),
    Done(BatchedDNSLookupsResults)
}

impl BatchedDNSLookupsState {
    
    pub fn new(urls: Vec<UrlString>) -> BatchedDNSLookupsState {
        BatchedDNSLookupsState::Initialized(urls)
    }
    
    fn try_proceed(fsm: BatchedDNSLookupsState, dns_client: &mut DNSClient, connection_options: &ConnectionOptions) -> BatchedDNSLookupsState {
        let mut fsm = fsm;
        match fsm {
            BatchedDNSLookupsState::Initialized(ref mut urls) => {
                
                let mut state = BatchedDNSLookupsResults::default();

                for url_str in urls.drain(..) {
                    if url_str.len() == 0 {
                        continue;
                    }
                    let url = match url_str.parse_to_block_url() {
                        Ok(url) => url,
                        Err(e) => {
                            warn!("Atlas: Unsupported URL {:?}, {}", url_str, e);
                            state.errors.insert(url_str, e);
                            continue;
                        }
                    };
                    let port = match url.port_or_known_default() {
                        Some(p) => p,
                        None => {
                            warn!("Atlas: Unsupported URL {:?}: unknown port", &url);
                            continue;
                        }
                    };
                    match url.host() {
                        Some(url::Host::Domain(domain)) => {
                            let res = dns_client.queue_lookup(
                                domain.clone(),
                                port,
                                get_epoch_time_ms() + connection_options.dns_timeout,
                            );
                            match res {
                                Ok(_) => {
                                    state.dns_lookups.insert(url_str.clone(), None);
                                    state.parsed_urls
                                        .insert(url_str, DNSRequest::new(domain.to_string(), port, 0));        
                                },
                                Err(e) => {
                                    state.errors.insert(url_str.clone(), e);
                                }
                            }
                        }
                        Some(url::Host::Ipv4(addr)) => {
                            state.dns_lookups
                                .insert(url_str, Some(vec![SocketAddr::new(IpAddr::V4(addr), port)]));
                        }
                        Some(url::Host::Ipv6(addr)) => {
                            state.dns_lookups
                                .insert(url_str, Some(vec![SocketAddr::new(IpAddr::V6(addr), port)]));
                        }
                        None => {
                            warn!("Atlas: Unsupported URL {:?}", &url_str);
                        }
                    }
                }
                BatchedDNSLookupsState::Resolving(state)
            }
            BatchedDNSLookupsState::Resolving(ref mut state) => {
                if let Err(e) = dns_client.try_recv() {
                    warn!("Atlas: DNS client unable to receive data {}", e);
                    // todo(ludo): retry count?
                    return fsm
                }

                let mut inflight = 0;
                for (url_str, request) in state.parsed_urls.iter() {
                    match dns_client.poll_lookup(&request.host, request.port) {
                        Ok(Some(query_result)) => {
                            if let Some(dns_result) = state.dns_lookups.get_mut(url_str) {
                                // solicited
                                match query_result.result {
                                    Ok(addrs) => {
                                        *dns_result = Some(addrs);
                                    }
                                    Err(msg) => {
                                        warn!("Atlas: DNS failed to look up {:?}: {}", &url_str, msg);
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            inflight += 1;
                        }
                        Err(e) => {
                            warn!("Atlas: DNS lookup failed on {:?}: {:?}", url_str, &e);
                            state.errors.insert(url_str.clone(), e);
                        }
                    }
                }

                if inflight > 0 {
                    return fsm
                }
                
                // Step successfully completed - todo(ludo) find a better approach - maybe deref?
                let mut result = BatchedDNSLookupsResults::default();
                for (k, v) in state.errors.drain() {
                    result.errors.insert(k, v);
                }
                for (k, v) in state.dns_lookups.drain() {
                    result.dns_lookups.insert(k, v);
                }                
                for (k, v) in state.parsed_urls.drain() {
                    result.parsed_urls.insert(k, v);
                }
                BatchedDNSLookupsState::Done(result)
            }
            BatchedDNSLookupsState::Done(state) => {
                unimplemented!()
            }
        }
    }
}

#[derive(Debug)]
enum BatchedRequestsState <T: Ord + Requestable + fmt::Display + std::hash::Hash> {
    Initialized(BinaryHeap<T>),
    Downloading(BatchedRequestsResult<T>),
    Done(BatchedRequestsResult<T>),
}

impl <T: Ord + Requestable + fmt::Display + std::hash::Hash> BatchedRequestsState <T> {

    fn try_proceed(fsm: BatchedRequestsState<T>, dns_lookups: &HashMap<UrlString, Option<Vec<SocketAddr>>>, network: &mut PeerNetwork, chainstate: &mut StacksChainState) -> BatchedRequestsState<T> {
        let mut fsm = fsm;

        match fsm {
            BatchedRequestsState::Initialized(ref mut queue) => {
                let mut requests = HashMap::new();
                while let Some(requestable) = queue.pop() {
                    let mut requestables = VecDeque::new();
                    requestables.push_back(requestable); // todo(ludo): revisit this design
                    let res = PeerNetwork::begin_request(
                        network, 
                        dns_lookups,
                        "Request", // todo(ludo)
                        &mut requestables, 
                        chainstate);
                    if let Some((request, event_id)) = res {
                        requests.insert(event_id, request);
                    }
                }
                let next_state = BatchedRequestsResult::new(requests);
                BatchedRequestsState::Downloading(next_state)
            }
            BatchedRequestsState::Downloading(ref mut state) => {
                
                let mut pending_requests = HashMap::new();

                for (event_id, request) in state.remaining.drain() {
                    match network.http.get_conversation(event_id) {
                        None => {
                            if network.http.is_connecting(event_id) {
                                info!("Atlas: Request {} is still connecting", request);
                                pending_requests.insert(event_id, request);
                            } else {
                                info!("Atlas: Request {} failed to connect. Temporarily blocking URL", request);
                                
                                // todo(ludo): restore
                                // self.dead_peers.push(event_id);
                                // don't try this again for a while
                                // self.blocked_urls.insert(
                                //     request_key.data_url,
                                //     get_epoch_time_secs() + BLOCK_DOWNLOAD_BAN_URL,
                                // );
                            }
                        }
                        Some(ref mut convo) => {
                            match convo.try_get_response() {
                                None => {
                                    // still waiting
                                    info!("Atlas: Request {} is still waiting for a response", request);
                                    pending_requests.insert(event_id, request);
                                }
                                Some(response) => {
                                    if let HttpResponseType::NotFound(_, _) = response {
                                        // todo(ludo): restore
                                        // remote peer didn't have the block
                                        // info!("Remote neighbor {:?} ({:?}) does not actually have attachment {} indexed at {} ({})", &request_key.neighbor, &request_key.data_url, request_key.sortition_height, &request_key.index_block_hash, &request_key.consensus_hash);
                                        // the fact that we asked this peer means that it's block inv indicated
                                        // it was present, so the absence is the mark of a broken peer
                                        // self.broken_peers.push(event_id);
                                        // self.broken_neighbors.push(request_key.neighbor.clone());
                                        continue;
                                    }

                                    info!("Atlas: Request {} received response {:?}", request, response);
                                    let request_url = request.get_url().clone();
                                    match state.succeeded.entry(request) {
                                        Entry::Occupied(responses) => {
                                            responses.into_mut().insert(request_url, Some(response));
                                        }
                                        Entry::Vacant(v) => {
                                            let mut responses = HashMap::new();
                                            responses.insert(request_url, Some(response));
                                            v.insert(responses);
                                        }
                                    };
                                    
                                    // todo(ludo): restore
                                    // _ => {
                                    //     // wrong message response
                                    //     info!(
                                    //         "Got bad HTTP response from {:?}: {:?}",
                                    //         &request_key.data_url, &http_response
                                    //     );
                                    //     self.broken_peers.push(event_id);
                                    //     self.broken_neighbors.push(request_key.neighbor.clone());
                                    // }
                                },
                            }
                        }
                    }
                }
        
                // We completed this step
                if pending_requests.len() > 0 {
                    for (event_id, request) in pending_requests.drain() {
                        state.remaining.insert(event_id, request);
                    }
                    return fsm    
                }

                // Step successfully completed - todo(ludo) find a better approach
                let mut result = BatchedRequestsResult::empty();
                for (k, v) in state.errors.drain() {
                    result.errors.insert(k, v);
                }
                for (k, v) in state.succeeded.drain() {
                    result.succeeded.insert(k, v);
                }
                BatchedRequestsState::Done(result)
            }
            BatchedRequestsState::Done(done_state) => {
                unimplemented!()
            }
        }
    }
}

#[derive(Debug, Default)]
struct BatchedDNSLookupsResults {
    pub parsed_urls: HashMap<UrlString, DNSRequest>,
    pub dns_lookups: HashMap<UrlString, Option<Vec<SocketAddr>>>,
    pub errors: HashMap<UrlString, net_error>,
}

#[derive(Debug, Clone)]
struct BatchedRequestsInitializedState <T: Ord + Requestable> {
    pub queue: BinaryHeap<T>,
}

#[derive(Debug, Default)]
struct BatchedRequestsResult <T: Requestable> {
    pub remaining: HashMap<usize, T>,
    pub succeeded: HashMap<T, HashMap<UrlString, Option<HttpResponseType>>>,
    pub errors: HashMap<T, HashMap<UrlString, net_error>>,
}


impl <T: Requestable> BatchedRequestsResult <T> {
    pub fn new(remaining: HashMap<usize, T>) -> BatchedRequestsResult<T> {
        BatchedRequestsResult {
            remaining,
            succeeded: HashMap::new(),
            errors: HashMap::new(),
        }
    }

    pub fn empty() -> BatchedRequestsResult<T> {
        BatchedRequestsResult {
            remaining: HashMap::new(),
            succeeded: HashMap::new(),
            errors: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AttachmentsInventoryRequest {
    url: UrlString,
    contract_id: QualifiedContractIdentifier,
    pages: Vec<u32>,
    block_height: u64,    
    consensus_hash: ConsensusHash,
    block_header_hash: BlockHeaderHash,
}

impl Hash for AttachmentsInventoryRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.contract_id.hash(state);
        self.pages.hash(state);
        self.consensus_hash.hash(state);
        self.block_height.hash(state);
        self.block_header_hash.hash(state);
    }
}

impl Ord for AttachmentsInventoryRequest {
    fn cmp(&self, other: &AttachmentsInventoryRequest) -> Ordering {
        other.block_height.cmp(&self.block_height)
    }
}

impl PartialOrd for AttachmentsInventoryRequest {
    fn partial_cmp(&self, other: &AttachmentsInventoryRequest) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Requestable for AttachmentsInventoryRequest {

    fn get_url(&self) -> &UrlString {
        &self.url
    }

    fn get_request_type(&self, peer_host: PeerHost) -> HttpRequestType {
        HttpRequestType::GetAttachmentsInv(
            HttpRequestMetadata::from_host(peer_host),
            None,
            HashSet::new(),
        )
    }
}

impl std::fmt::Display for AttachmentsInventoryRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Request<AttachmentsInventory>: ---- >")
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AttachmentRequest {
    urls: Vec<UrlString>,
    content_hash: Hash160,
}

impl Hash for AttachmentRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.content_hash.hash(state);
    }
}

impl Ord for AttachmentRequest {
    fn cmp(&self, other: &AttachmentRequest) -> Ordering {
        other.urls.len().cmp(&self.urls.len())
    }
}

impl PartialOrd for AttachmentRequest {
    fn partial_cmp(&self, other: &AttachmentRequest) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Requestable for AttachmentRequest {

    fn get_url(&self) -> &UrlString {
        &self.urls[0] // todo(ludo)
    }

    fn get_request_type(&self, peer_host: PeerHost) -> HttpRequestType {
        HttpRequestType::GetAttachment(
            HttpRequestMetadata::from_host(peer_host),
            self.content_hash,
        )
    }
}

impl std::fmt::Display for AttachmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Request<Attachment>: ---- >")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentsBatch {
    pub block_height: u64,    
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub attachments_instances: HashMap<QualifiedContractIdentifier, HashMap<(u32, u32), Hash160>>,
    retry_count: u64,
}

impl AttachmentsBatch {

    pub fn new() -> AttachmentsBatch {
        AttachmentsBatch {
            block_height: 0,
            consensus_hash: ConsensusHash::empty(),
            block_header_hash: BlockHeaderHash([0u8; 32]),
            attachments_instances: HashMap::new(),
            retry_count: 0
        }
    }

    pub fn track_attachment_instance(&mut self, attachment: &AttachmentInstance) {
        if self.attachments_instances.is_empty() {
            self.block_height = attachment.block_height.clone();
            self.consensus_hash = attachment.consensus_hash.clone();
            self.block_header_hash = attachment.block_header_hash;
        } else {
            assert!(self.block_height == attachment.block_height);
            assert!(self.consensus_hash == attachment.consensus_hash);
            assert!(self.block_header_hash == attachment.block_header_hash);
        }

        let inner_key = (attachment.page_index, attachment.position_in_page);
        match self.attachments_instances.entry(attachment.contract_id.clone()) {
            Entry::Occupied(missing_attachments) => {
                missing_attachments.into_mut().insert(inner_key, attachment.content_hash.clone());
            }
            Entry::Vacant(v) => {
                let mut missing_attachments = HashMap::new();
                missing_attachments.insert(inner_key, attachment.content_hash.clone());
                v.insert(missing_attachments);
            }
        };
    }

    pub fn get_missing_pages_for_contract_id(&self, contract_id: &QualifiedContractIdentifier) -> Vec<u32> {
        let mut pages_indexes = vec![];
        if let Some(missing_attachments) = self.attachments_instances.get(&contract_id) {
            for ((page_index, _), _) in missing_attachments.iter() {
                pages_indexes.push(*page_index);
            }    
        }
        pages_indexes
    }

    pub fn get_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockHeader::make_index_block_hash(
            &self.consensus_hash,
            &self.block_header_hash
        )
    }
}

impl Ord for AttachmentsBatch {
    fn cmp(&self, other: &AttachmentsBatch) -> Ordering {
        other.block_height.cmp(&self.block_height)
            .then_with(|| self.retry_count.cmp(&other.retry_count))
    }
}

impl PartialOrd for AttachmentsBatch {
    fn partial_cmp(&self, other: &AttachmentsBatch) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

struct ResolvedAttachment {
}

struct AttachmentsAnalytics {
    pub total_attachments_inv_requested: u32,
    pub total_attachments_inv_downloaded: u32,
    pub total_attachments_requested: u32,
    pub total_attachments_downloaded: u32,
}
