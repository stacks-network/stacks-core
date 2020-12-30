use super::{AtlasDB, Attachment, AttachmentInstance, MAX_ATTACHMENT_INV_PAGES_PER_REQUEST};
use chainstate::burn::{BlockHeaderHash, ConsensusHash};
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::{StacksBlockHeader, StacksBlockId};
use net::connection::ConnectionOptions;
use net::dns::*;
use net::p2p::PeerNetwork;
use net::server::HttpPeer;
use net::Error as net_error;
use net::NeighborKey;
use net::{GetAttachmentResponse, GetAttachmentsInvResponse};
use net::{HttpRequestMetadata, HttpRequestType, HttpResponseType, PeerHost, Requestable};
use util::hash::{Hash160, MerkleHashFunc};
use util::strings;
use util::{get_epoch_time_ms, get_epoch_time_secs};
use vm::representations::UrlString;
use vm::types::QualifiedContractIdentifier;

use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct AttachmentsDownloader {
    priority_queue: BinaryHeap<AttachmentsBatch>,
    ongoing_batch: Option<AttachmentsBatchStateMachine>,
    processed_batches: Vec<AttachmentsBatch>,
    reliability_reports: HashMap<UrlString, ReliabilityReport>,
}

impl AttachmentsDownloader {
    pub fn new() -> AttachmentsDownloader {
        AttachmentsDownloader {
            priority_queue: BinaryHeap::new(),
            ongoing_batch: None,
            processed_batches: vec![],
            reliability_reports: HashMap::new(),
        }
    }

    pub fn run(
        &mut self,
        dns_client: &mut DNSClient,
        chainstate: &mut StacksChainState,
        network: &mut PeerNetwork,
    ) -> Result<Vec<AttachmentInstance>, net_error> {
        let mut resolved_attachments = vec![];

        let ongoing_fsm = match self.ongoing_batch.take() {
            Some(batch) => batch,
            None => match self.priority_queue.pop() {
                Some(attachments_batch) => {
                    // Build a brand new set of peer
                    let mut peers = HashMap::new();
                    for peer in network.get_outbound_sync_peers() {
                        if let Some(peer_url) = network.get_data_url(&peer) {
                            let report = match self.reliability_reports.get(&peer_url) {
                                Some(report) => report.clone(),
                                None => ReliabilityReport::empty(),
                            };
                            peers.insert(peer_url, report);
                        }
                    }
                    let ctx = AttachmentsBatchStateContext::new(
                        attachments_batch,
                        peers,
                        &network.connection_opts,
                    );
                    AttachmentsBatchStateMachine::new(ctx)
                }
                None => {
                    // Nothing to do!
                    return Ok(vec![]);
                }
            },
        };

        let mut progress =
            AttachmentsBatchStateMachine::try_proceed(ongoing_fsm, dns_client, network, chainstate);

        match progress {
            AttachmentsBatchStateMachine::Done(ref mut context) => {
                for attachment in context.attachments.drain() {
                    let mut attachments_instances = network
                        .atlasdb
                        .find_all_attachment_instances(&attachment.hash())
                        .map_err(|e| net_error::DBError(e))?;
                    network
                        .atlasdb
                        .insert_instantiated_attachment(&attachment)
                        .map_err(|e| net_error::DBError(e))?;
                    resolved_attachments.append(&mut attachments_instances);
                    context
                        .attachments_batch
                        .resolve_attachment(&attachment.hash())
                }

                // Every once in a while, we delete uninstantiated attachments
                network.atlasdb.evict_expired_uninstantiated_attachments()?;

                // Update reliability reports
                for (peer_url, report) in context.peers.drain() {
                    self.reliability_reports.insert(peer_url, report);
                }

                // Re-insert AttachmentsBatch back to the queue if not fully processed
                if !context.attachments_batch.has_fully_succeed() {
                    context.attachments_batch.bump_retry_count();
                    self.priority_queue.push(context.attachments_batch.clone());
                }
            }
            next_state => {
                self.ongoing_batch = Some(next_state);
            }
        };

        Ok(resolved_attachments)
    }

    pub fn enqueue_new_attachments(
        &mut self,
        new_attachments: &mut HashSet<AttachmentInstance>,
        atlasdb: &mut AtlasDB,
    ) -> Result<Vec<AttachmentInstance>, net_error> {
        if new_attachments.is_empty() {
            return Ok(vec![]);
        }

        let mut resolved_attachments = vec![];
        let mut attachments_batch = AttachmentsBatch::new();
        for attachment_instance in new_attachments.drain() {
            // Are we dealing with an empty hash - allowed for undoing onchain binding
            if attachment_instance.content_hash == Hash160::empty() {
                // todo(ludo) insert or update ?
                atlasdb
                    .insert_uninstantiated_attachment_instance(&attachment_instance, true)
                    .map_err(|e| net_error::DBError(e))?;
                debug!("Atlas: inserting and pairing new attachment instance with empty hash");
                resolved_attachments.push(attachment_instance);
                continue;
            }

            // Do we already have a matching validated attachment
            if let Ok(Some(_entry)) = atlasdb.find_attachment(&attachment_instance.content_hash) {
                atlasdb
                    .insert_uninstantiated_attachment_instance(&attachment_instance, true)
                    .map_err(|e| net_error::DBError(e))?;
                debug!(
                    "Atlas: inserting and pairing new attachment instance to existing attachment"
                );
                resolved_attachments.push(attachment_instance);
                continue;
            }

            // Do we already have a matching inboxed attachment
            if let Ok(Some(attachment)) =
                atlasdb.find_uninstantiated_attachment(&attachment_instance.content_hash)
            {
                atlasdb
                    .insert_instantiated_attachment(&attachment)
                    .map_err(|e| net_error::DBError(e))?;
                atlasdb
                    .insert_uninstantiated_attachment_instance(&attachment_instance, true)
                    .map_err(|e| net_error::DBError(e))?;
                debug!("Atlas: inserting and pairing new attachment instance to inboxed attachment, now validated");
                resolved_attachments.push(attachment_instance);
                continue;
            }

            // This attachment in refering to an unknown attachment.
            // Let's append it to the batch being constructed in this routine.
            attachments_batch.track_attachment(&attachment_instance);
            atlasdb
                .insert_uninstantiated_attachment_instance(&attachment_instance, false)
                .map_err(|e| net_error::DBError(e))?;
        }

        if !attachments_batch.attachments_instances.is_empty() {
            self.priority_queue.push(attachments_batch);
        }

        Ok(resolved_attachments)
    }
}

#[derive(Debug)]
pub struct AttachmentsBatchStateContext {
    pub attachments_batch: AttachmentsBatch,
    pub peers: HashMap<UrlString, ReliabilityReport>,
    pub connection_options: ConnectionOptions,
    pub dns_lookups: HashMap<UrlString, Option<Vec<SocketAddr>>>,
    pub inventories:
        HashMap<AttachmentsInventoryRequest, HashMap<UrlString, GetAttachmentsInvResponse>>,
    pub attachments: HashSet<Attachment>,
}

impl AttachmentsBatchStateContext {
    pub fn new(
        attachments_batch: AttachmentsBatch,
        peers: HashMap<UrlString, ReliabilityReport>,
        connection_options: &ConnectionOptions,
    ) -> AttachmentsBatchStateContext {
        AttachmentsBatchStateContext {
            attachments_batch,
            peers,
            connection_options: connection_options.clone(),
            dns_lookups: HashMap::new(),
            inventories: HashMap::new(),
            attachments: HashSet::new(),
        }
    }

    pub fn get_peers_urls(&self) -> Vec<UrlString> {
        self.peers.keys().map(|e| e.clone()).collect()
    }

    pub fn get_prioritized_attachments_inventory_requests(
        &self,
    ) -> BinaryHeap<AttachmentsInventoryRequest> {
        let mut queue = BinaryHeap::new();
        for (contract_id, _) in self.attachments_batch.attachments_instances.iter() {
            for (peer_url, reliability_report) in self.peers.iter() {
                for pages in self
                    .attachments_batch
                    .get_paginated_missing_pages_for_contract_id(contract_id)
                {
                    let request = AttachmentsInventoryRequest {
                        url: peer_url.clone(),
                        reliability_report: reliability_report.clone(),
                        contract_id: contract_id.clone(),
                        pages: pages,
                        block_height: self.attachments_batch.block_height,
                        consensus_hash: self.attachments_batch.consensus_hash,
                        block_header_hash: self.attachments_batch.block_header_hash,
                    };
                    queue.push(request);
                }
            }
        }
        queue
    }

    pub fn get_prioritized_attachments_requests(&self) -> BinaryHeap<AttachmentRequest> {
        let mut queue = BinaryHeap::new();
        for (inventory_request, peers_responses) in self.inventories.iter() {
            let missing_attachments = match self
                .attachments_batch
                .attachments_instances
                .get(&inventory_request.contract_id)
            {
                None => continue,
                Some(missing_attachments) => missing_attachments,
            };
            for (attachment_index, content_hash) in missing_attachments.iter() {
                let mut sources = HashMap::new();
                let page_index = attachment_index / AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
                let position_in_page =
                    attachment_index % AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;

                for (peer_url, response) in peers_responses.iter() {
                    let index = response
                        .pages
                        .iter()
                        .position(|page| page.index == page_index);

                    let has_attachment = match index {
                        Some(index) => match response.pages[index]
                            .inventory
                            .get(position_in_page as usize)
                        {
                            Some(result) if *result == 1 => true,
                            _ => false,
                        },
                        None => false,
                    };

                    if !has_attachment {
                        info!(
                            "Atlas: peer does not have attachment ({}, {}) in its inventory {:?}",
                            page_index, position_in_page, response.pages
                        );
                        continue;
                    }

                    let report = self
                        .peers
                        .get(peer_url)
                        .expect("Atlas: unable to retrieve reliability report for peer");
                    sources.insert(peer_url.clone(), report.clone());
                }

                if sources.is_empty() {
                    warn!("Atlas: could not find a peer including attachment in its inventory");
                    continue;
                }

                // Success, we found at least one inventory including the attachment we're looking for.
                let request = AttachmentRequest {
                    sources,
                    content_hash: content_hash.clone(),
                };
                queue.push(request);
            }
        }
        queue
    }

    pub fn extend_with_dns_lookups(
        mut self,
        results: &mut BatchedDNSLookupsResults,
    ) -> AttachmentsBatchStateContext {
        for (k, v) in results.dns_lookups.drain() {
            self.dns_lookups.insert(k, v);
        }
        self
    }

    pub fn extend_with_inventories(
        mut self,
        results: &mut BatchedRequestsResult<AttachmentsInventoryRequest>,
    ) -> AttachmentsBatchStateContext {
        for (k, mut responses) in results.succeeded.drain() {
            let mut inventories = HashMap::new();
            for (peer_url, response) in responses.drain() {
                let report = self
                    .peers
                    .get_mut(&peer_url)
                    .expect("Atlas: unable to retrieve reliability report for peer");
                if let Some(HttpResponseType::GetAttachmentsInv(_, response)) = response {
                    inventories.insert(peer_url, response);
                    report.bump_successful_requests();
                } else {
                    report.bump_failed_requests();
                }
            }
            self.inventories.insert(k, inventories);
        }
        self
    }

    pub fn extend_with_attachments(
        mut self,
        results: &mut BatchedRequestsResult<AttachmentRequest>,
    ) -> AttachmentsBatchStateContext {
        for (_, mut responses) in results.succeeded.drain() {
            for (peer_url, response) in responses.drain() {
                let report = self
                    .peers
                    .get_mut(&peer_url)
                    .expect("Atlas: unable to retrieve reliability report for peer");
                if let Some(HttpResponseType::GetAttachment(_, response)) = response {
                    self.attachments.insert(response.attachment);
                    report.bump_successful_requests();
                } else {
                    report.bump_failed_requests();
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
    DownloadingAttachmentsInv(
        (
            BatchedRequestsState<AttachmentsInventoryRequest>,
            AttachmentsBatchStateContext,
        ),
    ),
    DownloadingAttachment(
        (
            BatchedRequestsState<AttachmentRequest>,
            AttachmentsBatchStateContext,
        ),
    ),
    Done(AttachmentsBatchStateContext),
}

impl AttachmentsBatchStateMachine {
    pub fn new(ctx: AttachmentsBatchStateContext) -> AttachmentsBatchStateMachine {
        AttachmentsBatchStateMachine::Initialized(ctx)
    }

    fn try_proceed(
        fsm: AttachmentsBatchStateMachine,
        dns_client: &mut DNSClient,
        network: &mut PeerNetwork,
        chainstate: &mut StacksChainState,
    ) -> AttachmentsBatchStateMachine {
        match fsm {
            AttachmentsBatchStateMachine::Initialized(context) => {
                let sub_state = BatchedDNSLookupsState::new(context.get_peers_urls());
                AttachmentsBatchStateMachine::DNSLookup((sub_state, context))
            }
            AttachmentsBatchStateMachine::DNSLookup((dns_lookup_state, context)) => {
                match BatchedDNSLookupsState::try_proceed(
                    dns_lookup_state,
                    dns_client,
                    &context.connection_options,
                ) {
                    BatchedDNSLookupsState::Done(ref mut results) => {
                        let context = context.extend_with_dns_lookups(results);
                        let sub_state = {
                            let requests_queue =
                                context.get_prioritized_attachments_inventory_requests();
                            BatchedRequestsState::BeginRequests(Some(requests_queue), None)
                        };
                        AttachmentsBatchStateMachine::DownloadingAttachmentsInv((
                            sub_state, context,
                        ))
                    }
                    state => AttachmentsBatchStateMachine::DNSLookup((state, context)),
                }
            }
            AttachmentsBatchStateMachine::DownloadingAttachmentsInv((
                attachments_invs_requests,
                context,
            )) => {
                match BatchedRequestsState::try_proceed(
                    attachments_invs_requests,
                    &context.dns_lookups,
                    network,
                    chainstate,
                    &context.connection_options,
                ) {
                    BatchedRequestsState::Done(ref mut results) => {
                        let context = context.extend_with_inventories(results);
                        let sub_state = {
                            let requests_queue = context.get_prioritized_attachments_requests();
                            BatchedRequestsState::BeginRequests(Some(requests_queue), None)
                        };
                        AttachmentsBatchStateMachine::DownloadingAttachment((sub_state, context))
                    }
                    state => {
                        AttachmentsBatchStateMachine::DownloadingAttachmentsInv((state, context))
                    }
                }
            }
            AttachmentsBatchStateMachine::DownloadingAttachment((
                attachments_requests,
                context,
            )) => {
                match BatchedRequestsState::try_proceed(
                    attachments_requests,
                    &context.dns_lookups,
                    network,
                    chainstate,
                    &context.connection_options,
                ) {
                    BatchedRequestsState::Done(ref mut results) => {
                        let context = context.extend_with_attachments(results);
                        AttachmentsBatchStateMachine::Done(context)
                    }
                    state => AttachmentsBatchStateMachine::DownloadingAttachment((state, context)),
                }
            }
            AttachmentsBatchStateMachine::Done(_context) => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum BatchedDNSLookupsState {
    Initialized(Vec<UrlString>),
    Resolving(Option<BatchedDNSLookupsResults>),
    Done(BatchedDNSLookupsResults),
}

impl BatchedDNSLookupsState {
    pub fn new(urls: Vec<UrlString>) -> BatchedDNSLookupsState {
        BatchedDNSLookupsState::Initialized(urls)
    }

    fn try_proceed(
        fsm: BatchedDNSLookupsState,
        dns_client: &mut DNSClient,
        connection_options: &ConnectionOptions,
    ) -> BatchedDNSLookupsState {
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
                                    state.parsed_urls.insert(
                                        url_str,
                                        DNSRequest::new(domain.to_string(), port, 0),
                                    );
                                }
                                Err(e) => {
                                    state.errors.insert(url_str.clone(), e);
                                }
                            }
                        }
                        Some(url::Host::Ipv4(addr)) => {
                            state.dns_lookups.insert(
                                url_str,
                                Some(vec![SocketAddr::new(IpAddr::V4(addr), port)]),
                            );
                        }
                        Some(url::Host::Ipv6(addr)) => {
                            state.dns_lookups.insert(
                                url_str,
                                Some(vec![SocketAddr::new(IpAddr::V6(addr), port)]),
                            );
                        }
                        None => {
                            warn!("Atlas: Unsupported URL {:?}", &url_str);
                        }
                    }
                }
                BatchedDNSLookupsState::Resolving(Some(state))
            }
            BatchedDNSLookupsState::Resolving(ref mut results) => {
                if let Err(e) = dns_client.try_recv() {
                    warn!("Atlas: DNS client unable to receive data {}", e);
                    return fsm;
                }
                let state = match results {
                    Some(state) => state,
                    None => unreachable!(),
                };

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
                                        warn!(
                                            "Atlas: DNS failed to look up {:?}: {}",
                                            &url_str, msg
                                        );
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
                    return fsm;
                }

                // Step successfully completed
                let results = match results.take() {
                    Some(state) => state,
                    None => unreachable!(),
                };
                BatchedDNSLookupsState::Done(results)
            }
            BatchedDNSLookupsState::Done(_) => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum BatchedRequestsState<T: Ord + Requestable + fmt::Display + std::hash::Hash> {
    BeginRequests(Option<BinaryHeap<T>>, Option<BatchedRequestsResult<T>>),
    PollRequests(Option<BinaryHeap<T>>, Option<BatchedRequestsResult<T>>),
    Done(BatchedRequestsResult<T>),
}

impl<T: Ord + Requestable + fmt::Display + std::hash::Hash> BatchedRequestsState<T> {
    fn try_proceed(
        fsm: BatchedRequestsState<T>,
        dns_lookups: &HashMap<UrlString, Option<Vec<SocketAddr>>>,
        network: &mut PeerNetwork,
        chainstate: &mut StacksChainState,
        connection_options: &ConnectionOptions,
    ) -> BatchedRequestsState<T> {
        let mut fsm = fsm;

        match fsm {
            BatchedRequestsState::BeginRequests(ref mut queue, ref mut results) => {
                let mut queue = match queue.take() {
                    Some(queue) => queue,
                    None => unreachable!(),
                };
                let mut requests = HashMap::new();

                // We want to limit the number of requests in flight,
                // so we will be batching our requests.
                for _ in 0..connection_options.max_inflight_attachments {
                    if let Some(requestable) = queue.pop() {
                        let mut requestables = VecDeque::new();
                        requestables.push_back(requestable);
                        let res = PeerNetwork::begin_request(
                            network,
                            dns_lookups,
                            &mut requestables,
                            chainstate,
                        );
                        if let Some((request, event_id)) = res {
                            requests.insert(event_id, request);
                        }
                    }
                }

                let results = if results.is_none() {
                    Some(BatchedRequestsResult::new(requests))
                } else {
                    results.take()
                };
                BatchedRequestsState::PollRequests(Some(queue), results)
            }
            BatchedRequestsState::PollRequests(ref mut queue, ref mut results) => {
                let mut pending_requests = HashMap::new();

                let state = match results {
                    Some(state) => state,
                    None => unreachable!(),
                };

                for (event_id, request) in state.remaining.drain() {
                    match network.http.get_conversation(event_id) {
                        None => {
                            if network.http.is_connecting(event_id) {
                                info!("Atlas: Request {} is still connecting", request);
                                pending_requests.insert(event_id, request);
                            } else {
                                info!(
                                    "Atlas: Request {} failed to connect. Temporarily blocking URL",
                                    request
                                );
                                let peer_url = request.get_url().clone();
                                state.faulty_peers.insert(peer_url);
                            }
                        }
                        Some(ref mut convo) => {
                            match convo.try_get_response() {
                                None => {
                                    // still waiting
                                    info!(
                                        "Atlas: Request {} is still waiting for a response",
                                        request
                                    );
                                    pending_requests.insert(event_id, request);
                                    continue;
                                }
                                Some(response) => {
                                    let peer_url = request.get_url().clone();

                                    if let HttpResponseType::NotFound(_, _) = response {
                                        state.faulty_peers.insert(peer_url);
                                        continue;
                                    }
                                    info!(
                                        "Atlas: Request {} received response {:?}",
                                        request, response
                                    );
                                    match state.succeeded.entry(request) {
                                        Entry::Occupied(responses) => {
                                            responses.into_mut().insert(peer_url, Some(response));
                                        }
                                        Entry::Vacant(v) => {
                                            let mut responses = HashMap::new();
                                            responses.insert(peer_url, Some(response));
                                            v.insert(responses);
                                        }
                                    };
                                }
                            }
                        }
                    }
                }

                if pending_requests.len() > 0 {
                    // We need to keep polling
                    for (event_id, request) in pending_requests.drain() {
                        state.remaining.insert(event_id, request);
                    }
                    return fsm;
                }

                // Requests completed!
                // any requests left to perform?
                let queue = match queue.take() {
                    Some(queue) => queue,
                    None => unreachable!(),
                };
                match queue.len() {
                    0 => BatchedRequestsState::Done(results.take().unwrap()),
                    _ => BatchedRequestsState::BeginRequests(Some(queue), results.take()),
                }
            }
            BatchedRequestsState::Done(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
pub struct BatchedDNSLookupsResults {
    pub parsed_urls: HashMap<UrlString, DNSRequest>,
    pub dns_lookups: HashMap<UrlString, Option<Vec<SocketAddr>>>,
    pub errors: HashMap<UrlString, net_error>,
}

#[derive(Debug, Clone)]
struct BatchedRequestsInitializedState<T: Ord + Requestable> {
    pub queue: BinaryHeap<T>,
}

#[derive(Debug, Default)]
pub struct BatchedRequestsResult<T: Requestable> {
    pub remaining: HashMap<usize, T>,
    pub succeeded: HashMap<T, HashMap<UrlString, Option<HttpResponseType>>>,
    pub errors: HashMap<T, HashMap<UrlString, net_error>>,
    pub faulty_peers: HashSet<UrlString>,
}

impl<T: Requestable> BatchedRequestsResult<T> {
    pub fn new(remaining: HashMap<usize, T>) -> BatchedRequestsResult<T> {
        BatchedRequestsResult {
            remaining,
            succeeded: HashMap::new(),
            errors: HashMap::new(),
            faulty_peers: HashSet::new(),
        }
    }

    pub fn empty() -> BatchedRequestsResult<T> {
        BatchedRequestsResult {
            remaining: HashMap::new(),
            succeeded: HashMap::new(),
            errors: HashMap::new(),
            faulty_peers: HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttachmentsInventoryRequest {
    pub url: UrlString,
    pub contract_id: QualifiedContractIdentifier,
    pub pages: Vec<u32>,
    pub block_height: u64,
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub reliability_report: ReliabilityReport,
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
        self.reliability_report.cmp(&other.reliability_report)
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

    fn make_request_type(&self, peer_host: PeerHost) -> HttpRequestType {
        let mut pages_indexes = HashSet::new();
        for page in self.pages.iter() {
            pages_indexes.insert(*page);
        }
        HttpRequestType::GetAttachmentsInv(
            HttpRequestMetadata::from_host(peer_host),
            None,
            pages_indexes,
        )
    }
}

impl std::fmt::Display for AttachmentsInventoryRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let url = &**self.get_url();
        write!(f, "<Request<AttachmentsInventory>: url={}>", url)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttachmentRequest {
    pub content_hash: Hash160,
    pub sources: HashMap<UrlString, ReliabilityReport>,
}

impl AttachmentRequest {
    pub fn get_most_reliable_source(&self) -> (&UrlString, &ReliabilityReport) {
        self.sources
            .iter()
            .max_by_key(|(_, v)| v.score())
            .expect("Atlas: trying to select an Url out of an empty set")
    }
}

impl Hash for AttachmentRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.content_hash.hash(state)
    }
}

impl Ord for AttachmentRequest {
    fn cmp(&self, other: &AttachmentRequest) -> Ordering {
        other.sources.len().cmp(&self.sources.len()).then_with(|| {
            let (_, report) = self.get_most_reliable_source();
            let (_, other_report) = other.get_most_reliable_source();
            report.cmp(&other_report)
        })
    }
}

impl PartialOrd for AttachmentRequest {
    fn partial_cmp(&self, other: &AttachmentRequest) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Requestable for AttachmentRequest {
    fn get_url(&self) -> &UrlString {
        let (url, _) = self.get_most_reliable_source();
        url
    }

    fn make_request_type(&self, peer_host: PeerHost) -> HttpRequestType {
        HttpRequestType::GetAttachment(HttpRequestMetadata::from_host(peer_host), self.content_hash)
    }
}

impl std::fmt::Display for AttachmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let url = &**self.get_url();
        write!(f, "<Request<Attachment>: url={}>", url)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentsBatch {
    pub block_height: u64,
    pub consensus_hash: ConsensusHash,
    pub block_header_hash: BlockHeaderHash,
    pub attachments_instances: HashMap<QualifiedContractIdentifier, HashMap<u32, Hash160>>,
    pub retry_count: u64,
}

impl AttachmentsBatch {
    pub fn new() -> AttachmentsBatch {
        AttachmentsBatch {
            block_height: 0,
            consensus_hash: ConsensusHash::empty(),
            block_header_hash: BlockHeaderHash([0u8; 32]),
            attachments_instances: HashMap::new(),
            retry_count: 0,
        }
    }

    pub fn track_attachment(&mut self, attachment: &AttachmentInstance) {
        if self.attachments_instances.is_empty() {
            self.block_height = attachment.block_height.clone();
            self.consensus_hash = attachment.consensus_hash.clone();
            self.block_header_hash = attachment.block_header_hash;
        } else {
            assert_eq!(self.block_height, attachment.block_height);
            assert_eq!(self.consensus_hash, attachment.consensus_hash);
            assert_eq!(self.block_header_hash, attachment.block_header_hash);
        }

        let inner_key = attachment.attachment_index;
        match self
            .attachments_instances
            .entry(attachment.contract_id.clone())
        {
            Entry::Occupied(missing_attachments) => {
                missing_attachments
                    .into_mut()
                    .insert(inner_key, attachment.content_hash.clone());
            }
            Entry::Vacant(v) => {
                let mut missing_attachments = HashMap::new();
                missing_attachments.insert(inner_key, attachment.content_hash.clone());
                v.insert(missing_attachments);
            }
        };
    }

    pub fn bump_retry_count(&mut self) {
        self.retry_count += 1;
    }

    pub fn has_fully_succeed(&self) -> bool {
        self.attachments_instances_count() == 0
    }

    pub fn get_missing_pages_for_contract_id(
        &self,
        contract_id: &QualifiedContractIdentifier,
    ) -> Vec<u32> {
        let mut pages_indexes = HashSet::new();
        if let Some(missing_attachments) = self.attachments_instances.get(&contract_id) {
            for (attachment_index, _) in missing_attachments.iter() {
                let page_index = attachment_index / AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
                pages_indexes.insert(page_index);
            }
        }
        pages_indexes.into_iter().collect()
    }

    pub fn get_paginated_missing_pages_for_contract_id(
        &self,
        contract_id: &QualifiedContractIdentifier,
    ) -> Vec<Vec<u32>> {
        let mut paginated = vec![];
        let pages_indexes = self.get_missing_pages_for_contract_id(contract_id);
        for page in pages_indexes.chunks(MAX_ATTACHMENT_INV_PAGES_PER_REQUEST) {
            paginated.push(page.to_vec());
        }
        paginated
    }

    pub fn resolve_attachment(&mut self, content_hash: &Hash160) {
        for missing_attachments in self.attachments_instances.values_mut() {
            let mut keys = vec![];
            for (k, hash) in missing_attachments.iter() {
                if hash == content_hash {
                    keys.push(k.clone());
                }
            }
            for key in keys {
                missing_attachments.remove(&key);
            }
        }
    }

    pub fn get_stacks_block_id(&self) -> StacksBlockId {
        StacksBlockHeader::make_index_block_hash(&self.consensus_hash, &self.block_header_hash)
    }

    pub fn attachments_instances_count(&self) -> usize {
        self.attachments_instances
            .values()
            .fold(0, |count, a| count + a.len())
    }
}

impl Ord for AttachmentsBatch {
    fn cmp(&self, other: &AttachmentsBatch) -> Ordering {
        other
            .retry_count
            .cmp(&self.retry_count)
            .then_with(|| {
                self.attachments_instances_count()
                    .cmp(&other.attachments_instances_count())
            })
            .then_with(|| other.block_height.cmp(&self.block_height))
    }
}

impl PartialOrd for AttachmentsBatch {
    fn partial_cmp(&self, other: &AttachmentsBatch) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReliabilityReport {
    pub total_requests_sent: u32,
    pub total_requests_success: u32,
}

impl ReliabilityReport {
    pub fn bump_successful_requests(&mut self) {
        self.total_requests_sent += 1;
        self.total_requests_success += 1;
    }

    pub fn bump_failed_requests(&mut self) {
        self.total_requests_sent += 1;
    }
}

impl ReliabilityReport {
    pub fn new(total_requests_sent: u32, total_requests_success: u32) -> ReliabilityReport {
        ReliabilityReport {
            total_requests_sent,
            total_requests_success,
        }
    }

    pub fn empty() -> ReliabilityReport {
        ReliabilityReport {
            total_requests_sent: 0,
            total_requests_success: 0,
        }
    }

    pub fn score(&self) -> u32 {
        match self.total_requests_sent {
            0 => 0 as u32,
            n => self.total_requests_success * 1000 / (n * 1000) + n,
        }
    }
}

impl Ord for ReliabilityReport {
    fn cmp(&self, other: &ReliabilityReport) -> Ordering {
        self.score().cmp(&other.score()).then_with(|| {
            self.total_requests_success
                .cmp(&other.total_requests_success)
        })
    }
}

impl PartialOrd for ReliabilityReport {
    fn partial_cmp(&self, other: &ReliabilityReport) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
