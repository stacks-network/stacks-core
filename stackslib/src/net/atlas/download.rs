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

use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::{cmp, fmt};

use clarity::vm::types::QualifiedContractIdentifier;
use rand::{thread_rng, Rng};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};
use stacks_common::util::hash::{Hash160, MerkleHashFunc};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use super::{AtlasDB, Attachment, AttachmentInstance, MAX_ATTACHMENT_INV_PAGES_PER_REQUEST};
use crate::chainstate::burn::ConsensusHash;
use crate::net::atlas::{GetAttachmentResponse, GetAttachmentsInvResponse, MAX_RETRY_DELAY};
use crate::net::connection::ConnectionOptions;
use crate::net::dns::*;
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::p2p::PeerNetwork;
use crate::net::server::HttpPeer;
use crate::net::{Error as net_error, NeighborKey, PeerHost, Requestable};
use crate::util_lib::db::Error as DBError;
use crate::util_lib::strings;
use crate::util_lib::strings::UrlString;

#[derive(Debug)]
pub struct AttachmentsDownloader {
    priority_queue: BinaryHeap<AttachmentsBatch>,
    initial_batch: Vec<AttachmentInstance>,
    ongoing_batch: Option<AttachmentsBatchStateMachine>,
    processed_batches: Vec<AttachmentsBatch>,
    reliability_reports: HashMap<UrlString, ReliabilityReport>,
}

impl AttachmentsDownloader {
    pub fn new(initial_batch: Vec<AttachmentInstance>) -> AttachmentsDownloader {
        AttachmentsDownloader {
            priority_queue: BinaryHeap::new(),
            ongoing_batch: None,
            processed_batches: vec![],
            reliability_reports: HashMap::new(),
            initial_batch,
        }
    }

    /// Identify whether or not any AttachmentBatches in the priority queue are ready for
    /// (re-)consideration by the downloader, based on whether or not its re-try deadline
    /// has passed.
    pub fn has_ready_batches(&self) -> bool {
        for batch in self.priority_queue.iter() {
            if batch.retry_deadline < get_epoch_time_secs() {
                return true;
            }
        }
        return false;
    }

    /// Returns the next attachments batch that is ready for processing -- i.e. after its deadline
    /// has passed.
    /// Because AttachmentBatches are ordered first by their retry deadlines, it follows that if
    /// there are any ready AttachmentBatches, they'll be at the head of the queue.
    pub fn pop_next_ready_batch(&mut self) -> Option<AttachmentsBatch> {
        let next_is_ready = if let Some(next) = self.priority_queue.peek() {
            next.retry_deadline < get_epoch_time_secs()
        } else {
            false
        };

        if next_is_ready {
            self.priority_queue.pop()
        } else {
            None
        }
    }

    /// This function executes `AttachmentsBatchStateMachine` for one step.
    /// It handles initializing and setting the batch to be processed by the machine.
    pub fn run(
        &mut self,
        dns_client: &mut DNSClient,
        network: &mut PeerNetwork,
    ) -> Result<(Vec<(AttachmentInstance, Attachment)>, Vec<usize>), net_error> {
        let mut resolved_attachments = vec![];
        let mut events_to_deregister = vec![];

        // Handle initial batch
        if !self.initial_batch.is_empty() {
            let mut resolved = self.enqueue_initial_attachments(&mut network.atlasdb)?;
            resolved_attachments.append(&mut resolved);
        }

        let ongoing_fsm = match self.ongoing_batch.take() {
            Some(batch) => batch,
            None => {
                if self.priority_queue.is_empty() || !self.has_ready_batches() {
                    // Nothing to do!
                    return Ok((vec![], vec![]));
                }

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
                if peers.is_empty() {
                    warn!("Atlas: could not get a peer to sync with");
                    // Nothing can be done!
                    return Ok((vec![], vec![]));
                }

                let attachments_batch = match self.pop_next_ready_batch() {
                    Some(ready_batch) => ready_batch,
                    None => {
                        // unreachable
                        warn!("BUG: Atlas; no batch ready although logic checking for ready batches found one");
                        return Ok((vec![], vec![]));
                    }
                };

                let ctx = AttachmentsBatchStateContext::new(
                    attachments_batch,
                    peers,
                    &network.connection_opts,
                );
                AttachmentsBatchStateMachine::new(ctx)
            }
        };

        let mut progress =
            AttachmentsBatchStateMachine::try_proceed(ongoing_fsm, dns_client, network);

        match progress {
            AttachmentsBatchStateMachine::Done(ref mut context) => {
                for attachment in context.attachments.drain() {
                    let attachments_instances = network
                        .atlasdb
                        .find_all_attachment_instances(&attachment.hash())
                        .map_err(net_error::DBError)?;
                    network
                        .atlasdb
                        .insert_instantiated_attachment(&attachment)
                        .map_err(net_error::DBError)?;
                    for attachment_instance in attachments_instances.into_iter() {
                        resolved_attachments.push((attachment_instance, attachment.clone()));
                    }
                    context
                        .attachments_batch
                        .resolve_attachment(&attachment.hash())
                }

                // Carrying events for centralized deregistration
                events_to_deregister.append(&mut context.events_to_deregister);

                // Every once in a while, we delete uninstantiated attachments
                network.atlasdb.evict_expired_uninstantiated_attachments()?;

                // Every once in a while, we delete outdated, unresolved attachments instances
                network
                    .atlasdb
                    .evict_expired_unresolved_attachment_instances()?;

                // Update reliability reports
                for (peer_url, report) in context.peers.drain() {
                    self.reliability_reports.insert(peer_url, report);
                }

                // Re-insert AttachmentsBatch back to the queue if not fully processed
                if !context.attachments_batch.has_fully_succeed() {
                    context.attachments_batch.bump_retry_count();
                    // If max_attachment_retry_count not reached, we'll re-enqueue the batch
                    if context.attachments_batch.retry_count
                        < context.connection_options.max_attachment_retry_count
                    {
                        info!(
                            "Atlas: re-enqueuing batch {:?} for retry",
                            context.attachments_batch
                        );
                        self.priority_queue.push(context.attachments_batch.clone());
                    } else {
                        info!(
                            "Atlas: dropping batch {:?} retries count exceeded",
                            context.attachments_batch
                        );
                    }
                }
            }
            next_state => {
                self.ongoing_batch = Some(next_state);
            }
        };

        Ok((resolved_attachments, events_to_deregister))
    }

    /// Given a list of `AttachmentInstance`, check if the content corresponding to that
    ///  instance is (1) already validated (2) inboxed or (3) unknown.
    ///
    /// In the event of (1) or (2), `do_if_found` is invoked, and the attachment instance will
    ///  be returned (with the attachment data) in the result set. If the attachment was inboxed (case 2),
    ///  the attachment is marked as instantiated in the atlas db.
    ///
    /// In the event of (3), `do_if_not_found` is invoked, and the attachment instance is added
    ///  to `self.priority_queue`.
    ///
    /// The return value of this function is a vector of all the instances from `iterator` which
    ///  resolved to Attachment data, paired with that data.
    fn check_attachment_instances<F, G>(
        &mut self,
        atlas_db: &mut AtlasDB,
        iterator: Vec<AttachmentInstance>,
        do_if_found: F,
        do_if_not_found: G,
    ) -> Result<Vec<(AttachmentInstance, Attachment)>, DBError>
    where
        F: Fn(&mut AtlasDB, &AttachmentInstance) -> Result<(), DBError>,
        G: Fn(&mut AtlasDB, &AttachmentInstance) -> Result<(), DBError>,
    {
        let mut attachments_batches: HashMap<StacksBlockId, AttachmentsBatch> = HashMap::new();
        let mut resolved_attachments = vec![];
        for attachment_instance in iterator {
            if attachment_instance.content_hash == Hash160::empty() {
                // Are we dealing with an empty hash - allowed for undoing onchain binding
                do_if_found(atlas_db, &attachment_instance)?;
                debug!("Atlas: inserting and pairing new attachment instance with empty hash");
                resolved_attachments.push((attachment_instance, Attachment::empty()));
            } else if let Ok(Some(entry)) =
                atlas_db.find_attachment(&attachment_instance.content_hash)
            {
                // Do we already have a matching validated attachment
                do_if_found(atlas_db, &attachment_instance)?;
                debug!(
                    "Atlas: inserting and pairing new attachment instance to existing attachment"
                );
                resolved_attachments.push((attachment_instance, entry));
            } else if let Ok(Some(attachment)) =
                atlas_db.find_uninstantiated_attachment(&attachment_instance.content_hash)
            {
                // Do we already have a matching inboxed attachment
                atlas_db.insert_instantiated_attachment(&attachment)?;
                do_if_found(atlas_db, &attachment_instance)?;
                debug!("Atlas: inserting and pairing new attachment instance to inboxed attachment, now validated");
                resolved_attachments.push((attachment_instance, attachment));
            } else {
                // This attachment refers to an unknown attachment.
                // Let's append it to the batch being constructed in this routine.
                match attachments_batches.entry(attachment_instance.index_block_hash) {
                    Entry::Occupied(entry) => {
                        entry.into_mut().track_attachment(&attachment_instance);
                    }
                    Entry::Vacant(v) => {
                        let mut batch = AttachmentsBatch::new();
                        batch.track_attachment(&attachment_instance);
                        v.insert(batch);
                    }
                };

                do_if_not_found(atlas_db, &attachment_instance)?;
            }
        }

        for (_, batch) in attachments_batches.into_iter() {
            self.priority_queue.push(batch);
        }

        Ok(resolved_attachments)
    }

    /// Check any queued attachment instances to see if we already have data for them,
    ///  returning a vector of (instance, attachment) pairs for any of the queued attachments
    ///  which already had the associated data
    /// Marks any processed attachments as checked
    ///
    /// This method is invoked in the thread managing the AttachmentDownloader. This is currently
    ///  the P2P thread.
    pub fn check_queued_attachment_instances(
        &mut self,
        atlas_db: &mut AtlasDB,
    ) -> Result<Vec<(AttachmentInstance, Attachment)>, DBError> {
        let new_attachments = atlas_db.queued_attachments()?;

        self.check_attachment_instances(
            atlas_db,
            new_attachments,
            |atlas_db, attachment_instance| {
                atlas_db.mark_attachment_instance_checked(attachment_instance, true)
            },
            |atlas_db, attachment_instance| {
                atlas_db.mark_attachment_instance_checked(attachment_instance, false)
            },
        )
    }

    /// Insert the initial attachments set. Only add the attachment instance if associated data
    ///  was found.
    pub fn enqueue_initial_attachments(
        &mut self,
        atlas_db: &mut AtlasDB,
    ) -> Result<Vec<(AttachmentInstance, Attachment)>, DBError> {
        if self.initial_batch.is_empty() {
            return Ok(vec![]);
        }

        // we're draining the initial batch, so to avoid angering The Borrow Checker
        //  use mem replace to just take the whole vec.
        let initial_batch = std::mem::replace(&mut self.initial_batch, vec![]);

        self.check_attachment_instances(
            atlas_db,
            initial_batch,
            |atlas_db, attachment_instance| {
                atlas_db.insert_initial_attachment_instance(attachment_instance)
            },
            |_atlas_db, _attachment_instance| {
                // If attachment not found, don't insert attachment instance
                Ok(())
            },
        )
    }
}

#[derive(Debug)]
pub struct AttachmentsBatchStateContext {
    pub attachments_batch: AttachmentsBatch,
    pub peers: HashMap<UrlString, ReliabilityReport>,
    pub connection_options: ConnectionOptions,
    pub dns_lookups: HashMap<UrlString, Option<Vec<SocketAddr>>>,
    pub inventories: HashMap<
        (QualifiedContractIdentifier, Vec<u32>, StacksBlockId),
        HashMap<UrlString, GetAttachmentsInvResponse>,
    >,
    pub attachments: HashSet<Attachment>,
    pub events_to_deregister: Vec<usize>,
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
            events_to_deregister: vec![],
        }
    }

    pub fn get_peers_urls(&self) -> Vec<UrlString> {
        self.peers.keys().cloned().collect()
    }

    pub fn get_prioritized_attachments_inventory_requests(
        &self,
    ) -> BinaryHeap<AttachmentsInventoryRequest> {
        let mut queue = BinaryHeap::new();
        for (contract_id, _) in self.attachments_batch.attachments_instances.iter() {
            let pages_batches = self
                .attachments_batch
                .get_paginated_missing_pages_for_contract_id(contract_id);
            for (peer_url, reliability_report) in self.peers.iter() {
                for pages in pages_batches.iter() {
                    let request = AttachmentsInventoryRequest {
                        url: peer_url.clone(),
                        reliability_report: reliability_report.clone(),
                        contract_id: contract_id.clone(),
                        pages: pages.clone(),
                        stacks_block_height: self.attachments_batch.stacks_block_height,
                        index_block_hash: self.attachments_batch.index_block_hash,
                        canonical_stacks_tip_height: self
                            .attachments_batch
                            .canonical_stacks_tip_height,
                    };
                    queue.push(request);
                }
            }
        }
        queue
    }

    pub fn get_prioritized_attachments_requests(&self) -> BinaryHeap<AttachmentRequest> {
        let mut queue = BinaryHeap::new();
        let mut enqueued = HashSet::new();
        for ((contract_id, pages, _), peers_responses) in self.inventories.iter() {
            let missing_attachments = match self
                .attachments_batch
                .attachments_instances
                .get(contract_id)
            {
                None => continue,
                Some(missing_attachments) => missing_attachments,
            };
            // Note: we're getting missing_attachments (attachment_id: content_hash)
            for (attachment_index, content_hash) in missing_attachments.iter() {
                let page_index = attachment_index / AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
                // Since there's a limit in the number of pages that a node can request,
                // we can potentially have multiple inventory request at once.
                if !pages.contains(&page_index) {
                    continue;
                }

                if enqueued.contains(content_hash) {
                    debug!("Atlas: {} already enqueued", content_hash);
                    continue;
                }

                let mut sources = HashMap::new();
                let position_in_page =
                    attachment_index % AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;

                for (peer_url, response) in peers_responses.iter() {
                    // Considering the response, look for the page with the index
                    // we're looking for.
                    let index = response
                        .pages
                        .iter()
                        .position(|page| page.index == page_index);

                    let has_attachment = index
                        .and_then(|i| response.pages[i].inventory.get(position_in_page as usize))
                        .map(|result| *result == 1)
                        .unwrap_or(false);

                    if !has_attachment {
                        debug!(
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
                    stacks_block_height: self.attachments_batch.stacks_block_height,
                    canonical_stacks_tip_height: self.attachments_batch.canonical_stacks_tip_height,
                };
                enqueued.insert(content_hash);
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
        for (request, response) in results.succeeded.drain() {
            let report = self
                .peers
                .get_mut(request.get_url())
                .expect("Atlas: unable to retrieve reliability report for peer");

            let response = if let Some(r) = response {
                r
            } else {
                report.bump_failed_requests();
                continue;
            };

            if let Ok(response) = response.decode_atlas_attachments_inv_response() {
                let peer_url = request.get_url().clone();
                match self.inventories.entry(request.key()) {
                    Entry::Occupied(responses) => {
                        responses.into_mut().insert(peer_url, response);
                    }
                    Entry::Vacant(v) => {
                        let mut responses = HashMap::new();
                        responses.insert(peer_url, response);
                        v.insert(responses);
                    }
                };
                report.bump_successful_requests();
            } else {
                report.bump_failed_requests();
            }
        }
        let mut events_ids = results.faulty_peers.keys().copied().collect::<Vec<usize>>();
        self.events_to_deregister.append(&mut events_ids);

        self
    }

    pub fn extend_with_attachments(
        mut self,
        results: &mut BatchedRequestsResult<AttachmentRequest>,
    ) -> AttachmentsBatchStateContext {
        for (request, response) in results.succeeded.drain() {
            let report = self
                .peers
                .get_mut(request.get_url())
                .expect("Atlas: unable to retrieve reliability report for peer");

            let response = if let Some(r) = response {
                r
            } else {
                report.bump_failed_requests();
                continue;
            };

            if let Ok(response) = response.decode_atlas_get_attachment() {
                self.attachments.insert(response.attachment);
                report.bump_successful_requests();
            } else {
                report.bump_failed_requests();
            }
        }
        let mut events_ids = results.faulty_peers.keys().copied().collect::<Vec<usize>>();
        self.events_to_deregister.append(&mut events_ids);

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

    /// Runs the state machine one step. The machine transitions through the states sequentially:
    /// `Initialized`, `DNSLookup` (which invokes a sub state machine, `BatchedDNSLookupsState`),
    /// `DownloadingAttachmentsInv`, `DownloadingAttachment`, and `Done`.
    fn try_proceed(
        fsm: AttachmentsBatchStateMachine,
        dns_client: &mut DNSClient,
        network: &mut PeerNetwork,
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

/// State machine for doing DNS lookups for a list of URLs. The machine progresses linearly through
/// the states, and advances through calls to `try_proceed`.
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
                    if url_str.is_empty() {
                        continue;
                    }
                    let url = match url_str.parse_to_block_url() {
                        Ok(url) => url,
                        Err(e) => {
                            warn!("Atlas: Unsupported URL {:?}, {}", url_str, e);
                            state.errors.insert(url_str, e.into());
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
                                domain,
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
                let mut completed_lookups = Vec::new();
                for (url_str, request) in state.parsed_urls.iter() {
                    match dns_client.poll_lookup(&request.host, request.port) {
                        Ok(Some(query_result)) => {
                            if let Some(dns_result) = state.dns_lookups.get_mut(url_str) {
                                // solicited
                                match query_result.result {
                                    Ok(addrs) => {
                                        *dns_result = Some(addrs);
                                        completed_lookups.push(url_str.clone());
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

                // Remove urls that have successfully been looked up by the DNS client.
                // If not removed, `poll_lookup` will return an error in successive calls of this
                // function, when trying to process remaining inflight requests.
                for url_str in completed_lookups.iter() {
                    state
                        .parsed_urls
                        .remove(url_str)
                        .expect("BUG: had key but then didn't");
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
        connection_options: &ConnectionOptions,
    ) -> BatchedRequestsState<T> {
        let mut fsm = fsm;

        match fsm {
            BatchedRequestsState::BeginRequests(ref mut queue, ref mut results) => {
                let mut queue = match queue.take() {
                    Some(queue) => queue,
                    None => unreachable!(),
                };
                let mut results = match results.take() {
                    Some(results) => results,
                    None => BatchedRequestsResult::new(HashMap::new()),
                };

                // We want to limit the number of requests in flight,
                // so we will be batching our requests.
                for _ in 0..connection_options.max_inflight_attachments {
                    if let Some(requestable) = queue.pop() {
                        let mut requestables = VecDeque::new();
                        requestables.push_back(requestable);
                        let res =
                            PeerNetwork::begin_request(network, dns_lookups, &mut requestables);
                        if let Some((request, event_id)) = res {
                            results.remaining.insert(event_id, request);
                        }
                    }
                }

                BatchedRequestsState::PollRequests(Some(queue), Some(results))
            }
            BatchedRequestsState::PollRequests(ref mut queue, ref mut results) => {
                let mut pending_requests = HashMap::new();

                let state = match results {
                    Some(state) => state,
                    None => unreachable!(),
                };
                debug!(
                    "Atlas: will poll {} remaining requests",
                    state.remaining.len()
                );

                PeerNetwork::with_http(network, |_, ref mut http| {
                    for (event_id, request) in state.remaining.drain() {
                        match http.get_conversation(event_id) {
                            None => {
                                if http.is_connecting(event_id) {
                                    debug!(
                                        "Atlas: Request {} (event_id: {}) is still connecting",
                                        request, event_id
                                    );
                                    pending_requests.insert(event_id, request);
                                } else {
                                    debug!(
                                        "Atlas: Request {} (event_id: {}) failed to connect. Temporarily blocking URL",
                                        request,
                                        event_id
                                    );
                                    let peer_url = request.get_url().clone();
                                    state.faulty_peers.insert(event_id, peer_url);
                                }
                            }
                            Some(ref mut convo) => {
                                match convo.try_get_response() {
                                    None => {
                                        // still waiting
                                        debug!(
                                            "Atlas: Request {} (event_id: {}) is still waiting for a response",
                                            request,
                                            event_id
                                        );
                                        pending_requests.insert(event_id, request);
                                        continue;
                                    }
                                    Some(response) => {
                                        let peer_url = request.get_url().clone();
                                        if response.preamble().status_code == 404 {
                                            state.faulty_peers.insert(event_id, peer_url);
                                            continue;
                                        }
                                        debug!(
                                            "Atlas: Request {} (event_id: {}) received HTTP 200",
                                            request, event_id
                                        );
                                        state.succeeded.insert(request, Some(response));
                                    }
                                }
                            }
                        }
                    }
                });

                if !pending_requests.is_empty() {
                    // We need to keep polling
                    for (event_id, request) in pending_requests.drain() {
                        state.remaining.insert(event_id, request);
                    }
                    return fsm;
                }
                debug!(
                    "Atlas: Processed request batch ({} success, {} faults)",
                    state.succeeded.len(),
                    state.faulty_peers.len()
                );

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
    pub succeeded: HashMap<T, Option<StacksHttpResponse>>,
    pub errors: HashMap<T, net_error>,
    pub faulty_peers: HashMap<usize, UrlString>,
}

impl<T: Requestable> BatchedRequestsResult<T> {
    pub fn new(remaining: HashMap<usize, T>) -> BatchedRequestsResult<T> {
        BatchedRequestsResult {
            remaining,
            succeeded: HashMap::new(),
            errors: HashMap::new(),
            faulty_peers: HashMap::new(),
        }
    }

    pub fn empty() -> BatchedRequestsResult<T> {
        BatchedRequestsResult {
            remaining: HashMap::new(),
            succeeded: HashMap::new(),
            errors: HashMap::new(),
            faulty_peers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttachmentsInventoryRequest {
    pub url: UrlString,
    pub contract_id: QualifiedContractIdentifier,
    pub pages: Vec<u32>,
    pub stacks_block_height: u64,
    pub index_block_hash: StacksBlockId,
    pub reliability_report: ReliabilityReport,
    pub canonical_stacks_tip_height: Option<u64>,
}

impl Hash for AttachmentsInventoryRequest {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.contract_id.hash(state);
        self.pages.hash(state);
        self.index_block_hash.hash(state);
        self.stacks_block_height.hash(state);
    }
}

impl AttachmentsInventoryRequest {
    pub fn key(&self) -> (QualifiedContractIdentifier, Vec<u32>, StacksBlockId) {
        (
            self.contract_id.clone(),
            self.pages.clone(),
            self.index_block_hash.clone(),
        )
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

    fn make_request_type(&self, peer_host: PeerHost) -> StacksHttpRequest {
        let mut page_indexes = HashSet::new();
        for page in self.pages.iter() {
            page_indexes.insert(*page);
        }
        let mut page_list: Vec<String> = page_indexes
            .into_iter()
            .map(|i| format!("{}", &i))
            .collect();
        page_list.sort();
        StacksHttpRequest::new_for_peer(
            peer_host,
            "GET".into(),
            "/v2/attachments/inv".into(),
            HttpRequestContents::new()
                .query_arg(
                    "index_block_hash".into(),
                    format!("{}", &self.index_block_hash),
                )
                .query_arg("pages_indexes".into(), page_list[..].join(",")),
        )
        .expect("FATAL: failed to create an HTTP request for infallible data")
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
    pub stacks_block_height: u64,
    pub canonical_stacks_tip_height: Option<u64>,
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
            report.cmp(other_report)
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

    fn make_request_type(&self, peer_host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            peer_host,
            "GET".to_string(),
            format!("/v2/attachments/{}", &self.content_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to create an HTTP request for infallible data")
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
    pub stacks_block_height: u64,
    pub canonical_stacks_tip_height: Option<u64>,
    pub index_block_hash: StacksBlockId,
    pub attachments_instances: HashMap<QualifiedContractIdentifier, HashMap<u32, Hash160>>,
    pub retry_count: u64,
    pub retry_deadline: u64,
}

impl AttachmentsBatch {
    pub fn new() -> AttachmentsBatch {
        AttachmentsBatch {
            stacks_block_height: 0,
            canonical_stacks_tip_height: None,
            index_block_hash: StacksBlockId([0u8; 32]),
            attachments_instances: HashMap::new(),
            retry_count: 0,
            retry_deadline: 0,
        }
    }

    pub fn track_attachment(&mut self, attachment: &AttachmentInstance) {
        if self.attachments_instances.is_empty() {
            self.stacks_block_height = attachment.stacks_block_height.clone();
            self.index_block_hash = attachment.index_block_hash.clone();
            self.canonical_stacks_tip_height = attachment.canonical_stacks_tip_height;
        } else if self.stacks_block_height != attachment.stacks_block_height
            || self.index_block_hash != attachment.index_block_hash
        {
            warn!(
                "Atlas: attempt to add unrelated AttachmentInstance ({}, {}) to AttachmentsBatch",
                attachment.attachment_index, attachment.index_block_hash
            );
            return;
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
        let delay = cmp::min(
            MAX_RETRY_DELAY,
            2u64.saturating_pow(self.retry_count as u32).saturating_add(
                thread_rng().gen::<u64>() % 2u64.saturating_pow((self.retry_count - 1) as u32),
            ),
        );

        debug!("Atlas: Re-attempt download in {} seconds", delay);
        self.retry_deadline = get_epoch_time_secs() + delay;
    }

    pub fn has_fully_succeed(&self) -> bool {
        self.attachments_instances_count() == 0
    }

    pub fn get_missing_pages_for_contract_id(
        &self,
        contract_id: &QualifiedContractIdentifier,
    ) -> Vec<u32> {
        let mut pages_indexes = HashSet::new();
        if let Some(missing_attachments) = self.attachments_instances.get(contract_id) {
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
        let mut pages_indexes = self.get_missing_pages_for_contract_id(contract_id);
        pages_indexes.sort();
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

    pub fn attachments_instances_count(&self) -> usize {
        self.attachments_instances
            .values()
            .fold(0, |count, a| count + a.len())
    }
}

impl Ord for AttachmentsBatch {
    fn cmp(&self, other: &AttachmentsBatch) -> Ordering {
        other
            .retry_deadline
            .cmp(&self.retry_deadline)
            .then_with(|| {
                self.attachments_instances_count()
                    .cmp(&other.attachments_instances_count())
            })
            .then_with(|| other.stacks_block_height.cmp(&self.stacks_block_height))
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
        let n = self.total_requests_sent;
        if n == 0 {
            return n;
        }
        self.total_requests_success * 1000 / (n * 1000) + n
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
