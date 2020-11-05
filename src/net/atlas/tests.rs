use super::download::{AttachmentsBatch, AttachmentRequest, AttachmentsInventoryRequest, ReliabilityReport};
use super::{AttachmentInstance, Attachment};

use chainstate::burn::{BlockHeaderHash, ConsensusHash};
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::{StacksBlockHeader, StacksBlockId};
use vm::types::QualifiedContractIdentifier;
use vm::representations::UrlString;
use util::hash::Hash160;

use std::collections::{BinaryHeap, HashMap};
use std::convert::TryFrom;

fn new_attachment_from(content: &str) -> Attachment {
    Attachment {
        hash: Hash160::from_data(&content.as_bytes()),
        content: content.as_bytes().to_vec(),
    }
}

fn new_attachment_instance_from(attachment: &Attachment, position_in_page: u32, page_index: u32, block_height: u64) -> AttachmentInstance {
    AttachmentInstance {
        content_hash: attachment.hash.clone(),
        page_index,
        position_in_page,
        block_height,
        consensus_hash: ConsensusHash::empty(),
        metadata: "".to_string(),
        contract_id: QualifiedContractIdentifier::transient(),
        block_header_hash: BlockHeaderHash([0x00; 32]),
    }
}

fn new_attachments_batch_from(attachment_instances: Vec<AttachmentInstance>, retry_count: u32) -> AttachmentsBatch {
    let mut attachments_batch = AttachmentsBatch::new();
    for attachment_instance in attachment_instances.iter() {
        attachments_batch.track_attachment_instance(&attachment_instance);
    }
    for _ in 0..retry_count {
        attachments_batch.bump_retry_count();
    }
    attachments_batch
}

fn new_attachment_request(sources: Vec<(&str, u32, u32)>, content_hash: &Hash160) -> AttachmentRequest {
    let sources = {
        let mut s = HashMap::new();
        for (url, req_sent, req_success) in sources {
            let url = UrlString::try_from(format!("{}", url).as_str()).unwrap();
            s.insert(url, ReliabilityReport::new(req_sent, req_success));
        }
        s
    };
    AttachmentRequest {
        sources,
        content_hash: content_hash.clone(),
    }
}

fn new_attachments_inventory_request(url: &str, pages: Vec<u32>, block_height: u64, req_sent: u32, req_success: u32) -> AttachmentsInventoryRequest {
    let url = UrlString::try_from(format!("{}", url).as_str()).unwrap();
    AttachmentsInventoryRequest {
        url,
        block_height,
        pages,
        contract_id: QualifiedContractIdentifier::transient(),
        consensus_hash: ConsensusHash::empty(),
        block_header_hash: BlockHeaderHash([0x00; 32]),
        reliability_report: ReliabilityReport::new(req_sent, req_success),
    }
}

#[test]
fn test_attachments_batch_constructs() {
}

#[test]
fn test_attachments_batch_ordering() {
    // Ensuring that when batches are being queued, we are correctly dequeueing, based on the following priorities:
    // 1) the batch that has been the least retried,
    // 2) if tie, the batch that will lead to the maximum number of downloads,
    // 3) if tie, the most oldest batch

    // Batch 1: 4 attachments, never tried, emitted at block #1
    let attachments_batch_1 = new_attachments_batch_from(vec![
        new_attachment_instance_from(&new_attachment_from("facade01"), 1, 1, 1),
        new_attachment_instance_from(&new_attachment_from("facade02"), 2, 1, 1),
        new_attachment_instance_from(&new_attachment_from("facade03"), 3, 1, 1),
        new_attachment_instance_from(&new_attachment_from("facade04"), 4, 1, 1),
    ], 0);

    // Batch 2: 5 attachments, never tried, emitted at block #2
    let attachments_batch_2 = new_attachments_batch_from(vec![
        new_attachment_instance_from(&new_attachment_from("facade11"), 1, 1, 2),
        new_attachment_instance_from(&new_attachment_from("facade12"), 2, 1, 2),
        new_attachment_instance_from(&new_attachment_from("facade13"), 3, 1, 2),
        new_attachment_instance_from(&new_attachment_from("facade14"), 4, 1, 2),
        new_attachment_instance_from(&new_attachment_from("facade15"), 5, 1, 2),
    ], 0);

    // Batch 3: 4 attachments, tried once, emitted at block #3
    let attachments_batch_3 = new_attachments_batch_from(vec![
        new_attachment_instance_from(&new_attachment_from("facade21"), 1, 2, 3),
        new_attachment_instance_from(&new_attachment_from("facade22"), 2, 2, 3),
        new_attachment_instance_from(&new_attachment_from("facade23"), 3, 2, 3),
        new_attachment_instance_from(&new_attachment_from("facade24"), 4, 2, 3),
    ], 1);

    // Batch 1: 4 attachments, never tried, emitted at block #4
    let attachments_batch_4 = new_attachments_batch_from(vec![
        new_attachment_instance_from(&new_attachment_from("facade31"), 1, 3, 4),
        new_attachment_instance_from(&new_attachment_from("facade32"), 2, 3, 4),
        new_attachment_instance_from(&new_attachment_from("facade33"), 3, 3, 4),
        new_attachment_instance_from(&new_attachment_from("facade34"), 4, 3, 4),
    ], 0);

    let mut priority_queue = BinaryHeap::new();
    priority_queue.push(attachments_batch_1.clone());
    priority_queue.push(attachments_batch_2.clone());
    priority_queue.push(attachments_batch_3.clone());
    priority_queue.push(attachments_batch_4.clone());

    // According to the rules above, the expected order is: 
    // 1) Batch 2 (tie on retry count with 1 and 4 -> attachments count)
    // 2) Batch 1 (tie on retry count with 4 -> tie on attachments count 4 -> block height)
    // 3) Batch 4 (retry count)
    // 4) Batch 3
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_2);
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_1);
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_4);
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_3);
}

#[test]
fn test_attachments_inventory_requests_ordering() {
    // Ensuring that when we're flooding a set of peers with GetAttachmentsInventory requests, the order is based on the following rules:
    // 1) Nodes with highest ratio successful requests / total requests
    // 2) if tie, biggest number of total requests
    let attachments_inventory_1_request = new_attachments_inventory_request(
        "http://localhost:20443", vec![0, 1], 1, 0, 0);

    let attachments_inventory_2_request = new_attachments_inventory_request(
        "http://localhost:30443", vec![0, 1], 1, 2, 1);
    
    let attachments_inventory_3_request = new_attachments_inventory_request(
        "http://localhost:40443", vec![0, 1], 1, 2, 2);
    
    let attachments_inventory_4_request = new_attachments_inventory_request(
        "http://localhost:50443", vec![0, 1], 1, 4, 4);
    
    let mut priority_queue = BinaryHeap::new();
    priority_queue.push(attachments_inventory_2_request.clone());
    priority_queue.push(attachments_inventory_1_request.clone());
    priority_queue.push(attachments_inventory_4_request.clone());
    priority_queue.push(attachments_inventory_3_request.clone());

    // According to the rules above, the expected order is: 
    // 1) Request 4
    // 2) Request 3
    // 2) Request 2
    // 3) Request 1
    assert_eq!(priority_queue.pop().unwrap(), attachments_inventory_4_request);
    assert_eq!(priority_queue.pop().unwrap(), attachments_inventory_3_request);
    assert_eq!(priority_queue.pop().unwrap(), attachments_inventory_2_request);
    assert_eq!(priority_queue.pop().unwrap(), attachments_inventory_1_request);
}

#[test]
fn test_attachment_requests_ordering() {
    // Ensuring that when we're downloading some attachments, the order is based on the following rules:
    // 1) attachments that are the least available
    // 2) if tie, starting with the most reliable peer
    let attachment_1 = new_attachment_from("facade01");
    let attachment_2 = new_attachment_from("facade02");
    let attachment_3 = new_attachment_from("facade03");
    let attachment_4 = new_attachment_from("facade04");

    let attachment_1_request = new_attachment_request(vec![
        ("http://localhost:20443", 2, 2), 
        ("http://localhost:40443", 0, 1)], 
        &attachment_1.hash);

    let attachment_2_request = new_attachment_request(vec![
        ("http://localhost:20443", 2, 2), 
        ("http://localhost:40443", 0, 1), 
        ("http://localhost:30443", 0, 1)], 
        &attachment_2.hash);

    let attachment_3_request = new_attachment_request(vec![
        ("http://localhost:30443", 0, 1)], 
        &attachment_3.hash);

    let attachment_4_request = new_attachment_request(vec![
        ("http://localhost:50443", 4, 4)], 
        &attachment_4.hash);
    
    let mut priority_queue = BinaryHeap::new();
    priority_queue.push(attachment_1_request.clone());
    priority_queue.push(attachment_3_request.clone());
    priority_queue.push(attachment_4_request.clone());
    priority_queue.push(attachment_2_request.clone());

    // According to the rules above, the expected order is:
    // 1) Request 4
    // 2) Request 3
    // 3) Request 1
    // 4) Request 2
    assert_eq!(priority_queue.pop().unwrap(), attachment_4_request);
    assert_eq!(priority_queue.pop().unwrap(), attachment_3_request);
    assert_eq!(priority_queue.pop().unwrap(), attachment_1_request);
    assert_eq!(priority_queue.pop().unwrap(), attachment_2_request);
}

#[test]
fn test_downloader_dns_state_machine() {
}

#[test]
fn test_downloader_batched_requests_state_machine() {
}

// todo(ludo): write tests around the fact that one hash can exist multiple inside the same fork as well.

