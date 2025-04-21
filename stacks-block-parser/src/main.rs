use anyhow::Result;
use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::{StacksTransaction, TransactionAnchorMode, TransactionPostConditionMode};
use blockstack_lib::types::chainstate::TrieHash;
use blockstack_lib::codec::{read_next, MAX_MESSAGE_LEN, StacksMessageCodec};
use serde_json::{json, Value};
use stacks_common::util::retry::BoundReader;
use stacks_common::bitvec::BitVec;
use std::io::Cursor;

fn bytes_to_json<T: AsRef<[u8]>>(bytes: T) -> Value {
    let bytes = bytes.as_ref();
    if bytes.len() == 1 {
        Value::Number(bytes[0].into())
    } else {
        Value::String(hex::encode(bytes))
    }
}

fn bitvec_to_json<const MAX_SIZE: u16>(bits: &BitVec<MAX_SIZE>) -> Value {
    let mut bytes = vec![0u8; ((bits.len() + 7) / 8) as usize];
    for (i, bit) in bits.iter().enumerate() {
        if bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    Value::String(hex::encode(bytes))
}

fn anchor_mode_to_number(mode: TransactionAnchorMode) -> u8 {
    match mode {
        TransactionAnchorMode::OnChainOnly => 1,
        TransactionAnchorMode::OffChainOnly => 2,
        TransactionAnchorMode::Any => 3,
    }
}

fn post_condition_mode_to_number(mode: TransactionPostConditionMode) -> u8 {
    match mode {
        TransactionPostConditionMode::Allow => 1,
        TransactionPostConditionMode::Deny => 2,
    }
}

fn main() -> Result<()> {
    // Fetch the block data
    let url = "https://stacks-node-api.mainnet.stacks.co/v3/blocks/height/999129";
    let response = reqwest::blocking::get(url)?;
    let block_bytes = response.bytes()?;

    // Parse the block
    let mut cursor = Cursor::new(block_bytes);
    let (header, txs) = {
        let mut bound_read = BoundReader::from_reader(&mut cursor, u64::from(MAX_MESSAGE_LEN));
        let header: NakamotoBlockHeader = read_next(&mut bound_read)?;
        let txs: Vec<StacksTransaction> = read_next(&mut bound_read)?;
        (header, txs)
    };

    // Create JSON output
    let output = json!({
        "block_header": {
            "version": header.version,
            "chain_length": header.chain_length,
            "burn_spent": header.burn_spent,
            "consensus_hash": bytes_to_json(header.consensus_hash.as_bytes()),
            "parent_block_id": bytes_to_json(header.parent_block_id.as_bytes()),
            "tx_merkle_root": bytes_to_json(header.tx_merkle_root.as_bytes()),
            "state_index_root": bytes_to_json(header.state_index_root.as_bytes()),
            "timestamp": header.timestamp,
            "miner_signature": bytes_to_json(header.miner_signature.as_bytes()),
            "signer_signatures": header.signer_signature.iter().map(|sig| bytes_to_json(sig.as_bytes())).collect::<Vec<Value>>(),
            "pox_treatment": bitvec_to_json(&header.pox_treatment)
        },
        "transactions": txs.iter().map(|tx| {
            json!({
                "version": tx.version as u64,
                "chain_id": tx.chain_id,
                "anchor_mode": anchor_mode_to_number(tx.anchor_mode),
                "post_condition_mode": post_condition_mode_to_number(tx.post_condition_mode),
                "post_conditions": tx.post_conditions.iter().map(|pc| bytes_to_json(pc.serialize_to_vec())).collect::<Vec<Value>>(),
                "payload": bytes_to_json(tx.payload.serialize_to_vec()),
                "auth": bytes_to_json(tx.auth.serialize_to_vec())
            })
        }).collect::<Vec<Value>>()
    });

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}
