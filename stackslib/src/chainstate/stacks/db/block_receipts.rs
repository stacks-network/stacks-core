// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::io::{Result, Write};

use clarity::vm::{costs::ExecutionCost, events::StacksTransactionEvent};
use stacks_common::codec::StacksMessageCodec;

use crate::chainstate::stacks::{
    events::{StacksTransactionReceipt, TransactionOrigin},
    StacksBlockHeader, StacksMicroblockHeader, StacksTransaction,
};

use super::{accounts::MinerReward, MinerRewardInfo, StacksEpochReceipt, StacksHeaderInfo};

fn serialize_option<T, F>(w: &mut dyn Write, item: &Option<T>, mut item_serialize: F) -> Result<()>
where
    F: FnMut(&mut dyn Write, &T) -> Result<()>,
{
    match item {
        Some(ref t) => {
            w.write(&1u8.to_be_bytes())?;
            item_serialize(w, t)?;
        }
        None => {
            w.write(&0u8.to_be_bytes())?;
        }
    }
    Ok(())
}

fn serialize_vec<T, F>(w: &mut dyn Write, list: &Vec<T>, mut item_serialize: F) -> Result<()>
where
    F: FnMut(&mut dyn Write, &T) -> Result<()>,
{
    w.write(&list.len().to_be_bytes())?;
    for item in list.iter() {
        item_serialize(w, item)?;
    }
    Ok(())
}

fn serialize_str(w: &mut dyn Write, s: &str) -> Result<()> {
    let buf = s.as_bytes();
    w.write(&buf.len().to_be_bytes())?;
    w.write(buf)?;
    Ok(())
}

fn serialize_string(w: &mut dyn Write, s: &String) -> Result<()> {
    serialize_str(w, s)
}

fn serialize_bool(w: &mut dyn Write, b: bool) -> Result<()> {
    w.write(&[if b { 1u8 } else { 0u8 }])?;
    Ok(())
}

/// Reuse serde_json serialization if necessary
fn serialize_as_json<T>(w: &mut dyn Write, value: &T) -> Result<()>
where
    T: serde::ser::Serialize,
{
    let json = serde_json::to_string(value)?;
    serialize_str(w, &json)?;
    Ok(())
}

/// Reuse StacksMessageCodec implementation when possible
fn serialize_stacks_message<T>(w: &mut dyn Write, value: &T) -> Result<()>
where
    T: StacksMessageCodec,
{
    let buf = value.serialize_to_vec();
    let buf = buf.as_slice();
    w.write(&buf.len().to_be_bytes())?;
    w.write(buf)?;
    Ok(())
}

fn serialize_microblock_header(
    w: &mut dyn Write,
    microblock_header: &StacksMicroblockHeader,
) -> Result<()> {
    w.write(&microblock_header.version.to_be_bytes())?;
    w.write(&microblock_header.sequence.to_be_bytes())?;
    w.write(microblock_header.prev_block.as_bytes())?;
    w.write(microblock_header.tx_merkle_root.as_bytes())?;
    w.write(microblock_header.signature.as_bytes())?;
    Ok(())
}

fn serialize_block_header(w: &mut dyn Write, block_header: &StacksBlockHeader) -> Result<()> {
    w.write(&block_header.version.to_be_bytes())?;
    w.write(&block_header.total_work.burn.to_be_bytes())?;
    w.write(&block_header.total_work.work.to_be_bytes())?;
    w.write(&block_header.proof.to_bytes())?;
    w.write(block_header.parent_block.as_bytes())?;
    w.write(block_header.parent_microblock.as_bytes())?;
    w.write(&block_header.parent_microblock_sequence.to_be_bytes())?;
    w.write(block_header.tx_merkle_root.as_bytes())?;
    w.write(block_header.state_index_root.as_bytes())?;
    w.write(block_header.microblock_pubkey_hash.as_bytes())?;
    Ok(())
}

fn serialize_header_info(w: &mut dyn Write, header: &StacksHeaderInfo) -> Result<()> {
    serialize_block_header(w, &header.anchored_header)?;
    serialize_option(w, &header.microblock_tail, serialize_microblock_header)?;
    w.write(&header.stacks_block_height.to_be_bytes())?;
    w.write(header.index_root.as_bytes())?;
    w.write(header.consensus_hash.as_bytes())?;
    w.write(header.burn_header_hash.as_bytes())?;
    w.write(&header.burn_header_height.to_be_bytes())?;
    w.write(&header.burn_header_timestamp.to_be_bytes())?;
    w.write(&header.anchored_block_size.to_be_bytes())?;
    Ok(())
}

fn serialize_execution_cost(w: &mut dyn Write, item: &ExecutionCost) -> Result<()> {
    w.write(&item.write_length.to_be_bytes())?;
    w.write(&item.write_count.to_be_bytes())?;
    w.write(&item.read_length.to_be_bytes())?;
    w.write(&item.read_count.to_be_bytes())?;
    w.write(&item.runtime.to_be_bytes())?;
    Ok(())
}

fn serialize_miner_reward(w: &mut dyn Write, item: &MinerReward) -> Result<()> {
    serialize_stacks_message(w, &item.address)?;
    serialize_stacks_message(w, &item.recipient)?;
    w.write(&item.coinbase.to_be_bytes())?;
    w.write(&item.tx_fees_anchored.to_be_bytes())?;
    w.write(&item.tx_fees_streamed_produced.to_be_bytes())?;
    w.write(&item.tx_fees_streamed_confirmed.to_be_bytes())?;
    w.write(&item.vtxindex.to_be_bytes())?;
    Ok(())
}

fn serialize_miner_reward_info(w: &mut dyn Write, item: &MinerRewardInfo) -> Result<()> {
    w.write(item.from_block_consensus_hash.as_bytes())?;
    w.write(item.from_stacks_block_hash.as_bytes())?;
    w.write(item.from_parent_block_consensus_hash.as_bytes())?;
    w.write(item.from_parent_stacks_block_hash.as_bytes())?;
    Ok(())
}

fn serialize_tx_receipt(w: &mut dyn Write, tx_receipt: &StacksTransactionReceipt) -> Result<()> {
    match tx_receipt.transaction {
        TransactionOrigin::Stacks(ref tx) => {
            w.write(&0u8.to_be_bytes())?;
            serialize_stacks_message(w, tx)?;
        }
        TransactionOrigin::Burn(ref burnchain_tx) => {
            w.write(&1u8.to_be_bytes())?;
            serialize_as_json(w, burnchain_tx)?;
        }
    }
    w.write(&tx_receipt.events.len().to_be_bytes())?;
    for i in 0..tx_receipt.events.len() {
        let tx_event = &tx_receipt.events[i];
        let value = tx_event.json_serialize(i, &tx_receipt.transaction.txid(), true);
        serialize_as_json(w, &value)?;
    }
    serialize_bool(w, tx_receipt.post_condition_aborted)?;
    serialize_as_json(w, &tx_receipt.result)?;
    w.write(&tx_receipt.stx_burned.to_be_bytes())?;
    serialize_option(w, &tx_receipt.contract_analysis, serialize_as_json)?;
    serialize_execution_cost(w, &tx_receipt.execution_cost)?;
    serialize_option(
        w,
        &tx_receipt.microblock_header,
        serialize_microblock_header,
    )?;
    w.write(&tx_receipt.tx_index.to_be_bytes())?;
    serialize_option(w, &tx_receipt.vm_error, serialize_string)?;
    Ok(())
}

/// Serialize block receipt into binary format and write it to a Writer
pub fn serialize_block_receipt(
    w: &mut dyn Write,
    block_receipt: &StacksEpochReceipt,
) -> Result<()> {
    serialize_header_info(w, &block_receipt.header)?;
    serialize_vec(w, &block_receipt.tx_receipts, serialize_tx_receipt)?;
    serialize_vec(w, &block_receipt.matured_rewards, serialize_miner_reward)?;
    serialize_option(
        w,
        &block_receipt.matured_rewards_info,
        serialize_miner_reward_info,
    )?;
    serialize_execution_cost(w, &block_receipt.parent_microblocks_cost)?;
    serialize_execution_cost(w, &block_receipt.anchored_block_cost)?;
    w.write(block_receipt.parent_burn_block_hash.as_bytes())?;
    w.write(&block_receipt.parent_burn_block_height.to_be_bytes())?;
    w.write(&block_receipt.parent_burn_block_timestamp.to_be_bytes())?;
    w.write(&(block_receipt.evaluated_epoch as u32).to_be_bytes())?;
    serialize_bool(w, block_receipt.epoch_transition)?;
    Ok(())
}
