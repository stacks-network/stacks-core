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

use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::StacksPrivateKey;

use crate::chainstate::stacks::db::blocks::test::*;
use crate::chainstate::stacks::db::test::instantiate_chainstate;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as chainstate_error;
use crate::chainstate::stacks::StacksBlock;
use crate::chainstate::stacks::StacksBlockHeader;
use crate::chainstate::stacks::StacksMicroblock;
use crate::core::MemPoolDB;
use crate::net::ExtendedStacksHeader;
use crate::net::StreamCursor;
use crate::util_lib::db::DBConn;

fn stream_one_header_to_vec(
    blocks_conn: &DBConn,
    blocks_path: &str,
    stream: &mut StreamCursor,
    count: u64,
) -> Result<Vec<u8>, chainstate_error> {
    if let StreamCursor::Headers(ref mut stream) = stream {
        let mut bytes = vec![];
        StacksChainState::stream_one_header(blocks_conn, blocks_path, &mut bytes, stream, count)
            .map(|nr| {
                assert_eq!(bytes.len(), nr as usize);

                // truncate trailing ',' if it exists
                let len = bytes.len();
                if len > 0 {
                    if bytes[len - 1] == ',' as u8 {
                        let _ = bytes.pop();
                    }
                }
                bytes
            })
    } else {
        panic!("not a header stream");
    }
}

fn stream_one_staging_microblock_to_vec(
    blocks_conn: &DBConn,
    stream: &mut StreamCursor,
    count: u64,
) -> Result<Vec<u8>, chainstate_error> {
    if let StreamCursor::Microblocks(ref mut stream) = stream {
        let mut bytes = vec![];
        StacksChainState::stream_one_microblock(blocks_conn, &mut bytes, stream, count).map(|nr| {
            assert_eq!(bytes.len(), nr as usize);
            bytes
        })
    } else {
        panic!("not a microblock stream");
    }
}

fn stream_chunk_to_vec(
    blocks_path: &str,
    stream: &mut StreamCursor,
    count: u64,
) -> Result<Vec<u8>, chainstate_error> {
    if let StreamCursor::Block(ref mut stream) = stream {
        let mut bytes = vec![];
        StacksChainState::stream_data_from_chunk_store(blocks_path, &mut bytes, stream, count).map(
            |nr| {
                assert_eq!(bytes.len(), nr as usize);
                bytes
            },
        )
    } else {
        panic!("not a block stream");
    }
}

fn stream_headers_to_vec(
    chainstate: &mut StacksChainState,
    stream: &mut StreamCursor,
    count: u64,
) -> Result<Vec<u8>, chainstate_error> {
    let mempool = MemPoolDB::open_test(
        chainstate.mainnet,
        chainstate.chain_id,
        &chainstate.root_path,
    )
    .unwrap();
    let mut bytes = vec![];
    stream
        .stream_to(&mempool, chainstate, &mut bytes, count)
        .map(|nr| {
            assert_eq!(bytes.len(), nr as usize);
            bytes
        })
}

fn stream_unconfirmed_microblocks_to_vec(
    chainstate: &mut StacksChainState,
    stream: &mut StreamCursor,
    count: u64,
) -> Result<Vec<u8>, chainstate_error> {
    let mempool = MemPoolDB::open_test(
        chainstate.mainnet,
        chainstate.chain_id,
        &chainstate.root_path,
    )
    .unwrap();
    let mut bytes = vec![];
    stream
        .stream_to(&mempool, chainstate, &mut bytes, count)
        .map(|nr| {
            assert_eq!(bytes.len(), nr as usize);
            bytes
        })
}

fn stream_confirmed_microblocks_to_vec(
    chainstate: &mut StacksChainState,
    stream: &mut StreamCursor,
    count: u64,
) -> Result<Vec<u8>, chainstate_error> {
    let mempool = MemPoolDB::open_test(
        chainstate.mainnet,
        chainstate.chain_id,
        &chainstate.root_path,
    )
    .unwrap();
    let mut bytes = vec![];
    stream
        .stream_to(&mempool, chainstate, &mut bytes, count)
        .map(|nr| {
            assert_eq!(bytes.len(), nr as usize);
            bytes
        })
}

#[test]
fn stacks_db_stream_blocks() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let privk = StacksPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let block = make_16k_block(&privk);

    let consensus_hash = ConsensusHash([2u8; 20]);
    let parent_consensus_hash = ConsensusHash([1u8; 20]);
    let index_block_header =
        StacksBlockHeader::make_index_block_hash(&consensus_hash, &block.block_hash());

    // can't stream a non-existant block
    let mut stream = StreamCursor::new_block(index_block_header.clone());
    assert!(stream_chunk_to_vec(&chainstate.blocks_path, &mut stream, 123).is_err());

    // stream unmodified
    let stream_2 = StreamCursor::new_block(index_block_header.clone());
    assert_eq!(stream, stream_2);

    // store block to staging
    store_staging_block(
        &mut chainstate,
        &consensus_hash,
        &block,
        &parent_consensus_hash,
        1,
        2,
    );

    // stream it back
    let mut all_block_bytes = vec![];
    loop {
        let mut next_bytes = stream_chunk_to_vec(&chainstate.blocks_path, &mut stream, 16).unwrap();
        if next_bytes.len() == 0 {
            break;
        }
        test_debug!(
            "Got {} more bytes from staging; add to {} total",
            next_bytes.len(),
            all_block_bytes.len()
        );
        all_block_bytes.append(&mut next_bytes);
    }

    // should decode back into the block
    let staging_block = StacksBlock::consensus_deserialize(&mut &all_block_bytes[..]).unwrap();
    assert_eq!(staging_block, block);

    // accept it
    set_block_processed(&mut chainstate, &consensus_hash, &block.block_hash(), true);

    // can still stream it
    let mut stream = StreamCursor::new_block(index_block_header.clone());

    // stream from chunk store
    let mut all_block_bytes = vec![];
    loop {
        let mut next_bytes = stream_chunk_to_vec(&chainstate.blocks_path, &mut stream, 16).unwrap();
        if next_bytes.len() == 0 {
            break;
        }
        test_debug!(
            "Got {} more bytes from chunkstore; add to {} total",
            next_bytes.len(),
            all_block_bytes.len()
        );
        all_block_bytes.append(&mut next_bytes);
    }

    // should decode back into the block
    let staging_block = StacksBlock::consensus_deserialize(&mut &all_block_bytes[..]).unwrap();
    assert_eq!(staging_block, block);
}

#[test]
fn stacks_db_stream_headers() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let privk = StacksPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let mut blocks: Vec<StacksBlock> = vec![];
    let mut blocks_index_hashes: Vec<StacksBlockId> = vec![];

    // make a linear stream
    for i in 0..32 {
        let mut block = make_empty_coinbase_block(&privk);

        if i == 0 {
            block.header.total_work.work = 1;
            block.header.total_work.burn = 1;
        }
        if i > 0 {
            block.header.parent_block = blocks.get(i - 1).unwrap().block_hash();
            block.header.total_work.work = blocks.get(i - 1).unwrap().header.total_work.work + 1;
            block.header.total_work.burn = blocks.get(i - 1).unwrap().header.total_work.burn + 1;
        }

        let consensus_hash = ConsensusHash([((i + 1) as u8); 20]);
        let parent_consensus_hash = ConsensusHash([(i as u8); 20]);

        store_staging_block(
            &mut chainstate,
            &consensus_hash,
            &block,
            &parent_consensus_hash,
            i as u64,
            i as u64,
        );

        blocks_index_hashes.push(StacksBlockHeader::make_index_block_hash(
            &consensus_hash,
            &block.block_hash(),
        ));
        blocks.push(block);
    }

    let mut blocks_fork = blocks[0..16].to_vec();
    let mut blocks_fork_index_hashes = blocks_index_hashes[0..16].to_vec();

    // make a stream that branches off
    for i in 16..32 {
        let mut block = make_empty_coinbase_block(&privk);

        if i == 16 {
            block.header.parent_block = blocks.get(i - 1).unwrap().block_hash();
            block.header.total_work.work = blocks.get(i - 1).unwrap().header.total_work.work + 1;
            block.header.total_work.burn = blocks.get(i - 1).unwrap().header.total_work.burn + 2;
        } else {
            block.header.parent_block = blocks_fork.get(i - 1).unwrap().block_hash();
            block.header.total_work.work =
                blocks_fork.get(i - 1).unwrap().header.total_work.work + 1;
            block.header.total_work.burn =
                blocks_fork.get(i - 1).unwrap().header.total_work.burn + 2;
        }

        let consensus_hash = ConsensusHash([((i + 1) as u8) | 0x80; 20]);
        let parent_consensus_hash = if i == 16 {
            ConsensusHash([(i as u8); 20])
        } else {
            ConsensusHash([(i as u8) | 0x80; 20])
        };

        store_staging_block(
            &mut chainstate,
            &consensus_hash,
            &block,
            &parent_consensus_hash,
            i as u64,
            i as u64,
        );

        blocks_fork_index_hashes.push(StacksBlockHeader::make_index_block_hash(
            &consensus_hash,
            &block.block_hash(),
        ));
        blocks_fork.push(block);
    }

    // can't stream a non-existant header
    assert!(StreamCursor::new_headers(&chainstate, &StacksBlockId([0x11; 32]), 1).is_err());

    // stream back individual headers
    for i in 0..blocks.len() {
        let mut stream =
            StreamCursor::new_headers(&chainstate, &blocks_index_hashes[i], 1).unwrap();
        let mut next_header_bytes = vec![];
        loop {
            // torture test
            let mut next_bytes = stream_one_header_to_vec(
                &chainstate.db(),
                &chainstate.blocks_path,
                &mut stream,
                25,
            )
            .unwrap();
            if next_bytes.len() == 0 {
                break;
            }
            next_header_bytes.append(&mut next_bytes);
        }
        test_debug!("Got {} total bytes", next_header_bytes.len());
        let header: ExtendedStacksHeader =
            serde_json::from_reader(&mut &next_header_bytes[..]).unwrap();

        assert_eq!(header.consensus_hash, ConsensusHash([(i + 1) as u8; 20]));
        assert_eq!(header.header, blocks[i].header);

        if i > 0 {
            assert_eq!(header.parent_block_id, blocks_index_hashes[i - 1]);
        }
    }

    // stream back a run of headers
    let block_expected_headers: Vec<StacksBlockHeader> =
        blocks.iter().rev().map(|blk| blk.header.clone()).collect();

    let block_expected_index_hashes: Vec<StacksBlockId> = blocks_index_hashes
        .iter()
        .rev()
        .map(|idx| idx.clone())
        .collect();

    let block_fork_expected_headers: Vec<StacksBlockHeader> = blocks_fork
        .iter()
        .rev()
        .map(|blk| blk.header.clone())
        .collect();

    let block_fork_expected_index_hashes: Vec<StacksBlockId> = blocks_fork_index_hashes
        .iter()
        .rev()
        .map(|idx| idx.clone())
        .collect();

    // get them all -- ask for more than there is
    let mut stream =
        StreamCursor::new_headers(&chainstate, blocks_index_hashes.last().unwrap(), 4096).unwrap();
    let header_bytes = stream_headers_to_vec(&mut chainstate, &mut stream, 1024 * 1024).unwrap();

    eprintln!(
        "headers: {}",
        String::from_utf8(header_bytes.clone()).unwrap()
    );
    let headers: Vec<ExtendedStacksHeader> =
        serde_json::from_reader(&mut &header_bytes[..]).unwrap();

    assert_eq!(headers.len(), block_expected_headers.len());
    for ((i, h), eh) in headers
        .iter()
        .enumerate()
        .zip(block_expected_headers.iter())
    {
        assert_eq!(h.header, *eh);
        assert_eq!(h.consensus_hash, ConsensusHash([(32 - i) as u8; 20]));
        if i + 1 < block_expected_index_hashes.len() {
            assert_eq!(h.parent_block_id, block_expected_index_hashes[i + 1]);
        }
    }

    let mut stream =
        StreamCursor::new_headers(&chainstate, blocks_fork_index_hashes.last().unwrap(), 4096)
            .unwrap();
    let header_bytes = stream_headers_to_vec(&mut chainstate, &mut stream, 1024 * 1024).unwrap();
    let fork_headers: Vec<ExtendedStacksHeader> =
        serde_json::from_reader(&mut &header_bytes[..]).unwrap();

    assert_eq!(fork_headers.len(), block_fork_expected_headers.len());
    for ((i, h), eh) in fork_headers
        .iter()
        .enumerate()
        .zip(block_fork_expected_headers.iter())
    {
        let consensus_hash = if i >= 16 {
            ConsensusHash([((32 - i) as u8); 20])
        } else {
            ConsensusHash([((32 - i) as u8) | 0x80; 20])
        };

        assert_eq!(h.header, *eh);
        assert_eq!(h.consensus_hash, consensus_hash);
        if i + 1 < block_fork_expected_index_hashes.len() {
            assert_eq!(h.parent_block_id, block_fork_expected_index_hashes[i + 1]);
        }
    }

    assert_eq!(fork_headers[16..32], headers[16..32]);

    // ask for only a few
    let mut stream =
        StreamCursor::new_headers(&chainstate, blocks_index_hashes.last().unwrap(), 10).unwrap();
    let mut header_bytes = vec![];
    loop {
        // torture test
        let mut next_bytes = stream_headers_to_vec(&mut chainstate, &mut stream, 17).unwrap();
        if next_bytes.len() == 0 {
            break;
        }
        header_bytes.append(&mut next_bytes);
    }

    eprintln!(
        "header bytes: {}",
        String::from_utf8(header_bytes.clone()).unwrap()
    );

    let headers: Vec<ExtendedStacksHeader> =
        serde_json::from_reader(&mut &header_bytes[..]).unwrap();

    assert_eq!(headers.len(), 10);
    for (i, hdr) in headers.iter().enumerate() {
        assert_eq!(hdr.header, block_expected_headers[i]);
        assert_eq!(hdr.parent_block_id, block_expected_index_hashes[i + 1]);
    }

    // ask for only a few
    let mut stream =
        StreamCursor::new_headers(&chainstate, blocks_fork_index_hashes.last().unwrap(), 10)
            .unwrap();
    let mut header_bytes = vec![];
    loop {
        // torture test
        let mut next_bytes = stream_headers_to_vec(&mut chainstate, &mut stream, 17).unwrap();
        if next_bytes.len() == 0 {
            break;
        }
        header_bytes.append(&mut next_bytes);
    }
    let headers: Vec<ExtendedStacksHeader> =
        serde_json::from_reader(&mut &header_bytes[..]).unwrap();

    assert_eq!(headers.len(), 10);
    for (i, hdr) in headers.iter().enumerate() {
        assert_eq!(hdr.header, block_fork_expected_headers[i]);
        assert_eq!(hdr.parent_block_id, block_fork_expected_index_hashes[i + 1]);
    }
}

#[test]
fn stacks_db_stream_staging_microblocks() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let privk = StacksPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let block = make_empty_coinbase_block(&privk);
    let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
    mblocks.truncate(15);

    let consensus_hash = ConsensusHash([2u8; 20]);
    let parent_consensus_hash = ConsensusHash([1u8; 20]);
    let index_block_header =
        StacksBlockHeader::make_index_block_hash(&consensus_hash, &block.block_hash());

    // can't stream a non-existant microblock
    if let Err(chainstate_error::NoSuchBlockError) =
        StreamCursor::new_microblock_confirmed(&chainstate, index_block_header.clone())
    {
    } else {
        panic!("Opened nonexistant microblock");
    }

    if let Err(chainstate_error::NoSuchBlockError) =
        StreamCursor::new_microblock_unconfirmed(&chainstate, index_block_header.clone(), 0)
    {
    } else {
        panic!("Opened nonexistant microblock");
    }

    // store microblocks to staging and stream them back
    for (i, mblock) in mblocks.iter().enumerate() {
        store_staging_microblock(
            &mut chainstate,
            &consensus_hash,
            &block.block_hash(),
            mblock,
        );

        // read back all the data we have so far, block-by-block
        let mut staging_mblocks = vec![];
        for j in 0..(i + 1) {
            let mut next_mblock_bytes = vec![];
            let mut stream = StreamCursor::new_microblock_unconfirmed(
                &chainstate,
                index_block_header.clone(),
                j as u16,
            )
            .unwrap();
            loop {
                let mut next_bytes =
                    stream_one_staging_microblock_to_vec(&chainstate.db(), &mut stream, 4096)
                        .unwrap();
                if next_bytes.len() == 0 {
                    break;
                }
                test_debug!(
                    "Got {} more bytes from staging; add to {} total",
                    next_bytes.len(),
                    next_mblock_bytes.len()
                );
                next_mblock_bytes.append(&mut next_bytes);
            }
            test_debug!("Got {} total bytes", next_mblock_bytes.len());

            // should deserialize to a microblock
            let staging_mblock =
                StacksMicroblock::consensus_deserialize(&mut &next_mblock_bytes[..]).unwrap();
            staging_mblocks.push(staging_mblock);
        }

        assert_eq!(staging_mblocks.len(), mblocks[0..(i + 1)].len());
        for j in 0..(i + 1) {
            test_debug!("check {}", j);
            assert_eq!(staging_mblocks[j], mblocks[j])
        }

        // can also read partial stream in one shot, from any seq
        for k in 0..(i + 1) {
            test_debug!("start at seq {}", k);
            let mut staging_mblock_bytes = vec![];
            let mut stream = StreamCursor::new_microblock_unconfirmed(
                &chainstate,
                index_block_header.clone(),
                k as u16,
            )
            .unwrap();
            loop {
                let mut next_bytes =
                    stream_unconfirmed_microblocks_to_vec(&mut chainstate, &mut stream, 4096)
                        .unwrap();
                if next_bytes.len() == 0 {
                    break;
                }
                test_debug!(
                    "Got {} more bytes from staging; add to {} total",
                    next_bytes.len(),
                    staging_mblock_bytes.len()
                );
                staging_mblock_bytes.append(&mut next_bytes);
            }

            test_debug!("Got {} total bytes", staging_mblock_bytes.len());

            // decode stream
            let staging_mblocks = decode_microblock_stream(&staging_mblock_bytes);

            assert_eq!(staging_mblocks.len(), mblocks[k..(i + 1)].len());
            for j in 0..staging_mblocks.len() {
                test_debug!("check {}", j);
                assert_eq!(staging_mblocks[j], mblocks[k + j])
            }
        }
    }
}

#[test]
fn stacks_db_stream_confirmed_microblocks() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let privk = StacksPrivateKey::from_hex(
        "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
    )
    .unwrap();

    let block = make_empty_coinbase_block(&privk);
    let mut mblocks = make_sample_microblock_stream(&privk, &block.block_hash());
    mblocks.truncate(5);

    let mut child_block = make_empty_coinbase_block(&privk);
    child_block.header.parent_block = block.block_hash();
    child_block.header.parent_microblock = mblocks.last().as_ref().unwrap().block_hash();
    child_block.header.parent_microblock_sequence =
        mblocks.last().as_ref().unwrap().header.sequence;

    let consensus_hash = ConsensusHash([2u8; 20]);
    let parent_consensus_hash = ConsensusHash([1u8; 20]);
    let child_consensus_hash = ConsensusHash([3u8; 20]);

    let index_block_header =
        StacksBlockHeader::make_index_block_hash(&consensus_hash, &block.block_hash());

    // store microblocks to staging
    for (i, mblock) in mblocks.iter().enumerate() {
        store_staging_microblock(
            &mut chainstate,
            &consensus_hash,
            &block.block_hash(),
            mblock,
        );
    }

    // store block to staging
    store_staging_block(
        &mut chainstate,
        &consensus_hash,
        &block,
        &parent_consensus_hash,
        1,
        2,
    );

    // store child block to staging
    store_staging_block(
        &mut chainstate,
        &child_consensus_hash,
        &child_block,
        &consensus_hash,
        1,
        2,
    );

    // accept it
    set_block_processed(&mut chainstate, &consensus_hash, &block.block_hash(), true);
    set_block_processed(
        &mut chainstate,
        &child_consensus_hash,
        &child_block.block_hash(),
        true,
    );

    for i in 0..mblocks.len() {
        // set different parts of this stream as confirmed
        set_microblocks_processed(
            &mut chainstate,
            &child_consensus_hash,
            &child_block.block_hash(),
            &mblocks[i].block_hash(),
        );

        // verify that we can stream everything
        let microblock_index_header =
            StacksBlockHeader::make_index_block_hash(&consensus_hash, &mblocks[i].block_hash());
        let mut stream =
            StreamCursor::new_microblock_confirmed(&chainstate, microblock_index_header.clone())
                .unwrap();

        let mut confirmed_mblock_bytes = vec![];
        loop {
            let mut next_bytes =
                stream_confirmed_microblocks_to_vec(&mut chainstate, &mut stream, 16).unwrap();
            if next_bytes.len() == 0 {
                break;
            }
            test_debug!(
                "Got {} more bytes from staging; add to {} total",
                next_bytes.len(),
                confirmed_mblock_bytes.len()
            );
            confirmed_mblock_bytes.append(&mut next_bytes);
        }

        // decode stream (should be length-prefixed)
        let mut confirmed_mblocks =
            Vec::<StacksMicroblock>::consensus_deserialize(&mut &confirmed_mblock_bytes[..])
                .unwrap();

        confirmed_mblocks.reverse();

        assert_eq!(confirmed_mblocks.len(), mblocks[0..(i + 1)].len());
        for j in 0..(i + 1) {
            test_debug!("check {}", j);
            assert_eq!(confirmed_mblocks[j], mblocks[j])
        }
    }
}
