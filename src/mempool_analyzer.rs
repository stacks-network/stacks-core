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

#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[macro_use]
extern crate blockstack_lib;
extern crate rusqlite;

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

use std::io;
use std::io::prelude::*;
use std::process;
use std::{collections::HashMap, env};
use std::{convert::TryFrom, fs};

use blockstack_lib::burnchains::BLOCKSTACK_MAGIC_MAINNET;
use blockstack_lib::cost_estimates::UnitEstimator;
use cost_estimates::metrics::UnitMetric;
use rusqlite::types::ToSql;
use rusqlite::Connection;
use rusqlite::OpenFlags;

use blockstack_lib::burnchains::bitcoin::indexer::{BitcoinIndexerConfig, BitcoinIndexerRuntime};
use blockstack_lib::burnchains::bitcoin::spv;
use blockstack_lib::burnchains::bitcoin::BitcoinNetworkType;
use blockstack_lib::chainstate::burn::ConsensusHash;
use blockstack_lib::chainstate::stacks::db::ChainStateBootData;
use blockstack_lib::chainstate::stacks::index::marf::MarfConnection;
use blockstack_lib::chainstate::stacks::index::marf::MARF;
use blockstack_lib::chainstate::stacks::miner::*;
use blockstack_lib::chainstate::stacks::*;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, PoxId};
use blockstack_lib::types::chainstate::{StacksBlockHeader, StacksBlockId};
use blockstack_lib::types::proof::ClarityMarfTrieId;
use blockstack_lib::util::get_epoch_time_ms;
use blockstack_lib::util::hash::{hex_bytes, to_hex};
use blockstack_lib::util::log;
use blockstack_lib::util::retry::LogReader;
use blockstack_lib::*;
use blockstack_lib::{
    burnchains::{db::BurnchainBlockData, PoxConstants},
    chainstate::{
        burn::db::sortdb::SortitionDB,
        stacks::db::{StacksChainState, StacksHeaderInfo},
    },
    core::MemPoolDB,
    util::db::sqlite_open,
    util::{hash::Hash160, vrf::VRFProof},
    vm::costs::ExecutionCost,
};
use blockstack_lib::{
    net::{db::LocalPeer, p2p::PeerNetwork, PeerAddress},
    vm::representations::UrlString,
};

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 1 {
        eprintln!(
            "Usage: {} <working-dir> [min-fee [max-time]]

Given a <working-dir>, try to ''mine'' an anchored block. This invokes the miner block
assembly, but does not attempt to broadcast a block commit. This is useful for determining
what transactions a given chain state would include in an anchor block, or otherwise
simulating a miner.
",
            argv[0]
        );
        process::exit(1);
    }

    let start = get_epoch_time_ms();
    let sort_db_path = format!("{}/mainnet/burnchain/sortition", &argv[2]);
    let chain_state_path = format!("{}/mainnet/chainstate/", &argv[2]);

    let mut min_fee = u64::max_value();
    let mut max_time = u64::max_value();

    if argv.len() >= 3 {
        min_fee = argv[2].parse().expect("Could not parse min_fee");
    }
    if argv.len() >= 4 {
        max_time = argv[3].parse().expect("Could not parse max_time");
    }

    let sort_db = SortitionDB::open(&sort_db_path, false)
        .expect(&format!("Failed to open {}", &sort_db_path));
    let chain_id = core::CHAIN_ID_MAINNET;
    let (chain_state, _) = StacksChainState::open(true, chain_id, &chain_state_path)
        .expect("Failed to open stacks chain state");
    let chain_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn())
        .expect("Failed to get sortition chain tip");

    let estimator = Box::new(UnitEstimator);
    let metric = Box::new(UnitMetric);

    let mut mempool_db = MemPoolDB::open(true, chain_id, &chain_state_path, estimator, metric)
        .expect("Failed to open mempool db");

    let stacks_block = chain_state.get_stacks_chain_tip(&sort_db).unwrap().unwrap();
    let parent_header = StacksChainState::get_anchored_block_header_info(
        chain_state.db(),
        &stacks_block.consensus_hash,
        &stacks_block.anchored_block_hash,
    )
    .expect("Failed to load chain tip header info")
    .expect("Failed to load chain tip header info");

    let sk = StacksPrivateKey::new();
    let mut tx_auth = TransactionAuth::from_p2pkh(&sk).unwrap();
    tx_auth.set_origin_nonce(0);

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
    );

    coinbase_tx.chain_id = chain_id;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&coinbase_tx);
    tx_signer.sign_origin(&sk).unwrap();
    let coinbase_tx = tx_signer.get_tx().unwrap();

    let mut settings = BlockBuilderSettings::limited();
    settings.max_miner_time_ms = max_time;
    settings.mempool_settings.min_tx_fee = min_fee;

    let result = StacksBlockBuilder::build_anchored_block(
        &chain_state,
        &sort_db.index_conn(),
        &mut mempool_db,
        &parent_header,
        chain_tip.total_burn,
        VRFProof::empty(),
        Hash160([0; 20]),
        &coinbase_tx,
        settings,
        None,
    );

    let stop = get_epoch_time_ms();

    println!(
        "{} mined block @ height = {} off of {} ({}/{}) in {}ms. Min-fee: {}, Max-time: {}",
        if result.is_ok() {
            "Successfully"
        } else {
            "Failed to"
        },
        parent_header.block_height + 1,
        StacksBlockHeader::make_index_block_hash(
            &parent_header.consensus_hash,
            &parent_header.anchored_header.block_hash()
        ),
        &parent_header.consensus_hash,
        &parent_header.anchored_header.block_hash(),
        stop.saturating_sub(start),
        min_fee,
        max_time
    );

    if let Ok((block, execution_cost, size)) = result {
        let mut total_fees = 0;
        for tx in block.txs.iter() {
            total_fees += tx.get_tx_fee();
        }
        println!(
            "Block {}: {} uSTX, {} bytes, cost {:?}",
            block.block_hash(),
            total_fees,
            size,
            &execution_cost
        );
    }

    process::exit(0);
}
