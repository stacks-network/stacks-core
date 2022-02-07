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

use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use crate::burnchains::StacksHyperOpType;
use crate::types::chainstate::StacksAddress;
use crate::types::proof::TrieHash;
use address::public_keys_to_address_hash;
use address::AddressHashMode;
use burnchains::db::BurnchainDB;
use burnchains::indexer::{
    BurnBlockIPC, BurnHeaderIPC, BurnchainBlockDownloader, BurnchainBlockParser, BurnchainIndexer,
};
use burnchains::Address;
use burnchains::Burnchain;
use burnchains::PublicKey;
use burnchains::Txid;
use burnchains::{
    BurnchainBlock, BurnchainBlockHeader, BurnchainParameters, BurnchainRecipient, BurnchainSigner,
    BurnchainStateTransition, BurnchainTransaction, Error as burnchain_error, PoxConstants,
};
use chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn, SortitionHandleTx};
use chainstate::burn::operations::{
    leader_block_commit::MissedBlockCommit, BlockstackOperationType, LeaderBlockCommitOp,
    LeaderKeyRegisterOp, PreStxOp, StackStxOp, TransferStxOp, UserBurnSupportOp,
};
use chainstate::burn::{BlockSnapshot, Opcodes};
use chainstate::coordinator::comm::CoordinatorChannels;
use chainstate::stacks::StacksPublicKey;
use core::MINING_COMMITMENT_WINDOW;
use core::NETWORK_ID_MAINNET;
use core::NETWORK_ID_TESTNET;
use core::PEER_VERSION_MAINNET;
use core::PEER_VERSION_TESTNET;
use deps;
use deps::bitcoin::util::hash::Sha256dHash as BitcoinSha256dHash;
use monitoring::update_burnchain_height;
use util::db::DBConn;
use util::db::DBTx;
use util::db::Error as db_error;
use util::get_epoch_time_ms;
use util::get_epoch_time_secs;
use util::hash::to_hex;
use util::log;
use util::vrf::VRFPublicKey;

use crate::types::chainstate::{BurnchainHeaderHash, PoxId};

impl BurnchainStateTransition {
    pub fn noop() -> BurnchainStateTransition {
        BurnchainStateTransition {
            accepted_ops: vec![],
        }
    }

    pub fn from_block_ops(
        _sort_tx: &mut SortitionHandleTx,
        _burnchain: &Burnchain,
        _parent_snapshot: &BlockSnapshot,
        block_ops: &Vec<BlockstackOperationType>,
    ) -> Result<BurnchainStateTransition, burnchain_error> {
        // block commits discovered in this block.
        let mut accepted_ops = Vec::with_capacity(block_ops.len());

        assert!(Burnchain::ops_are_sorted(block_ops));

        // accept all leader keys we found.
        // don't treat block commits and user burn supports just yet.
        for block_op in block_ops.iter() {
            match block_op {
                BlockstackOperationType::LeaderBlockCommit(op) => {
                    // we don't yet know which block commits are going to be accepted until we have
                    // the burn distribution, so just account for them for now.
                    accepted_ops.push(op.clone().into());
                }
            };
        }

        Ok(BurnchainStateTransition { accepted_ops })
    }
}

impl BurnchainSigner {
    #[cfg(test)]
    pub fn new_p2pkh(pubk: &StacksPublicKey) -> BurnchainSigner {
        BurnchainSigner {
            hash_mode: AddressHashMode::SerializeP2PKH,
            num_sigs: 1,
            public_keys: vec![pubk.clone()],
        }
    }

    pub fn to_address_bits(&self) -> Vec<u8> {
        let h = public_keys_to_address_hash(&self.hash_mode, self.num_sigs, &self.public_keys);
        h.as_bytes().to_vec()
    }
}

impl BurnchainBlock {
    pub fn block_height(&self) -> u64 {
        match self {
            BurnchainBlock::StacksHyperBlock(b) => b.block_height,
        }
    }

    pub fn block_hash(&self) -> BurnchainHeaderHash {
        match self {
            BurnchainBlock::StacksHyperBlock(b) => BurnchainHeaderHash(b.current_block.clone().0),
        }
    }

    pub fn parent_block_hash(&self) -> BurnchainHeaderHash {
        match self {
            BurnchainBlock::StacksHyperBlock(b) => BurnchainHeaderHash(b.parent_block.clone().0),
        }
    }

    pub fn txs(&self) -> Vec<BurnchainTransaction> {
        match self {
            BurnchainBlock::StacksHyperBlock(b) => b
                .ops
                .iter()
                .map(|ev_op| BurnchainTransaction::StacksBase(ev_op.clone()))
                .collect(),
        }
    }

    pub fn timestamp(&self) -> u64 {
        0
    }

    pub fn header(&self) -> BurnchainBlockHeader {
        match self {
            BurnchainBlock::StacksHyperBlock(b) => BurnchainBlockHeader {
                block_height: self.block_height(),
                block_hash: self.block_hash(),
                parent_block_hash: self.parent_block_hash(),
                num_txs: b.ops.len() as u64,
                timestamp: self.timestamp(),
            },
        }
    }
}

impl Burnchain {
    pub fn new(
        working_dir: &str,
        chain_name: &str,
        network_name: &str,
    ) -> Result<Burnchain, burnchain_error> {
        let (params, pox_constants, peer_version) = match (chain_name, network_name) {
            ("bitcoin", "mainnet") => (
                BurnchainParameters::bitcoin_mainnet(),
                PoxConstants::mainnet_default(),
                PEER_VERSION_MAINNET,
            ),
            ("bitcoin", "testnet") => (
                BurnchainParameters::bitcoin_testnet(),
                PoxConstants::testnet_default(),
                PEER_VERSION_TESTNET,
            ),
            ("bitcoin", "regtest") => (
                BurnchainParameters::bitcoin_regtest(),
                PoxConstants::regtest_default(),
                PEER_VERSION_TESTNET,
            ),
            (_, _) => {
                return Err(burnchain_error::UnsupportedBurnchain);
            }
        };

        Ok(Burnchain {
            peer_version,
            network_id: params.network_id,
            chain_name: params.chain_name.clone(),
            network_name: params.network_name.clone(),
            working_dir: working_dir.into(),
            consensus_hash_lifetime: params.consensus_hash_lifetime,
            stable_confirmations: params.stable_confirmations,
            first_block_height: params.first_block_height,
            initial_reward_start_block: params.initial_reward_start_block,
            first_block_hash: params.first_block_hash,
            first_block_timestamp: params.first_block_timestamp,
            pox_constants,
        })
    }

    pub fn is_mainnet(&self) -> bool {
        self.network_id == NETWORK_ID_MAINNET
    }

    /// the expected sunset burn is:
    ///   total_commit * (progress through sunset phase) / (sunset phase duration)
    pub fn expected_sunset_burn(&self, burn_height: u64, total_commit: u64) -> u64 {
        if burn_height < self.pox_constants.sunset_start
            || burn_height >= self.pox_constants.sunset_end
        {
            return 0;
        }

        // no sunset burn needed in prepare phase -- it's already getting burnt
        if self.is_in_prepare_phase(burn_height) {
            return 0;
        }

        let reward_cycle_height = self.reward_cycle_to_block_height(
            self.block_height_to_reward_cycle(burn_height)
                .expect("BUG: Sunset start is less than first_block_height"),
        );

        if reward_cycle_height <= self.pox_constants.sunset_start {
            return 0;
        }

        let sunset_duration =
            (self.pox_constants.sunset_end - self.pox_constants.sunset_start) as u128;
        let sunset_progress = (reward_cycle_height - self.pox_constants.sunset_start) as u128;

        // use u128 to avoid any possibilities of overflowing in the calculation here.
        let expected_u128 = (total_commit as u128) * (sunset_progress) / sunset_duration;
        u64::try_from(expected_u128)
            // should never be possible, because sunset_burn is <= total_commit, which is a u64
            .expect("Overflowed u64 in calculating expected sunset_burn")
    }

    pub fn is_reward_cycle_start(&self, burn_height: u64) -> bool {
        let effective_height = burn_height - self.first_block_height;
        // first block of the new reward cycle
        (effective_height % (self.pox_constants.reward_cycle_length as u64)) == 1
    }

    pub fn reward_cycle_to_block_height(&self, reward_cycle: u64) -> u64 {
        // NOTE: the `+ 1` is because the height of the first block of a reward cycle is mod 1, not
        // mod 0.
        self.first_block_height + reward_cycle * (self.pox_constants.reward_cycle_length as u64) + 1
    }

    pub fn block_height_to_reward_cycle(&self, block_height: u64) -> Option<u64> {
        if block_height < self.first_block_height {
            return None;
        }
        Some(
            (block_height - self.first_block_height)
                / (self.pox_constants.reward_cycle_length as u64),
        )
    }

    pub fn is_in_prepare_phase(&self, block_height: u64) -> bool {
        if block_height <= self.first_block_height {
            // not a reward cycle start if we're the first block after genesis.
            false
        } else {
            let effective_height = block_height - self.first_block_height;
            let reward_index = effective_height % (self.pox_constants.reward_cycle_length as u64);

            // NOTE: first block in reward cycle is mod 1, so mod 0 is the last block in the
            // prepare phase.
            reward_index == 0
                || reward_index
                    > ((self.pox_constants.reward_cycle_length - self.pox_constants.prepare_length)
                        as u64)
        }
    }

    pub fn regtest(working_dir: &str) -> Burnchain {
        let ret =
            Burnchain::new(working_dir, &"bitcoin".to_string(), &"regtest".to_string()).unwrap();
        ret
    }

    #[cfg(test)]
    pub fn default_unittest(
        first_block_height: u64,
        first_block_hash: &BurnchainHeaderHash,
    ) -> Burnchain {
        let mut ret = Burnchain::new(
            &"/unit-tests".to_string(),
            &"bitcoin".to_string(),
            &"mainnet".to_string(),
        )
        .unwrap();
        ret.first_block_height = first_block_height;
        ret.initial_reward_start_block = first_block_height;
        ret.first_block_hash = first_block_hash.clone();
        ret
    }

    pub fn get_chainstate_path_str(working_dir: &String) -> String {
        let chainstate_dir_path = PathBuf::from(working_dir);
        let dirpath = chainstate_dir_path.to_str().unwrap().to_string();
        dirpath
    }

    pub fn get_chainstate_config_path(working_dir: &String, chain_name: &String) -> String {
        let chainstate_dir = Burnchain::get_chainstate_path_str(working_dir);
        let mut config_pathbuf = PathBuf::from(&chainstate_dir);
        let chainstate_config_name = format!("{}.ini", chain_name);
        config_pathbuf.push(&chainstate_config_name);

        config_pathbuf.to_str().unwrap().to_string()
    }

    pub fn setup_chainstate_dirs(working_dir: &String) -> Result<(), burnchain_error> {
        let chainstate_dir = Burnchain::get_chainstate_path_str(working_dir);
        let chainstate_pathbuf = PathBuf::from(&chainstate_dir);

        if !chainstate_pathbuf.exists() {
            fs::create_dir_all(&chainstate_pathbuf).map_err(burnchain_error::FSError)?;
        }
        Ok(())
    }

    fn setup_chainstate<I: BurnchainIndexer>(
        &self,
        indexer: &mut I,
    ) -> Result<(), burnchain_error> {
        let headers_path = indexer.get_headers_path();
        let headers_pathbuf = PathBuf::from(&headers_path);

        let headers_height = if headers_pathbuf.exists() {
            indexer.get_highest_header_height()?
        } else {
            0
        };

        if headers_height == 0 || headers_height < self.first_block_height {
            debug!("Fetch initial headers");
            indexer.sync_headers(headers_height, None).map_err(|e| {
                error!("Failed to sync initial headers");
                e
            })?;
        }
        Ok(())
    }

    pub fn get_db_path(&self) -> String {
        let chainstate_dir = Burnchain::get_chainstate_path_str(&self.working_dir);
        let mut db_pathbuf = PathBuf::from(&chainstate_dir);
        db_pathbuf.push("sortition");

        let db_path = db_pathbuf.to_str().unwrap().to_string();
        db_path
    }

    pub fn get_burnchaindb_path(&self) -> String {
        let chainstate_dir = Burnchain::get_chainstate_path_str(&self.working_dir);
        let mut db_pathbuf = PathBuf::from(&chainstate_dir);
        db_pathbuf.push("burnchain.sqlite");

        let db_path = db_pathbuf.to_str().unwrap().to_string();
        db_path
    }

    pub fn connect_db<I: BurnchainIndexer>(
        &self,
        indexer: &I,
        readwrite: bool,
        first_block_header_hash: BurnchainHeaderHash,
        first_block_header_timestamp: u64,
    ) -> Result<(SortitionDB, BurnchainDB), burnchain_error> {
        Burnchain::setup_chainstate_dirs(&self.working_dir)?;

        let epochs = indexer.get_stacks_epochs();

        let db_path = self.get_db_path();
        let burnchain_db_path = self.get_burnchaindb_path();

        let sortitiondb = SortitionDB::connect(
            &db_path,
            self.first_block_height,
            &first_block_header_hash,
            first_block_header_timestamp,
            &epochs,
            readwrite,
        )?;
        let burnchaindb = BurnchainDB::connect(
            &burnchain_db_path,
            self.first_block_height,
            &first_block_header_hash,
            first_block_header_timestamp,
            readwrite,
        )?;

        Ok((sortitiondb, burnchaindb))
    }

    /// Open the burn database.  It must already exist.
    pub fn open_db(&self, readwrite: bool) -> Result<(SortitionDB, BurnchainDB), burnchain_error> {
        let db_path = self.get_db_path();
        let burnchain_db_path = self.get_burnchaindb_path();

        let db_pathbuf = PathBuf::from(db_path.clone());
        if !db_pathbuf.exists() {
            return Err(burnchain_error::DBError(db_error::NoDBError));
        }

        let db_pathbuf = PathBuf::from(burnchain_db_path.clone());
        if !db_pathbuf.exists() {
            return Err(burnchain_error::DBError(db_error::NoDBError));
        }

        let sortition_db = SortitionDB::open(&db_path, readwrite)?;
        let burnchain_db = BurnchainDB::open(&burnchain_db_path, readwrite)?;

        Ok((sortition_db, burnchain_db))
    }

    /// Try to parse a burnchain transaction into a Blockstack operation
    /// `pre_stx_op_map` should contain any valid PreStxOps that occurred before
    ///   the currently-being-evaluated tx in the same burn block.
    pub fn classify_transaction(
        _burnchain: &Burnchain,
        _burnchain_db: &BurnchainDB,
        _block_header: &BurnchainBlockHeader,
        burn_tx: &BurnchainTransaction,
    ) -> Option<BlockstackOperationType> {
        let result = match burn_tx {
            BurnchainTransaction::StacksBase(ref event) => match event.event {
                StacksHyperOpType::BlockCommit { .. } => LeaderBlockCommitOp::try_from(event),
            },
        };

        match result {
            Ok(op) => Some(BlockstackOperationType::from(op)),
            Err(e) => {
                warn!(
                    "Failed to parse subnet block operation";
                    "txid" => %burn_tx.txid(),
                    "error" => ?e,
                );
                None
            }
        }
    }

    /// Sanity check -- a list of checked ops is sorted and all vtxindexes are unique
    pub fn ops_are_sorted(ops: &Vec<BlockstackOperationType>) -> bool {
        if ops.len() > 1 {
            for i in 0..ops.len() - 1 {
                if ops[i].vtxindex() >= ops[i + 1].vtxindex() {
                    return false;
                }
            }
        }
        true
    }

    /// Top-level entry point to check and process a block.
    pub fn process_block(
        burnchain: &Burnchain,
        burnchain_db: &mut BurnchainDB,
        block: &BurnchainBlock,
    ) -> Result<BurnchainBlockHeader, burnchain_error> {
        debug!(
            "Process block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let _blockstack_txs = burnchain_db.store_new_burnchain_block(burnchain, &block)?;

        let header = block.header();

        Ok(header)
    }

    /// Hand off the block to the ChainsCoordinator _and_ process the sortition
    ///   *only* to be used by legacy stacks node interfaces, like the Helium node
    pub fn process_block_and_sortition_deprecated(
        db: &mut SortitionDB,
        burnchain_db: &mut BurnchainDB,
        burnchain: &Burnchain,
        block: &BurnchainBlock,
    ) -> Result<(BlockSnapshot, BurnchainStateTransition), burnchain_error> {
        debug!(
            "Process block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let header = block.header();
        let blockstack_txs = burnchain_db.store_new_burnchain_block(burnchain, &block)?;

        let sortition_tip = SortitionDB::get_canonical_sortition_tip(db.conn())?;

        db.evaluate_sortition(&header, blockstack_txs, burnchain, &sortition_tip, None)
            .map(|(snapshot, transition, _)| (snapshot, transition))
    }

    /// Determine if there has been a chain reorg, given our current canonical burnchain tip.
    /// Return the new chain tip and a boolean signaling the presence of a reorg
    fn sync_reorg<I: BurnchainIndexer>(indexer: &mut I) -> Result<(u64, bool), burnchain_error> {
        let headers_path = indexer.get_headers_path();

        // sanity check -- what is the height of our highest header
        let headers_height = indexer.get_highest_header_height().map_err(|e| {
            error!(
                "Failed to read headers height from {}: {:?}",
                headers_path, &e
            );
            e
        })?;

        if headers_height == 0 {
            return Ok((0, false));
        }

        // did we encounter a reorg since last sync?  Find the highest common ancestor of the
        // remote bitcoin peer's chain state.
        // Note that this value is 0-indexed -- the smallest possible value it returns is 0.
        let reorg_height = indexer.find_chain_reorg().map_err(|e| {
            error!("Failed to check for reorgs from {}: {:?}", headers_path, &e);
            e
        })?;

        if reorg_height < headers_height {
            warn!(
                "Burnchain reorg detected: highest common ancestor at height {}",
                reorg_height
            );
            return Ok((reorg_height, true));
        } else {
            // no reorg
            return Ok((headers_height, false));
        }
    }

    /// Top-level burnchain sync.
    /// Returns the burnchain block header for the new burnchain tip, which will be _at least_ as
    /// high as target_block_height_opt (if given), or whatever is currently at the tip of the
    /// burnchain DB.
    /// If this method returns Err(burnchain_error::TrySyncAgain), then call this method again.
    pub fn sync_with_indexer<I>(
        &mut self,
        _indexer: &mut I,
        _coord_comm: CoordinatorChannels,
        _target_block_height_opt: Option<u64>,
        _max_blocks_opt: Option<u64>,
        _should_keep_running: Option<Arc<AtomicBool>>,
    ) -> Result<BurnchainBlockHeader, burnchain_error>
    where
        I: BurnchainIndexer + 'static,
    {
        panic!("Not implemented")
    }
}
