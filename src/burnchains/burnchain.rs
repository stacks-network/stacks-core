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
use crate::types::chainstate::TrieHash;
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
    leader_block_commit::MissedBlockCommit, BlockstackOperationType, DepositFtOp, DepositNftOp,
    LeaderBlockCommitOp, LeaderKeyRegisterOp, PreStxOp, StackStxOp, TransferStxOp,
    UserBurnSupportOp, WithdrawFtOp, WithdrawNftOp,
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
use monitoring::update_burnchain_height;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash as BitcoinSha256dHash;
use util::get_epoch_time_ms;
use util::get_epoch_time_secs;
use util::hash::to_hex;
use util::log;
use util::vrf::VRFPublicKey;
use util_lib::db::DBConn;
use util_lib::db::DBTx;
use util_lib::db::Error as db_error;

use crate::types::chainstate::BurnchainHeaderHash;
use chainstate::stacks::address::StacksAddressExtensions;

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

        // accept all leader keys we found.
        // don't treat block commits and user burn supports just yet.
        for block_op in block_ops.iter() {
            match block_op {
                BlockstackOperationType::LeaderBlockCommit(op) => {
                    // we don't yet know which block commits are going to be accepted until we have
                    // the burn distribution, so just account for them for now.
                    accepted_ops.push(op.clone().into());
                }
                BlockstackOperationType::DepositFt(op) => {
                    accepted_ops.push(op.clone().into());
                }
                BlockstackOperationType::DepositNft(op) => {
                    accepted_ops.push(op.clone().into());
                }
                BlockstackOperationType::WithdrawFt(op) => {
                    accepted_ops.push(op.clone().into());
                }
                BlockstackOperationType::WithdrawNft(op) => {
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
    /// Creates a burnchain using default values chosen based on chain and network.
    pub fn new(
        working_dir: &str,
        chain_name: &str,
        network_name: &str,
    ) -> Result<Burnchain, burnchain_error> {
        let (params, pox_constants, peer_version) = match (chain_name, network_name) {
            ("mockstack", "hyperchain") => (
                BurnchainParameters::hyperchain_mocknet(),
                PoxConstants::mainnet_default(),
                PEER_VERSION_MAINNET,
            ),
            ("stacks_layer_1", "hyperchain") => (
                BurnchainParameters::hyperchain_mocknet(),
                PoxConstants::mainnet_default(),
                PEER_VERSION_MAINNET,
            ),
            (_, _) => {
                warn!(
                    "Burnchain parameters not supported. chain_name: {}, network_name: {}",
                    &chain_name, &network_name
                );
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

    pub fn regtest(working_dir: &str) -> Burnchain {
        let ret = Burnchain::new(
            working_dir,
            &"mockstack".to_string(),
            &"hyperchain".to_string(),
        )
        .unwrap();
        ret
    }

    #[cfg(test)]
    pub fn default_unittest(
        first_block_height: u64,
        first_block_hash: &BurnchainHeaderHash,
    ) -> Burnchain {
        let mut ret = Burnchain::new(
            &"/tmp/stacks-node-tests/unit-tests".to_string(),
            &"mockstack".to_string(),
            &"hyperchain".to_string(),
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

    /// Connect to the burnchain databases.  They may or may not already exist.
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

    /// Open the burn databases.  They must already exist.
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
        match burn_tx {
            BurnchainTransaction::StacksBase(ref event) => match event.event {
                StacksHyperOpType::BlockCommit { .. } => {
                    match LeaderBlockCommitOp::try_from(event) {
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
                StacksHyperOpType::DepositFt { .. } => match DepositFtOp::try_from(event) {
                    Ok(op) => Some(BlockstackOperationType::from(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse deposit fungible token operation";
                            "txid" => %burn_tx.txid(),
                            "error" => ?e,
                        );
                        None
                    }
                },
                StacksHyperOpType::DepositNft { .. } => match DepositNftOp::try_from(event) {
                    Ok(op) => Some(BlockstackOperationType::from(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse deposit NFT operation";
                            "txid" => %burn_tx.txid(),
                            "error" => ?e,
                        );
                        None
                    }
                },
                StacksHyperOpType::WithdrawFt { .. } => match WithdrawFtOp::try_from(event) {
                    Ok(op) => Some(BlockstackOperationType::from(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse withdraw fungible token operation";
                            "txid" => %burn_tx.txid(),
                            "error" => ?e,
                        );
                        None
                    }
                },
                StacksHyperOpType::WithdrawNft { .. } => match WithdrawNftOp::try_from(event) {
                    Ok(op) => Some(BlockstackOperationType::from(op)),
                    Err(e) => {
                        warn!(
                            "Failed to parse withdraw NFT operation";
                            "txid" => %burn_tx.txid(),
                            "error" => ?e,
                        );
                        None
                    }
                },
            },
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
    ///
    /// First, check if a block with the hash exists. If it exists, return the existing one and don't store.
    /// If it doesn't exist, store it.
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

        // Step 1: Check if we already have a block with this header. If so, make sure blocks
        // are the same, and short-circuit.
        match burnchain_db.get_burnchain_block(&block.header().block_hash) {
            Ok(_block_data) => {
                return Ok(block.header());
            }
            Err(burnchain_error::UnknownBlock(_)) => {
                // This case means we need to add the block. Standard case. Pass through.
            }
            Err(error) => {
                return Err(error);
            }
        }

        // Step 2: Store the block.
        let _blockstack_txs = burnchain_db.store_new_burnchain_block(burnchain, &block)?;
        let header = block.header();
        Ok(header)
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

    /// Get the highest burnchain block processed, if we have processed any.
    /// Return Some(..) if we have processed at least one processed burnchain block; return None
    /// otherwise.
    pub fn get_highest_burnchain_block(
        &self,
    ) -> Result<Option<BurnchainBlockHeader>, burnchain_error> {
        let burndb = match self.open_db(true) {
            Ok((_sortdb, burndb)) => burndb,
            Err(burnchain_error::DBError(db_error::NoDBError)) => {
                // databases not yet initialized, so no blocks processed
                return Ok(None);
            }
            Err(e) => {
                return Err(e);
            }
        };

        let burn_chain_tip = match burndb.get_canonical_chain_tip() {
            Ok(tip) => tip,
            Err(burnchain_error::MissingParentBlock) => {
                // database is empty
                return Ok(None);
            }
            Err(e) => {
                return Err(e);
            }
        };

        Ok(Some(burn_chain_tip))
    }

    /// Top-level burnchain sync.
    /// Returns the burnchain block header for the new burnchain tip, which will be _at least_ as
    /// high as target_block_height_opt (if given), or whatever is currently at the tip of the
    /// burnchain DB.
    /// If this method returns Err(burnchain_error::TrySyncAgain), then call this method again.
    pub fn sync_with_indexer<I>(
        &mut self,
        indexer: &mut I,
        coord_comm: CoordinatorChannels,
        target_block_height_opt: Option<u64>,
        max_blocks_opt: Option<u64>,
        should_keep_running: Option<Arc<AtomicBool>>,
    ) -> Result<BurnchainBlockHeader, burnchain_error>
    where
        I: BurnchainIndexer + 'static,
    {
        self.setup_chainstate(indexer)?;
        let (_, mut burnchain_db) = self.connect_db(
            indexer,
            true,
            indexer.get_first_block_header_hash()?,
            indexer.get_first_block_header_timestamp()?,
        )?;

        let burn_chain_tip = burnchain_db.get_canonical_chain_tip().map_err(|e| {
            error!("Failed to query burn chain tip from burn DB: {}", e);
            e
        })?;

        let db_height = burn_chain_tip.block_height;

        // handle reorgs
        let (sync_height, did_reorg) = Burnchain::sync_reorg(indexer)?;
        if did_reorg {
            // a reorg happened
            warn!(
                "Dropping headers higher than {} due to burnchain reorg",
                sync_height
            );
            indexer.drop_headers(sync_height)?;
        }

        // get latest headers.
        trace!("Sync headers from {}", sync_height);

        // fetch all headers, no matter what
        let mut end_block = indexer.sync_headers(sync_height, None)?;
        if did_reorg && sync_height > 0 {
            // a reorg happened, and the last header fetched
            // is on a smaller fork than the one we just
            // invalidated. Wait for more blocks.
            while end_block < db_height {
                if let Some(ref should_keep_running) = should_keep_running {
                    if !should_keep_running.load(Ordering::SeqCst) {
                        return Err(burnchain_error::CoordinatorClosed);
                    }
                }
                let end_height = target_block_height_opt.unwrap_or(0).max(db_height);
                info!("Burnchain reorg happened at height {} invalidating chain tip {} but only {} headers presents on canonical chain. Retry in 2s", sync_height, db_height, end_block);
                thread::sleep(Duration::from_millis(2000));
                end_block = indexer.sync_headers(sync_height, Some(end_height))?;
            }
        }

        let mut start_block = sync_height;
        if db_height < start_block {
            start_block = db_height;
        }

        debug!(
            "Sync'ed headers from {} to {}. DB at {}",
            sync_height, end_block, db_height
        );

        if let Some(target_block_height) = target_block_height_opt {
            // `target_block_height` is used as a hint, but could also be completely off
            // in certain situations. This function is directly reading the
            // headers and syncing with the bitcoin-node, and the interval of blocks
            // to download computed here should be considered as our source of truth.
            if target_block_height > start_block && target_block_height < end_block {
                debug!(
                    "Will download up to max burn block height {}",
                    target_block_height
                );
                end_block = target_block_height;
            } else {
                debug!(
                    "Ignoring target block height {} considered as irrelevant",
                    target_block_height
                );
            }
        }

        if let Some(max_blocks) = max_blocks_opt {
            if start_block + max_blocks < end_block {
                debug!(
                    "Will download only {} blocks (up to block height {})",
                    max_blocks,
                    start_block + max_blocks
                );
                end_block = start_block + max_blocks;

                // make sure we resume at this height next time
                indexer.drop_headers(end_block.saturating_sub(1))?;
            }
        }

        if end_block < start_block {
            // nothing to do -- go get the burnchain block data at that height
            let mut hdrs = indexer.read_headers(end_block, end_block + 1)?;
            if let Some(hdr) = hdrs.pop() {
                debug!("Nothing to do; already have blocks up to {}", end_block);
                let bhh =
                    BurnchainHeaderHash::from_bitcoin_hash(&BitcoinSha256dHash(hdr.header_hash()));
                return burnchain_db
                    .get_burnchain_block(&bhh)
                    .map(|block_data| block_data.header);
            }
        }

        if start_block == db_height && db_height == end_block {
            // all caught up
            return Ok(burn_chain_tip);
        }

        let total = sync_height - self.first_block_height;
        let progress = (end_block - self.first_block_height) as f32 / total as f32 * 100.;
        info!(
            "Syncing STACKS MAINCHAIN blocks: {:.1}% ({} to {} out of {})",
            progress, start_block, end_block, sync_height
        );

        // synchronize
        let (downloader_send, downloader_recv) = sync_channel(1);
        let (parser_send, parser_recv) = sync_channel(1);
        let (db_send, db_recv) = sync_channel(1);

        let mut downloader = indexer.downloader();
        let mut parser = indexer.parser();

        let myself = self.clone();

        // TODO: don't re-process blocks.  See if the block hash is already present in the burn db,
        // and if so, do nothing.
        let download_thread: thread::JoinHandle<Result<(), burnchain_error>> =
            thread::Builder::new()
                .name("burnchain-downloader".to_string())
                .spawn(move || {
                    while let Ok(Some(ipc_header)) = downloader_recv.recv() {
                        debug!("Try recv next header");

                        match should_keep_running {
                            Some(ref should_keep_running)
                                if !should_keep_running.load(Ordering::SeqCst) =>
                            {
                                return Err(burnchain_error::CoordinatorClosed);
                            }
                            _ => {}
                        };

                        let download_start = get_epoch_time_ms();
                        let ipc_block = downloader.download(&ipc_header)?;
                        let download_end = get_epoch_time_ms();

                        debug!(
                            "Downloaded block {} in {}ms",
                            ipc_block.height(),
                            download_end.saturating_sub(download_start)
                        );

                        parser_send
                            .send(Some(ipc_block))
                            .map_err(|_e| burnchain_error::ThreadChannelError)?;
                    }
                    parser_send
                        .send(None)
                        .map_err(|_e| burnchain_error::ThreadChannelError)?;
                    Ok(())
                })
                .unwrap();

        let parse_thread: thread::JoinHandle<Result<(), burnchain_error>> = thread::Builder::new()
            .name("burnchain-parser".to_string())
            .spawn(move || {
                while let Ok(Some(ipc_block)) = parser_recv.recv() {
                    debug!("Try recv next block");

                    let parse_start = get_epoch_time_ms();
                    let burnchain_block = parser.parse(&ipc_block)?;
                    let parse_end = get_epoch_time_ms();

                    debug!(
                        "Parsed block {} in {}ms",
                        burnchain_block.block_height(),
                        parse_end.saturating_sub(parse_start)
                    );

                    db_send
                        .send(Some(burnchain_block))
                        .map_err(|_e| burnchain_error::ThreadChannelError)?;
                }
                db_send
                    .send(None)
                    .map_err(|_e| burnchain_error::ThreadChannelError)?;
                Ok(())
            })
            .unwrap();

        let first_block_hash = self.first_block_hash.clone();
        let db_thread: thread::JoinHandle<Result<BurnchainBlockHeader, burnchain_error>> =
            thread::Builder::new()
                .name("burnchain-db".to_string())
                .spawn(move || {
                    let mut last_processed = burn_chain_tip;
                    while let Ok(Some(burnchain_block)) = db_recv.recv() {
                        debug!("Try recv next parsed block"; "burnchain_block" => ?burnchain_block);
                        let insert_start = get_epoch_time_ms();

                        last_processed =
                            Burnchain::process_block(&myself, &mut burnchain_db, &burnchain_block)
                                .map_err(|e| {
                                    warn!(
                                        "Error processing block";
                                        "burnchain_block" => ?burnchain_block,
                                        "error" => ?e,
                                        "first_hash" => ?first_block_hash
                                    );
                                    e
                                })
                                .unwrap();

                        if !coord_comm.announce_new_burn_block() {
                            warn!("Coordinator communication failed");
                            return Err(burnchain_error::CoordinatorClosed);
                        }
                        let insert_end = get_epoch_time_ms();

                        debug!(
                            "Inserted block {} in {}ms",
                            burnchain_block.block_height(),
                            insert_end.saturating_sub(insert_start)
                        );
                    }
                    Ok(last_processed)
                })
                .unwrap();

        // feed the pipeline!
        let input_headers = indexer.read_headers(start_block + 1, end_block + 1)?;
        let mut downloader_result: Result<(), burnchain_error> = Ok(());
        for i in 0..input_headers.len() {
            debug!(
                "Downloading burnchain block {} out of {}...",
                start_block + 1 + (i as u64),
                end_block
            );
            if let Err(e) = downloader_send.send(Some(input_headers[i].clone())) {
                info!(
                    "Failed to feed burnchain block header {}: {:?}",
                    start_block + 1 + (i as u64),
                    &e
                );
                downloader_result = Err(burnchain_error::TrySyncAgain);
                break;
            }
        }

        if downloader_result.is_ok() {
            if let Err(e) = downloader_send.send(None) {
                info!("Failed to instruct downloader thread to finish: {:?}", &e);
                downloader_result = Err(burnchain_error::TrySyncAgain);
            }
        }

        // join up
        let _ = download_thread.join().unwrap();
        let _ = parse_thread.join().unwrap();
        let block_header = match db_thread.join().unwrap() {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to join burnchain download thread: {:?}", &e);
                if let burnchain_error::CoordinatorClosed = e {
                    return Err(burnchain_error::CoordinatorClosed);
                } else {
                    return Err(burnchain_error::TrySyncAgain);
                }
            }
        };

        if block_header.block_height < end_block {
            warn!(
                "Try synchronizing the burn chain again: final snapshot {} < {}",
                block_header.block_height, end_block
            );
            return Err(burnchain_error::TrySyncAgain);
        }

        if let Err(e) = downloader_result {
            return Err(e);
        }
        update_burnchain_height(block_header.block_height as i64);
        Ok(block_header)
    }
}
