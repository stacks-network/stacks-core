use rusqlite::{Connection, OptionalExtension};

use crate::chainstate::burn::db::sortdb::{
    SortitionDB, SortitionDBConn, SortitionHandleConn, SortitionHandleTx,
};
use crate::chainstate::stacks::db::{MinerPaymentSchedule, StacksHeaderInfo};
use crate::chainstate::stacks::index::MarfTrieId;
use crate::util_lib::db::{DBConn, FromRow};
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::database::{
    BurnStateDB, ClarityBackingStore, ClarityDatabase, HeadersDB, SqliteConnection,
    NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use clarity::vm::errors::{InterpreterResult, RuntimeErrorType};

use crate::chainstate::stacks::db::ChainstateTx;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::{ClarityMarfTrieId, TrieMerkleProof};
use crate::types::chainstate::StacksBlockId;
use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, SortitionId};
use crate::types::chainstate::{StacksAddress, VRFSeed};

use crate::core::StacksEpoch;
use crate::core::StacksEpochId;
use std::ops::{Deref, DerefMut};

use crate::clarity_vm::special::handle_contract_call_special_cases;
use clarity::vm::database::SpecialCaseHandler;

pub mod marf;

pub struct HeadersDBConn<'a>(pub &'a Connection);

impl<'a> HeadersDB for HeadersDBConn<'a> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        get_stacks_header_info(self.0, id_bhh).map(|x| x.anchored_header.block_hash())
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        get_stacks_header_info(self.0, id_bhh).map(|x| x.burn_header_hash)
    }

    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        get_stacks_header_info(self.0, id_bhh).map(|x| x.burn_header_timestamp)
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        get_stacks_header_info(self.0, id_bhh).map(|x| x.burn_header_height)
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        get_stacks_header_info(self.0, id_bhh)
            .map(|x| VRFSeed::from_proof(&x.anchored_header.proof))
    }

    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        get_miner_info(self.0, id_bhh).map(|x| x.address)
    }
}

impl<'a> HeadersDB for ChainstateTx<'a> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        get_stacks_header_info(self.deref().deref(), id_bhh).map(|x| x.anchored_header.block_hash())
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        get_stacks_header_info(self.deref().deref(), id_bhh).map(|x| x.burn_header_hash)
    }

    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        get_stacks_header_info(self.deref().deref(), id_bhh).map(|x| x.burn_header_timestamp)
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        get_stacks_header_info(self.deref().deref(), id_bhh).map(|x| x.burn_header_height)
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        get_stacks_header_info(self.deref().deref(), id_bhh)
            .map(|x| VRFSeed::from_proof(&x.anchored_header.proof))
    }

    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        get_miner_info(self.deref().deref(), id_bhh).map(|x| x.address)
    }
}

impl HeadersDB for crate::chainstate::stacks::index::marf::MARF<StacksBlockId> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        get_stacks_header_info(self.sqlite_conn(), id_bhh).map(|x| x.anchored_header.block_hash())
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        get_stacks_header_info(self.sqlite_conn(), id_bhh).map(|x| x.burn_header_hash)
    }

    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        get_stacks_header_info(self.sqlite_conn(), id_bhh).map(|x| x.burn_header_timestamp)
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        get_stacks_header_info(self.sqlite_conn(), id_bhh).map(|x| x.burn_header_height)
    }

    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        get_stacks_header_info(self.sqlite_conn(), id_bhh)
            .map(|x| VRFSeed::from_proof(&x.anchored_header.proof))
    }

    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        get_miner_info(self.sqlite_conn(), id_bhh).map(|x| x.address)
    }
}

fn get_stacks_header_info(conn: &DBConn, id_bhh: &StacksBlockId) -> Option<StacksHeaderInfo> {
    conn.query_row(
        "SELECT * FROM block_headers WHERE index_block_hash = ?",
        [id_bhh].iter(),
        |x| Ok(StacksHeaderInfo::from_row(x).expect("Bad stacks header info in database")),
    )
    .optional()
    .expect("Unexpected SQL failure querying block header table")
}

fn get_miner_info(conn: &DBConn, id_bhh: &StacksBlockId) -> Option<MinerPaymentSchedule> {
    conn.query_row(
        "SELECT * FROM payments WHERE index_block_hash = ? AND miner = 1",
        [id_bhh].iter(),
        |x| Ok(MinerPaymentSchedule::from_row(x).expect("Bad payment info in database")),
    )
    .optional()
    .expect("Unexpected SQL failure querying payment table")
}

impl BurnStateDB for SortitionHandleTx<'_> {
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        match SortitionDB::get_block_snapshot(self.tx(), sortition_id) {
            Ok(Some(x)) => Some(x.block_height as u32),
            _ => return None,
        }
    }

    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        let readonly_marf = self
            .index()
            .reopen_readonly()
            .expect("BUG: failure trying to get a read-only interface into the sortition db.");
        let mut context = self.context.clone();
        context.chain_tip = sortition_id.clone();
        let db_handle = SortitionHandleConn::new(&readonly_marf, context);
        match db_handle.get_block_snapshot_by_height(height as u64) {
            Ok(Some(x)) => Some(x.burn_header_hash),
            _ => return None,
        }
    }

    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch(self.tx(), height as u64)
            .expect("BUG: failed to get epoch for burn block height")
    }

    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch_by_epoch_id(self.tx(), epoch_id)
            .expect("BUG: failed to get epoch for epoch id")
    }
}

impl BurnStateDB for SortitionDBConn<'_> {
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        match SortitionDB::get_block_snapshot(self.conn(), sortition_id) {
            Ok(Some(x)) => Some(x.block_height as u32),
            _ => return None,
        }
    }

    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        let db_handle = SortitionHandleConn::open_reader(self, &sortition_id).ok()?;
        match db_handle.get_block_snapshot_by_height(height as u64) {
            Ok(Some(x)) => Some(x.burn_header_hash),
            _ => return None,
        }
    }

    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch(self.conn(), height as u64)
            .expect("BUG: failed to get epoch for burn block height")
    }

    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        SortitionDB::get_stacks_epoch_by_epoch_id(self.conn(), epoch_id)
            .expect("BUG: failed to get epoch for epoch id")
    }
}

pub struct MemoryBackingStore {
    side_store: Connection,
}

impl MemoryBackingStore {
    pub fn new() -> MemoryBackingStore {
        let side_store = SqliteConnection::memory().unwrap();

        let mut memory_marf = MemoryBackingStore { side_store };

        memory_marf.as_clarity_db().initialize();

        memory_marf
    }

    pub fn as_clarity_db<'a>(&'a mut self) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    pub fn as_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        Err(RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into())
    }

    fn get(&mut self, key: &str) -> Option<String> {
        SqliteConnection::get(self.get_side_store(), key)
    }

    fn get_with_proof(&mut self, key: &str) -> Option<(String, Vec<u8>)> {
        SqliteConnection::get(self.get_side_store(), key).map(|x| (x, vec![]))
    }

    fn get_side_store(&mut self) -> &Connection {
        &self.side_store
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        if height == 0 {
            Some(StacksBlockId::sentinel())
        } else {
            None
        }
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId::sentinel()
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        0
    }

    fn get_current_block_height(&mut self) -> u32 {
        0
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        Some(&handle_contract_call_special_cases)
    }

    fn put_all(&mut self, items: Vec<(String, String)>) {
        for (key, value) in items.into_iter() {
            SqliteConnection::put(self.get_side_store(), &key, &value);
        }
    }
}
