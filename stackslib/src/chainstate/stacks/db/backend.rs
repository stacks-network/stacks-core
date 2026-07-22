// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::path::PathBuf;
use std::{fs, io};

use stacks_common::types::sqlite::NO_PARAMS;

use super::*;
use crate::chainstate::nakamoto::staging_blocks::NakamotoStagingBlocksDb;
use crate::chainstate::stacks::index::marf::test_override_marf_compression;
use crate::util_lib::db::query_row;
#[cfg(any(test, feature = "testing"))]
use crate::util_lib::db::sqlite_memory_namespace;

#[derive(Debug, Clone)]
pub struct MissingBackendComponent;

#[derive(Clone)]
pub struct ChainStateBackend<I, C, B, S> {
    index: I,
    clarity: C,
    blocks: B,
    staging_blocks: S,
}

impl ChainStateBackend<(), (), (), ()> {
    pub fn builder() -> ChainStateBackendBuilder<
        MissingBackendComponent,
        MissingBackendComponent,
        MissingBackendComponent,
        MissingBackendComponent,
    > {
        ChainStateBackendBuilder::new()
    }
}

impl<I, C, B, S> ChainStateBackend<I, C, B, S> {
    pub fn components(&self) -> (&I, &C, &B, &S) {
        (
            &self.index,
            &self.clarity,
            &self.blocks,
            &self.staging_blocks,
        )
    }
}

pub struct ChainStateBackendBuilder<I, C, B, S> {
    index: I,
    clarity: C,
    blocks: B,
    staging_blocks: S,
}

impl
    ChainStateBackendBuilder<
        MissingBackendComponent,
        MissingBackendComponent,
        MissingBackendComponent,
        MissingBackendComponent,
    >
{
    pub fn new() -> Self {
        Self {
            index: MissingBackendComponent,
            clarity: MissingBackendComponent,
            blocks: MissingBackendComponent,
            staging_blocks: MissingBackendComponent,
        }
    }
}

impl<I, C, B, S> ChainStateBackendBuilder<I, C, B, S> {
    pub fn with_index<I2>(self, index: I2) -> ChainStateBackendBuilder<I2, C, B, S> {
        ChainStateBackendBuilder {
            index,
            clarity: self.clarity,
            blocks: self.blocks,
            staging_blocks: self.staging_blocks,
        }
    }

    pub fn with_clarity<C2>(self, clarity: C2) -> ChainStateBackendBuilder<I, C2, B, S> {
        ChainStateBackendBuilder {
            index: self.index,
            clarity,
            blocks: self.blocks,
            staging_blocks: self.staging_blocks,
        }
    }

    pub fn with_blocks<B2>(self, blocks: B2) -> ChainStateBackendBuilder<I, C, B2, S> {
        ChainStateBackendBuilder {
            index: self.index,
            clarity: self.clarity,
            blocks,
            staging_blocks: self.staging_blocks,
        }
    }

    pub fn with_staging_blocks<S2>(
        self,
        staging_blocks: S2,
    ) -> ChainStateBackendBuilder<I, C, B, S2> {
        ChainStateBackendBuilder {
            index: self.index,
            clarity: self.clarity,
            blocks: self.blocks,
            staging_blocks,
        }
    }
}

impl<I, C, B, S> ChainStateBackendBuilder<I, C, B, S>
where
    I: IndexDbBackend,
    C: ClarityDbBackend,
    B: BlockStoreBackend,
    S: StagingBlocksBackend,
{
    pub fn build(self) -> ChainStateBackend<I, C, B, S> {
        ChainStateBackend {
            index: self.index,
            clarity: self.clarity,
            blocks: self.blocks,
            staging_blocks: self.staging_blocks,
        }
    }
}

#[derive(Clone)]
pub struct ChainStateOpenConfig {
    pub mainnet: bool,
    pub chain_id: u32,
    pub root_path: String,
    pub marf_opts: Option<MARFOpenOpts>,
}

pub struct ChainStateOpenParts {
    pub clarity_state: ClarityInstance,
    pub nakamoto_staging_blocks_conn: NakamotoStagingBlocksConn,
    pub state_index: MARF<StacksBlockId>,
    pub blocks_path: String,
    pub clarity_state_index_path: String,
    pub clarity_state_index_root: String,
    pub root_path: String,
    pub marf_opts: Option<MARFOpenOpts>,
}

/// Chainstate schema creation and migration helpers.
pub struct ChainStateSchema;

impl ChainStateSchema {
    pub fn load_db_config(conn: &DBConn) -> Result<DBConfig, db_error> {
        let config = query_row::<DBConfig, _>(conn, "SELECT * FROM db_config LIMIT 1", NO_PARAMS)?;
        Ok(config.expect("BUG: no db_config installed"))
    }

    pub(crate) fn instantiate_db(
        mainnet: bool,
        chain_id: u32,
        marf_path: &str,
        migrate: bool,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<MARF<StacksBlockId>, Error> {
        Self::instantiate_db_with_external_blobs(
            mainnet, chain_id, marf_path, migrate, marf_opts, true,
        )
    }

    pub(crate) fn instantiate_db_with_external_blobs(
        mainnet: bool,
        chain_id: u32,
        marf_path: &str,
        migrate: bool,
        marf_opts: Option<MARFOpenOpts>,
        external_blobs: bool,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let mut marf =
            DiskIndexDb::open_marf_index_with_external_blobs(marf_path, marf_opts, external_blobs)?;
        let mut dbtx = StacksDBTx::new(&mut marf, ());

        {
            let tx = dbtx.tx();

            for cmd in CHAINSTATE_INITIAL_SCHEMA {
                tx.execute_batch(cmd)?;
            }
            tx.execute(
                "INSERT INTO db_config (version,mainnet,chain_id) VALUES (?1,?2,?3)",
                params!["1".to_string(), (if mainnet { 1 } else { 0 }), chain_id,],
            )?;

            if migrate {
                Self::apply_schema_migrations(tx, mainnet, chain_id)?;
            }

            Self::add_indexes(tx)?;
        }

        dbtx.instantiate_index()?;
        dbtx.commit()?;
        Ok(marf)
    }

    /// Do we need a schema migration?
    /// Return Ok(true) if so
    /// Return Ok(false) if not
    /// Return Err(..) on DB errors, or if this DB is not consistent with `mainnet` or `chain_id`
    pub(crate) fn need_schema_migrations(
        conn: &Connection,
        mainnet: bool,
        chain_id: u32,
    ) -> Result<bool, Error> {
        let db_config = Self::load_db_config(conn).expect("CORRUPTION: no db_config found");

        if db_config.mainnet != mainnet {
            error!(
                "Invalid chain state database: expected mainnet = {}, got {}",
                mainnet, db_config.mainnet
            );
            return Err(Error::InvalidChainstateDB);
        }

        if db_config.chain_id != chain_id {
            error!(
                "Invalid chain ID: expected {}, got {}",
                chain_id, db_config.chain_id
            );
            return Err(Error::InvalidChainstateDB);
        }

        Ok(db_config.version != CHAINSTATE_VERSION)
    }

    pub(crate) fn apply_schema_migrations(
        tx: &DBTx<'_>,
        mainnet: bool,
        chain_id: u32,
    ) -> Result<(), Error> {
        if !Self::need_schema_migrations(tx, mainnet, chain_id)? {
            return Ok(());
        }

        let mut db_config = Self::load_db_config(tx).expect("CORRUPTION: no db_config found");

        while db_config.version != CHAINSTATE_VERSION {
            match db_config.version.as_str() {
                "1" => {
                    info!("Migrating chainstate schema from version 1 to 2");
                    for cmd in CHAINSTATE_SCHEMA_2.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "2" => {
                    info!("Migrating chainstate schema from version 2 to 3");
                    for cmd in CHAINSTATE_SCHEMA_3.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "3" => {
                    info!("Migrating chainstate schema from version 3 to 4: nakamoto support");
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_1.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "4" => {
                    info!(
                        "Migrating chainstate schema from version 4 to 5: fix nakamoto tenure typo"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_2.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "5" => {
                    info!("Migrating chainstate schema from version 5 to 6: adds height_in_tenure field");
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_3.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "6" => {
                    info!(
                        "Migrating chainstate schema from version 6 to 7: adds signer_stats table"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_4.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "7" => {
                    info!(
                        "Migrating chainstate schema from version 7 to 8: add index for nakamoto block headers"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_5.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "8" => {
                    info!(
                        "Migrating chainstate schema from version 8 to 9: add index for staging_blocks"
                    );
                    for cmd in CHAINSTATE_SCHEMA_4.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "9" => {
                    info!(
                        "Migrating chainstate schema from version 9 to 10: add index for nakamoto_block_headers"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_6.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "10" => {
                    info!(
                        "Migrating chainstate schema from version 10 to 11: drop affirmation_weight from block_headers"
                    );
                    for cmd in CHAINSTATE_SCHEMA_5.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "11" => {
                    info!(
                        "Migrating chainstate schema from version 11 to 12: add index for nakamoto_block_headers"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_7.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                "12" => {
                    info!(
                        "Migrating chainstate schema from version 12 to 13: add total_tenure_size field"
                    );
                    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_8.iter() {
                        tx.execute_batch(cmd)?;
                    }
                }
                _ => {
                    error!(
                        "Invalid chain state database: expected version = {}, got {}",
                        CHAINSTATE_VERSION, db_config.version
                    );
                    return Err(Error::InvalidChainstateDB);
                }
            }
            db_config = Self::load_db_config(tx).expect("CORRUPTION: no db_config found");
        }
        Ok(())
    }

    pub(crate) fn add_indexes(tx: &DBTx<'_>) -> Result<(), Error> {
        for cmd in CHAINSTATE_INDEXES {
            tx.execute_batch(cmd)?;
        }
        Ok(())
    }
}

/// Disk-backed chainstate path layout helpers.
pub struct DiskChainStateLayout;

impl DiskChainStateLayout {
    pub(crate) fn blocks_path(mut path: PathBuf) -> PathBuf {
        path.push("blocks");
        path
    }

    pub(crate) fn vm_state_path(mut path: PathBuf) -> PathBuf {
        path.push("vm");
        path
    }

    pub(crate) fn vm_state_index_root_path(path: PathBuf) -> PathBuf {
        let mut ret = Self::vm_state_path(path);
        ret.push("clarity");
        ret
    }

    pub(crate) fn vm_state_index_marf_path(path: PathBuf) -> PathBuf {
        let mut ret = Self::vm_state_index_root_path(path);
        ret.push("marf.sqlite");
        ret
    }

    pub(crate) fn header_index_root_path(path: PathBuf) -> PathBuf {
        let mut ret = Self::vm_state_path(path);
        ret.push("index.sqlite");
        ret
    }

    pub(crate) fn nakamoto_staging_blocks_path(root_path: PathBuf) -> Result<String, Error> {
        let mut nakamoto_blocks_path = Self::blocks_path(root_path);
        nakamoto_blocks_path.push("nakamoto.sqlite");
        Ok(nakamoto_blocks_path
            .to_str()
            .ok_or(Error::DBError(db_error::ParseError))?
            .to_string())
    }

    pub(crate) fn make_chainstate_dirs(path_str: &str) -> Result<(), Error> {
        #[cfg(any(test, feature = "testing"))]
        if Self::is_ephemeral_root_path(path_str) {
            return Err(Error::DBError(db_error::Other(
                "ephemeral chainstate roots are not filesystem paths".into(),
            )));
        }

        let path = PathBuf::from(path_str);
        Self::mkdirs(&path)?;

        let blocks_path = Self::blocks_path(path.clone());
        Self::mkdirs(&blocks_path)?;

        let vm_state_path = Self::vm_state_path(path);
        Self::mkdirs(&vm_state_path)?;
        Ok(())
    }

    /// Load the chainstate DBConfig, given the path to the chainstate root.
    pub(crate) fn get_db_config_from_path(
        chainstate_root_path: &str,
    ) -> Result<DBConfig, db_error> {
        #[cfg(any(test, feature = "testing"))]
        if Self::is_ephemeral_root_path(chainstate_root_path) {
            return Err(db_error::Other(
                "ephemeral chainstate roots cannot be reopened from a filesystem path".into(),
            ));
        }

        let index_pathbuf = Self::header_index_root_path(PathBuf::from(chainstate_root_path));
        let index_path = index_pathbuf
            .to_str()
            .ok_or_else(|| db_error::ParseError)?
            .to_string();

        let marf = DiskIndexDb::open_marf_index(&index_path, None)?;
        ChainStateSchema::load_db_config(marf.sqlite_conn())
    }

    /// Idempotent `mkdir -p`
    pub(crate) fn mkdirs(path: &PathBuf) -> Result<(), Error> {
        match fs::metadata(path) {
            Ok(md) => {
                if !md.is_dir() {
                    error!("Not a directory: {:?}", path);
                    return Err(Error::DBError(db_error::ExistsError));
                }
                Ok(())
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    return Err(Error::DBError(db_error::IOError(e)));
                }
                fs::create_dir_all(path).map_err(|e| Error::DBError(db_error::IOError(e)))
            }
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn ephemeral_root_path() -> Result<String, Error> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::DBError(db_error::Other(e.to_string())))?
            .as_nanos();
        Ok(format!(
            "memory://stacks-chainstate/{}-{}",
            std::process::id(),
            nanos
        ))
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn is_ephemeral_root_path(path: &str) -> bool {
        path.starts_with("memory://stacks-chainstate/")
    }
}

pub trait IndexDbBackend: Clone + Send + Sync + 'static {
    fn open_index(
        &self,
        config: &ChainStateOpenConfig,
    ) -> Result<(MARF<StacksBlockId>, String), Error>;

    fn reopen_index(
        &self,
        config: &ChainStateOpenConfig,
        source: &MARF<StacksBlockId>,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        let _ = source;
        self.open_index(config)
    }

    fn open_mining_candidate_index(
        &self,
        config: &ChainStateOpenConfig,
        source: &MARF<StacksBlockId>,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        self.reopen_index(config, source)
    }
}

pub trait ClarityDbBackend: Clone + Send + Sync + 'static {
    fn open_clarity(
        &self,
        config: &ChainStateOpenConfig,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error>;

    fn reopen_clarity(
        &self,
        config: &ChainStateOpenConfig,
        source: &ClarityInstance,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        let _ = source;
        self.open_clarity(config, miner_tip)
    }

    fn open_mining_candidate_clarity(
        &self,
        config: &ChainStateOpenConfig,
        source: &ClarityInstance,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        self.reopen_clarity(config, source, miner_tip)
    }
}

pub trait BlockStoreBackend: Clone + Send + Sync + 'static {
    fn blocks_path(&self, config: &ChainStateOpenConfig) -> Result<String, Error>;

    fn reopen_blocks_path(
        &self,
        config: &ChainStateOpenConfig,
        source_blocks_path: &str,
    ) -> Result<String, Error> {
        let _ = source_blocks_path;
        self.blocks_path(config)
    }

    fn open_mining_candidate_blocks_path(
        &self,
        config: &ChainStateOpenConfig,
        source_blocks_path: &str,
    ) -> Result<String, Error> {
        self.reopen_blocks_path(config, source_blocks_path)
    }
}

pub trait StagingBlocksBackend: Clone + Send + Sync + 'static {
    fn open_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
    ) -> Result<NakamotoStagingBlocksConn, Error>;

    fn reopen_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        let _ = source;
        self.open_staging_blocks(config)
    }

    fn open_mining_candidate_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        self.reopen_staging_blocks(config, source)
    }
}

pub trait ChainStatePersistence: Clone + Send + Sync + 'static {
    fn open_parts(&self, config: &ChainStateOpenConfig) -> Result<ChainStateOpenParts, Error>;

    fn reopen_shared_parts<SourceBackend: ChainStatePersistence>(
        &self,
        config: &ChainStateOpenConfig,
        source: &StacksChainState<SourceBackend>,
    ) -> Result<ChainStateOpenParts, Error>;

    fn open_mining_candidate_parts<SourceBackend: ChainStatePersistence>(
        &self,
        config: &ChainStateOpenConfig,
        source: &StacksChainState<SourceBackend>,
    ) -> Result<ChainStateOpenParts, Error>;

    fn reopen_nakamoto_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error>;
}

impl<I, C, B, S> ChainStatePersistence for ChainStateBackend<I, C, B, S>
where
    I: IndexDbBackend,
    C: ClarityDbBackend,
    B: BlockStoreBackend,
    S: StagingBlocksBackend,
{
    fn open_parts(&self, config: &ChainStateOpenConfig) -> Result<ChainStateOpenParts, Error> {
        let (state_index, _header_index_root) = self.index.open_index(config)?;
        let (clarity_state, clarity_state_index_path, clarity_state_index_root) =
            self.clarity.open_clarity(
                config,
                Some(&StacksBlockHeader::make_index_block_hash(
                    &MINER_BLOCK_CONSENSUS_HASH,
                    &MINER_BLOCK_HEADER_HASH,
                )),
            )?;
        let blocks_path = self.blocks.blocks_path(config)?;
        let nakamoto_staging_blocks_conn = self.staging_blocks.open_staging_blocks(config)?;

        Ok(ChainStateOpenParts {
            clarity_state,
            nakamoto_staging_blocks_conn,
            state_index,
            blocks_path,
            clarity_state_index_path,
            clarity_state_index_root,
            root_path: config.root_path.clone(),
            marf_opts: config.marf_opts.clone(),
        })
    }

    fn reopen_shared_parts<SourceBackend: ChainStatePersistence>(
        &self,
        config: &ChainStateOpenConfig,
        source: &StacksChainState<SourceBackend>,
    ) -> Result<ChainStateOpenParts, Error> {
        let (state_index, _header_index_root) =
            self.index.reopen_index(config, &source.state_index)?;
        let (clarity_state, clarity_state_index_path, clarity_state_index_root) = self
            .clarity
            .reopen_clarity(config, &source.clarity_state, None)?;
        let blocks_path = self
            .blocks
            .reopen_blocks_path(config, &source.blocks_path)?;
        let nakamoto_staging_blocks_conn = self
            .staging_blocks
            .reopen_staging_blocks(config, &source.nakamoto_staging_blocks_conn)?;

        Ok(ChainStateOpenParts {
            clarity_state,
            nakamoto_staging_blocks_conn,
            state_index,
            blocks_path,
            clarity_state_index_path,
            clarity_state_index_root,
            root_path: config.root_path.clone(),
            marf_opts: config.marf_opts.clone(),
        })
    }

    fn open_mining_candidate_parts<SourceBackend: ChainStatePersistence>(
        &self,
        config: &ChainStateOpenConfig,
        source: &StacksChainState<SourceBackend>,
    ) -> Result<ChainStateOpenParts, Error> {
        let (state_index, _header_index_root) = self
            .index
            .open_mining_candidate_index(config, &source.state_index)?;
        let (clarity_state, clarity_state_index_path, clarity_state_index_root) = self
            .clarity
            .open_mining_candidate_clarity(config, &source.clarity_state, None)?;
        let blocks_path = self
            .blocks
            .open_mining_candidate_blocks_path(config, &source.blocks_path)?;
        let nakamoto_staging_blocks_conn = self
            .staging_blocks
            .open_mining_candidate_staging_blocks(config, &source.nakamoto_staging_blocks_conn)?;

        Ok(ChainStateOpenParts {
            clarity_state,
            nakamoto_staging_blocks_conn,
            state_index,
            blocks_path,
            clarity_state_index_path,
            clarity_state_index_root,
            root_path: config.root_path.clone(),
            marf_opts: config.marf_opts.clone(),
        })
    }

    fn reopen_nakamoto_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        self.staging_blocks.reopen_staging_blocks(config, source)
    }
}

macro_rules! delegate_chain_state_persistence {
    ($backend:ty) => {
        impl ChainStatePersistence for $backend {
            fn open_parts(
                &self,
                config: &ChainStateOpenConfig,
            ) -> Result<ChainStateOpenParts, Error> {
                self.inner.open_parts(config)
            }

            fn reopen_shared_parts<SourceBackend: ChainStatePersistence>(
                &self,
                config: &ChainStateOpenConfig,
                source: &StacksChainState<SourceBackend>,
            ) -> Result<ChainStateOpenParts, Error> {
                self.inner.reopen_shared_parts(config, source)
            }

            fn open_mining_candidate_parts<SourceBackend: ChainStatePersistence>(
                &self,
                config: &ChainStateOpenConfig,
                source: &StacksChainState<SourceBackend>,
            ) -> Result<ChainStateOpenParts, Error> {
                self.inner.open_mining_candidate_parts(config, source)
            }

            fn reopen_nakamoto_staging_blocks(
                &self,
                config: &ChainStateOpenConfig,
                source: &NakamotoStagingBlocksConn,
            ) -> Result<NakamotoStagingBlocksConn, Error> {
                self.inner.reopen_nakamoto_staging_blocks(config, source)
            }
        }
    };
}

#[derive(Clone)]
pub struct DiskChainStateBackend {
    inner: ChainStateBackend<DiskIndexDb, DiskClarityDb, DiskBlockStore, DiskStagingBlocks>,
}

impl DiskChainStateBackend {
    pub fn for_root(root_path: &str) -> Result<Self, Error> {
        let root = PathBuf::from(root_path);
        let blocks_path = DiskChainStateLayout::blocks_path(root.clone())
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();
        let clarity_state_index_root = DiskChainStateLayout::vm_state_index_root_path(root.clone())
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();
        let clarity_state_index_path = DiskChainStateLayout::vm_state_index_marf_path(root.clone())
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();
        let header_index_root = DiskChainStateLayout::header_index_root_path(root.clone())
            .to_str()
            .ok_or_else(|| Error::DBError(db_error::ParseError))?
            .to_string();
        let staging_blocks_path = DiskChainStateLayout::nakamoto_staging_blocks_path(root)?;

        Ok(Self {
            inner: ChainStateBackend::builder()
                .with_index(DiskIndexDb::new(header_index_root))
                .with_clarity(DiskClarityDb::new(
                    clarity_state_index_path,
                    clarity_state_index_root,
                ))
                .with_blocks(DiskBlockStore::new(blocks_path))
                .with_staging_blocks(DiskStagingBlocks::new(staging_blocks_path))
                .build(),
        })
    }
}

delegate_chain_state_persistence!(DiskChainStateBackend);

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct MemoryChainStateBackend {
    inner: ChainStateBackend<MemoryIndexDb, MemoryClarityDb, MemoryBlockStore, MemoryStagingBlocks>,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryChainStateBackend {
    pub fn for_namespace(namespace: &str) -> Self {
        Self {
            inner: ChainStateBackend::builder()
                .with_index(MemoryIndexDb::new(namespace))
                .with_clarity(MemoryClarityDb::new(namespace))
                .with_blocks(MemoryBlockStore::new(namespace))
                .with_staging_blocks(MemoryStagingBlocks::new(namespace))
                .build(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
delegate_chain_state_persistence!(MemoryChainStateBackend);

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct SharedMemoryChainStateBackend {
    inner: ChainStateBackend<
        SharedMemoryIndexDb,
        SharedMemoryClarityDb,
        MemoryBlockStore,
        SharedMemoryStagingBlocks,
    >,
}

#[cfg(any(test, feature = "testing"))]
impl SharedMemoryChainStateBackend {
    pub fn for_namespace(namespace: &str) -> Self {
        Self {
            inner: ChainStateBackend::builder()
                .with_index(SharedMemoryIndexDb::new(namespace))
                .with_clarity(SharedMemoryClarityDb::new(namespace))
                .with_blocks(MemoryBlockStore::new(namespace))
                .with_staging_blocks(SharedMemoryStagingBlocks::new(namespace))
                .build(),
        }
    }

    /// Snapshot an existing in-memory chainstate into this backend's namespace.
    pub(crate) fn snapshot_parts<SourceBackend: ChainStatePersistence>(
        &self,
        config: &ChainStateOpenConfig,
        source: &StacksChainState<SourceBackend>,
    ) -> Result<ChainStateOpenParts, Error> {
        let state_index = source
            .state_index
            .try_clone_ephemeral_at(&self.inner.index.path)?;
        let clarity_state = source
            .clarity_state
            .try_clone_ephemeral_at(&self.inner.clarity.path)
            .map_err(|e| Error::ClarityError(e.into()))?;
        let blocks_path = self
            .inner
            .blocks
            .reopen_blocks_path(config, &source.blocks_path)?;
        let nakamoto_staging_blocks_conn = source
            .nakamoto_staging_blocks_conn
            .try_clone_ephemeral_at(&self.inner.staging_blocks.path)?;

        Ok(ChainStateOpenParts {
            clarity_state,
            nakamoto_staging_blocks_conn,
            state_index,
            blocks_path,
            clarity_state_index_path: self.inner.clarity.path.clone(),
            clarity_state_index_root: self.inner.clarity.path.clone(),
            root_path: config.root_path.clone(),
            marf_opts: config.marf_opts.clone(),
        })
    }
}

#[cfg(any(test, feature = "testing"))]
delegate_chain_state_persistence!(SharedMemoryChainStateBackend);

#[derive(Clone)]
pub struct DiskIndexDb {
    header_index_root: String,
}

impl DiskIndexDb {
    pub fn new(header_index_root: impl Into<String>) -> Self {
        Self {
            header_index_root: header_index_root.into(),
        }
    }

    pub(crate) fn open_db(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            ChainStateSchema::instantiate_db(mainnet, chain_id, index_path, true, marf_opts.clone())
        } else {
            let mut marf = Self::open_marf_index(index_path, marf_opts)?;
            if !ChainStateSchema::need_schema_migrations(marf.sqlite_conn(), mainnet, chain_id)? {
                return Ok(marf);
            }

            // need a migration
            let tx = marf.storage_tx()?;
            ChainStateSchema::apply_schema_migrations(&tx, mainnet, chain_id)?;
            ChainStateSchema::add_indexes(&tx)?;
            tx.commit()?;
            Ok(marf)
        }
    }

    #[cfg(test)]
    pub(crate) fn open_db_without_migrations(
        mainnet: bool,
        chain_id: u32,
        index_path: &str,
    ) -> Result<MARF<StacksBlockId>, Error> {
        let create_flag = fs::metadata(index_path).is_err();

        if create_flag {
            // instantiate!
            ChainStateSchema::instantiate_db(mainnet, chain_id, index_path, false, None)
        } else {
            let mut marf = Self::open_marf_index(index_path, None)?;

            // do we need to apply a schema change?
            let _db_config = ChainStateSchema::load_db_config(marf.sqlite_conn())
                .expect("CORRUPTION: no db_config found");

            let tx = marf.storage_tx()?;
            ChainStateSchema::add_indexes(&tx)?;
            tx.commit()?;
            Ok(marf)
        }
    }

    /// Open or create the chainstate MARF index database and its associated blobs file.
    ///
    /// This function opens the SQLite-based MARF index at `marf_path`. If the index
    /// database or its corresponding blobs file does not exist, they will be created.
    ///
    /// # Arguments
    /// * `marf_path` - Path to the MARF SQLite index database.
    /// * `marf_opts` - Configuration options for opening the MARF.
    ///
    /// # Behavior
    /// Given a `marf_path` such as `chainstate/vm/clarity/index.sqlite`,
    /// the related blobs file will be `chainstate/vm/clarity/index.sqlite.blobs`.
    pub(crate) fn open_marf_index(
        marf_path: &str,
        marf_opts: Option<MARFOpenOpts>,
    ) -> Result<MARF<StacksBlockId>, db_error> {
        Self::open_marf_index_with_external_blobs(marf_path, marf_opts, true)
    }

    pub(crate) fn open_marf_index_with_external_blobs(
        marf_path: &str,
        marf_opts: Option<MARFOpenOpts>,
        external_blobs: bool,
    ) -> Result<MARF<StacksBlockId>, db_error> {
        test_debug!("Open MARF index at {}", marf_path);
        let mut open_opts = marf_opts.unwrap_or(MARFOpenOpts::default());
        open_opts.external_blobs = external_blobs;
        test_override_marf_compression(&mut open_opts);
        let marf = MARF::from_path(marf_path, open_opts).map_err(db_error::IndexError)?;
        Ok(marf)
    }
}

impl IndexDbBackend for DiskIndexDb {
    fn open_index(
        &self,
        config: &ChainStateOpenConfig,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        let state_index = DiskIndexDb::open_db(
            config.mainnet,
            config.chain_id,
            &self.header_index_root,
            config.marf_opts.clone(),
        )?;
        Ok((state_index, self.header_index_root.clone()))
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct MemoryIndexDb {
    namespace: String,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryIndexDb {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl IndexDbBackend for MemoryIndexDb {
    fn open_index(
        &self,
        config: &ChainStateOpenConfig,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        let _ = &self.namespace;
        let state_index = ChainStateSchema::instantiate_db_with_external_blobs(
            config.mainnet,
            config.chain_id,
            ":memory:",
            true,
            config.marf_opts.clone(),
            false,
        )?;
        Ok((state_index, ":memory:".into()))
    }

    fn reopen_index(
        &self,
        _config: &ChainStateOpenConfig,
        source: &MARF<StacksBlockId>,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        Ok((source.try_clone_ephemeral()?, ":memory:".into()))
    }

    fn open_mining_candidate_index(
        &self,
        config: &ChainStateOpenConfig,
        source: &MARF<StacksBlockId>,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        self.reopen_index(config, source)
    }
}

#[derive(Clone)]
pub struct DiskClarityDb {
    clarity_state_index_path: String,
    clarity_state_index_root: String,
}

impl DiskClarityDb {
    pub fn new(
        clarity_state_index_path: impl Into<String>,
        clarity_state_index_root: impl Into<String>,
    ) -> Self {
        Self {
            clarity_state_index_path: clarity_state_index_path.into(),
            clarity_state_index_root: clarity_state_index_root.into(),
        }
    }
}

impl ClarityDbBackend for DiskClarityDb {
    fn open_clarity(
        &self,
        config: &ChainStateOpenConfig,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        let vm_state = MarfedKV::open(
            &self.clarity_state_index_root,
            miner_tip,
            config.marf_opts.clone(),
        )
        .map_err(|e| Error::ClarityError(e.into()))?;
        Ok((
            ClarityInstance::new(config.mainnet, config.chain_id, vm_state),
            self.clarity_state_index_path.clone(),
            self.clarity_state_index_root.clone(),
        ))
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct MemoryClarityDb {
    namespace: String,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryClarityDb {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl ClarityDbBackend for MemoryClarityDb {
    fn open_clarity(
        &self,
        config: &ChainStateOpenConfig,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        let _ = &self.namespace;
        let vm_state = MarfedKV::open_ephemeral(miner_tip, config.marf_opts.clone())
            .map_err(|e| Error::ClarityError(e.into()))?;
        Ok((
            ClarityInstance::new(config.mainnet, config.chain_id, vm_state),
            ":memory:".into(),
            ":memory:".into(),
        ))
    }

    fn reopen_clarity(
        &self,
        _config: &ChainStateOpenConfig,
        source: &ClarityInstance,
        _miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        Ok((
            source
                .try_clone_ephemeral()
                .map_err(|e| Error::ClarityError(e.into()))?,
            ":memory:".into(),
            ":memory:".into(),
        ))
    }

    fn open_mining_candidate_clarity(
        &self,
        config: &ChainStateOpenConfig,
        source: &ClarityInstance,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        self.reopen_clarity(config, source, miner_tip)
    }
}

#[derive(Clone)]
pub struct DiskBlockStore {
    blocks_path: String,
}

impl DiskBlockStore {
    pub fn new(blocks_path: impl Into<String>) -> Self {
        Self {
            blocks_path: blocks_path.into(),
        }
    }
}

impl BlockStoreBackend for DiskBlockStore {
    fn blocks_path(&self, _config: &ChainStateOpenConfig) -> Result<String, Error> {
        Ok(self.blocks_path.clone())
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct MemoryBlockStore {
    namespace: String,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryBlockStore {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl BlockStoreBackend for MemoryBlockStore {
    fn blocks_path(&self, _config: &ChainStateOpenConfig) -> Result<String, Error> {
        Ok(EphemeralBlockStore::blocks_path(&self.namespace))
    }

    fn reopen_blocks_path(
        &self,
        _config: &ChainStateOpenConfig,
        source_blocks_path: &str,
    ) -> Result<String, Error> {
        let dst_blocks_path = EphemeralBlockStore::blocks_path(&self.namespace);
        EphemeralBlockStore::clone_store(source_blocks_path, &dst_blocks_path)?;
        Ok(dst_blocks_path)
    }

    fn open_mining_candidate_blocks_path(
        &self,
        config: &ChainStateOpenConfig,
        source_blocks_path: &str,
    ) -> Result<String, Error> {
        self.reopen_blocks_path(config, source_blocks_path)
    }
}

#[derive(Clone)]
pub struct DiskStagingBlocks {
    path: String,
}

impl DiskStagingBlocks {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl StagingBlocksBackend for DiskStagingBlocks {
    fn open_staging_blocks(
        &self,
        _config: &ChainStateOpenConfig,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        NakamotoStagingBlocksDb::open_nakamoto_staging_blocks(&self.path, true)
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct MemoryStagingBlocks {
    namespace: String,
}

#[cfg(any(test, feature = "testing"))]
impl MemoryStagingBlocks {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl StagingBlocksBackend for MemoryStagingBlocks {
    fn open_staging_blocks(
        &self,
        _config: &ChainStateOpenConfig,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        let _ = &self.namespace;
        NakamotoStagingBlocksDb::open_nakamoto_staging_blocks_ephemeral()
    }

    fn reopen_staging_blocks(
        &self,
        _config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        Ok(source.try_clone_ephemeral()?)
    }

    fn open_mining_candidate_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        self.reopen_staging_blocks(config, source)
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct SharedMemoryIndexDb {
    path: String,
}

#[cfg(any(test, feature = "testing"))]
impl SharedMemoryIndexDb {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            path: shared_sqlite_memory_path(&namespace.into(), "headers"),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl IndexDbBackend for SharedMemoryIndexDb {
    fn open_index(
        &self,
        config: &ChainStateOpenConfig,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        let state_index = ChainStateSchema::instantiate_db_with_external_blobs(
            config.mainnet,
            config.chain_id,
            &self.path,
            true,
            config.marf_opts.clone(),
            false,
        )?;
        Ok((state_index, self.path.clone()))
    }

    fn reopen_index(
        &self,
        config: &ChainStateOpenConfig,
        _source: &MARF<StacksBlockId>,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        let state_index = DiskIndexDb::open_marf_index_with_external_blobs(
            &self.path,
            config.marf_opts.clone(),
            false,
        )
        .map_err(Error::DBError)?;
        Ok((state_index, self.path.clone()))
    }

    fn open_mining_candidate_index(
        &self,
        config: &ChainStateOpenConfig,
        source: &MARF<StacksBlockId>,
    ) -> Result<(MARF<StacksBlockId>, String), Error> {
        self.reopen_index(config, source)
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct SharedMemoryClarityDb {
    path: String,
}

#[cfg(any(test, feature = "testing"))]
impl SharedMemoryClarityDb {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            path: shared_sqlite_memory_path(&namespace.into(), "clarity"),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl ClarityDbBackend for SharedMemoryClarityDb {
    fn open_clarity(
        &self,
        config: &ChainStateOpenConfig,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        let vm_state =
            MarfedKV::open_shared_ephemeral(&self.path, miner_tip, config.marf_opts.clone())
                .map_err(|e| Error::ClarityError(e.into()))?;
        Ok((
            ClarityInstance::new(config.mainnet, config.chain_id, vm_state),
            self.path.clone(),
            self.path.clone(),
        ))
    }

    fn reopen_clarity(
        &self,
        config: &ChainStateOpenConfig,
        _source: &ClarityInstance,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        self.open_clarity(config, miner_tip)
    }

    fn open_mining_candidate_clarity(
        &self,
        config: &ChainStateOpenConfig,
        source: &ClarityInstance,
        miner_tip: Option<&StacksBlockId>,
    ) -> Result<(ClarityInstance, String, String), Error> {
        self.reopen_clarity(config, source, miner_tip)
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Clone)]
pub struct SharedMemoryStagingBlocks {
    path: String,
}

#[cfg(any(test, feature = "testing"))]
impl SharedMemoryStagingBlocks {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            path: shared_sqlite_memory_path(&namespace.into(), "staging-blocks"),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl StagingBlocksBackend for SharedMemoryStagingBlocks {
    fn open_staging_blocks(
        &self,
        _config: &ChainStateOpenConfig,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        NakamotoStagingBlocksDb::open_nakamoto_staging_blocks(&self.path, true)
    }

    fn reopen_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        _source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        self.open_staging_blocks(config)
    }

    fn open_mining_candidate_staging_blocks(
        &self,
        config: &ChainStateOpenConfig,
        source: &NakamotoStagingBlocksConn,
    ) -> Result<NakamotoStagingBlocksConn, Error> {
        self.reopen_staging_blocks(config, source)
    }
}

#[cfg(any(test, feature = "testing"))]
fn shared_sqlite_memory_path(namespace: &str, component: &str) -> String {
    let namespace = sqlite_memory_namespace(namespace);
    format!("file:{namespace}-{component}?mode=memory&cache=shared")
}

pub fn disk_backend_for_root(root_path: &str) -> Result<DiskChainStateBackend, Error> {
    DiskChainStateBackend::for_root(root_path)
}

#[cfg(any(test, feature = "testing"))]
pub fn memory_backend_for_namespace(namespace: &str) -> MemoryChainStateBackend {
    MemoryChainStateBackend::for_namespace(namespace)
}

#[cfg(any(test, feature = "testing"))]
pub fn shared_memory_backend_for_namespace(namespace: &str) -> SharedMemoryChainStateBackend {
    SharedMemoryChainStateBackend::for_namespace(namespace)
}
