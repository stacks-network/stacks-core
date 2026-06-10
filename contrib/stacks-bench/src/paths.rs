// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::db::app::AppDb;

#[derive(Debug, Clone)]
pub struct AppDataDir(PathBuf);

impl AsRef<Path> for AppDataDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl TryFrom<PathBuf> for AppDataDir {
    type Error = anyhow::Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Ok(AppDataDir(value.canonicalize()?))
    }
}

impl TryFrom<&Path> for AppDataDir {
    type Error = anyhow::Error;

    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        Ok(AppDataDir(value.canonicalize()?))
    }
}

impl AppDataDir {
    pub const APP_DATA_DIR_NAME: &'static str = ".stacks-bench";
    const ENV_VAR: &'static str = "STACKS_BENCH_DATA_DIR";

    /// Resolve the app data directory.
    ///
    /// Order: `--db`, `STACKS_BENCH_DATA_DIR`, then `~/.stacks-bench`.
    pub fn resolve_from_opt<P: AsRef<Path>>(custom_path: Option<P>) -> Result<Self> {
        if let Some(path) = custom_path {
            let path_ref = path.as_ref();
            if path_ref.is_dir() {
                return path_ref.try_into();
            }
            let parent = path_ref.parent().unwrap_or_else(|| Path::new("."));
            let dir = if parent.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                parent.to_path_buf()
            };
            return dir.try_into();
        }

        if let Ok(env_dir) = std::env::var(Self::ENV_VAR) {
            let p = PathBuf::from(env_dir);
            if !p.exists() {
                std::fs::create_dir_all(&p).with_context(|| {
                    format!("Failed to create ${} directory at {p:?}", Self::ENV_VAR)
                })?;
            }
            return p.try_into();
        }

        let home = home::home_dir().ok_or_else(|| anyhow!("Unable to determine home directory"))?;
        let storage_dir = home.join(Self::APP_DATA_DIR_NAME);

        if !storage_dir.exists() {
            std::fs::create_dir_all(&storage_dir)
                .with_context(|| format!("Failed to create data directory at {storage_dir:?}"))?;
        }

        let new_db = storage_dir.join("appdata").join("stacks-bench.db");
        if !new_db.exists()
            && let Some(legacy) = Self::detect_legacy_data_dir()
        {
            eprintln!(
                "Note: stacks-bench data directory has moved to {}\n\
                 Found existing data at {}\n\
                 To migrate: mv {}/* {}/",
                storage_dir.display(),
                legacy.display(),
                legacy.display(),
                storage_dir.display(),
            );
        }

        storage_dir.try_into()
    }

    fn detect_legacy_data_dir() -> Option<PathBuf> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))?;
        let legacy = exe_dir.join(Self::APP_DATA_DIR_NAME);
        if legacy.is_dir() { Some(legacy) } else { None }
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn as_str(&self) -> Result<&str> {
        self.path()
            .to_str()
            .ok_or(anyhow!("Failed to convert app data path to str"))
    }

    pub fn app_db_dir(&self) -> PathBuf {
        self.path().join("appdata")
    }

    pub fn app_db_path(&self) -> PathBuf {
        self.app_db_dir().join(AppDb::DEFAULT_DB_FILENAME)
    }

    pub fn postgres_data_dir(&self) -> PathBuf {
        self.path().join("pgdata")
    }
}

#[derive(Debug, Clone)]
pub struct BurnChainDir(PathBuf);

impl BurnChainDir {
    pub const BURNCHAIN_DIR_NAME: &'static str = "burnchain";
    pub const SORTITION_DB_RELATIVE_FILE_PATH: &str = "sortition/marf.sqlite";

    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        BurnChainDir(path.into())
    }

    pub fn from_node_root<P: AsRef<Path>>(node_root: P) -> Self {
        Self::new(node_root.as_ref().join("burnchain"))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn as_str(&self) -> Result<&str> {
        self.path()
            .to_str()
            .ok_or(anyhow!("Failed to convert burnchain path to str"))
    }

    pub fn sortition_db_path(&self) -> PathBuf {
        self.path().join(Self::SORTITION_DB_RELATIVE_FILE_PATH)
    }
}

impl AsRef<Path> for BurnChainDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

#[derive(Debug, Clone)]
pub struct ChainStateDir(PathBuf);

impl ChainStateDir {
    pub const CHAINSTATE_DIR_NAME: &'static str = "chainstate";
    pub const INDEX_DB_RELATIVE_FILE_PATH: &'static str = "vm/index.sqlite";
    pub const CLARITY_DB_RELATIVE_FILE_PATH: &'static str = "vm/clarity/marf.sqlite";
    pub const BLOCKS_DIR_RELATIVE_PATH: &str = "blocks";
    pub const NAKA_DB_RELATIVE_FILE_PATH: &str = "blocks/nakamoto.sqlite";

    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        ChainStateDir(path.into())
    }

    pub fn from_node_root<P: AsRef<Path>>(node_root: P) -> Self {
        Self::new(node_root.as_ref().join("chainstate"))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn as_str(&self) -> Result<&str> {
        self.path()
            .to_str()
            .ok_or(anyhow!("Failed to convert chainstate path to str"))
    }

    pub fn index_db_path(&self) -> PathBuf {
        self.path().join(Self::INDEX_DB_RELATIVE_FILE_PATH)
    }

    pub fn clarity_db_path(&self) -> PathBuf {
        self.path().join(Self::CLARITY_DB_RELATIVE_FILE_PATH)
    }

    pub fn blocks_dir(&self) -> PathBuf {
        self.path().join(Self::BLOCKS_DIR_RELATIVE_PATH)
    }

    pub fn nakamoto_db_path(&self) -> PathBuf {
        self.path().join(Self::NAKA_DB_RELATIVE_FILE_PATH)
    }
}

impl AsRef<Path> for ChainStateDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}
