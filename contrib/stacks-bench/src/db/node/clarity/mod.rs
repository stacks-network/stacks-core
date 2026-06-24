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

use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use anyhow::{Context, Result};
use diesel_async::RunQueryDsl;

use crate::db::{DbOpen, ReadWrite, SqliteDbHandle};

pub mod models;
pub mod schema;

#[derive(Clone)]
pub struct ClarityDb<Mode> {
    handle: SqliteDbHandle<Mode>,
}

impl<Mode> Deref for ClarityDb<Mode> {
    type Target = SqliteDbHandle<Mode>;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<Mode> DerefMut for ClarityDb<Mode> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

/// Generic implementation: If [`SqliteDbHandle`] can be opened in Mode,
/// then [`ClarityDb`] can also be opened in Mode.
impl<Mode> DbOpen<Mode> for ClarityDb<Mode>
where
    SqliteDbHandle<Mode>: DbOpen<Mode>,
{
    async fn open<P: AsRef<Path> + Debug + Send>(path: P) -> Result<Self> {
        Ok(Self {
            handle: SqliteDbHandle::<Mode>::open(path).await?,
        })
    }
}

impl ClarityDb<ReadWrite> {
    pub async fn checkpoint(&mut self) -> Result<()> {
        diesel::sql_query("PRAGMA wal_checkpoint(FULL)")
            .execute(&mut self.handle.get_conn().await?)
            .await
            .context("Failed to perform WAL checkpoint")?;

        Ok(())
    }

    pub async fn vacuum(&mut self) -> Result<()> {
        diesel::sql_query("VACUUM")
            .execute(&mut self.handle.get_conn().await?)
            .await
            .context("Failed to vacuum the database")?;
        Ok(())
    }
}
