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
use std::marker::PhantomData;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use diesel::prelude::*;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;
use diesel_async::{AsyncConnection, RunQueryDsl};

pub mod app;
pub mod node;

type AsyncSqliteConnection = SyncConnectionWrapper<SqliteConnection>;
type SqlitePool = Pool<AsyncSqliteConnection>;

/// Marker type for read-only database access
#[derive(Debug, Clone, Copy)]
pub struct ReadOnly;
/// Marker type for read-write database access
#[derive(Debug, Clone, Copy)]
pub struct ReadWrite;

/// Trait for opening a database in a specific mode (read-only, read-write).
pub trait DbOpen<Mode>: Sized {
    fn open<P: AsRef<Path> + Debug + Send>(path: P) -> impl Future<Output = Result<Self>> + Send;
}

pub trait DbOpenForRead: Sized {
    fn open_for_read<P: AsRef<Path> + Debug + Send>(
        path: P,
    ) -> impl Future<Output = Result<Self>> + Send;
}

pub trait DbOpenForWrite: Sized {
    fn open_for_write<P: AsRef<Path> + Debug + Send>(
        path: P,
    ) -> impl Future<Output = Result<Self>> + Send;
}

impl<T> DbOpenForRead for T
where
    T: DbOpen<ReadOnly>,
{
    async fn open_for_read<P: AsRef<Path> + Debug + Send>(path: P) -> Result<T> {
        T::open(path).await
    }
}

impl<T> DbOpenForWrite for T
where
    T: DbOpen<ReadWrite>,
{
    async fn open_for_write<P: AsRef<Path> + Debug + Send>(path: P) -> Result<T> {
        T::open(path).await
    }
}

/// A generic handle to a SQLite database connection.
#[derive(Clone)]
pub struct SqliteDbHandle<Mode> {
    pool: SqlitePool,
    _mode: PhantomData<Mode>,
}

impl<Mode> SqliteDbHandle<Mode> {
    pub async fn get_conn(&self) -> Result<PooledConnection<'_, AsyncSqliteConnection>> {
        self.pool
            .get()
            .await
            .context("Failed to get connection from SqliteDbHandle pool")
    }
}

impl DbOpen<ReadOnly> for SqliteDbHandle<ReadOnly> {
    async fn open<P: AsRef<Path> + Debug + Send>(path: P) -> Result<Self> {
        let path_str = path
            .as_ref()
            .to_str()
            .ok_or_else(|| anyhow!("Invalid database path: {:?}", path))?;

        let conn_str = format!("file:{}?mode=ro", path_str);

        let pool = build_pool(conn_str, 16).await?;

        Ok(SqliteDbHandle {
            pool,
            _mode: PhantomData,
        })
    }
}

impl DbOpen<ReadWrite> for SqliteDbHandle<ReadWrite> {
    async fn open<P: AsRef<Path> + Debug + Send>(path: P) -> Result<Self> {
        let path_str = path
            .as_ref()
            .to_str()
            .ok_or_else(|| anyhow!("Invalid database path: {:?}", path))?;

        let pool = build_pool(path_str, 16).await?;

        Ok(SqliteDbHandle {
            pool,
            _mode: PhantomData,
        })
    }
}

async fn build_pool<U: Into<String>>(url: U, size: u32) -> Result<Pool<AsyncSqliteConnection>> {
    let url = url.into();

    let mut manager_config = diesel_async::pooled_connection::ManagerConfig::default();
    manager_config.custom_setup = Box::new(|url| {
        Box::pin(async move {
            let mut conn = AsyncSqliteConnection::establish(url).await?;

            diesel::sql_query("PRAGMA busy_timeout = 10000")
                .execute(&mut conn)
                .await
                .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
            Ok(conn)
        })
    });

    let manager = AsyncDieselConnectionManager::<AsyncSqliteConnection>::new_with_config(
        url.clone(),
        manager_config,
    );

    Pool::builder()
        .max_size(size)
        .min_idle(8)
        .connection_timeout(Duration::from_secs(1))
        .build(manager)
        .await
        .with_context(|| format!("Failed to build SQLite pool (ReadWrite) for URL/path: {url}"))
}
