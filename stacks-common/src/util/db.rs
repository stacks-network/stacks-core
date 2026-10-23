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

use std::backtrace::Backtrace;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Instant;
use std::{fmt, thread};

use hashbrown::HashMap;
use rand::{thread_rng, Rng};
use rusqlite::types::ToSql;
use rusqlite::{
    Connection, Error as SqliteError, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};

use crate::types::sqlite::NO_PARAMS;
use crate::util::sleep_ms;

// 256MB
pub const SQLITE_MMAP_SIZE: i64 = 256 * 1024 * 1024;

// 32K
pub const SQLITE_MARF_PAGE_SIZE: i64 = 32768;

/// Statement-cache capacity for `sqlite_open` connections. The widest observed
/// working set is ~120 distinct statements (the sortition MARF);
/// rusqlite's default of 16 would LRU-thrash.
pub const SQLITE_STATEMENT_CACHE_CAPACITY: usize = 200;

/// The SQLite VFS (OS interface layer) used to open on-disk databases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SqliteVfs {
    /// SQLite's platform default VFS. Databases can be shared between processes, and every
    /// WAL-mode transaction takes and releases `fcntl` locks on the database and `-shm` files.
    #[default]
    Default,
    /// SQLite's `unix-excl` VFS. The first lock on a database takes an exclusive lock that is
    /// held until the process closes its last connection to it, and the WAL index is kept in
    /// heap memory instead of a `-shm` file. Connections within the process share the database
    /// as usual, but no other process can open it. This removes the per-transaction lock
    /// system calls, which are costly on network and clustered filesystems.
    UnixExcl,
}

impl SqliteVfs {
    const DEFAULT_NAME: &'static str = "default";
    const UNIX_EXCL_NAME: &'static str = "unix-excl";

    /// Name of the SQLite VFS to request at open time, or `None` for SQLite's default.
    fn sqlite_vfs_name(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::UnixExcl => Some(Self::UNIX_EXCL_NAME),
        }
    }

    /// Whether this VFS can only apply its locking model to file handles opened for writing.
    ///
    /// `unix-excl` takes its process-wide lock as a POSIX write lock, which a read-only file
    /// descriptor cannot hold, so SQLite skips the exclusive path for read-only handles and
    /// falls back to per-transaction locking and a `-shm` file for them (`unixFileLock` in
    /// `os_unix.c`).
    fn requires_writable_handles(self) -> bool {
        matches!(self, Self::UnixExcl)
    }

    /// Check that SQLite provides this VFS on the platform the node was built for.
    pub fn ensure_supported(self) -> Result<Self, String> {
        match self {
            Self::UnixExcl if !cfg!(unix) => Err(format!(
                "SQLite VFS '{self}' is only available on unix platforms"
            )),
            _ => Ok(self),
        }
    }
}

impl fmt::Display for SqliteVfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Default => Self::DEFAULT_NAME,
            Self::UnixExcl => Self::UNIX_EXCL_NAME,
        };
        f.write_str(name)
    }
}

impl FromStr for SqliteVfs {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::DEFAULT_NAME => Ok(Self::Default),
            Self::UNIX_EXCL_NAME => Ok(Self::UnixExcl),
            _ => Err(format!(
                "unknown SQLite VFS '{s}' (expected '{}' or '{}')",
                Self::DEFAULT_NAME,
                Self::UNIX_EXCL_NAME
            )),
        }
    }
}

/// A VFS choice that can be made once and is never changed afterwards.
struct SqliteVfsSelection(OnceLock<SqliteVfs>);

impl SqliteVfsSelection {
    const fn new() -> Self {
        Self(OnceLock::new())
    }

    /// Make the choice, or confirm it if `vfs` is already the choice. Returns the VFS already
    /// chosen if it differs.
    fn select(&self, vfs: SqliteVfs) -> Result<(), SqliteVfs> {
        let active = *self.0.get_or_init(|| vfs);
        if active == vfs {
            Ok(())
        } else {
            Err(active)
        }
    }

    /// The VFS chosen, or the default while no choice has been made. Does not make a choice.
    fn current(&self) -> SqliteVfs {
        self.0.get().copied().unwrap_or_default()
    }

    /// The VFS chosen, making the default the choice if none has been made yet.
    fn fix(&self) -> SqliteVfs {
        *self.0.get_or_init(SqliteVfs::default)
    }
}

/// Process-wide VFS used by [`sqlite_open`] and [`sqlite_open_exclusive`]. Fixed by
/// [`set_sqlite_vfs`], or by the first call to either, whichever happens first.
static SQLITE_VFS: SqliteVfsSelection = SqliteVfsSelection::new();

/// Select the VFS used by every [`sqlite_open`] and [`sqlite_open_exclusive`] call in this
/// process.
///
/// The choice is fixed for the lifetime of the process, and it is also fixed implicitly by the
/// first database open, so this must run before any database is opened. Setting the value that
/// is already in effect succeeds; setting a different one returns the VFS already in effect.
pub fn set_sqlite_vfs(vfs: SqliteVfs) -> Result<(), SqliteVfs> {
    SQLITE_VFS.select(vfs)
}

/// The VFS that [`sqlite_open`] uses in this process: the one selected, or the default while
/// none has been selected. Reading it does not fix the choice.
pub fn sqlite_vfs() -> SqliteVfs {
    SQLITE_VFS.current()
}

/// Keep track of DB locks, for deadlock debugging
///  - **key:** `rusqlite::Connection` debug print
///  - **value:** Lock holder (thread name + timestamp)
///
/// This uses a `Mutex` inside of `LazyLock` because:
///  - Using `Mutex` alone, it can't be statically initialized because `HashMap::new()` isn't `const`
///  - Using `LazyLock` alone doesn't allow interior mutability
static LOCK_TABLE: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Generate timestanps for use in `LOCK_TABLE`
/// `Instant` is preferable to `SystemTime` because it uses `CLOCK_MONOTONIC` and is not affected by NTP adjustments
static LOCK_TABLE_TIMER: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Call when using an operation which locks a database
/// Updates `LOCK_TABLE`
pub fn update_lock_table(conn: &Connection) {
    let timestamp = LOCK_TABLE_TIMER.elapsed().as_millis();
    // The debug format for `Connection` includes the path
    let k = format!("{conn:?}");
    let v = format!("{:?}@{timestamp}", thread::current().name());
    LOCK_TABLE.lock().unwrap().insert(k, v);
}

/// Called by `rusqlite` if we are waiting too long on a database lock
/// If called too many times, will assume a deadlock and panic
pub fn tx_busy_handler(run_count: i32) -> bool {
    const AVG_SLEEP_TIME_MS: u64 = 100;

    // Every ~5min, report an error with a backtrace
    //   5min * 60s/min * 1_000ms/s / 100ms
    const ERROR_COUNT: u32 = 3_000;

    // First, check if this is taking unreasonably long. If so, it's probably a deadlock
    let run_count = run_count.unsigned_abs();
    if run_count > 0 && run_count.is_multiple_of(ERROR_COUNT) {
        error!("Deadlock detected. Waited 5 minutes (estimated) for database lock.";
            "run_count" => run_count,
            "backtrace" => ?Backtrace::capture()
        );
        for (k, v) in LOCK_TABLE.lock().unwrap().iter() {
            error!("Database '{k}' last locked by {v}");
        }
    }

    let mut sleep_time_ms = 2u64.saturating_pow(run_count);
    sleep_time_ms = sleep_time_ms.saturating_add(thread_rng().gen_range(0..sleep_time_ms));

    if sleep_time_ms > AVG_SLEEP_TIME_MS {
        let jitter = 10;
        sleep_time_ms =
            thread_rng().gen_range((AVG_SLEEP_TIME_MS - jitter)..(AVG_SLEEP_TIME_MS + jitter));
    }

    let msg = format!("Database is locked; sleeping {sleep_time_ms}ms and trying again");
    if run_count > 10 && run_count.is_multiple_of(10) {
        warn!("{msg}";
            "run_count" => run_count,
            "backtrace" => ?Backtrace::capture()
        );
    } else {
        debug!("{msg}");
    }

    sleep_ms(sleep_time_ms);
    true
}

/// Run a PRAGMA statement.  This can't always be done via execute(), because it may return a result (and
/// rusqlite does not like this).
pub fn sql_pragma(
    conn: &Connection,
    pragma_name: &str,
    pragma_value: &dyn ToSql,
) -> Result<(), SqliteError> {
    conn.pragma_update(None, pragma_name, pragma_value)
}

/// Run a VACUUM command
pub fn sql_vacuum(conn: &Connection) -> Result<(), SqliteError> {
    conn.execute("VACUUM", NO_PARAMS).map(|_| ())
}

/// Returns true if the database table `table_name` exists in the active
///  database of the provided SQLite connection.
pub fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, SqliteError> {
    let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    conn.query_row(sql, [table_name], |row| row.get::<_, String>(0))
        .optional()
        .map(|r| r.is_some())
}

/// Begin an immediate-mode transaction, and handle busy errors with exponential backoff.
/// Handling busy errors when the tx begins is preferable to doing it when the tx commits, since
/// then we don't have to worry about any extra rollback logic.
pub fn tx_begin_immediate(conn: &mut Connection) -> Result<Transaction<'_>, SqliteError> {
    conn.busy_handler(Some(tx_busy_handler))?;
    let tx = Transaction::new(conn, TransactionBehavior::Immediate)?;
    update_lock_table(&tx);
    Ok(tx)
}

#[cfg(feature = "profile-sqlite")]
fn trace_profile(query: &str, duration: std::time::Duration) {
    use serde_json::json;
    let obj = json!({"millis":duration.as_millis(), "query":query});
    debug!(
        "sqlite trace profile {}",
        serde_json::to_string(&obj).unwrap()
    );
}

fn open_connection<P: AsRef<Path>>(
    path: P,
    flags: OpenFlags,
    vfs: SqliteVfs,
) -> Result<Connection, SqliteError> {
    match vfs.sqlite_vfs_name() {
        None => Connection::open_with_flags(path, flags),
        Some(vfs_name) => Connection::open_with_flags_and_vfs(path, flags, vfs_name),
    }
}

#[cfg(feature = "profile-sqlite")]
fn inner_connection_open<P: AsRef<Path>>(
    path: P,
    flags: OpenFlags,
    vfs: SqliteVfs,
) -> Result<Connection, SqliteError> {
    let mut db = open_connection(path, flags, vfs)?;
    db.profile(Some(trace_profile));
    Ok(db)
}

#[cfg(not(feature = "profile-sqlite"))]
fn inner_connection_open<P: AsRef<Path>>(
    path: P,
    flags: OpenFlags,
    vfs: SqliteVfs,
) -> Result<Connection, SqliteError> {
    open_connection(path, flags, vfs)
}

/// Open a database connection and set some typically-used pragmas.
/// Connections are always opened in SQLite multi-thread (`NO_MUTEX`) mode;
/// passing `FULL_MUTEX` panics.
///
/// The connection uses the process-wide VFS (see [`set_sqlite_vfs`]).
pub fn sqlite_open<P: AsRef<Path>>(
    path: P,
    flags: OpenFlags,
    foreign_keys: bool,
) -> Result<Connection, SqliteError> {
    sqlite_open_with_vfs(path, flags, foreign_keys, SQLITE_VFS.fix())
}

fn sqlite_open_with_vfs<P: AsRef<Path>>(
    path: P,
    mut flags: OpenFlags,
    foreign_keys: bool,
    vfs: SqliteVfs,
) -> Result<Connection, SqliteError> {
    // Without an explicit mutex flag the bundled SQLite defaults to serialized
    // mode, whose per-connection mutex is pure overhead here: `Connection` is
    // `!Sync`, so no thread can ever contend on it.
    assert!(
        !flags.contains(OpenFlags::SQLITE_OPEN_FULL_MUTEX),
        "sqlite_open always opens in multi-thread mode; FULL_MUTEX is not supported"
    );
    let read_only = flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY);
    // A read-only file handle would fall outside the VFS's locking model (see
    // `SqliteVfs::requires_writable_handles`). Open it for writing instead, never creating the
    // file, and make the connection itself read-only with `query_only`, so writes still fail
    // with `SQLITE_READONLY` as they would on a read-only handle.
    let emulate_read_only = read_only && vfs.requires_writable_handles();
    if emulate_read_only {
        flags.remove(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_CREATE);
        flags.insert(OpenFlags::SQLITE_OPEN_READ_WRITE);
    }
    flags.insert(OpenFlags::SQLITE_OPEN_NO_MUTEX);
    let db = inner_connection_open(path, flags, vfs)?;
    if emulate_read_only {
        sql_pragma(&db, "query_only", &true)?;
    }
    db.busy_handler(Some(tx_busy_handler))?;
    db.set_prepared_statement_cache_capacity(SQLITE_STATEMENT_CACHE_CAPACITY);
    if !read_only {
        sql_pragma(&db, "journal_mode", &"WAL")?;
    }
    sql_pragma(&db, "synchronous", &"NORMAL")?;
    if foreign_keys {
        sql_pragma(&db, "foreign_keys", &true)?;
    }
    Ok(db)
}

/// Open an existing database for maintenance (e.g. [`sql_vacuum_with_temp`]), with an exclusive
/// lock held until the connection is dropped. It never creates a database.
///
/// Unlike [`sqlite_open`], it never waits for a lock: if another connection has the database
/// open, in this process or another, even idle, it fails at once with `SQLITE_BUSY` (see
/// [`is_busy`]). A connection opened meanwhile with [`sqlite_open`] waits in its busy handler
/// until the lock is released. Like [`sqlite_open`], it uses the process-wide VFS (see
/// [`set_sqlite_vfs`]), in WAL mode.
pub fn sqlite_open_exclusive<P: AsRef<Path>>(path: P) -> Result<Connection, SqliteError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let db = inner_connection_open(path, flags, SQLITE_VFS.fix())?;
    db.busy_timeout(std::time::Duration::ZERO)?;
    // Before the first access, so that SQLite keeps the WAL index in heap memory and never
    // shares the `-shm` file with another process
    sql_pragma(&db, "locking_mode", &"EXCLUSIVE")?;
    db.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
    sql_pragma(&db, "journal_mode", &"WAL")?;
    sql_pragma(&db, "synchronous", &"NORMAL")?;
    Ok(db)
}

/// How a database file is used, in pages (see [`sql_space_usage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceUsage {
    /// Size of a page, in bytes
    pub page_size: u64,
    /// Pages in the database file
    pub page_count: u64,
    /// Pages on the freelist: freed by deletes, reused by later writes, and only given back to
    /// the OS by a `VACUUM`
    pub freelist_count: u64,
}

impl SpaceUsage {
    /// Size of the database file, in bytes, once the WAL is checkpointed
    pub fn file_bytes(&self) -> u64 {
        self.page_count.saturating_mul(self.page_size)
    }

    /// Bytes holding data: what a `VACUUM` keeps
    pub fn live_bytes(&self) -> u64 {
        self.page_count
            .saturating_sub(self.freelist_count)
            .saturating_mul(self.page_size)
    }

    /// Bytes on the freelist: what a `VACUUM` gives back to the OS
    pub fn free_bytes(&self) -> u64 {
        self.freelist_count.saturating_mul(self.page_size)
    }
}

/// How the database of `conn` uses its pages, as the connection sees it: changes still in the
/// WAL are included, so the file on disk has [`SpaceUsage::file_bytes`] only once the WAL is
/// checkpointed (see [`sql_checkpoint_truncate`]).
pub fn sql_space_usage(conn: &Connection) -> Result<SpaceUsage, SqliteError> {
    let pragma = |name: &str| -> Result<u64, SqliteError> {
        conn.pragma_query_value(None, name, |row| row.get(0))
    };
    Ok(SpaceUsage {
        page_size: pragma("page_size")?,
        page_count: pragma("page_count")?,
        freelist_count: pragma("freelist_count")?,
    })
}

/// Write the whole WAL back into the database file, then truncate the WAL to zero bytes.
/// Fails with `SQLITE_BUSY` (see [`is_busy`]) if another connection keeps part of the WAL from
/// being written back.
pub fn sql_checkpoint_truncate(conn: &Connection) -> Result<(), SqliteError> {
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", NO_PARAMS, |row| {
        row.get(0)
    })?;
    if busy != 0 {
        return Err(SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("WAL checkpoint incomplete: another connection is using the database".into()),
        ));
    }
    Ok(())
}

/// Where a `VACUUM` builds its temporary copy of the live data (see [`sql_vacuum_with_temp`]):
/// a file about the size of the live data, deleted as soon as the `VACUUM` ends
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VacuumTemp {
    /// In this directory, e.g. the database's own, on the disk sized for it. It must exist and
    /// be writable.
    Dir(PathBuf),
    /// In SQLite's default temporary directory: on Unix the first usable one of
    /// `SQLITE_TMPDIR`, `TMPDIR`, `/var/tmp`, `/usr/tmp` and `/tmp`
    SystemDefault,
}

/// Rebuild the database file of `conn` in place with only its live data, giving the freelist
/// back to the OS. Run it only when no other connection uses the database, e.g. after
/// [`sqlite_open_exclusive`].
///
/// SQLite first builds a compacted copy of the live data in a temporary file (see
/// [`VacuumTemp`]), then writes it back through a WAL of about the same size next to the
/// database, which [`sql_checkpoint_truncate`] then truncates. If it fails, e.g. for lack of
/// disk space, the database is left as it was. A [`VacuumTemp::Dir`] that is missing, not
/// writable or not valid UTF-8 is rejected before anything is written.
///
/// The connection's `temp_store` and SQLite's process-wide temporary directory are set only for
/// the `VACUUM`, and put back however it ends. Changing `temp_store` drops the connection's
/// temporary tables, indices and views, so if it was not `FILE` before, those are gone.
pub fn sql_vacuum_with_temp(conn: &Connection, temp: &VacuumTemp) -> Result<(), SqliteError> {
    let dir = match temp {
        VacuumTemp::Dir(dir) => Some(
            dir.to_str()
                .ok_or_else(|| SqliteError::InvalidPath(dir.clone()))?,
        ),
        VacuumTemp::SystemDefault => None,
    };
    let previous: i64 = conn.pragma_query_value(None, "temp_store", |row| row.get(0))?;
    // A file, never memory: running out of disk makes the `VACUUM` fail cleanly, whereas
    // running out of memory can get the whole process killed
    sql_pragma(conn, "temp_store", &"FILE")?;
    let result = match dir {
        Some(dir) => vacuum_in_dir(conn, dir),
        None => sql_vacuum(conn),
    };
    // The connection's own setting: 0 (the default), 1 (file) or 2 (memory)
    let restored = sql_pragma(conn, "temp_store", &previous);
    result?;
    restored
}

/// Run a `VACUUM` with SQLite's process-wide temporary directory set to `dir` (see
/// [`sql_vacuum_with_temp`])
fn vacuum_in_dir(conn: &Connection, dir: &str) -> Result<(), SqliteError> {
    // The temporary directory is a global setting of SQLite: while it is set, every connection
    // of the process puts its temporary files there. It is set only for this `VACUUM`, and the
    // previous value is put back however the `VACUUM` ends.
    let previous: Option<String> = conn
        .pragma_query_value(None, "temp_store_directory", |row| row.get(0))
        .optional()?;
    // Rejected at once if the directory is missing or not writable
    sql_pragma(conn, "temp_store_directory", &dir)?;
    let result = sql_vacuum(conn);
    // An empty value puts SQLite's default back
    let restored = sql_pragma(conn, "temp_store_directory", &previous.unwrap_or_default());
    result?;
    restored
}

/// Whether `error` means another connection holds the database, e.g. from
/// [`sqlite_open_exclusive`] while another connection has it open
pub fn is_busy(error: &SqliteError) -> bool {
    matches!(
        error,
        SqliteError::SqliteFailure(e, _)
            if matches!(e.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

/// Whether `error` means the disk ran out of space, e.g. during a `VACUUM`
pub fn is_disk_full(error: &SqliteError) -> bool {
    matches!(
        error,
        SqliteError::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DiskFull
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use rusqlite::{ErrorCode, OpenFlags};

    use super::*;

    const CREATE_FLAGS: OpenFlags =
        OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_CREATE);

    /// A per-test directory under the system temp dir, removed on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(test_name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "stacks-common-db-{test_name}-{}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create test dir");
            Self(dir)
        }

        fn db_path(&self) -> PathBuf {
            self.0.join("test.sqlite")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sidecar(db_path: &Path, suffix: &str) -> PathBuf {
        let mut name = db_path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    }

    fn create_table(conn: &Connection) {
        conn.execute_batch("CREATE TABLE kv (k INTEGER PRIMARY KEY, v TEXT NOT NULL)")
            .expect("create table");
    }

    fn insert(conn: &Connection, k: i64, v: &str) -> Result<usize, SqliteError> {
        conn.execute(
            "INSERT INTO kv (k, v) VALUES (?1, ?2)",
            rusqlite::params![k, v],
        )
    }

    fn value(conn: &Connection, k: i64) -> Option<String> {
        conn.query_row("SELECT v FROM kv WHERE k = ?1", [k], |row| row.get(0))
            .optional()
            .expect("select")
    }

    fn assert_read_only_error(result: Result<usize, SqliteError>) {
        match result {
            Err(SqliteError::SqliteFailure(e, _)) => {
                assert_eq!(e.code, ErrorCode::ReadOnly, "unexpected error: {e:?}")
            }
            other => panic!("expected SQLITE_READONLY, got {other:?}"),
        }
    }

    #[test]
    fn sqlite_vfs_parses_config_values() {
        assert_eq!("default".parse::<SqliteVfs>(), Ok(SqliteVfs::Default));
        assert_eq!("unix-excl".parse::<SqliteVfs>(), Ok(SqliteVfs::UnixExcl));
        for invalid in ["", "unix", "Default", "unix_excl", "win32"] {
            let err = invalid.parse::<SqliteVfs>().unwrap_err();
            assert!(err.contains("unknown SQLite VFS"), "{invalid:?}: {err}");
        }
    }

    #[test]
    fn sqlite_vfs_display_round_trips() {
        assert_eq!(
            SqliteVfs::Default.to_string().parse::<SqliteVfs>(),
            Ok(SqliteVfs::Default)
        );
        assert_eq!(
            SqliteVfs::UnixExcl.to_string().parse::<SqliteVfs>(),
            Ok(SqliteVfs::UnixExcl)
        );
    }

    #[test]
    fn sqlite_vfs_platform_support() {
        assert_eq!(
            SqliteVfs::Default.ensure_supported(),
            Ok(SqliteVfs::Default)
        );
        #[cfg(unix)]
        assert_eq!(
            SqliteVfs::UnixExcl.ensure_supported(),
            Ok(SqliteVfs::UnixExcl)
        );
        #[cfg(not(unix))]
        assert_eq!(
            SqliteVfs::UnixExcl.ensure_supported(),
            Err("SQLite VFS 'unix-excl' is only available on unix platforms".to_string())
        );
    }

    #[test]
    fn reading_vfs_selection_does_not_fix_it() {
        let selection = SqliteVfsSelection::new();
        assert_eq!(selection.current(), SqliteVfs::Default);
        assert_eq!(selection.select(SqliteVfs::UnixExcl), Ok(()));
        assert_eq!(selection.current(), SqliteVfs::UnixExcl);
        assert_eq!(selection.fix(), SqliteVfs::UnixExcl);
        assert_eq!(selection.select(SqliteVfs::UnixExcl), Ok(()));
        assert_eq!(
            selection.select(SqliteVfs::Default),
            Err(SqliteVfs::UnixExcl)
        );
        assert_eq!(selection.current(), SqliteVfs::UnixExcl);
    }

    #[test]
    fn opening_fixes_default_vfs_selection() {
        let selection = SqliteVfsSelection::new();
        assert_eq!(selection.fix(), SqliteVfs::Default);
        assert_eq!(
            selection.select(SqliteVfs::UnixExcl),
            Err(SqliteVfs::Default)
        );
        assert_eq!(selection.current(), SqliteVfs::Default);
    }

    #[test]
    fn sqlite_vfs_is_fixed_once_chosen() {
        // No test in this crate selects `UnixExcl` process-wide, so whether this call or an
        // earlier `sqlite_open` fixed the choice, it is `Default`.
        assert_eq!(set_sqlite_vfs(SqliteVfs::Default), Ok(()));
        assert_eq!(sqlite_vfs(), SqliteVfs::Default);
        assert_eq!(set_sqlite_vfs(SqliteVfs::UnixExcl), Err(SqliteVfs::Default));
        assert_eq!(sqlite_vfs(), SqliteVfs::Default);
    }

    #[test]
    fn default_vfs_keeps_shm_and_read_only_handles() {
        let dir = TestDir::new("default-vfs");
        let db_path = dir.db_path();

        let writer = sqlite_open_with_vfs(&db_path, CREATE_FLAGS, false, SqliteVfs::Default)
            .expect("open writer");
        create_table(&writer);
        insert(&writer, 1, "one").expect("insert");
        assert!(
            sidecar(&db_path, "-shm").exists(),
            "default VFS keeps the WAL index in a -shm file"
        );

        let reader = sqlite_open_with_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            false,
            SqliteVfs::Default,
        )
        .expect("open reader");
        assert!(reader.is_readonly(rusqlite::DatabaseName::Main).unwrap());
        assert_eq!(value(&reader, 1).as_deref(), Some("one"));
        assert_read_only_error(insert(&reader, 2, "two"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_excl_shares_database_within_process_without_shm() {
        let dir = TestDir::new("unix-excl-rw");
        let db_path = dir.db_path();

        let writer = sqlite_open_with_vfs(&db_path, CREATE_FLAGS, false, SqliteVfs::UnixExcl)
            .expect("open writer");
        create_table(&writer);
        insert(&writer, 1, "one").expect("insert");

        let journal_mode: String = writer
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal_mode");
        assert_eq!(journal_mode, "wal", "unix-excl keeps WAL journaling");
        assert!(sidecar(&db_path, "-wal").exists(), "WAL file stays on disk");

        let second = sqlite_open_with_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            false,
            SqliteVfs::UnixExcl,
        )
        .expect("open second connection");
        assert_eq!(value(&second, 1).as_deref(), Some("one"));
        insert(&second, 2, "two").expect("insert through second connection");
        assert_eq!(value(&writer, 2).as_deref(), Some("two"));

        assert!(
            !sidecar(&db_path, "-shm").exists(),
            "unix-excl keeps the WAL index in heap memory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_excl_read_only_request_rejects_writes_without_shm() {
        let dir = TestDir::new("unix-excl-ro");
        let db_path = dir.db_path();

        let writer = sqlite_open_with_vfs(&db_path, CREATE_FLAGS, false, SqliteVfs::UnixExcl)
            .expect("open writer");
        create_table(&writer);
        insert(&writer, 1, "one").expect("insert");

        let reader = sqlite_open_with_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            false,
            SqliteVfs::UnixExcl,
        )
        .expect("open reader");
        let query_only: bool = reader
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .expect("query_only");
        assert!(query_only, "read-only request is enforced by query_only");
        assert_eq!(value(&reader, 1).as_deref(), Some("one"));
        assert_read_only_error(insert(&reader, 2, "two"));
        assert_eq!(value(&writer, 2), None);

        insert(&writer, 3, "three").expect("insert after reader opened");
        assert_eq!(
            value(&reader, 3).as_deref(),
            Some("three"),
            "reader sees writes committed by another connection"
        );

        assert!(
            !sidecar(&db_path, "-shm").exists(),
            "read-only request shares the process lock instead of falling back to a -shm file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_excl_read_only_request_on_unwritable_file_still_opens() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("unix-excl-ro-unwritable");
        let db_path = dir.db_path();
        {
            let writer = sqlite_open_with_vfs(&db_path, CREATE_FLAGS, false, SqliteVfs::Default)
                .expect("open writer");
            create_table(&writer);
            insert(&writer, 1, "one").expect("insert");
        }
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444))
            .expect("make database read-only");

        // SQLite retries a refused read-write open as read-only, so the widened request
        // degrades to a plain read-only handle. Running as root the open succeeds read-write;
        // either way the connection must read and must not write.
        let reader = sqlite_open_with_vfs(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            false,
            SqliteVfs::UnixExcl,
        )
        .expect("open reader on unwritable file");
        assert_eq!(value(&reader, 1).as_deref(), Some("one"));
        assert_read_only_error(insert(&reader, 2, "two"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_excl_read_only_request_never_creates_database() {
        let dir = TestDir::new("unix-excl-ro-missing");
        let db_path = dir.db_path();

        for flags in [
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_CREATE,
        ] {
            sqlite_open_with_vfs(&db_path, flags, false, SqliteVfs::UnixExcl)
                .expect_err("read-only open of a missing database must fail");
            assert!(!db_path.exists(), "{flags:?} created the database file");
        }
    }

    /// Size of a file, or 0 if it does not exist
    fn file_size(path: &Path) -> u64 {
        fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    /// A database at `db_path` with `rows` rows of 1 KiB stored, then all but the first `kept`
    /// deleted, and its WAL checkpointed: most of the file is on the freelist
    fn create_bloated_db(db_path: &Path, rows: i64, kept: i64) {
        let conn = sqlite_open(db_path, CREATE_FLAGS, false).expect("open");
        create_table(&conn);
        let value = "x".repeat(1024);
        for k in 0..rows {
            insert(&conn, k, &value).expect("insert");
        }
        conn.execute("DELETE FROM kv WHERE k >= ?1", [kept])
            .expect("delete");
        sql_checkpoint_truncate(&conn).expect("checkpoint");
    }

    fn row_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM kv", NO_PARAMS, |row| row.get(0))
            .expect("count")
    }

    /// SQLite's process-wide temporary directory, `None` for its default
    fn temp_store_directory(conn: &Connection) -> Option<String> {
        conn.pragma_query_value(None, "temp_store_directory", |row| row.get(0))
            .optional()
            .expect("temp_store_directory")
    }

    /// The `temp_store` setting of `conn`: 0 (the default), 1 (file) or 2 (memory)
    fn temp_store(conn: &Connection) -> i64 {
        conn.pragma_query_value(None, "temp_store", |row| row.get(0))
            .expect("temp_store")
    }

    /// Held by the tests that `VACUUM` with a temporary directory: the setting is process-wide
    /// (see [`sql_vacuum_with_temp`]), and tests run in parallel threads of one process
    fn lock_temp_store_directory() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn open_exclusive_holds_the_lock_without_waiting() {
        let dir = TestDir::new("open-exclusive-lock");
        let db_path = dir.db_path();
        drop(sqlite_open(&db_path, CREATE_FLAGS, false).expect("create"));

        let conn = sqlite_open_exclusive(&db_path).expect("open exclusive");
        // A second exclusive open is refused while the first one is held, without waiting
        let start = Instant::now();
        let err = sqlite_open_exclusive(&db_path).unwrap_err();
        assert!(is_busy(&err), "{err:?}");
        assert!(start.elapsed() < std::time::Duration::from_secs(1));

        drop(conn);
        sqlite_open_exclusive(&db_path).expect("open exclusive again");
    }

    #[test]
    fn open_exclusive_refuses_a_database_in_use() {
        let dir = TestDir::new("open-exclusive-in-use");
        let db_path = dir.db_path();
        let other = sqlite_open(&db_path, CREATE_FLAGS, false).expect("create");
        create_table(&other);

        // idle
        let err = sqlite_open_exclusive(&db_path).unwrap_err();
        assert!(is_busy(&err), "{err:?}");

        // in a read transaction
        other.execute_batch("BEGIN").expect("begin");
        value(&other, 1);
        let err = sqlite_open_exclusive(&db_path).unwrap_err();
        assert!(is_busy(&err), "{err:?}");
        other.execute_batch("COMMIT").expect("commit");

        drop(other);
        sqlite_open_exclusive(&db_path).expect("open exclusive");
    }

    #[test]
    fn open_exclusive_never_creates_a_database() {
        let dir = TestDir::new("open-exclusive-missing");
        let db_path = dir.db_path();
        sqlite_open_exclusive(&db_path).expect_err("no database to open");
        assert!(!db_path.exists());
    }

    #[test]
    fn checkpoint_truncates_the_wal() {
        let dir = TestDir::new("checkpoint-truncate");
        let db_path = dir.db_path();
        let conn = sqlite_open(&db_path, CREATE_FLAGS, false).expect("open");
        create_table(&conn);
        insert(&conn, 1, "one").expect("insert");
        assert!(file_size(&sidecar(&db_path, "-wal")) > 0);

        sql_checkpoint_truncate(&conn).expect("checkpoint");
        assert_eq!(file_size(&sidecar(&db_path, "-wal")), 0);
    }

    #[test]
    fn vacuum_gives_the_freelist_back() {
        let _lock = lock_temp_store_directory();
        let dir = TestDir::new("vacuum-freelist");
        for (i, temp) in [VacuumTemp::Dir(dir.0.clone()), VacuumTemp::SystemDefault]
            .into_iter()
            .enumerate()
        {
            let db_path = dir.0.join(format!("bloated-{i}.sqlite"));
            create_bloated_db(&db_path, 300, 10);
            let conn = sqlite_open_exclusive(&db_path).expect("open exclusive");
            let before = sql_space_usage(&conn).expect("space");
            assert!(before.free_bytes() > before.live_bytes(), "{before:?}");
            assert_eq!(file_size(&db_path), before.file_bytes());

            sql_vacuum_with_temp(&conn, &temp).expect("vacuum");
            sql_checkpoint_truncate(&conn).expect("checkpoint");

            let after = sql_space_usage(&conn).expect("space");
            assert_eq!(after.freelist_count, 0, "{temp:?}");
            assert!(
                after.file_bytes() <= before.live_bytes(),
                "{temp:?}: {after:?} {before:?}"
            );
            assert_eq!(file_size(&db_path), after.file_bytes(), "{temp:?}");
            assert_eq!(file_size(&sidecar(&db_path, "-wal")), 0, "{temp:?}");
            // The data is still there, and the process-wide temporary directory is back to
            // SQLite's default
            assert_eq!(row_count(&conn), 10, "{temp:?}");
            assert_eq!(temp_store_directory(&conn), None, "{temp:?}");
        }
    }

    #[test]
    fn vacuum_refuses_a_missing_temp_dir_and_leaves_the_database() {
        let _lock = lock_temp_store_directory();
        let dir = TestDir::new("vacuum-missing-temp");
        let db_path = dir.db_path();
        create_bloated_db(&db_path, 100, 10);
        let conn = sqlite_open_exclusive(&db_path).expect("open exclusive");
        let before = sql_space_usage(&conn).expect("space");

        sql_pragma(&conn, "temp_store", &"MEMORY").expect("set");
        sql_vacuum_with_temp(&conn, &VacuumTemp::Dir(dir.0.join("missing")))
            .expect_err("a missing directory is rejected");
        assert_eq!(temp_store(&conn), 2);

        assert_eq!(sql_space_usage(&conn).expect("space"), before);
        assert_eq!(file_size(&db_path), before.file_bytes());
        assert_eq!(temp_store_directory(&conn), None);
    }

    #[test]
    fn vacuum_puts_the_previous_temp_dir_back() {
        let _lock = lock_temp_store_directory();
        let dir = TestDir::new("vacuum-restore-temp");
        let db_path = dir.db_path();
        create_bloated_db(&db_path, 100, 10);
        let conn = sqlite_open_exclusive(&db_path).expect("open exclusive");
        let previous = std::env::temp_dir().to_str().expect("utf-8").to_string();
        sql_pragma(&conn, "temp_store_directory", &previous).expect("set");

        sql_vacuum_with_temp(&conn, &VacuumTemp::Dir(dir.0.clone())).expect("vacuum");
        assert_eq!(temp_store_directory(&conn), Some(previous));

        // Back to SQLite's default for the other tests
        sql_pragma(&conn, "temp_store_directory", &"").expect("reset");
        assert_eq!(temp_store_directory(&conn), None);
    }

    #[test]
    fn vacuum_puts_the_previous_temp_store_back() {
        let _lock = lock_temp_store_directory();
        let dir = TestDir::new("vacuum-restore-store");
        for (i, temp) in [VacuumTemp::Dir(dir.0.clone()), VacuumTemp::SystemDefault]
            .into_iter()
            .enumerate()
        {
            let db_path = dir.0.join(format!("bloated-{i}.sqlite"));
            create_bloated_db(&db_path, 100, 10);
            let conn = sqlite_open_exclusive(&db_path).expect("open exclusive");
            for (setting, value) in [("DEFAULT", 0), ("FILE", 1), ("MEMORY", 2)] {
                sql_pragma(&conn, "temp_store", &setting).expect("set");
                sql_vacuum_with_temp(&conn, &temp).expect("vacuum");
                assert_eq!(temp_store(&conn), value, "{temp:?} {setting}");
            }
        }
    }

    #[test]
    fn classifies_busy_and_disk_full_errors() {
        let failure = |code| SqliteError::SqliteFailure(rusqlite::ffi::Error::new(code), None);
        assert!(is_busy(&failure(rusqlite::ffi::SQLITE_BUSY)));
        assert!(is_busy(&failure(rusqlite::ffi::SQLITE_LOCKED)));
        assert!(!is_busy(&failure(rusqlite::ffi::SQLITE_FULL)));
        assert!(is_disk_full(&failure(rusqlite::ffi::SQLITE_FULL)));
        assert!(!is_disk_full(&failure(rusqlite::ffi::SQLITE_BUSY)));
    }
}
