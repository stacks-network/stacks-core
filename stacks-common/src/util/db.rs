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
use std::path::Path;
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
            Self::UNIX_EXCL_NAME if cfg!(unix) => Ok(Self::UnixExcl),
            Self::UNIX_EXCL_NAME => Err(format!(
                "SQLite VFS '{s}' is only available on unix platforms"
            )),
            _ => Err(format!(
                "unknown SQLite VFS '{s}' (expected '{}' or '{}')",
                Self::DEFAULT_NAME,
                Self::UNIX_EXCL_NAME
            )),
        }
    }
}

/// Process-wide VFS used by [`sqlite_open`]. Fixed by [`set_sqlite_vfs`], or by the first
/// [`sqlite_open`] call, whichever happens first.
static SQLITE_VFS: OnceLock<SqliteVfs> = OnceLock::new();

/// Select the VFS used by every [`sqlite_open`] call in this process.
///
/// The choice is fixed for the lifetime of the process, and it is also fixed implicitly by the
/// first database open, so this must run before any database is opened. Setting the value that
/// is already in effect succeeds; setting a different one returns the VFS already in effect.
pub fn set_sqlite_vfs(vfs: SqliteVfs) -> Result<(), SqliteVfs> {
    let active = *SQLITE_VFS.get_or_init(|| vfs);
    if active == vfs {
        Ok(())
    } else {
        Err(active)
    }
}

/// The VFS used by [`sqlite_open`] in this process.
pub fn sqlite_vfs() -> SqliteVfs {
    *SQLITE_VFS.get_or_init(SqliteVfs::default)
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
    sqlite_open_with_vfs(path, flags, foreign_keys, sqlite_vfs())
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
        #[cfg(unix)]
        assert_eq!("unix-excl".parse::<SqliteVfs>(), Ok(SqliteVfs::UnixExcl));
        #[cfg(not(unix))]
        assert!("unix-excl".parse::<SqliteVfs>().is_err());
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
        #[cfg(unix)]
        assert_eq!(
            SqliteVfs::UnixExcl.to_string().parse::<SqliteVfs>(),
            Ok(SqliteVfs::UnixExcl)
        );
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
}
