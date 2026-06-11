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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock as StdRwLock};

use anyhow::{Context, Result, anyhow};
use blockstack_lib::chainstate::stacks::{StacksTransaction, TransactionPayload};
use chrono::NaiveDateTime;
use diesel::sql_types::{BigInt, Binary, Nullable, Text};
use diesel::upsert::excluded;
use diesel::{
    ExpressionMethods as _, JoinOnDsl as _, NullableExpressionMethods as _, OptionalExtension as _,
    QueryDsl as _, QueryableByName, SelectableHelper as _, SqliteConnection, sql_query,
};
use diesel_async::pooled_connection::bb8::{Pool, PooledConnection};
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, ManagerConfig};
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;
use diesel_async::{
    AsyncConnection, AsyncMigrationHarness, RunQueryDsl as _, SimpleAsyncConnection,
};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use futures::FutureExt;
use futures::future::BoxFuture;
use globset::{Glob, GlobSet, GlobSetBuilder};
use models::*;
use schema::*;
use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use stacks_common::types::chainstate::StacksBlockId;
use tokio::sync::RwLock;

use crate::blocks::{BlockHeaderProvider, BlockRef, ChainCache};
use crate::metrics::BlockMetrics;
use crate::{StacksBlockHeader, StacksEpoch};

pub mod models;
pub mod schema;
mod util;

use super::{AsyncSqliteConnection, SqlitePool};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

const MERGE_STAGING_SQL: &str = include_str!("scripts/merge_staging.sql");
const POST_RUN_SQL: &str = include_str!("scripts/post_run.sql");
const MERGE_PROFILER_KV_SQL: &str = include_str!("scripts/merge_profiler_kv.sql");
const MERGE_PROFILER_CLARITY_COSTS_SQL: &str =
    include_str!("scripts/merge_profiler_clarity_costs.sql");

#[derive(Debug, Clone, Copy)]
pub enum SynchronizationMode {
    Normal,
    Off,
}

#[derive(Debug, Clone, Copy)]
pub enum ForeignKeyMode {
    Enforced,
    Off,
}

#[derive(Debug, Clone, Copy)]
pub enum CheckpointMode {
    Full,
    Truncate,
    Restart,
    Passive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilerThresholdNs(pub u64);

impl FromStr for ProfilerThresholdNs {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("duration cannot be empty".to_string());
        }

        let split_at = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        let (number, unit) = s.split_at(split_at);
        if number.is_empty() {
            return Err(format!("duration '{raw}' is missing a number"));
        }
        if number.matches('.').count() > 1 {
            return Err(format!("duration '{raw}' has too many decimal points"));
        }

        let value: f64 = number
            .parse()
            .map_err(|_| format!("duration '{raw}' has an invalid number"))?;
        if !value.is_finite() || value < 0.0 {
            return Err(format!(
                "duration '{raw}' must be a non-negative finite value"
            ));
        }

        let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
            "ns" | "nsec" | "nanosecond" | "nanoseconds" => 1.0,
            "us" | "µs" | "μs" | "usec" | "microsecond" | "microseconds" => 1_000.0,
            "ms" | "msec" | "millisecond" | "milliseconds" => 1_000_000.0,
            "s" | "sec" | "second" | "seconds" => 1_000_000_000.0,
            "" => {
                return Err(format!(
                    "duration '{raw}' is missing a unit (use ns, us, ms, or s)"
                ));
            }
            other => return Err(format!("duration '{raw}' has unsupported unit '{other}'")),
        };

        let nanos = value * multiplier;
        if nanos > u64::MAX as f64 {
            return Err(format!("duration '{raw}' is too large"));
        }

        Ok(Self(nanos.round() as u64))
    }
}

impl std::fmt::Display for ProfilerThresholdNs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ns", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfilerThresholdMetric {
    Wall,
    SelfWall,
    Cpu,
    SelfCpu,
    Wait,
    SelfWait,
}

impl FromStr for ProfilerThresholdMetric {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        match raw {
            "wall" => Ok(Self::Wall),
            "self-wall" => Ok(Self::SelfWall),
            "cpu" => Ok(Self::Cpu),
            "self-cpu" => Ok(Self::SelfCpu),
            "wait" => Ok(Self::Wait),
            "self-wait" => Ok(Self::SelfWait),
            other => Err(format!(
                "unsupported threshold metric '{other}' (use wall, self-wall, cpu, self-cpu, wait, or self-wait)"
            )),
        }
    }
}

impl std::fmt::Display for ProfilerThresholdMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Wall => "wall",
            Self::SelfWall => "self-wall",
            Self::Cpu => "cpu",
            Self::SelfCpu => "self-cpu",
            Self::Wait => "wait",
            Self::SelfWait => "self-wait",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfilerThreshold {
    pub metric: ProfilerThresholdMetric,
    pub threshold: ProfilerThresholdNs,
}

impl FromStr for ProfilerThreshold {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        let (metric, duration) = if let Some((metric, duration)) = raw.split_once(':') {
            if duration.starts_with(':') {
                return Err(format!("threshold '{raw}' has too many ':' separators"));
            }
            (metric.parse()?, duration)
        } else {
            (ProfilerThresholdMetric::Wall, raw)
        };

        Ok(Self {
            metric,
            threshold: duration.parse()?,
        })
    }
}

impl std::fmt::Display for ProfilerThreshold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.metric, self.threshold)
    }
}

impl Serialize for ProfilerThreshold {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProfilerThreshold {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ProfilerThresholdVisitor)
    }
}

struct ProfilerThresholdVisitor;

impl<'de> Visitor<'de> for ProfilerThresholdVisitor {
    type Value = ProfilerThreshold;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a profiler threshold string, nanosecond integer, or threshold object")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        value.parse().map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_str(&value)
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(ProfilerThreshold {
            metric: ProfilerThresholdMetric::Wall,
            threshold: ProfilerThresholdNs(value),
        })
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        let value = u64::try_from(value)
            .map_err(|_| E::custom("profiler threshold nanoseconds must be non-negative"))?;
        self.visit_u64(value)
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut metric = None;
        let mut threshold = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "metric" => metric = Some(map.next_value()?),
                "threshold" => threshold = Some(map.next_value()?),
                _ => {
                    let _ = map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }

        Ok(ProfilerThreshold {
            metric: metric.unwrap_or(ProfilerThresholdMetric::Wall),
            threshold: threshold.ok_or_else(|| A::Error::missing_field("threshold"))?,
        })
    }
}

pub fn deserialize_profiler_thresholds<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ProfilerThreshold>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(ProfilerThresholdListVisitor)
}

struct ProfilerThresholdListVisitor;

impl<'de> Visitor<'de> for ProfilerThresholdListVisitor {
    type Value = Vec<ProfilerThreshold>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a profiler threshold or a list of profiler thresholds")
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Vec::new())
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Vec::new())
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        value
            .parse()
            .map(|threshold| vec![threshold])
            .map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_str(&value)
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(vec![ProfilerThreshold {
            metric: ProfilerThresholdMetric::Wall,
            threshold: ProfilerThresholdNs(value),
        }])
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        let value = u64::try_from(value)
            .map_err(|_| E::custom("profiler threshold nanoseconds must be non-negative"))?;
        self.visit_u64(value)
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut thresholds = Vec::new();
        while let Some(threshold) = seq.next_element()? {
            thresholds.push(threshold);
        }
        Ok(thresholds)
    }

    fn visit_map<A>(self, map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        ProfilerThresholdVisitor
            .visit_map(map)
            .map(|threshold| vec![threshold])
    }
}

impl ProfilerThreshold {
    fn matches(&self, timing: ProfilerNodeTiming) -> bool {
        let observed = match self.metric {
            ProfilerThresholdMetric::Wall => timing.wall,
            ProfilerThresholdMetric::SelfWall => timing.self_wall,
            ProfilerThresholdMetric::Cpu => timing.cpu,
            ProfilerThresholdMetric::SelfCpu => timing.self_cpu,
            ProfilerThresholdMetric::Wait => timing.wait,
            ProfilerThresholdMetric::SelfWait => timing.self_wait,
        };
        observed >= self.threshold.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfilerNodeTiming {
    wall: u64,
    self_wall: u64,
    cpu: u64,
    self_cpu: u64,
    wait: u64,
    self_wait: u64,
}

impl ProfilerNodeTiming {
    fn from_node(node: &stacks_profiler::ProfileStats) -> Self {
        let children_wall = node
            .children
            .iter()
            .map(|child| child.wall_time_ns)
            .sum::<u64>();
        let children_cpu = node
            .children
            .iter()
            .map(|child| child.cpu_time_ns)
            .sum::<u64>();
        let self_wall = node.wall_time_ns.saturating_sub(children_wall);
        let self_cpu = node.cpu_time_ns.saturating_sub(children_cpu);

        Self {
            wall: node.wall_time_ns,
            self_wall,
            cpu: node.cpu_time_ns,
            self_cpu,
            wait: node.wall_time_ns.saturating_sub(node.cpu_time_ns),
            self_wait: self_wall.saturating_sub(self_cpu),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfilerSpanMode {
    All,
    BenchOnly,
    Include,
    Exclude,
}

type ProfilerSpanKey = (Option<&'static str>, &'static str);
type ProfilerDecisionCache = Arc<StdRwLock<HashMap<ProfilerSpanKey, bool>>>;
type ProfilerSpanCache = Arc<RwLock<HashMap<ProfilerSpanKey, i32>>>;

#[derive(Debug, Clone)]
pub struct ProfilerStoragePolicy {
    mode: ProfilerSpanMode,
    thresholds: Arc<[ProfilerThreshold]>,
    patterns: Arc<GlobSet>,
    decision_cache: ProfilerDecisionCache,
}

impl ProfilerStoragePolicy {
    pub fn new(
        no_profiler: bool,
        thresholds: &[ProfilerThreshold],
        spans: &[String],
        ignored_spans: &[String],
    ) -> Result<Self> {
        if !spans.is_empty() && !ignored_spans.is_empty() {
            anyhow::bail!("--span and --ignore-span are mutually exclusive");
        }
        if no_profiler && !thresholds.is_empty() {
            anyhow::bail!("--no-profiler and --profiler-threshold are mutually exclusive");
        }
        if no_profiler && (!spans.is_empty() || !ignored_spans.is_empty()) {
            anyhow::bail!("--no-profiler cannot be combined with --span or --ignore-span");
        }

        let mode = if no_profiler {
            ProfilerSpanMode::BenchOnly
        } else if !spans.is_empty() {
            ProfilerSpanMode::Include
        } else if !ignored_spans.is_empty() {
            ProfilerSpanMode::Exclude
        } else {
            ProfilerSpanMode::All
        };

        let mut builder = GlobSetBuilder::new();
        for pattern in spans.iter().chain(ignored_spans.iter()) {
            builder.add(
                Glob::new(pattern)
                    .with_context(|| format!("Invalid profiler span pattern '{pattern}'"))?,
            );
        }

        Ok(Self {
            mode,
            thresholds: Arc::from(thresholds),
            patterns: Arc::new(
                builder
                    .build()
                    .context("Failed to build profiler span filter")?,
            ),
            decision_cache: Arc::new(StdRwLock::new(HashMap::new())),
        })
    }

    pub fn keep_tree(&self, node: &stacks_profiler::ProfileStats) -> ProfilerKeepTree {
        let keep_self = self.keep_node_self(node);
        let children: Vec<Option<ProfilerKeepTree>> = node
            .children
            .iter()
            .map(|child| {
                let child_tree = self.keep_tree(child);
                child_tree.should_insert().then_some(child_tree)
            })
            .collect();

        ProfilerKeepTree {
            keep_self,
            children,
        }
    }

    fn keep_node_self(&self, node: &stacks_profiler::ProfileStats) -> bool {
        if is_stacks_bench_span(node.context()) {
            return true;
        }
        if !self.name_policy_allows(node.context(), node.name()) {
            return false;
        }
        if self.thresholds.is_empty() {
            return true;
        }
        let timing = ProfilerNodeTiming::from_node(node);
        self.thresholds
            .iter()
            .any(|threshold| threshold.matches(timing))
    }

    fn name_policy_allows(&self, context: Option<&'static str>, name: &'static str) -> bool {
        if self.mode == ProfilerSpanMode::All {
            return true;
        }
        if self.mode == ProfilerSpanMode::BenchOnly {
            return false;
        }

        if let Some(&cached) = self
            .decision_cache
            .read()
            .expect("poisoned lock")
            .get(&(context, name))
        {
            return cached;
        }

        let matched = self.matches_pattern(context, name);
        let allowed = match self.mode {
            ProfilerSpanMode::All => true,
            ProfilerSpanMode::BenchOnly => false,
            ProfilerSpanMode::Include => matched,
            ProfilerSpanMode::Exclude => !matched,
        };

        self.decision_cache
            .write()
            .expect("poisoned lock")
            .insert((context, name), allowed);
        allowed
    }

    fn matches_pattern(&self, context: Option<&'static str>, name: &'static str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        if self.patterns.is_match(name) {
            return true;
        }
        if let Some(context) = context {
            let full_name = format!("{context}::{name}");
            return self.patterns.is_match(full_name);
        }
        false
    }
}

impl Default for ProfilerStoragePolicy {
    fn default() -> Self {
        Self::new(false, &[], &[], &[]).expect("default profiler storage policy is valid")
    }
}

#[derive(Debug, Clone)]
pub struct ProfilerKeepTree {
    keep_self: bool,
    children: Vec<Option<ProfilerKeepTree>>,
}

impl ProfilerKeepTree {
    fn should_insert(&self) -> bool {
        self.keep_self || self.children.iter().any(Option::is_some)
    }
}

fn is_stacks_bench_span(context: Option<&'static str>) -> bool {
    context
        .is_some_and(|context| context == "stacks_bench" || context.starts_with("stacks_bench::"))
}

#[derive(Debug, QueryableByName)]
struct CheckpointResult {
    #[diesel(sql_type = BigInt)]
    busy: i64,
    #[diesel(sql_type = BigInt)]
    log: i64,
    #[diesel(sql_type = BigInt)]
    checkpointed: i64,
}

/// A row from `sqlite_master` used for schema introspection.
#[derive(Debug, QueryableByName)]
pub struct SchemaRow {
    #[diesel(sql_type = Text)]
    pub object_type: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub tbl_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub sql: Option<String>,
}

#[derive(Clone)]
pub struct AppDb {
    pool: SqlitePool,
    /// Cache of profiler span name to ID mappings.
    profiler_span_cache: ProfilerSpanCache,
    /// Cache of profiler location (file,line) to ID mappings.
    profiler_loc_cache: Arc<RwLock<HashMap<(String, i32), i32>>>,
    /// Cache of profiler tag string to ID mappings.
    profiler_tag_cache: Arc<RwLock<HashMap<&'static str, i32>>>,
}

impl AppDb {
    /// Default filename for the app database.
    pub const DEFAULT_DB_FILENAME: &'static str = "stacks-bench.db";

    /// Apply standard SQLite PRAGMAs.
    async fn setup_connection(
        conn: &mut AsyncSqliteConnection,
    ) -> Result<(), diesel::ConnectionError> {
        sql_query("PRAGMA page_size = 8192;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA wal_autocheckpoint = 0;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA journal_mode=WAL")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA locking_mode = NORMAL;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA synchronous = NORMAL;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA temp_store = MEMORY;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA cache_size = -262144;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA mmap_size = 30000000000;")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        sql_query("PRAGMA foreign_keys = ON")
            .execute(conn)
            .await
            .map_err(diesel::ConnectionError::CouldntSetupConfiguration)?;
        Ok(())
    }

    async fn run_migrations(database_url: &str) -> Result<()> {
        let mut conn = SyncConnectionWrapper::<SqliteConnection>::establish(database_url)
            .await
            .context("Failed to establish dedicated connection for migrations")?;

        Self::setup_connection(&mut conn)
            .await
            .map_err(anyhow::Error::new)
            .context("Failed to configure migration connection")?;

        let mut harness = AsyncMigrationHarness::new(conn);

        let pending = harness
            .pending_migrations(MIGRATIONS)
            .map_err(anyhow::Error::from_boxed)
            .context("Failed to check pending migrations")?;

        if !pending.is_empty() {
            harness
                .run_pending_migrations(MIGRATIONS)
                .map_err(anyhow::Error::from_boxed)
                .context("Failed to run migrations")?;
        }

        Ok(())
    }

    pub async fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let database_url = path_ref
            .to_str()
            .ok_or_else(|| anyhow!("Invalid database path (non-UTF8): {path_ref:?}"))?;

        if let Some(parent) = path_ref.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory at {:?}", parent))?;
        }

        Self::run_migrations(database_url).await?;

        let mut manager_config: ManagerConfig<AsyncSqliteConnection> = ManagerConfig::default();

        manager_config.custom_setup = Box::new(|url: &str| {
            Box::pin(async move {
                let mut conn = SyncConnectionWrapper::<SqliteConnection>::establish(url).await?;
                Self::setup_connection(&mut conn).await?;

                Ok(conn)
            })
        });

        let manager = AsyncDieselConnectionManager::<AsyncSqliteConnection>::new_with_config(
            database_url.to_owned(),
            manager_config,
        );

        let pool = Pool::builder()
            .max_size(64)
            .retry_connection(false)
            .build(manager)
            .await
            .with_context(|| format!("Failed to build SQLite pool for {database_url}"))?;

        Ok(AppDb {
            pool,
            profiler_span_cache: Arc::new(RwLock::new(HashMap::new())),
            profiler_loc_cache: Arc::new(RwLock::new(HashMap::new())),
            profiler_tag_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn get_conn(&self) -> Result<PooledConnection<'_, AsyncSqliteConnection>> {
        let conn = self
            .pool
            .get()
            .await
            .context("Failed to get connection from AppDb pool")?;
        Ok(conn)
    }

    pub async fn set_synchronization_mode(&mut self, mode: SynchronizationMode) -> Result<()> {
        let pragma_sql = match mode {
            SynchronizationMode::Normal => "PRAGMA synchronous = NORMAL;",
            SynchronizationMode::Off => "PRAGMA synchronous = OFF;",
        };
        sql_query(pragma_sql)
            .execute(&mut self.get_conn().await?)
            .await
            .with_context(|| format!("Failed to set synchronization mode: {}", pragma_sql))?;
        Ok(())
    }

    pub async fn set_foreign_key_enforcement(&mut self, mode: ForeignKeyMode) -> Result<()> {
        let pragma_sql = match mode {
            ForeignKeyMode::Enforced => "PRAGMA foreign_keys = ON;",
            ForeignKeyMode::Off => "PRAGMA foreign_keys = OFF;",
        };
        sql_query(pragma_sql)
            .execute(&mut self.get_conn().await?)
            .await
            .with_context(|| {
                format!("Failed to set foreign key enforcement mode: {}", pragma_sql)
            })?;
        Ok(())
    }

    pub async fn checkpoint(&mut self, mode: CheckpointMode) -> Result<()> {
        let sql = match mode {
            CheckpointMode::Full => "PRAGMA wal_checkpoint(FULL)",
            CheckpointMode::Truncate => "PRAGMA wal_checkpoint(TRUNCATE)",
            CheckpointMode::Restart => "PRAGMA wal_checkpoint(RESTART)",
            CheckpointMode::Passive => "PRAGMA wal_checkpoint(PASSIVE)",
        };

        let conn = &mut self.get_conn().await?;
        let res: CheckpointResult = sql_query(sql)
            .get_result(conn)
            .await
            .with_context(|| format!("Failed to run checkpoint with mode {:?}", mode))?;

        if res.busy != 0 || res.log != res.checkpointed {
            return Err(anyhow!("Checkpoint incomplete: {:?}", res));
        }
        Ok(())
    }

    pub async fn vacuum(&mut self) -> Result<()> {
        diesel::sql_query("VACUUM")
            .execute(&mut self.get_conn().await?)
            .await
            .context("Failed to vacuum the database")?;
        Ok(())
    }

    /// Returns DDL rows from `sqlite_master` for tables and indexes, excluding
    /// internal/staging objects. Each row carries the object type, name, parent
    /// table name, and the `CREATE` SQL.
    pub async fn get_schema_ddl(&self) -> Result<Vec<SchemaRow>> {
        sql_query(
            "SELECT type AS object_type, name, tbl_name, sql \
             FROM sqlite_master \
             WHERE type IN ('table', 'index') \
               AND name NOT LIKE '\\_%' ESCAPE '\\' \
               AND name NOT LIKE 'sqlite_%' \
               AND sql IS NOT NULL \
             ORDER BY type DESC, name ASC",
        )
        .load::<SchemaRow>(&mut self.get_conn().await?)
        .await
        .context("Failed to query sqlite_master for schema DDL")
    }

    /// Maps the Network enum to the static IDs defined in the initial migration.
    /// 1=mainnet, 2=testnet, 3=regtest
    fn resolve_network_id(network: crate::Network) -> i32 {
        match network {
            crate::Network::Mainnet => Network::MAINNET,
            crate::Network::Testnet => Network::TESTNET,
            crate::Network::Regtest => Network::REGTEST,
        }
    }

    pub async fn get_or_create_chainstate(
        &mut self,
        network: crate::Network,
        chain_id: u32,
        chain_tip: &BlockRef,
        source_epochs: &[StacksEpoch],
    ) -> Result<(Chainstate, Vec<Epoch>)> {
        let network_id = Self::resolve_network_id(network);

        let chain_id_val: i64 = chain_id.into();
        let tip_height_val: i64 = chain_tip.height.try_into()?;

        let epochs_hash = Self::compute_epochs_hash(source_epochs);

        let conn = &mut self.get_conn().await?;

        conn.transaction::<_, anyhow::Error, _>(|conn| {
            Box::pin(async {
                let existing = chainstate::table
                    .filter(chainstate::network_id.eq(network_id))
                    .filter(chainstate::chain_id.eq(chain_id_val))
                    .filter(chainstate::tip_index_hash.eq(chain_tip.id.as_bytes()))
                    .filter(chainstate::epochs_hash.eq(&epochs_hash))
                    .first::<Chainstate>(conn)
                    .await
                    .optional()?;

                if let Some(chainstate) = existing {
                    let epochs = epoch::table
                        .filter(epoch::chainstate_id.eq(chainstate.id))
                        .order(epoch::start_height.asc())
                        .load::<Epoch>(conn)
                        .await?;

                    Ok((chainstate, epochs))
                } else {
                    let chainstate: Chainstate = diesel::insert_into(chainstate::table)
                        .values((
                            chainstate::network_id.eq(network_id),
                            chainstate::chain_id.eq(chain_id_val),
                            chainstate::tip_index_hash.eq(chain_tip.id.0.to_vec()),
                            chainstate::tip_height.eq(tip_height_val),
                            chainstate::epochs_hash.eq(epochs_hash),
                        ))
                        .get_result(conn)
                        .await?;

                    let mut epochs = Vec::with_capacity(source_epochs.len());
                    for e in source_epochs {
                        let epoch_entry = diesel::insert_into(epoch::table)
                            .values((
                                epoch::chainstate_id.eq(chainstate.id),
                                epoch::stacks_epoch_id.eq(e.epoch_id() as i32),
                                epoch::network_epoch_id.eq(e.network_epoch_id as i32),
                                epoch::start_height.eq(e.start_block_height() as i64),
                                epoch::end_height.eq(e.end_block_height() as i64),
                                epoch::write_length_budget
                                    .eq(TryInto::<i64>::try_into(e.write_length_budget)?),
                                epoch::write_count_budget
                                    .eq(TryInto::<i64>::try_into(e.write_count_budget)?),
                                epoch::read_length_budget
                                    .eq(TryInto::<i64>::try_into(e.read_length_budget)?),
                                epoch::read_count_budget
                                    .eq(TryInto::<i64>::try_into(e.read_count_budget)?),
                                epoch::runtime_budget
                                    .eq(TryInto::<i64>::try_into(e.runtime_budget)?),
                            ))
                            .get_result::<Epoch>(conn)
                            .await?;
                        epochs.push(epoch_entry);
                    }

                    Ok((chainstate, epochs))
                }
            })
        })
        .await
        .context("Failed to get or create chainstate with epochs")
    }

    pub async fn get_or_create_burn_block(
        &mut self,
        hash: &[u8],
        height: u32,
    ) -> Result<BurnBlock> {
        let height_i64: i64 = height.into();

        // Optimization: Use Upsert with dummy update to always return the row
        diesel::insert_into(burn_block::table)
            .values((
                burn_block::block_hash.eq(hash.to_vec()),
                burn_block::height.eq(height_i64),
            ))
            .on_conflict(burn_block::block_hash)
            .do_update()
            .set(burn_block::height.eq(height_i64)) // Dummy update (or actual update if height changed)
            .get_result(&mut self.get_conn().await?)
            .await
            .context("Failed to get or create burn_block")
    }

    pub async fn create_benchmark_run(
        &mut self,
        chainstate_id: i32,
        start_time: NaiveDateTime,
        git_commit_hash: Vec<u8>,
        run_name: Option<String>,
        args_json: String,
        prov: crate::provenance::BenchmarkProvenance,
    ) -> Result<BenchmarkRun> {
        diesel::insert_into(benchmark_run::table)
            .values((
                benchmark_run::chainstate_id.eq(chainstate_id),
                benchmark_run::start_time.eq(start_time),
                benchmark_run::git_commit_hash.eq(git_commit_hash),
                benchmark_run::run_name.eq(run_name),
                benchmark_run::args_json.eq(args_json),
                benchmark_run::build_profile.eq(prov.build.profile),
                benchmark_run::build_opt_level.eq(prov.build.opt_level),
                benchmark_run::build_debug_assertions.eq(prov.build.debug_assertions),
                benchmark_run::build_overflow_checks.eq(prov.build.overflow_checks),
                benchmark_run::build_target_triple.eq(prov.build.target_triple),
                benchmark_run::build_rustc_version.eq(prov.build.rustc_version),
                benchmark_run::git_branch.eq(prov.git.branch),
                benchmark_run::git_dirty.eq(prov.git.dirty),
            ))
            .get_result(&mut self.get_conn().await?)
            .await
            .context("Failed to create benchmark run")
    }

    pub async fn finish_benchmark_run(&mut self, run_id: i32, end_ts: NaiveDateTime) -> Result<()> {
        diesel::update(benchmark_run::table.find(run_id))
            .set(benchmark_run::end_time.eq(end_ts))
            .execute(&mut self.get_conn().await?)
            .await
            .context("Failed to update benchmark run end time")?;

        // inside finish_benchmark_run, after end_time update:
        let sql = POST_RUN_SQL.replace("?1", &run_id.to_string());
        self.get_conn()
            .await?
            .batch_execute(&sql)
            .await
            .context("Failed to build profiler span summary")?;
        Ok(())
    }

    /// Looks up a benchmark run by its ID, returning `None` if it doesn't exist.
    pub async fn get_benchmark_run(&self, run_id: i32) -> Result<Option<BenchmarkRun>> {
        benchmark_run::table
            .find(run_id)
            .first::<BenchmarkRun>(&mut self.get_conn().await?)
            .await
            .optional()
            .context("Failed to look up benchmark run")
    }

    /// Lists all benchmark runs, most recent first.
    pub async fn list_benchmark_runs(&self) -> Result<Vec<BenchmarkRun>> {
        benchmark_run::table
            .order(benchmark_run::start_time.desc())
            .load::<BenchmarkRun>(&mut self.get_conn().await?)
            .await
            .context("Failed to list benchmark runs")
    }

    /// Returns lightweight summary stats for a benchmark run.
    pub async fn get_run_summary(&self, run_id: i32) -> Result<Option<RunSummary>> {
        #[derive(Debug, QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            block_count: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_duration_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_execution_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_commit_us: i64,
        }

        let row: Option<Row> = sql_query(
            "SELECT \
                COUNT(*) AS block_count, \
                COALESCE(SUM(total_duration_us), 0) AS total_duration_us, \
                COALESCE(SUM(execution_duration_us), 0) AS total_execution_us, \
                COALESCE(SUM(commit_duration_us), 0) AS total_commit_us \
             FROM stacks_block_stats \
             WHERE benchmark_run_id = ?1",
        )
        .bind::<diesel::sql_types::Integer, _>(run_id)
        .get_result(&mut self.get_conn().await?)
        .await
        .optional()
        .context("Failed to get run summary")?;

        Ok(row.map(|r| RunSummary {
            block_count: r.block_count as u64,
            total_duration_us: r.total_duration_us as u64,
            total_execution_us: r.total_execution_us as u64,
            total_commit_us: r.total_commit_us as u64,
        }))
    }

    /// Returns detailed summary stats for `bench show --summary`.
    pub async fn get_run_detailed_summary(
        &self,
        run_id: i32,
    ) -> Result<Option<RunDetailedSummary>> {
        #[derive(Debug, QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            block_count: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_duration_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            avg_duration_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_setup_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_execution_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_commit_us: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_clarity_runtime: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_clarity_read_length: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_clarity_read_count: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_clarity_write_length: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_clarity_write_count: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_storage_delta: i64,
        }

        let row: Option<Row> = sql_query(
            "SELECT \
                COUNT(*) AS block_count, \
                COALESCE(SUM(total_duration_us), 0) AS total_duration_us, \
                COALESCE(AVG(total_duration_us), 0) AS avg_duration_us, \
                COALESCE(SUM(setup_duration_us), 0) AS total_setup_us, \
                COALESCE(SUM(execution_duration_us), 0) AS total_execution_us, \
                COALESCE(SUM(commit_duration_us), 0) AS total_commit_us, \
                COALESCE(SUM(clarity_runtime), 0) AS total_clarity_runtime, \
                COALESCE(SUM(clarity_read_length), 0) AS total_clarity_read_length, \
                COALESCE(SUM(clarity_read_count), 0) AS total_clarity_read_count, \
                COALESCE(SUM(clarity_write_length), 0) AS total_clarity_write_length, \
                COALESCE(SUM(clarity_write_count), 0) AS total_clarity_write_count, \
                COALESCE(SUM(total_storage_delta), 0) AS total_storage_delta \
             FROM stacks_block_stats \
             WHERE benchmark_run_id = ?1",
        )
        .bind::<diesel::sql_types::Integer, _>(run_id)
        .get_result(&mut self.get_conn().await?)
        .await
        .optional()
        .context("Failed to get detailed run summary")?;

        Ok(row.and_then(|r| {
            if r.block_count == 0 {
                return None;
            }
            Some(RunDetailedSummary {
                block_count: r.block_count as u64,
                total_duration_us: r.total_duration_us as u64,
                avg_duration_us: r.avg_duration_us as u64,
                total_setup_us: r.total_setup_us as u64,
                total_execution_us: r.total_execution_us as u64,
                total_commit_us: r.total_commit_us as u64,
                total_clarity_runtime: r.total_clarity_runtime as u64,
                total_clarity_read_length: r.total_clarity_read_length as u64,
                total_clarity_read_count: r.total_clarity_read_count as u64,
                total_clarity_write_length: r.total_clarity_write_length as u64,
                total_clarity_write_count: r.total_clarity_write_count as u64,
                total_storage_delta: r.total_storage_delta,
            })
        }))
    }

    /// Returns the top-N hottest profiler spans for a run, sorted by
    /// estimated self wall time descending.
    pub async fn get_profiler_hot_spans(
        &self,
        run_id: i32,
        limit: usize,
    ) -> Result<Vec<ProfilerHotSpan>> {
        #[derive(Debug, QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::Text)]
            span_name: String,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
            span_context: Option<String>,
            #[diesel(sql_type = diesel::sql_types::Double)]
            est_self_wall_us: f64,
            #[diesel(sql_type = diesel::sql_types::Double)]
            est_wall_us: f64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            call_count: i64,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            sample_count: i64,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
            file: Option<String>,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Integer>)]
            line: Option<i32>,
        }

        // Join one profiler_record location for file:line output.
        let rows: Vec<Row> = sql_query(
            "SELECT \
                ps.name AS span_name, \
                ps.context AS span_context, \
                COALESCE(pss.est_self_wall_us, pss.self_wall_time_us) AS est_self_wall_us, \
                COALESCE(pss.est_wall_us, pss.wall_time_us) AS est_wall_us, \
                pss.call_count, \
                pss.sample_count, \
                pl.file, \
                pl.line \
             FROM profiler_span_summary pss \
             JOIN profiler_span ps ON ps.id = pss.profiler_span_id \
             LEFT JOIN ( \
                SELECT profiler_span_id, profiler_location_id, \
                       ROW_NUMBER() OVER (PARTITION BY profiler_span_id ORDER BY id) AS rn \
                FROM profiler_record \
                WHERE benchmark_run_id = ?1 \
             ) pr ON pr.profiler_span_id = pss.profiler_span_id AND pr.rn = 1 \
             LEFT JOIN profiler_location pl ON pl.id = pr.profiler_location_id \
             WHERE pss.benchmark_run_id = ?1 \
             ORDER BY est_self_wall_us DESC \
             LIMIT ?2",
        )
        .bind::<diesel::sql_types::Integer, _>(run_id)
        .bind::<diesel::sql_types::BigInt, _>(limit as i64)
        .load(&mut self.get_conn().await?)
        .await
        .context("Failed to get profiler hot spans")?;

        Ok(rows
            .into_iter()
            .map(|r| ProfilerHotSpan {
                span_name: r.span_name,
                span_context: r.span_context,
                est_self_wall_us: r.est_self_wall_us,
                est_wall_us: r.est_wall_us,
                call_count: r.call_count,
                sample_count: r.sample_count,
                file: r.file,
                line: r.line,
            })
            .collect())
    }

    /// Gets a chainstate by ID, returning `None` if it doesn't exist.
    pub async fn get_chainstate(&self, chainstate_id: i32) -> Result<Option<Chainstate>> {
        chainstate::table
            .find(chainstate_id)
            .first::<Chainstate>(&mut self.get_conn().await?)
            .await
            .optional()
            .context("Failed to look up chainstate")
    }

    /// Lists all chainstates ordered by ID.
    pub async fn list_chainstates(&self) -> Result<Vec<Chainstate>> {
        chainstate::table
            .order(chainstate::id.asc())
            .load::<Chainstate>(&mut self.get_conn().await?)
            .await
            .context("Failed to list chainstates")
    }

    /// Gets the network name for a network ID.
    pub async fn get_network_name(&self, network_id: i32) -> Result<String> {
        network::table
            .select(network::name)
            .find(network_id)
            .first::<String>(&mut self.get_conn().await?)
            .await
            .context("Failed to get network name")
    }

    /// Counts benchmark runs associated with a given chainstate.
    pub async fn count_benchmark_runs_for_chainstate(&self, chainstate_id: i32) -> Result<i64> {
        benchmark_run::table
            .filter(benchmark_run::chainstate_id.eq(chainstate_id))
            .count()
            .get_result::<i64>(&mut self.get_conn().await?)
            .await
            .context("Failed to count benchmark runs for chainstate")
    }

    /// Returns all epochs for a chainstate, ordered by start height.
    pub async fn get_epochs_for_chainstate(
        &self,
        chainstate_id: i32,
    ) -> Result<Vec<models::Epoch>> {
        epoch::table
            .filter(epoch::chainstate_id.eq(chainstate_id))
            .order(epoch::start_height.asc())
            .load::<models::Epoch>(&mut self.get_conn().await?)
            .await
            .context("Failed to list epochs for chainstate")
    }

    /// Returns paginated per-block stats for a benchmark run, joined with
    /// block height and index hash.
    pub async fn get_block_stats(
        &self,
        run_id: i32,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<BlockStatsRow>> {
        #[derive(Debug, QueryableByName)]
        pub struct Row {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            height: i64,
            #[diesel(sql_type = diesel::sql_types::Text)]
            block_id: String,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            total_duration_us: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            setup_duration_us: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            execution_duration_us: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            commit_duration_us: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            commit_overhead_baseline_us: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_runtime: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_read_length: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_read_count: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_write_length: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_write_count: i32,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            total_storage_delta: i64,
        }

        let rows: Vec<Row> = sql_query(
            "SELECT \
                sb.height, \
                LOWER(HEX(sb.index_hash)) AS block_id, \
                sbs.total_duration_us, sbs.setup_duration_us, \
                sbs.execution_duration_us, sbs.commit_duration_us, \
                sbs.commit_overhead_baseline_us, \
                sbs.clarity_runtime, sbs.clarity_read_length, sbs.clarity_read_count, \
                sbs.clarity_write_length, sbs.clarity_write_count, \
                sbs.total_storage_delta \
             FROM stacks_block_stats sbs \
             JOIN synthetic_block syn ON syn.id = sbs.synthetic_block_id \
             JOIN stacks_block sb ON sb.id = syn.stacks_block_id \
             WHERE sbs.benchmark_run_id = ?1 \
             ORDER BY sb.height ASC \
             LIMIT ?2 OFFSET ?3",
        )
        .bind::<diesel::sql_types::Integer, _>(run_id)
        .bind::<diesel::sql_types::BigInt, _>(limit)
        .bind::<diesel::sql_types::BigInt, _>(offset)
        .load(&mut self.get_conn().await?)
        .await
        .context("Failed to get block stats")?;

        Ok(rows
            .into_iter()
            .map(|r| BlockStatsRow {
                height: r.height,
                block_id: r.block_id,
                total_duration_us: r.total_duration_us,
                setup_duration_us: r.setup_duration_us,
                execution_duration_us: r.execution_duration_us,
                commit_duration_us: r.commit_duration_us,
                commit_overhead_baseline_us: r.commit_overhead_baseline_us,
                clarity_runtime: r.clarity_runtime,
                clarity_read_length: r.clarity_read_length,
                clarity_read_count: r.clarity_read_count,
                clarity_write_length: r.clarity_write_length,
                clarity_write_count: r.clarity_write_count,
                total_storage_delta: r.total_storage_delta,
            })
            .collect())
    }

    /// Returns paginated per-tx stats for a benchmark run, optionally filtered
    /// to a single block by its index hash.
    pub async fn get_tx_stats(
        &self,
        run_id: i32,
        block_id_hex: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<TxStatsRow>> {
        #[derive(Debug, QueryableByName)]
        pub struct Row {
            #[diesel(sql_type = diesel::sql_types::Text)]
            tx_hash: String,
            #[diesel(sql_type = diesel::sql_types::Text)]
            tx_type: String,
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            block_height: i64,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            duration_us: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_runtime: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_read_length: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_read_count: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_write_length: i32,
            #[diesel(sql_type = diesel::sql_types::Integer)]
            clarity_write_count: i32,
        }

        let rows: Vec<Row> = if let Some(block_hex) = block_id_hex {
            sql_query(
                "SELECT \
                    st.tx_hash_hex AS tx_hash, stt.name AS tx_type, \
                    sb.height AS block_height, \
                    sts.duration_us, sts.clarity_runtime, \
                    sts.clarity_read_length, sts.clarity_read_count, \
                    sts.clarity_write_length, sts.clarity_write_count \
                 FROM stacks_tx_stats sts \
                 JOIN stacks_tx st ON st.id = sts.stacks_tx_id \
                 JOIN stacks_tx_type stt ON stt.id = st.stacks_tx_type_id \
                 JOIN synthetic_block syn ON syn.id = sts.synthetic_block_id \
                 JOIN stacks_block sb ON sb.id = syn.stacks_block_id \
                 WHERE sts.benchmark_run_id = ?1 \
                   AND LOWER(HEX(sb.index_hash)) = ?2 \
                 ORDER BY sts.duration_us DESC \
                 LIMIT ?3 OFFSET ?4",
            )
            .bind::<diesel::sql_types::Integer, _>(run_id)
            .bind::<diesel::sql_types::Text, _>(block_hex.to_lowercase())
            .bind::<diesel::sql_types::BigInt, _>(limit)
            .bind::<diesel::sql_types::BigInt, _>(offset)
            .load(&mut self.get_conn().await?)
            .await
            .context("Failed to get tx stats (filtered)")?
        } else {
            sql_query(
                "SELECT \
                    st.tx_hash_hex AS tx_hash, stt.name AS tx_type, \
                    sb.height AS block_height, \
                    sts.duration_us, sts.clarity_runtime, \
                    sts.clarity_read_length, sts.clarity_read_count, \
                    sts.clarity_write_length, sts.clarity_write_count \
                 FROM stacks_tx_stats sts \
                 JOIN stacks_tx st ON st.id = sts.stacks_tx_id \
                 JOIN stacks_tx_type stt ON stt.id = st.stacks_tx_type_id \
                 JOIN synthetic_block syn ON syn.id = sts.synthetic_block_id \
                 JOIN stacks_block sb ON sb.id = syn.stacks_block_id \
                 WHERE sts.benchmark_run_id = ?1 \
                 ORDER BY sts.duration_us DESC \
                 LIMIT ?2 OFFSET ?3",
            )
            .bind::<diesel::sql_types::Integer, _>(run_id)
            .bind::<diesel::sql_types::BigInt, _>(limit)
            .bind::<diesel::sql_types::BigInt, _>(offset)
            .load(&mut self.get_conn().await?)
            .await
            .context("Failed to get tx stats")?
        };

        Ok(rows
            .into_iter()
            .map(|r| TxStatsRow {
                tx_hash: r.tx_hash,
                tx_type: r.tx_type,
                block_height: r.block_height,
                duration_us: r.duration_us,
                clarity_runtime: r.clarity_runtime,
                clarity_read_length: r.clarity_read_length,
                clarity_read_count: r.clarity_read_count,
                clarity_write_length: r.clarity_write_length,
                clarity_write_count: r.clarity_write_count,
            })
            .collect())
    }

    /// Compares profiler spans between two benchmark runs. Returns per-span
    /// deltas ordered by absolute delta descending.
    pub async fn compare_run_spans(
        &self,
        baseline_id: i32,
        candidate_id: i32,
        limit: i64,
    ) -> Result<Vec<SpanComparisonRow>> {
        #[derive(Debug, QueryableByName)]
        pub struct Row {
            #[diesel(sql_type = diesel::sql_types::Text)]
            span_name: String,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
            span_context: Option<String>,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Double>)]
            baseline_self_wall_us: Option<f64>,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Double>)]
            candidate_self_wall_us: Option<f64>,
            #[diesel(sql_type = diesel::sql_types::Double)]
            delta_us: f64,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Double>)]
            delta_pct: Option<f64>,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
            baseline_calls: Option<i64>,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
            candidate_calls: Option<i64>,
        }

        let rows: Vec<Row> = sql_query(
            "SELECT * FROM ( \
                SELECT \
                    ps.name AS span_name, \
                    ps.context AS span_context, \
                    COALESCE(b.est_self_wall_us, b.self_wall_time_us) AS baseline_self_wall_us, \
                    COALESCE(c.est_self_wall_us, c.self_wall_time_us) AS candidate_self_wall_us, \
                    (COALESCE(COALESCE(c.est_self_wall_us, c.self_wall_time_us), 0) \
                     - COALESCE(b.est_self_wall_us, b.self_wall_time_us)) AS delta_us, \
                    CASE WHEN COALESCE(b.est_self_wall_us, b.self_wall_time_us) > 0 \
                         THEN ((COALESCE(COALESCE(c.est_self_wall_us, c.self_wall_time_us), 0) \
                                - COALESCE(b.est_self_wall_us, b.self_wall_time_us)) \
                               / COALESCE(b.est_self_wall_us, b.self_wall_time_us) * 100) \
                         ELSE NULL END AS delta_pct, \
                    b.call_count AS baseline_calls, \
                    c.call_count AS candidate_calls \
                FROM profiler_span_summary b \
                JOIN profiler_span ps ON ps.id = b.profiler_span_id \
                LEFT JOIN profiler_span_summary c \
                    ON c.profiler_span_id = b.profiler_span_id \
                    AND c.benchmark_run_id = ?2 \
                WHERE b.benchmark_run_id = ?1 \
                UNION ALL \
                SELECT \
                    ps.name AS span_name, \
                    ps.context AS span_context, \
                    NULL AS baseline_self_wall_us, \
                    COALESCE(c.est_self_wall_us, c.self_wall_time_us) AS candidate_self_wall_us, \
                    COALESCE(c.est_self_wall_us, c.self_wall_time_us) AS delta_us, \
                    NULL AS delta_pct, \
                    NULL AS baseline_calls, \
                    c.call_count AS candidate_calls \
                FROM profiler_span_summary c \
                JOIN profiler_span ps ON ps.id = c.profiler_span_id \
                WHERE c.benchmark_run_id = ?2 \
                  AND c.profiler_span_id NOT IN ( \
                      SELECT profiler_span_id \
                      FROM profiler_span_summary \
                      WHERE benchmark_run_id = ?1 \
                  ) \
            ) ORDER BY ABS(delta_us) DESC \
            LIMIT ?3",
        )
        .bind::<diesel::sql_types::Integer, _>(baseline_id)
        .bind::<diesel::sql_types::Integer, _>(candidate_id)
        .bind::<diesel::sql_types::BigInt, _>(limit)
        .load(&mut self.get_conn().await?)
        .await
        .context("Failed to compare run spans")?;

        Ok(rows
            .into_iter()
            .map(|r| SpanComparisonRow {
                span_name: r.span_name,
                span_context: r.span_context,
                baseline_self_wall_us: r.baseline_self_wall_us,
                candidate_self_wall_us: r.candidate_self_wall_us,
                delta_us: r.delta_us,
                delta_pct: r.delta_pct,
                baseline_calls: r.baseline_calls,
                candidate_calls: r.candidate_calls,
            })
            .collect())
    }

    /// Deletes a chainstate and all associated data (benchmark runs, epochs).
    ///
    /// Benchmark runs are deleted first (via [`delete_benchmark_run`]) since the
    /// `benchmark_run.chainstate_id` FK does not cascade. Epochs are deleted
    /// explicitly for the same reason.
    pub async fn delete_chainstate(&mut self, chainstate_id: i32) -> Result<()> {
        let run_ids: Vec<i32> = benchmark_run::table
            .select(benchmark_run::id)
            .filter(benchmark_run::chainstate_id.eq(chainstate_id))
            .load::<i32>(&mut self.get_conn().await?)
            .await
            .context("Failed to list benchmark runs for chainstate")?;

        for run_id in run_ids {
            self.delete_benchmark_run(run_id).await?;
        }

        self.get_conn()
            .await?
            .transaction::<_, anyhow::Error, _>(|conn| {
                Box::pin(async move {
                    diesel::delete(epoch::table.filter(epoch::chainstate_id.eq(chainstate_id)))
                        .execute(conn)
                        .await?;

                    let deleted = diesel::delete(chainstate::table.find(chainstate_id))
                        .execute(conn)
                        .await?;

                    if deleted == 0 {
                        return Err(anyhow!("Chainstate {} not found", chainstate_id));
                    }

                    Ok(())
                })
            })
            .await
            .context("Failed to delete chainstate")
    }

    /// Deletes a benchmark run and all of its dependent data.
    ///
    /// Tables with `ON DELETE CASCADE` (block_processing_baseline, profiler_record,
    /// profiler_record_kv, profiler_record_clarity_costs, profiler_span_block_summary,
    /// profiler_span_summary) are cleaned up automatically by SQLite.
    ///
    /// Tables without cascade (stacks_block_stats, stacks_tx_stats) are deleted
    /// explicitly before the benchmark_run row itself.
    pub async fn delete_benchmark_run(&mut self, run_id: i32) -> Result<()> {
        self.get_conn()
            .await?
            .transaction::<_, anyhow::Error, _>(|conn| {
                Box::pin(async move {
                    // These tables do not cascade from benchmark_run.
                    diesel::delete(
                        stacks_tx_stats::table.filter(stacks_tx_stats::benchmark_run_id.eq(run_id)),
                    )
                    .execute(conn)
                    .await?;

                    diesel::delete(
                        stacks_block_stats::table
                            .filter(stacks_block_stats::benchmark_run_id.eq(run_id)),
                    )
                    .execute(conn)
                    .await?;

                    let deleted = diesel::delete(benchmark_run::table.find(run_id))
                        .execute(conn)
                        .await?;

                    if deleted == 0 {
                        return Err(anyhow!("Benchmark run {} not found", run_id));
                    }

                    Ok(())
                })
            })
            .await
            .context("Failed to delete benchmark run")
    }

    /// Retrieves the internal DB ID for a Stacks block by its hash.
    pub async fn get_stacks_block_id(&self, block_id: &StacksBlockId) -> Result<i64> {
        let id_opt = schema::stacks_block::table
            .select(schema::stacks_block::id)
            .filter(schema::stacks_block::index_hash.eq(block_id.as_bytes()))
            .first::<i64>(&mut self.get_conn().await?)
            .await
            .optional()?;

        id_opt.ok_or_else(|| anyhow!("Stacks block not found in DB"))
    }

    /// Retrieves the ordered list of block IDs for the canonical chain segment.
    pub async fn get_chain_block_ids(
        &self,
        tip_index_hash: &StacksBlockId,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<StacksBlockId>> {
        // Recursive CTE to walk backwards from tip, then order ascending
        let query = r#"
            WITH RECURSIVE chain(index_hash, height, parent_stacks_block_id) AS (
                SELECT index_hash, height, parent_stacks_block_id
                FROM stacks_block
                WHERE index_hash = ?1
                UNION ALL
                SELECT p.index_hash, p.height, p.parent_stacks_block_id
                FROM stacks_block p
                INNER JOIN chain c ON c.parent_stacks_block_id = p.id
                WHERE c.height > ?2
            )
            SELECT index_hash
            FROM chain
            WHERE height <= ?3 AND height >= ?2
            ORDER BY height ASC
        "#;

        #[derive(Debug, QueryableByName)]
        struct RawId {
            #[diesel(sql_type = Binary)]
            index_hash: Vec<u8>,
        }

        let raw_ids: Vec<RawId> = sql_query(query)
            .bind::<Binary, _>(tip_index_hash.as_bytes())
            .bind::<BigInt, _>(start_height as i64)
            .bind::<BigInt, _>(end_height as i64)
            .load(&mut self.get_conn().await?)
            .await
            .context("Failed to query chain block IDs")?;

        let ids = raw_ids
            .into_iter()
            .map(|r| {
                StacksBlockId::from_vec(&r.index_hash)
                    .ok_or_else(|| anyhow!("Invalid hash in DB: {:?}", r.index_hash))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ids)
    }

    /// Retrieve chain block IDs that have indexed transactions.
    pub async fn get_indexed_chain_block_ids(
        &self,
        tip_index_hash: &StacksBlockId,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<StacksBlockId>> {
        let query = r#"
            WITH RECURSIVE chain(index_hash, height, parent_stacks_block_id) AS (
                SELECT index_hash, height, parent_stacks_block_id
                FROM stacks_block
                WHERE index_hash = ?1 AND txs_indexed = 1
                UNION ALL
                SELECT p.index_hash, p.height, p.parent_stacks_block_id
                FROM stacks_block p
                INNER JOIN chain c ON c.parent_stacks_block_id = p.id
                WHERE c.height > ?2 AND p.txs_indexed = 1
            )
            SELECT index_hash
            FROM chain
            WHERE height <= ?3 AND height >= ?2
            ORDER BY height ASC
        "#;

        #[derive(Debug, QueryableByName)]
        struct RawId {
            #[diesel(sql_type = Binary)]
            index_hash: Vec<u8>,
        }

        let raw_ids: Vec<RawId> = sql_query(query)
            .bind::<Binary, _>(tip_index_hash.as_bytes())
            .bind::<BigInt, _>(start_height as i64)
            .bind::<BigInt, _>(end_height as i64)
            .load(&mut self.get_conn().await?)
            .await
            .context("Failed to query chain block IDs")?;

        let ids = raw_ids
            .into_iter()
            .map(|r| {
                StacksBlockId::from_vec(&r.index_hash)
                    .ok_or_else(|| anyhow!("Invalid hash in DB: {:?}", r.index_hash))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ids)
    }

    /// Retrieve headers from AppDb, regardless of transaction index status.
    pub async fn get_chain_headers(
        &self,
        tip_index_hash: &StacksBlockId,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<StacksBlockHeader>> {
        let ids = self
            .get_chain_block_ids(tip_index_hash, start_height, end_height)
            .await?;
        let mut headers = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(h) = self.get_header(&id).await? {
                headers.push(h);
            }
        }
        Ok(headers)
    }

    /// Fetches a single block header by index block hash ([`StacksBlockId`]),
    /// resolving parent and burn info.
    pub async fn get_block(&self, id: &StacksBlockId) -> Result<StacksBlockHeader> {
        let parent_block = diesel::alias!(stacks_block as parent_block);

        // The genesis block has no parent, so the parent hash join is nullable.
        let (s_block, b_block, parent_hash_opt) = stacks_block::table
            .inner_join(burn_block::table)
            .left_join(
                parent_block.on(stacks_block::parent_stacks_block_id
                    .eq(parent_block.field(stacks_block::id).nullable())),
            )
            .select((
                StacksBlock::as_select(),
                BurnBlock::as_select(),
                parent_block.field(stacks_block::index_hash).nullable(),
            ))
            .filter(stacks_block::index_hash.eq(id.as_bytes()))
            .first::<(StacksBlock, BurnBlock, Option<Vec<u8>>)>(&mut self.get_conn().await?)
            .await
            .optional()?
            .ok_or_else(|| anyhow!("Block {} not found in App DB", id))
            .with_context(|| {
                format!("AppDb: Failed to fetch block header for stacks block id '{id}'")
            })?;

        (s_block, b_block, parent_hash_opt).try_into()
    }

    /// Resolve a transaction's block from indexed benchmark data.
    pub async fn find_block_for_tx_hash_on_chain_tip(
        &self,
        tx_hash: &[u8],
        chain_tip: &StacksBlockId,
    ) -> Result<Option<StacksBlockHeader>> {
        #[derive(Debug, QueryableByName)]
        struct Row {
            #[diesel(sql_type = Binary)]
            index_hash: Vec<u8>,
        }

        let query = r#"
            SELECT sb.index_hash
            FROM stacks_tx st
            JOIN stacks_block sb ON sb.id = st.stacks_block_id
            JOIN synthetic_block syn ON syn.stacks_block_id = sb.id
            JOIN stacks_block_stats sbs ON sbs.synthetic_block_id = syn.id
            JOIN benchmark_run br ON br.id = sbs.benchmark_run_id
            JOIN chainstate cs ON cs.id = br.chainstate_id
            WHERE st.tx_hash = ?1
              AND cs.tip_index_hash = ?2
            ORDER BY br.start_time DESC
            LIMIT 1
        "#;

        let row = sql_query(query)
            .bind::<Binary, _>(tx_hash)
            .bind::<Binary, _>(chain_tip.as_bytes())
            .get_result::<Row>(&mut self.get_conn().await?)
            .await
            .optional()
            .context("Failed to query tx fast-path block lookup")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let block_id = StacksBlockId::from_vec(&row.index_hash)
            .ok_or_else(|| anyhow!("Invalid stacks_block.index_hash in fast-path lookup"))?;

        self.get_block(&block_id).await.map(Some)
    }

    async fn get_or_create_synth_block_id(
        conn: &mut AsyncSqliteConnection,
        index_hash: &[u8],
        source_stacks_block_id: i64,
    ) -> Result<i64> {
        use crate::db::app::schema::synthetic_block;

        diesel::insert_into(synthetic_block::table)
            .values((
                synthetic_block::index_hash.eq(index_hash.to_vec()),
                synthetic_block::stacks_block_id.eq(source_stacks_block_id),
            ))
            .on_conflict(synthetic_block::index_hash)
            .do_nothing()
            .execute(conn)
            .await
            .context("Failed to insert synthetic_block")?;

        let (id, existing_stacks_block_id): (i64, i64) = synthetic_block::table
            .select((synthetic_block::id, synthetic_block::stacks_block_id))
            .filter(synthetic_block::index_hash.eq(index_hash))
            .first(conn)
            .await
            .context("Failed to load synthetic_block")?;

        if existing_stacks_block_id != source_stacks_block_id {
            return Err(anyhow!(
                "synthetic_block index_hash collision: existing stacks_block_id={} new stacks_block_id={}",
                existing_stacks_block_id,
                source_stacks_block_id
            ));
        }

        Ok(id)
    }

    pub async fn stage_blocks<'a, I>(&mut self, blocks: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a StacksBlockHeader> + Send,
        I::IntoIter: Send,
    {
        self.get_conn()
            .await?
            .transaction::<_, anyhow::Error, _>(|conn| {
                Box::pin(async {
                    for block in blocks {
                        let staged = StagedStacksBlock {
                            index_hash: block.id.0.to_vec(),
                            block_hash: block.hash.0.to_vec(),
                            parent_index_hash: block.parent_id.0.to_vec(),
                            height: block.height as i64,
                            burn_block_hash: block.burn_block_hash.0.to_vec(),
                            burn_block_height: block.burn_block_height as i64,
                        };

                        diesel::insert_into(_staged_stacks_block::table)
                            .values(&staged)
                            .execute(conn)
                            .await
                            .with_context(|| {
                                format!(
                                    "Failed to stage block {}:{}",
                                    block.hash.to_hex(),
                                    block.height
                                )
                            })?;
                    }
                    Ok(())
                })
            })
            .await
    }

    pub async fn stage_transactions<I>(&mut self, blocks_with_txs: I) -> Result<()>
    where
        I: IntoIterator<Item = (StacksBlockHeader, Vec<StacksTransaction>)> + Send,
        I::IntoIter: Send,
    {
        struct StagingBuffer {
            txs: Vec<StagedStacksTx>,
            tx_types: HashSet<StacksTxType>,
        }

        impl StagingBuffer {
            fn new() -> Self {
                Self {
                    txs: Vec::new(),
                    tx_types: HashSet::new(),
                }
            }

            fn process_txs(
                &mut self,
                block: &StacksBlockHeader,
                txs: &[StacksTransaction],
            ) -> Result<()> {
                for tx in txs {
                    let block_index_hash = block.id.as_bytes().to_vec();
                    let tx_hash = tx.txid().as_bytes().to_vec();

                    let tx_type = util::resolve_tx_type(&tx.payload);
                    let stacks_tx_type_id = tx_type.id;
                    self.tx_types.insert(tx_type);

                    let caller_address = tx.origin_address().to_string();

                    let mut contract_issuer_address = None;
                    let mut contract_name = None;
                    let mut contract_fn_name: Option<String> = None;
                    let mut contract_call_args_json: Option<String> = None;

                    if let TransactionPayload::SmartContract(sc, _) = &tx.payload {
                        // Deploy: issuer is caller; contract name is in payload
                        contract_issuer_address = Some(caller_address.clone());
                        contract_name = Some(sc.name.to_string());
                    }

                    if let TransactionPayload::ContractCall(cc) = &tx.payload {
                        // Call: issuer + contract name + fn name + args
                        contract_issuer_address =
                            Some(cc.contract_identifier().issuer.to_address().to_string());
                        contract_name = Some(cc.contract_name.to_string());
                        contract_fn_name = Some(cc.function_name.to_string());

                        // Store args as JSON array of Clarity string representations
                        // (keeps it stable and queryable even without a full Clarity->JSON mapping)
                        let args_json = serde_json::to_string(&cc.function_args)
                            .with_context(|| format!("Failed to serialize contract-call arguments to JSON string for tx '{}'", tx.txid().to_hex()))?;
                        contract_call_args_json = Some(args_json);
                    }

                    self.txs.push(StagedStacksTx {
                        block_index_hash,
                        tx_hash,
                        stacks_tx_type_id,
                        caller_address,
                        contract_issuer_address,
                        contract_name,
                        contract_fn_name,
                        contract_call_args_json,
                    });
                }
                Ok(())
            }

            async fn flush(&mut self, conn: &mut AsyncSqliteConnection) -> Result<()> {
                for tx_type in self.tx_types.drain() {
                    diesel::insert_into(stacks_tx_type::table)
                        .values(&tx_type)
                        .on_conflict(stacks_tx_type::id)
                        .do_update()
                        .set(stacks_tx_type::name.eq(&tx_type.name))
                        .execute(conn)
                        .await?;
                }

                for tx in self.txs.drain(..) {
                    diesel::insert_into(_staged_stacks_tx::table)
                        .values(tx)
                        .execute(conn)
                        .await?;
                }
                Ok(())
            }
        }

        const CHUNK_SIZE: usize = 1000;

        self.get_conn()
            .await?
            .transaction::<_, anyhow::Error, _>(|conn| {
                Box::pin(async {
                    let mut buffer = StagingBuffer::new();
                    let mut block_iter = blocks_with_txs.into_iter();

                    loop {
                        let chunk: Vec<(StacksBlockHeader, Vec<StacksTransaction>)> =
                            block_iter.by_ref().take(CHUNK_SIZE).collect();
                        if chunk.is_empty() {
                            break;
                        }

                        for (block, txs) in chunk {
                            buffer.process_txs(&block, &txs)?;
                        }

                        buffer.flush(conn).await?;
                    }
                    Ok(())
                })
            })
            .await
    }

    pub async fn stage_indexed_blocks<'a, I>(&mut self, headers: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a StacksBlockHeader> + Send,
        I::IntoIter: Send,
    {
        use crate::db::app::schema::_staged_indexed_stacks_block;

        let hashes: Vec<Vec<u8>> = headers
            .into_iter()
            .map(|h| h.id.as_bytes().to_vec())
            .collect();

        if hashes.is_empty() {
            return Ok(());
        }

        self.get_conn()
            .await?
            .transaction::<_, anyhow::Error, _>(|conn| {
                Box::pin(async move {
                    for block_index_hash in hashes {
                        diesel::insert_into(_staged_indexed_stacks_block::table)
                            .values(
                                _staged_indexed_stacks_block::block_index_hash.eq(block_index_hash),
                            )
                            .on_conflict(_staged_indexed_stacks_block::block_index_hash)
                            .do_nothing()
                            .execute(conn)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await
    }

    pub async fn merge_staging(&mut self) -> Result<()> {
        self.get_conn()
            .await?
            .transaction::<_, anyhow::Error, _>(|conn| {
                Box::pin(async {
                    conn.batch_execute(MERGE_STAGING_SQL).await?;

                    diesel::delete(_staged_stacks_block::table)
                        .execute(conn)
                        .await?;
                    diesel::delete(_staged_stacks_tx::table)
                        .execute(conn)
                        .await?;

                    Ok(())
                })
            })
            .await
    }

    /// Computes a deterministic hash of the epoch configuration.
    fn compute_epochs_hash(epochs: &[StacksEpoch]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let mut sorted = epochs.to_vec();
        // Keep the hash independent of input ordering.
        sorted.sort_by_key(|e| e.start_block_height());

        for epoch in sorted {
            hasher.update(epoch.epoch_id_le_bytes());
            hasher.update(epoch.start_block_height().to_le_bytes());
            hasher.update(epoch.end_block_height().to_le_bytes());
            hasher.update(epoch.write_length_budget.to_le_bytes());
            hasher.update(epoch.write_count_budget.to_le_bytes());
            hasher.update(epoch.read_length_budget.to_le_bytes());
            hasher.update(epoch.read_count_budget.to_le_bytes());
            hasher.update(epoch.runtime_budget.to_le_bytes());
        }
        hasher.finalize().to_vec()
    }

    async fn resolve_profiler_location(
        conn: &mut AsyncSqliteConnection,
        cache: Arc<RwLock<HashMap<(String, i32), i32>>>,
        file: &str,
        line: i32,
    ) -> Result<i32> {
        let loc_key = (file.to_string(), line);
        if let Some(&id) = cache.read().await.get(&loc_key) {
            return Ok(id);
        }

        let id_opt: Option<i32> = diesel::insert_into(profiler_location::table)
            .values((
                profiler_location::file.eq(file),
                profiler_location::line.eq(line),
            ))
            .on_conflict((profiler_location::file, profiler_location::line))
            .do_nothing()
            .returning(profiler_location::id)
            .get_result(conn)
            .await
            .optional()?;

        let id = if let Some(id) = id_opt {
            id
        } else {
            profiler_location::table
                .select(profiler_location::id)
                .filter(profiler_location::file.eq(file))
                .filter(profiler_location::line.eq(line))
                .first(conn)
                .await?
        };

        cache.write().await.insert(loc_key, id);
        Ok(id)
    }

    async fn resolve_profiler_span(
        conn: &mut AsyncSqliteConnection,
        cache: ProfilerSpanCache,
        context: Option<&'static str>,
        name: &'static str,
    ) -> Result<i32> {
        if let Some(&id) = cache.read().await.get(&(context, name)) {
            return Ok(id);
        }

        let id_opt: Option<i32> = diesel::insert_into(profiler_span::table)
            .values((
                profiler_span::context.eq(context),
                profiler_span::name.eq(name),
            ))
            .on_conflict((profiler_span::context, profiler_span::name))
            .do_nothing()
            .returning(profiler_span::id)
            .get_result(conn)
            .await
            .optional()?;

        let id = if let Some(id) = id_opt {
            id
        } else {
            profiler_span::table
                .select(profiler_span::id)
                .filter(profiler_span::context.eq(context))
                .filter(profiler_span::name.eq(name))
                .first(conn)
                .await?
        };
        cache.write().await.insert((context, name), id);
        Ok(id)
    }

    async fn resolve_profiler_tag(
        conn: &mut AsyncSqliteConnection,
        cache: Arc<RwLock<HashMap<&'static str, i32>>>,
        tag: &'static str,
    ) -> Result<i32> {
        if let Some(&id) = cache.read().await.get(&tag) {
            return Ok(id);
        }

        let id_opt: Option<i32> = diesel::insert_into(profiler_tag::table)
            .values(profiler_tag::tag.eq(tag))
            .on_conflict(profiler_tag::tag)
            .do_nothing()
            .returning(profiler_tag::id)
            .get_result(conn)
            .await
            .optional()?;

        let id = if let Some(id) = id_opt {
            id
        } else {
            profiler_tag::table
                .select(profiler_tag::id)
                .filter(profiler_tag::tag.eq(tag))
                .first(conn)
                .await?
        };

        cache.write().await.insert(tag, id);
        Ok(id)
    }

    pub async fn save_block_processing_baseline(
        &mut self,
        run_id: i32,
        start_parent: &StacksBlockId,
        warmup_blocks: u32,
        measured_blocks: u32,
        baseline: &crate::metrics::BlockProcessingBaseline,
    ) -> Result<()> {
        use crate::db::app::schema::block_processing_baseline;

        let conn = &mut self.get_conn().await?;

        diesel::insert_into(block_processing_baseline::table)
            .values((
                block_processing_baseline::benchmark_run_id.eq(run_id),
                block_processing_baseline::start_parent_index_hash
                    .eq(start_parent.as_bytes().to_vec()),
                block_processing_baseline::warmup_blocks.eq(warmup_blocks as i32),
                block_processing_baseline::measured_blocks.eq(measured_blocks as i32),
                block_processing_baseline::avg_setup_us
                    .eq(baseline.avg_setup_duration.as_micros() as i32),
                block_processing_baseline::avg_finalize_us
                    .eq(baseline.avg_finalize_duration.as_micros() as i32),
                block_processing_baseline::avg_clarity_commit_us
                    .eq(baseline.avg_clarity_state_commit_duration.as_micros() as i32),
                block_processing_baseline::avg_advance_tip_us
                    .eq(baseline.avg_advance_tip_duration.as_micros() as i32),
                block_processing_baseline::avg_index_commit_us
                    .eq(baseline.avg_index_commit_duration.as_micros() as i32),
            ))
            .execute(conn)
            .await
            .context("Failed to insert block processing baseline")?;

        Ok(())
    }

    pub async fn save_block_metrics<I>(
        &mut self,
        run_id: i32,
        blocks: I,
        profiler_policy: &ProfilerStoragePolicy,
    ) -> Result<()>
    where
        I: IntoIterator<Item = BlockMetrics> + Send,
        I::IntoIter: Send,
    {
        let span_cache = self.profiler_span_cache.clone();
        let loc_cache = self.profiler_loc_cache.clone();
        let profiler_policy = profiler_policy.clone();
        let mut staged_kv_count = 0;
        let mut staged_clarity_costs_count = 0;

        self.set_synchronization_mode(SynchronizationMode::Off)
            .await?;
        self.set_foreign_key_enforcement(ForeignKeyMode::Off)
            .await?;

        self.get_conn()
            .await?
            .transaction::<(), anyhow::Error, _>(|dbtx| {
                Box::pin(async {
                    for metrics in blocks.into_iter() {
                        let block_pk: i64 = stacks_block::table
                            .select(stacks_block::id)
                            .filter(stacks_block::index_hash.eq(metrics.id.as_bytes()))
                            .first(dbtx)
                            .await?;

                        let synthetic_block_pk = Self::get_or_create_synth_block_id(
                            dbtx,
                            metrics.synthetic_id.as_bytes(),
                            block_pk,
                        )
                        .await?;

                        diesel::insert_into(stacks_block_stats::table)
                            .values((
                                stacks_block_stats::benchmark_run_id.eq(run_id),
                                stacks_block_stats::synthetic_block_id.eq(synthetic_block_pk),
                                stacks_block_stats::total_duration_us
                                    .eq(metrics.total_duration.as_micros() as i32),
                                stacks_block_stats::setup_duration_us
                                    .eq(metrics.setup_duration.as_micros() as i32),
                                stacks_block_stats::execution_duration_us
                                    .eq(metrics.execution_duration.as_micros() as i32),
                                stacks_block_stats::commit_duration_us
                                    .eq(metrics.commit_duration.as_micros() as i32),
                                stacks_block_stats::commit_overhead_baseline_us
                                    .eq(metrics.commit_overhead_baseline.as_micros() as i32),
                                stacks_block_stats::clarity_write_length
                                    .eq(metrics.total_clarity_cost.write_length as i32),
                                stacks_block_stats::clarity_write_count
                                    .eq(metrics.total_clarity_cost.write_count as i32),
                                stacks_block_stats::clarity_read_length
                                    .eq(metrics.total_clarity_cost.read_length as i32),
                                stacks_block_stats::clarity_read_count
                                    .eq(metrics.total_clarity_cost.read_count as i32),
                                stacks_block_stats::clarity_runtime
                                    .eq(metrics.total_clarity_cost.runtime as i32),
                                stacks_block_stats::total_storage_delta.eq(metrics.total_storage_delta),
                            ))
                            .execute(dbtx)
                            .await
                            .context("Failed to insert stacks block stats")?;

                        let tx_map: HashMap<Vec<u8>, i64> = stacks_tx::table
                            .select((stacks_tx::tx_hash, stacks_tx::id))
                            .filter(stacks_tx::stacks_block_id.eq(block_pk))
                            .load::<(Vec<u8>, i64)>(dbtx)
                            .await?
                            .into_iter()
                            .collect();

                        let mut tx_pks: Vec<Option<i64>> =
                            Vec::with_capacity(metrics.transactions.len());
                        for tx_metric in &metrics.transactions {
                            let tx_hash = tx_metric.txid.as_bytes().to_vec();
                            let tx_pk = tx_map.get(&tx_hash).copied();
                            tx_pks.push(tx_pk);

                            if let Some(tx_pk) = tx_pk {
                                diesel::insert_into(stacks_tx_stats::table)
                                    .values((
                                        stacks_tx_stats::benchmark_run_id.eq(run_id),
                                        stacks_tx_stats::stacks_tx_id.eq(tx_pk),
                                        stacks_tx_stats::synthetic_block_id.eq(synthetic_block_pk),
                                        stacks_tx_stats::duration_us
                                            .eq(tx_metric.duration.as_micros() as i32),
                                        stacks_tx_stats::clarity_write_length
                                            .eq(tx_metric.cost.write_length as i32),
                                        stacks_tx_stats::clarity_write_count
                                            .eq(tx_metric.cost.write_count as i32),
                                        stacks_tx_stats::clarity_read_length
                                            .eq(tx_metric.cost.read_length as i32),
                                        stacks_tx_stats::clarity_read_count
                                            .eq(tx_metric.cost.read_count as i32),
                                        stacks_tx_stats::clarity_runtime
                                            .eq(tx_metric.cost.runtime as i32),
                                    ))
                                    .execute(dbtx)
                                    .await
                                    .context("Failed to insert stacks tx stats")?;
                            }
                        }

                        let ctx = ProfilerInsertContext {
                            run_id,
                            synthetic_block_pk,
                            tx_pks: &tx_pks,
                            span_cache: span_cache.clone(),
                            loc_cache: loc_cache.clone(),
                            tag_cache: self.profiler_tag_cache.clone(),
                        };

                        for (i, root) in metrics.profiler_roots.iter().enumerate() {
                            let keep_tree = profiler_policy.keep_tree(root);
                            if !keep_tree.should_insert() {
                                continue;
                            }
                            let result = ctx
                                .insert_node(
                                    dbtx,
                                    ProfilerInsertNode {
                                        node: root,
                                        keep_tree: &keep_tree,
                                        parent_id: None,
                                        child_index: i as i32,
                                        depth: 0,
                                        active_tx_id: None,
                                    },
                                )
                                .await?;
                            staged_kv_count += result.inserted_kv_records;
                            staged_clarity_costs_count += result.inserted_clarity_cost_records;
                        }
                    }

                    if staged_kv_count > 0 {
                        dbtx
                            .batch_execute(MERGE_PROFILER_KV_SQL)
                            .await
                            .with_context(|| format!("Failed to execute profiler KV staging merge script ({staged_kv_count} staged records)"))?;
                    }

                    if staged_clarity_costs_count > 0 {
                        dbtx
                            .batch_execute(MERGE_PROFILER_CLARITY_COSTS_SQL)
                            .await
                            .with_context(|| format!("Failed to execute profiler clarity costs staging merge script ({staged_clarity_costs_count} staged records)"))?;
                    }

                    Ok(())
                })
            })
            .await?;

        self.set_synchronization_mode(SynchronizationMode::Normal)
            .await?;
        self.set_foreign_key_enforcement(ForeignKeyMode::Enforced)
            .await?;
        self.checkpoint(CheckpointMode::Passive).await?;

        Ok(())
    }
}

#[derive(Debug, Default)]
struct ProfilerInsertContext<'a> {
    run_id: i32,
    synthetic_block_pk: i64,
    tx_pks: &'a [Option<i64>],
    span_cache: ProfilerSpanCache,
    loc_cache: Arc<RwLock<HashMap<(String, i32), i32>>>,
    tag_cache: Arc<RwLock<HashMap<&'static str, i32>>>,
}

#[derive(Clone, Copy)]
struct ProfilerInsertNode<'a> {
    node: &'a stacks_profiler::ProfileStats,
    keep_tree: &'a ProfilerKeepTree,
    parent_id: Option<i64>,
    child_index: i32,
    depth: i32,
    active_tx_id: Option<i64>,
}

#[derive(Debug, Default)]
struct InsertNodeResult {
    inserted_kv_records: usize,
    inserted_clarity_cost_records: usize,
}

impl std::ops::AddAssign for InsertNodeResult {
    fn add_assign(&mut self, other: Self) {
        self.inserted_kv_records += other.inserted_kv_records;
        self.inserted_clarity_cost_records += other.inserted_clarity_cost_records;
    }
}

impl ProfilerInsertContext<'_> {
    fn insert_node<'b>(
        &'b self,
        conn: &'b mut AsyncSqliteConnection,
        insert_node: ProfilerInsertNode<'b>,
    ) -> BoxFuture<'b, Result<InsertNodeResult>> {
        async move {
            let ProfilerInsertNode {
                node,
                keep_tree,
                parent_id,
                child_index,
                depth,
                active_tx_id,
            } = insert_node;

            if !keep_tree.should_insert() {
                return Ok(InsertNodeResult::default());
            }

            let mut stacks_tx_id = active_tx_id;

            let mut result = InsertNodeResult::default();

            if node.name() == "Transaction"
                && let Some(tag) = node.tag()
            {
                let idx = match tag {
                    stacks_profiler::Tag::Usize(v) => Some(*v),
                    stacks_profiler::Tag::U64(v) => usize::try_from(*v).ok(),
                    stacks_profiler::Tag::I64(v) => usize::try_from(*v).ok(), // negative => None
                    stacks_profiler::Tag::Str(_) => None,
                };

                if let Some(i) = idx {
                    stacks_tx_id = self.tx_pks.get(i).and_then(|x| *x);
                }
            }

            let loc_id = AppDb::resolve_profiler_location(
                conn,
                self.loc_cache.clone(),
                node.source_file(),
                node.source_line() as i32,
            )
            .await?;

            let span_id = AppDb::resolve_profiler_span(
                conn,
                self.span_cache.clone(),
                node.context(),
                node.name(),
            )
            .await?;

            let tag_id: Option<i32> = match node.tag() {
                Some(stacks_profiler::Tag::Str(s)) => {
                    Some(AppDb::resolve_profiler_tag(conn, self.tag_cache.clone(), s).await?)
                }
                _ => None, // numeric tags used for tx routing only
            };

            let wall_time_us = node.wall_time_micros() as i64;
            let children_wall_time_us: i64 = node
                .children
                .iter()
                .map(|c| c.wall_time_micros() as i64)
                .sum();
            let self_wall_time_us = wall_time_us.saturating_sub(children_wall_time_us);

            let cpu_time_us = node.cpu_time_micros() as i64;
            let children_cpu_time_us: i64 = node
                .children
                .iter()
                .map(|c| c.cpu_time_micros() as i64)
                .sum();
            let self_cpu_time_us = cpu_time_us.saturating_sub(children_cpu_time_us);

            let record_id: i64 = diesel::insert_into(schema::profiler_record::table)
                .values((
                    schema::profiler_record::benchmark_run_id.eq(self.run_id),
                    schema::profiler_record::parent_id.eq(parent_id),
                    schema::profiler_record::profiler_span_id.eq(span_id),
                    schema::profiler_record::profiler_tag_id.eq(tag_id),
                    schema::profiler_record::profiler_location_id.eq(loc_id),
                    schema::profiler_record::child_index.eq(child_index),
                    schema::profiler_record::depth.eq(depth),
                    schema::profiler_record::synthetic_block_id.eq(self.synthetic_block_pk),
                    schema::profiler_record::stacks_tx_id.eq(stacks_tx_id),
                    schema::profiler_record::wall_time_us.eq(wall_time_us),
                    schema::profiler_record::cpu_time_us.eq(cpu_time_us),
                    schema::profiler_record::self_wall_time_us.eq(self_wall_time_us),
                    schema::profiler_record::self_cpu_time_us.eq(self_cpu_time_us),
                    schema::profiler_record::call_count.eq(node.entered_count as i32),
                    schema::profiler_record::sample_count.eq(node.sampled_count as i32),
                ))
                .returning(schema::profiler_record::id)
                .get_result(conn)
                .await?;

            let staged_kvs = node.records.iter().filter_map(|r| {
                if !keep_tree.keep_self {
                    return None;
                }
                let (value_type_id, value_str) = map_record_value_string(r);
                Some(StagedProfilerRecordKv {
                    profiler_record_id: record_id,
                    key: r.key.to_string(),
                    value_type_id,
                    value: value_str,
                    count: 1,
                })
            });

            let mut clarity_costs_runtime: i64 = 0;
            let mut clarity_costs_read_count: i64 = 0;
            let mut clarity_costs_read_length: i64 = 0;
            let mut clarity_costs_write_count: i64 = 0;
            let mut clarity_costs_write_length: i64 = 0;
            let mut clarity_costs_input_n: i64 = 0;
            let mut has_clarity_costs = false;

            let staged_counter_kvs = node.counters.iter().filter_map(|c| {
                if !keep_tree.keep_self {
                    return None;
                }
                match c.key {
                    "CR" => {
                        has_clarity_costs = true;
                        clarity_costs_runtime = c.value as i64;
                        None
                    }
                    "CRC" => {
                        has_clarity_costs = true;
                        clarity_costs_read_count = c.value as i64;
                        None
                    }
                    "CRL" => {
                        has_clarity_costs = true;
                        clarity_costs_read_length = c.value as i64;
                        None
                    }
                    "CIN" => {
                        has_clarity_costs = true;
                        clarity_costs_input_n = c.value as i64;
                        None
                    }
                    "CWC" => {
                        has_clarity_costs = true;
                        clarity_costs_write_count = c.value as i64;
                        None
                    }
                    "CWL" => {
                        has_clarity_costs = true;
                        clarity_costs_write_length = c.value as i64;
                        None
                    }
                    _ => Some(StagedProfilerRecordKv {
                        profiler_record_id: record_id,
                        key: format!("counter:{}", c.key),
                        value_type_id: 1, // U64
                        value: c.value.to_string(),
                        count: 1,
                    }),
                }
            });

            for row in staged_kvs.chain(staged_counter_kvs) {
                diesel::insert_into(schema::_staged_profiler_record_kv::table)
                    .values(row)
                    .on_conflict((
                        schema::_staged_profiler_record_kv::profiler_record_id,
                        schema::_staged_profiler_record_kv::key,
                        schema::_staged_profiler_record_kv::value_type_id,
                        schema::_staged_profiler_record_kv::value,
                    ))
                    .do_update()
                    .set(
                        schema::_staged_profiler_record_kv::count
                            .eq(schema::_staged_profiler_record_kv::count
                                + excluded(schema::_staged_profiler_record_kv::count)),
                    )
                    .execute(conn)
                    .await
                    .context("Failed to insert profiler KV staging record")?;
                result.inserted_kv_records += 1;
            }

            if keep_tree.keep_self && has_clarity_costs {
                diesel::insert_into(schema::_staged_profiler_record_clarity_costs::table)
                    .values((
                        schema::_staged_profiler_record_clarity_costs::profiler_record_id
                            .eq(record_id),
                        schema::_staged_profiler_record_clarity_costs::runtime
                            .eq(clarity_costs_runtime),
                        schema::_staged_profiler_record_clarity_costs::read_count
                            .eq(clarity_costs_read_count),
                        schema::_staged_profiler_record_clarity_costs::read_length
                            .eq(clarity_costs_read_length),
                        schema::_staged_profiler_record_clarity_costs::write_count
                            .eq(clarity_costs_write_count),
                        schema::_staged_profiler_record_clarity_costs::write_length
                            .eq(clarity_costs_write_length),
                        schema::_staged_profiler_record_clarity_costs::input_n
                            .eq(clarity_costs_input_n),
                    ))
                    .on_conflict(schema::_staged_profiler_record_clarity_costs::profiler_record_id)
                    .do_update()
                    .set((
                        schema::_staged_profiler_record_clarity_costs::runtime
                            .eq(clarity_costs_runtime),
                        schema::_staged_profiler_record_clarity_costs::read_count
                            .eq(clarity_costs_read_count),
                        schema::_staged_profiler_record_clarity_costs::read_length
                            .eq(clarity_costs_read_length),
                        schema::_staged_profiler_record_clarity_costs::write_count
                            .eq(clarity_costs_write_count),
                        schema::_staged_profiler_record_clarity_costs::write_length
                            .eq(clarity_costs_write_length),
                        schema::_staged_profiler_record_clarity_costs::input_n
                            .eq(clarity_costs_input_n),
                    ))
                    .execute(conn)
                    .await
                    .context("Failed to insert profiler clarity costs staging record")?;
                result.inserted_clarity_cost_records += 1;
            }

            for (idx, child) in node.children.iter().enumerate() {
                let Some(child_keep_tree) = keep_tree.children.get(idx).and_then(Option::as_ref)
                else {
                    continue;
                };
                result += self
                    .insert_node(
                        conn,
                        ProfilerInsertNode {
                            node: child,
                            keep_tree: child_keep_tree,
                            parent_id: Some(record_id),
                            child_index: idx as i32,
                            depth: depth + 1,
                            active_tx_id: stacks_tx_id,
                        },
                    )
                    .await?;
            }

            Ok(result)
        }
        .boxed()
    }
}

fn map_record_value_string(r: &stacks_profiler::Record) -> (i32, String) {
    match &r.value {
        stacks_profiler::RecordValue::U64(v) => (1, v.to_string()),
        stacks_profiler::RecordValue::I64(v) => (2, v.to_string()),
        stacks_profiler::RecordValue::Str(s) => (3, s.to_string()),
        stacks_profiler::RecordValue::Bytes(b) => (4, hex::encode(b)),
    }
}

impl ChainCache for AppDb {
    async fn find_closest_ancestor(
        &self,
        tip: &StacksBlockId,
        target_height: u64,
    ) -> Result<Option<(StacksBlockId, u64)>> {
        // Use the nearest indexed ancestor that does not undershoot the target.
        let result = chain_tip_cache::table
            .select((chain_tip_cache::index_hash, chain_tip_cache::height))
            .filter(chain_tip_cache::tip_index_hash.eq(tip.as_bytes()))
            .filter(chain_tip_cache::height.ge(target_height as i64))
            .order(chain_tip_cache::height.asc())
            .first::<(Vec<u8>, i64)>(&mut self.get_conn().await?)
            .await
            .optional()?;

        if let Some((hash, height)) = result {
            let id =
                StacksBlockId::from_vec(&hash).ok_or_else(|| anyhow!("Invalid hash in cache"))?;
            Ok(Some((id, height as u64)))
        } else {
            Ok(None)
        }
    }

    async fn cache_ancestor(
        &mut self,
        tip: &StacksBlockId,
        height: u64,
        block: &StacksBlockId,
    ) -> Result<()> {
        diesel::insert_into(chain_tip_cache::table)
            .values((
                chain_tip_cache::tip_index_hash.eq(tip.as_bytes()),
                chain_tip_cache::height.eq(height as i64),
                chain_tip_cache::index_hash.eq(block.as_bytes()),
            ))
            .on_conflict((chain_tip_cache::tip_index_hash, chain_tip_cache::height))
            .do_nothing()
            .execute(&mut self.get_conn().await?)
            .await?;
        Ok(())
    }
}

impl BlockHeaderProvider for AppDb {
    async fn get_header(&self, id: &StacksBlockId) -> Result<Option<StacksBlockHeader>> {
        match self.get_block(id).await {
            Ok(h) => Ok(Some(h)),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use stacks_profiler::{ProfileStats, SpanId};

    use super::*;

    static BENCH_SPAN: SpanId = SpanId {
        name: "Segment",
        context: Some("stacks_bench::replay"),
        file: "contrib/stacks-bench/src/replay.rs",
        line: 1,
    };

    static NODE_SPAN: SpanId = SpanId {
        name: "load_contract",
        context: Some("clarity::vm::database"),
        file: "clarity/src/vm/database.rs",
        line: 1,
    };

    static OTHER_NODE_SPAN: SpanId = SpanId {
        name: "execute",
        context: Some("clarity::vm"),
        file: "clarity/src/vm/mod.rs",
        line: 1,
    };

    fn stats(id: &'static SpanId, wall_time_ns: u64, children: Vec<ProfileStats>) -> ProfileStats {
        stats_with_cpu(id, wall_time_ns, wall_time_ns, children)
    }

    fn stats_with_cpu(
        id: &'static SpanId,
        wall_time_ns: u64,
        cpu_time_ns: u64,
        children: Vec<ProfileStats>,
    ) -> ProfileStats {
        ProfileStats {
            id,
            tag: None,
            wall_time_ns,
            cpu_time_ns,
            children,
            entered_count: 1,
            sampled_count: 1,
            records: Vec::new(),
            counters: Vec::new(),
        }
    }

    #[test]
    fn profiler_threshold_parses_units_and_decimals() {
        assert_eq!(
            "1000us".parse::<ProfilerThresholdNs>().unwrap().0,
            1_000_000
        );
        assert_eq!("1ms".parse::<ProfilerThresholdNs>().unwrap().0, 1_000_000);
        assert_eq!(
            "1.3s".parse::<ProfilerThresholdNs>().unwrap().0,
            1_300_000_000
        );
        assert!("10".parse::<ProfilerThresholdNs>().is_err());
        assert!("abcms".parse::<ProfilerThresholdNs>().is_err());
    }

    #[test]
    fn profiler_threshold_parses_metric_prefixes() {
        let threshold = "self-cpu:1ms".parse::<ProfilerThreshold>().unwrap();
        assert_eq!(threshold.metric, ProfilerThresholdMetric::SelfCpu);
        assert_eq!(threshold.threshold.0, 1_000_000);

        let threshold = "1ms".parse::<ProfilerThreshold>().unwrap();
        assert_eq!(threshold.metric, ProfilerThresholdMetric::Wall);
        assert_eq!(threshold.threshold.0, 1_000_000);

        assert!("unknown:1ms".parse::<ProfilerThreshold>().is_err());
        assert!("wall::1ms".parse::<ProfilerThreshold>().is_err());
    }

    #[test]
    fn profiler_threshold_deserializes_legacy_and_current_shapes() {
        assert_eq!(
            serde_json::from_str::<Vec<ProfilerThreshold>>("[1000000]").unwrap(),
            vec![ProfilerThreshold {
                metric: ProfilerThresholdMetric::Wall,
                threshold: ProfilerThresholdNs(1_000_000),
            }]
        );
        assert_eq!(
            serde_json::from_str::<ProfilerThreshold>("\"self-wait:1ms\"").unwrap(),
            ProfilerThreshold {
                metric: ProfilerThresholdMetric::SelfWait,
                threshold: ProfilerThresholdNs(1_000_000),
            }
        );
        assert_eq!(
            serde_json::from_str::<ProfilerThreshold>(
                r#"{"metric":"self-cpu","threshold":1000000}"#
            )
            .unwrap(),
            ProfilerThreshold {
                metric: ProfilerThresholdMetric::SelfCpu,
                threshold: ProfilerThresholdNs(1_000_000),
            }
        );
    }

    #[test]
    fn profiler_policy_always_keeps_bench_spans() {
        let policy =
            ProfilerStoragePolicy::new(true, &[], &[], &[]).expect("valid bench-only policy");
        let bench = stats(&BENCH_SPAN, 1, Vec::new());
        let node = stats(&NODE_SPAN, 10_000_000, Vec::new());

        let bench_tree = policy.keep_tree(&bench);
        assert!(bench_tree.keep_self);
        assert!(bench_tree.should_insert());
        assert!(!policy.keep_tree(&node).should_insert());
    }

    #[test]
    fn profiler_policy_combines_globs_and_threshold() {
        let policy = ProfilerStoragePolicy::new(
            false,
            &[ProfilerThreshold {
                metric: ProfilerThresholdMetric::Wall,
                threshold: ProfilerThresholdNs(1_000_000),
            }],
            &["*load*".to_string()],
            &[],
        )
        .expect("valid include policy");

        assert!(
            policy
                .keep_tree(&stats(&NODE_SPAN, 1_000_000, Vec::new()))
                .keep_self
        );
        assert!(
            !policy
                .keep_tree(&stats(&NODE_SPAN, 999_999, Vec::new()))
                .should_insert()
        );
        assert!(
            !policy
                .keep_tree(&stats(&OTHER_NODE_SPAN, 2_000_000, Vec::new()))
                .should_insert()
        );
    }

    #[test]
    fn profiler_policy_ors_multiple_threshold_metrics() {
        let policy = ProfilerStoragePolicy::new(
            false,
            &[
                ProfilerThreshold {
                    metric: ProfilerThresholdMetric::SelfCpu,
                    threshold: ProfilerThresholdNs(1_000_000),
                },
                ProfilerThreshold {
                    metric: ProfilerThresholdMetric::Wait,
                    threshold: ProfilerThresholdNs(2_000_000),
                },
            ],
            &[],
            &[],
        )
        .expect("valid threshold policy");

        assert!(
            policy
                .keep_tree(&stats_with_cpu(&NODE_SPAN, 3_000_000, 500_000, Vec::new()))
                .keep_self
        );
        assert!(
            policy
                .keep_tree(&stats_with_cpu(
                    &NODE_SPAN,
                    1_500_000,
                    1_000_000,
                    Vec::new()
                ))
                .keep_self
        );
        assert!(
            !policy
                .keep_tree(&stats_with_cpu(&NODE_SPAN, 1_499_999, 999_999, Vec::new()))
                .should_insert()
        );
    }

    #[test]
    fn profiler_policy_uses_self_wall_and_self_wait_thresholds() {
        let child = stats_with_cpu(&OTHER_NODE_SPAN, 8_000_000, 7_000_000, Vec::new());
        let parent = stats_with_cpu(&NODE_SPAN, 10_000_000, 7_500_000, vec![child.clone()]);

        let self_wall_policy = ProfilerStoragePolicy::new(
            false,
            &[ProfilerThreshold {
                metric: ProfilerThresholdMetric::SelfWall,
                threshold: ProfilerThresholdNs(2_000_000),
            }],
            &[],
            &[],
        )
        .expect("valid self-wall policy");
        assert!(self_wall_policy.keep_tree(&parent).keep_self);

        let self_wait_policy = ProfilerStoragePolicy::new(
            false,
            &[ProfilerThreshold {
                metric: ProfilerThresholdMetric::SelfWait,
                threshold: ProfilerThresholdNs(1_500_000),
            }],
            &[],
            &[],
        )
        .expect("valid self-wait policy");
        assert!(self_wait_policy.keep_tree(&parent).keep_self);

        let too_high_policy = ProfilerStoragePolicy::new(
            false,
            &[ProfilerThreshold {
                metric: ProfilerThresholdMetric::SelfWait,
                threshold: ProfilerThresholdNs(1_500_001),
            }],
            &[],
            &[],
        )
        .expect("valid self-wait policy");
        assert!(!too_high_policy.keep_tree(&parent).keep_self);
    }

    #[test]
    fn profiler_policy_excludes_matching_globs() {
        let policy =
            ProfilerStoragePolicy::new(false, &[], &[], &["clarity::vm::database::*".to_string()])
                .expect("valid exclude policy");

        assert!(
            !policy
                .keep_tree(&stats(&NODE_SPAN, 1_000_000, Vec::new()))
                .should_insert()
        );
        assert!(
            policy
                .keep_tree(&stats(&OTHER_NODE_SPAN, 1_000_000, Vec::new()))
                .keep_self
        );
    }

    #[test]
    fn profiler_policy_keeps_structural_ancestors_for_matching_children() {
        let policy = ProfilerStoragePolicy::new(false, &[], &["*load_contract".to_string()], &[])
            .expect("valid include policy");
        let root = stats(
            &OTHER_NODE_SPAN,
            2_000_000,
            vec![stats(&NODE_SPAN, 1_000_000, Vec::new())],
        );

        let keep_tree = policy.keep_tree(&root);
        assert!(!keep_tree.keep_self);
        assert!(keep_tree.should_insert());
        assert!(keep_tree.children[0].as_ref().unwrap().keep_self);
    }
}
