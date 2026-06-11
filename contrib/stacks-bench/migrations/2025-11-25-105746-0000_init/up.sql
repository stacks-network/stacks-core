-- ==========================================
-- Enum table for Bitcoin (and implicitly Stacks) networks.
-- ==========================================
CREATE TABLE network (
  id INTEGER PRIMARY KEY NOT NULL,
  name TEXT NOT NULL UNIQUE
);

-- Default networks
INSERT INTO network (id, name) VALUES 
  (1, 'mainnet'), 
  (2, 'testnet'), 
  (3, 'regtest');

-- ==========================================
-- Chainstate snapshot tracking, effectively unique per (network, chain_id, 
-- tip, epochs).
-- ==========================================
CREATE TABLE chainstate (
  id INTEGER PRIMARY KEY NOT NULL,
  network_id INTEGER NOT NULL,
  chain_id INTEGER NOT NULL,
  tip_index_hash BLOB NOT NULL,
  tip_height INTEGER NOT NULL,
  epochs_hash BLOB NOT NULL,
  FOREIGN KEY (network_id) REFERENCES network(id),
  CHECK(length(tip_index_hash) = 32),
  CHECK(length(epochs_hash) = 32),
  UNIQUE (network_id, chain_id, tip_index_hash, epochs_hash)
);

-- ==========================================
-- Dimension for epochs, unique per chainstate. Pulled from the Stacks
-- sortition database.
-- ==========================================
CREATE TABLE epoch (
    id INTEGER PRIMARY KEY NOT NULL,
    chainstate_id INTEGER NOT NULL,
    stacks_epoch_id INTEGER NOT NULL,
    network_epoch_id INTEGER NOT NULL,
    start_height INTEGER NOT NULL,
    end_height INTEGER NOT NULL,
    write_length_budget INTEGER NOT NULL,
    write_count_budget INTEGER NOT NULL,
    read_length_budget INTEGER NOT NULL,
    read_count_budget INTEGER NOT NULL,
    runtime_budget INTEGER NOT NULL,
    FOREIGN KEY (chainstate_id) REFERENCES chainstate(id),
    UNIQUE(chainstate_id, stacks_epoch_id)
);

-- ==========================================
-- Dimension for Stacks transaction types which have been seen.
-- ==========================================
CREATE TABLE stacks_tx_type (
    id INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE
);

-- ==========================================
-- Dimension for Stacks principals which have been seen.
-- ==========================================
CREATE TABLE principal (
    id INTEGER PRIMARY KEY NOT NULL,
    address TEXT NOT NULL UNIQUE
);

-- ==========================================
-- Dimension for Stacks contracts which have been seen.
-- ==========================================
CREATE TABLE contract (
    id INTEGER PRIMARY KEY NOT NULL,
    issuer_principal_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    FOREIGN KEY (issuer_principal_id) REFERENCES principal(id),
    UNIQUE(issuer_principal_id, name)
);

CREATE INDEX idx_contract_name 
  ON contract(name);

-- ==========================================
-- Dimension for Stacks contract functions which have been seen.
-- ==========================================
CREATE TABLE contract_fn (
  id INTEGER PRIMARY KEY NOT NULL,
  contract_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  FOREIGN KEY (contract_id) REFERENCES contract(id),
  UNIQUE(contract_id, name)
);

-- ==========================================
-- Dimension for burn (Bitcoin) blocks. Not linked to any specific
-- chainstate as they are cryptographically deterministic.
-- ==========================================
CREATE TABLE burn_block (
    id INTEGER PRIMARY KEY NOT NULL,
    block_hash BLOB NOT NULL UNIQUE,
    block_hash_hex TEXT GENERATED ALWAYS AS (LOWER(HEX(block_hash))) STORED,
    height INTEGER NOT NULL,
    CHECK(height >= 0),
    CHECK(length(block_hash) = 32)
);

CREATE INDEX idx_burn_block_height 
  ON burn_block(height);
CREATE INDEX idx_burn_block_block_hash_hex 
  ON burn_block(block_hash_hex);

-- ==========================================
-- Dimension for Stacks blocks. Not linked to any specific chainstate as they
-- are cryptographically deterministic.
-- ==========================================
CREATE TABLE stacks_block (
  id INTEGER PRIMARY KEY NOT NULL,
  index_hash BLOB NOT NULL UNIQUE,
  block_hash BLOB NOT NULL,
  block_hash_hex TEXT GENERATED ALWAYS AS (LOWER(HEX(block_hash))) VIRTUAL,
  height INTEGER NOT NULL,
  parent_stacks_block_id INTEGER DEFAULT NULL,
  burn_block_id INTEGER NOT NULL,
  txs_indexed BOOLEAN NOT NULL DEFAULT 0,
  FOREIGN KEY (burn_block_id) REFERENCES burn_block(id),
  FOREIGN KEY (parent_stacks_block_id) REFERENCES stacks_block(id),
  CHECK(height >= 0),
  CHECK(length(block_hash) = 32),
  CHECK(length(index_hash) = 32)
);

CREATE INDEX idx_stacks_block_height 
  ON stacks_block(height);
CREATE INDEX idx_stacks_block_block_hash_hex 
  ON stacks_block(block_hash_hex);

-- ==========================================
-- Staging table for Stacks blocks during bulk import.
-- ==========================================
CREATE TABLE _staged_stacks_block (
    index_hash BLOB NOT NULL,
    block_hash BLOB NOT NULL,
    parent_index_hash BLOB NOT NULL,
    height INTEGER NOT NULL,
    burn_block_hash BLOB NOT NULL,
    burn_block_height INTEGER NOT NULL
);

-- ==========================================
-- Staging table: marks blocks whose tx set was fully staged
-- ==========================================
CREATE TABLE _staged_indexed_stacks_block (
  block_index_hash BLOB PRIMARY KEY
) WITHOUT ROWID;

-- ==========================================
-- Dimension for synthetic blocks created during benchmarks.
-- These are not part of any real chainstate.
-- ==========================================
CREATE TABLE synthetic_block (
  id INTEGER PRIMARY KEY NOT NULL,
  stacks_block_id INTEGER NOT NULL,
  index_hash BLOB NOT NULL,
  CHECK(length(index_hash) = 32),
  UNIQUE(index_hash),
  FOREIGN KEY (stacks_block_id) REFERENCES stacks_block(id)
);

CREATE INDEX idx_synth_block_source
  ON synthetic_block(stacks_block_id);

-- ==========================================
-- Dimension for Stacks transactions. Not linked to any specific chainstate as 
-- they are cryptographically deterministic.
-- ==========================================
CREATE TABLE stacks_tx (
  id INTEGER PRIMARY KEY NOT NULL,
  stacks_block_id INTEGER NOT NULL,
  tx_hash BLOB NOT NULL,
  tx_hash_hex TEXT GENERATED ALWAYS AS (LOWER(HEX(tx_hash))) VIRTUAL,
  stacks_tx_type_id INTEGER NOT NULL,
  caller_principal_id INTEGER NOT NULL,
  contract_id INTEGER,
  contract_fn_id INTEGER,
  contract_call_args_json TEXT,
  FOREIGN KEY (contract_fn_id) REFERENCES contract_fn(id),
  FOREIGN KEY (stacks_block_id) REFERENCES stacks_block(id),
  FOREIGN KEY (stacks_tx_type_id) REFERENCES stacks_tx_type(id),
  FOREIGN KEY (caller_principal_id) REFERENCES principal(id),
  FOREIGN KEY (contract_id) REFERENCES contract(id),
  UNIQUE(stacks_block_id, tx_hash),
  CHECK(length(tx_hash) = 32)
);

CREATE INDEX idx_tx_tx_hash_hex 
  ON stacks_tx(tx_hash_hex);
CREATE INDEX idx_tx_caller_principal 
  ON stacks_tx(caller_principal_id);
CREATE INDEX idx_tx_contract 
  ON stacks_tx(contract_id, contract_fn_id)
  WHERE contract_id IS NOT NULL;

CREATE INDEX idx_tx_contract_fn
  ON stacks_tx(contract_fn_id)
  WHERE contract_fn_id IS NOT NULL;

-- ==========================================
-- Staging table for Stacks transactions during bulk import.
-- ==========================================
CREATE TABLE _staged_stacks_tx (
    block_index_hash BLOB NOT NULL,
    tx_hash BLOB NOT NULL,
    stacks_tx_type_id INTEGER NOT NULL,
    caller_address TEXT NOT NULL,
    contract_issuer_address TEXT,
    contract_name TEXT,
    contract_fn_name TEXT,
    contract_call_args_json TEXT
);

-- ==========================================
-- Dimension for benchmark runs.
-- ==========================================
CREATE TABLE benchmark_run (
  id INTEGER PRIMARY KEY NOT NULL,
  run_name TEXT,
  chainstate_id INTEGER NOT NULL,
  git_commit_hash BLOB NOT NULL,
  start_time TIMESTAMP NOT NULL,
  end_time TIMESTAMP,
  args_json TEXT NOT NULL,
  FOREIGN KEY (chainstate_id) REFERENCES chainstate(id),
  CHECK(length(git_commit_hash) IN (20, 32)) -- SHA1 or SHA256
);

-- ==========================================
-- Fact table for block processing overhead baseline measurements per run.
-- These are the outputs of creating + committing a chain of empty Stacks blocks.
-- ==========================================
CREATE TABLE block_processing_baseline (
  benchmark_run_id INTEGER PRIMARY KEY NOT NULL,

  -- Parent used as the initial anchor for the baseline procedure
  start_parent_index_hash BLOB NOT NULL,

  warmup_blocks INTEGER NOT NULL,
  measured_blocks INTEGER NOT NULL,

  -- Duration metrics (microseconds), each is an average per block over the measured window
  avg_setup_us INTEGER NOT NULL,
  avg_finalize_us INTEGER NOT NULL,
  avg_clarity_commit_us INTEGER NOT NULL,
  avg_advance_tip_us INTEGER NOT NULL,
  avg_index_commit_us INTEGER NOT NULL,

  FOREIGN KEY (benchmark_run_id) REFERENCES benchmark_run(id) ON DELETE CASCADE,
  CHECK(length(start_parent_index_hash) = 32)
) WITHOUT ROWID;

-- ==========================================
-- Fact table for benchmark statistics per Stacks block.
-- ==========================================
CREATE TABLE stacks_block_stats (
  benchmark_run_id INTEGER NOT NULL,
  synthetic_block_id INTEGER NOT NULL,

  -- Duration metrics (microseconds)
  total_duration_us INTEGER NOT NULL,
  setup_duration_us INTEGER NOT NULL,
  execution_duration_us INTEGER NOT NULL,
  commit_duration_us INTEGER NOT NULL,
  commit_overhead_baseline_us INTEGER NOT NULL,

  -- Clarity cost metrics (aggregated for the whole block)
  clarity_write_length INTEGER NOT NULL,
  clarity_write_count  INTEGER NOT NULL,
  clarity_read_length  INTEGER NOT NULL,
  clarity_read_count   INTEGER NOT NULL,
  clarity_runtime      INTEGER NOT NULL,

  -- Total storage delta (in bytes) resulting from block processing
  total_storage_delta INTEGER NOT NULL,

  PRIMARY KEY (benchmark_run_id, synthetic_block_id),

  FOREIGN KEY (benchmark_run_id) REFERENCES benchmark_run(id),
  FOREIGN KEY (synthetic_block_id) REFERENCES synthetic_block(id)
) WITHOUT ROWID;

-- For block stats p95 / histograms
CREATE INDEX idx_block_stats_run_runtime
  ON stacks_block_stats(benchmark_run_id, clarity_runtime);

-- ==========================================
-- Fact table for benchmark statistics per Stacks transaction.
-- ==========================================
CREATE TABLE stacks_tx_stats (
  benchmark_run_id INTEGER NOT NULL,
  stacks_tx_id INTEGER NOT NULL,
  synthetic_block_id INTEGER NOT NULL,

  -- Duration metrics (microseconds)
  duration_us INTEGER NOT NULL,

  -- Clarity cost metrics
  clarity_write_length INTEGER NOT NULL,
  clarity_write_count  INTEGER NOT NULL,
  clarity_read_length  INTEGER NOT NULL,
  clarity_read_count   INTEGER NOT NULL,
  clarity_runtime      INTEGER NOT NULL,

  PRIMARY KEY (benchmark_run_id, synthetic_block_id, stacks_tx_id),

  FOREIGN KEY (benchmark_run_id) REFERENCES benchmark_run(id),
  FOREIGN KEY (stacks_tx_id) REFERENCES stacks_tx(id),
  FOREIGN KEY (synthetic_block_id) REFERENCES synthetic_block(id)
) WITHOUT ROWID;

CREATE INDEX idx_tx_stats_run_tx
  ON stacks_tx_stats(benchmark_run_id, stacks_tx_id);

  -- For TX stats p95 / histograms
CREATE INDEX idx_tx_stats_run_runtime
  ON stacks_tx_stats(benchmark_run_id, clarity_runtime);

-- ==========================================
-- Dimension table for profiler locations (file + line).
-- ==========================================
CREATE TABLE profiler_location (
  id INTEGER PRIMARY KEY NOT NULL,
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  UNIQUE(file, line)
);

-- ==========================================
-- Dimension table for profiler spans (named code regions).
-- ==========================================
CREATE TABLE profiler_span (
  id INTEGER PRIMARY KEY NOT NULL,
  context TEXT,
  name TEXT NOT NULL,
  UNIQUE(context, name)
);

-- ==========================================
-- Dimension table for profiler tags (arbitrary labels).
-- ==========================================
CREATE TABLE profiler_tag (
  id INTEGER PRIMARY KEY NOT NULL,
  tag TEXT NOT NULL UNIQUE
);

-- ==========================================
-- Dimension table for profiler records (hierarchical timing data, per span and parent).
-- ==========================================
CREATE TABLE profiler_record (
  id INTEGER PRIMARY KEY NOT NULL,
  benchmark_run_id INTEGER NOT NULL,

  -- Hierarchy
  parent_id INTEGER,
  profiler_span_id INTEGER NOT NULL,
  profiler_tag_id INTEGER,
  profiler_location_id INTEGER NOT NULL,
  child_index INTEGER NOT NULL, -- Preserves execution order for flamegraphs
  depth INTEGER NOT NULL,       -- Optimization for UI rendering

  -- Context
  synthetic_block_id INTEGER NOT NULL,
  stacks_tx_id INTEGER,

  -- Metrics
  wall_time_us INTEGER NOT NULL,
  cpu_time_us INTEGER NOT NULL,
  -- Exclusive wall time (wall_time - sum(children.wall_time))
  self_wall_time_us INTEGER NOT NULL,
  -- Exclusive CPU time (cpu_time - sum(children.cpu_time))
  self_cpu_time_us INTEGER NOT NULL,
  call_count INTEGER NOT NULL,
  sample_count INTEGER NOT NULL,

   -- Sampling expansion factor and estimated totals (NULL when sample_count = 0)
  expand_factor REAL GENERATED ALWAYS AS (
    CASE
      WHEN sample_count > 0 THEN (call_count * 1.0 / sample_count)
      ELSE NULL
    END
  ) VIRTUAL,

  est_wall_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN wall_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_self_wall_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN self_wall_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_cpu_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN cpu_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_self_cpu_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN self_cpu_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,

  -- Constraints
  FOREIGN KEY (benchmark_run_id) REFERENCES benchmark_run(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_id) REFERENCES profiler_record(id) ON DELETE CASCADE,
  FOREIGN KEY (profiler_span_id) REFERENCES profiler_span(id),
  FOREIGN KEY (profiler_location_id) REFERENCES profiler_location(id),
  FOREIGN KEY (profiler_tag_id) REFERENCES profiler_tag(id),
  FOREIGN KEY (synthetic_block_id) REFERENCES synthetic_block(id),
  FOREIGN KEY (stacks_tx_id) REFERENCES stacks_tx(id)
);

-- FLAMEGRAPH TRAVERSAL
-- Finds children of a node, pre-sorted by execution order. Critical for 
-- performant UI rendering.
CREATE INDEX idx_prof_parent_ordered
  ON profiler_record(parent_id, child_index)
  WHERE parent_id IS NOT NULL;

-- ROOT NODES LOOKUP
CREATE INDEX idx_prof_run_roots
  ON profiler_record(benchmark_run_id, id)
  WHERE parent_id IS NULL;

-- HOT PATH / AGGREGATION
-- "Show me stats for span X in run Y".
CREATE INDEX idx_prof_run_span
  ON profiler_record(benchmark_run_id, profiler_span_id);

-- SYNTHETIC BLOCK CONTEXT
CREATE INDEX idx_prof_run_synth
  ON profiler_record(benchmark_run_id, synthetic_block_id);

-- TX CONTEXT (Lookup by TX only)
CREATE INDEX idx_prof_run_tx
  ON profiler_record(benchmark_run_id, stacks_tx_id)
  WHERE stacks_tx_id IS NOT NULL;

CREATE INDEX idx_prof_run_tag
  ON profiler_record(benchmark_run_id, profiler_tag_id)
  WHERE profiler_tag_id IS NOT NULL;

CREATE INDEX idx_prof_run_hot
  ON profiler_record(
    benchmark_run_id,
    COALESCE(est_wall_us, wall_time_us)
  );

-- ==========================================
-- Dimension table for profiler KV value types.
-- ==========================================
CREATE TABLE profiler_kv_value_type (
  id INTEGER PRIMARY KEY NOT NULL,
  name TEXT NOT NULL UNIQUE
);

INSERT INTO profiler_kv_value_type (id, name)
VALUES 
  (1, 'Unsigned Integer'),
  (2, 'Signed Integer'),
  (3, 'String'),
  (4, 'Bytes');

-- ==========================================
-- Dimension table for profiler KV keys.
-- ==========================================
CREATE TABLE profiler_kv_key (
  id INTEGER PRIMARY KEY NOT NULL,
  key TEXT NOT NULL UNIQUE
);

-- ==========================================
-- Dimension table for profiler KV values.
-- ==========================================
CREATE TABLE profiler_kv_value (
  id INTEGER PRIMARY KEY NOT NULL,
  profiler_kv_value_type_id INTEGER NOT NULL,
  value TEXT NOT NULL,

  FOREIGN KEY (profiler_kv_value_type_id) REFERENCES profiler_kv_value_type(id),
  UNIQUE (value, profiler_kv_value_type_id)
);

-- ==========================================
-- Fact table for profiler key/value records per profiler_record node.
-- ==========================================
CREATE TABLE profiler_record_kv (
  profiler_record_id INTEGER NOT NULL,
  profiler_kv_key_id INTEGER NOT NULL,
  profiler_kv_value_id INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,

  PRIMARY KEY (profiler_record_id, profiler_kv_key_id, profiler_kv_value_id),

  FOREIGN KEY (profiler_record_id) REFERENCES profiler_record(id) ON DELETE CASCADE,
  FOREIGN KEY (profiler_kv_key_id) REFERENCES profiler_kv_key(id),
  FOREIGN KEY (profiler_kv_value_id) REFERENCES profiler_kv_value(id)
) WITHOUT ROWID;

CREATE INDEX idx_prkv_key_val_record
  ON profiler_record_kv(profiler_kv_key_id, profiler_kv_value_id, profiler_record_id);

-- ==========================================
-- Fact table for extracted Clarity cost counters per profiler_record.
-- ==========================================
CREATE TABLE profiler_record_clarity_costs (
  profiler_record_id INTEGER PRIMARY KEY NOT NULL,
  runtime INTEGER NOT NULL,
  read_count INTEGER NOT NULL,
  read_length INTEGER NOT NULL,
  write_count INTEGER NOT NULL,
  write_length INTEGER NOT NULL,
  input_n INTEGER NOT NULL,

  FOREIGN KEY (profiler_record_id) REFERENCES profiler_record(id) ON DELETE CASCADE
) WITHOUT ROWID;

-- ==========================================
-- Staging table for profiler Clarity cost rows.
-- ==========================================
CREATE TABLE _staged_profiler_record_clarity_costs (
  profiler_record_id INTEGER NOT NULL,
  runtime INTEGER NOT NULL,
  read_count INTEGER NOT NULL,
  read_length INTEGER NOT NULL,
  write_count INTEGER NOT NULL,
  write_length INTEGER NOT NULL,
  input_n INTEGER NOT NULL,

  PRIMARY KEY (profiler_record_id)
) WITHOUT ROWID;

-- ==========================================
-- Staging table for profiler KV rows.
-- ==========================================
CREATE TABLE _staged_profiler_record_kv (
  profiler_record_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  value_type_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,

  PRIMARY KEY (profiler_record_id, key, value_type_id, value)
) WITHOUT ROWID;

-- ==========================================
-- Summary table for profiler spans per run+block (real or synthetic).
-- ==========================================
CREATE TABLE profiler_span_block_summary (
  benchmark_run_id INTEGER NOT NULL,
  synthetic_block_id INTEGER NOT NULL,
  profiler_span_id INTEGER NOT NULL,

  record_count INTEGER NOT NULL,
  call_count INTEGER NOT NULL,
  sample_count INTEGER NOT NULL,

  wall_time_us INTEGER NOT NULL,
  self_wall_time_us INTEGER NOT NULL,
  cpu_time_us INTEGER NOT NULL,
  self_cpu_time_us INTEGER NOT NULL,

  -- Sampling expansion factor and estimated totals (NULL when sample_count = 0)
  expand_factor REAL GENERATED ALWAYS AS (
    CASE
      WHEN sample_count > 0 THEN (call_count * 1.0 / sample_count)
      ELSE NULL
    END
  ) VIRTUAL,

  est_wall_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN wall_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_self_wall_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN self_wall_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_cpu_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN cpu_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_self_cpu_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN self_cpu_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,

  PRIMARY KEY (benchmark_run_id, synthetic_block_id, profiler_span_id),

  FOREIGN KEY (benchmark_run_id) REFERENCES benchmark_run(id) ON DELETE CASCADE,
  FOREIGN KEY (synthetic_block_id) REFERENCES synthetic_block(id),
  FOREIGN KEY (profiler_span_id) REFERENCES profiler_span(id)
) WITHOUT ROWID;

CREATE INDEX idx_prof_span_block_summary_run_span
  ON profiler_span_block_summary(benchmark_run_id, profiler_span_id);

-- ==========================================
-- Summary table for profiler spans per run.
-- ==========================================
CREATE TABLE profiler_span_summary (
  benchmark_run_id INTEGER NOT NULL,
  profiler_span_id INTEGER NOT NULL,

  record_count INTEGER NOT NULL,
  call_count INTEGER NOT NULL,
  sample_count INTEGER NOT NULL,

  wall_time_us INTEGER NOT NULL,
  self_wall_time_us INTEGER NOT NULL,
  cpu_time_us INTEGER NOT NULL,
  self_cpu_time_us INTEGER NOT NULL,

    -- Sampling expansion factor and estimated totals (NULL when sample_count = 0)
  expand_factor REAL GENERATED ALWAYS AS (
    CASE
      WHEN sample_count > 0 THEN (call_count * 1.0 / sample_count)
      ELSE NULL
    END
  ) VIRTUAL,

  est_wall_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN wall_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_self_wall_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN self_wall_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_cpu_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN cpu_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,
  est_self_cpu_us REAL GENERATED ALWAYS AS (
    CASE WHEN sample_count > 0 THEN self_cpu_time_us * (call_count * 1.0 / sample_count) END
  ) VIRTUAL,

  PRIMARY KEY (benchmark_run_id, profiler_span_id),

  FOREIGN KEY (benchmark_run_id) REFERENCES benchmark_run(id) ON DELETE CASCADE,
  FOREIGN KEY (profiler_span_id) REFERENCES profiler_span(id)
) WITHOUT ROWID;

-- ==========================================
-- Cache table for chain tip lookups to speed up ancestor queries (e.g. when
-- determining the Stacks block at a given height for a specific tip).
-- ==========================================
CREATE TABLE chain_tip_cache (
  tip_index_hash BLOB NOT NULL,
  height BIGINT NOT NULL,
  index_hash BLOB NOT NULL,
  PRIMARY KEY (tip_index_hash, height),
  CHECK(LENGTH(tip_index_hash) = 32),
  CHECK(LENGTH(index_hash) = 32),
  CHECK(height >= 0)
) WITHOUT ROWID;
