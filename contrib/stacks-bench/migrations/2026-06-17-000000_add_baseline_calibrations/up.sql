-- Reusable empty-block overhead calibrations.
--
-- `block_processing_baseline` remains the per-run compatibility table. This
-- table stores first-class calibration records that benchmark runs may either
-- create inline or reuse by id.
CREATE TABLE baseline_calibration (
  id INTEGER PRIMARY KEY NOT NULL,
  chainstate_id INTEGER NOT NULL,
  created_at TIMESTAMP NOT NULL,
  git_commit_hash BLOB NOT NULL,
  args_json TEXT NOT NULL,

  -- Parent used as the initial anchor for the empty-block baseline procedure.
  start_parent_index_hash BLOB NOT NULL,

  warmup_blocks INTEGER NOT NULL,
  measured_blocks INTEGER NOT NULL,

  -- Duration metrics (microseconds), each is an average per block over the
  -- measured window.
  avg_setup_us INTEGER NOT NULL,
  avg_finalize_us INTEGER NOT NULL,
  avg_clarity_commit_us INTEGER NOT NULL,
  avg_advance_tip_us INTEGER NOT NULL,
  avg_index_commit_us INTEGER NOT NULL,

  converged BOOLEAN NOT NULL,
  segments_used INTEGER NOT NULL,
  measurement_window INTEGER NOT NULL,
  total_blocks INTEGER NOT NULL,
  duration_us BIGINT NOT NULL,

  FOREIGN KEY (chainstate_id) REFERENCES chainstate(id) ON DELETE CASCADE,
  CHECK(length(git_commit_hash) IN (20, 32)),
  CHECK(length(start_parent_index_hash) = 32)
);

CREATE INDEX idx_baseline_calibration_chainstate_created
  ON baseline_calibration(chainstate_id, created_at DESC);

ALTER TABLE benchmark_run ADD COLUMN baseline_calibration_id INTEGER
  REFERENCES baseline_calibration(id) ON DELETE SET NULL;
