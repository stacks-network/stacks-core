-- Requires SQLite >= 3.35.0 (bundled rusqlite satisfies this).
ALTER TABLE benchmark_run DROP COLUMN baseline_calibration_id;
DROP INDEX idx_baseline_calibration_chainstate_created;
DROP TABLE baseline_calibration;
