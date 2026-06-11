-- Requires SQLite >= 3.35.0 (bundled rusqlite satisfies this).
ALTER TABLE benchmark_run DROP COLUMN build_profile;
ALTER TABLE benchmark_run DROP COLUMN build_opt_level;
ALTER TABLE benchmark_run DROP COLUMN build_debug_assertions;
ALTER TABLE benchmark_run DROP COLUMN build_overflow_checks;
ALTER TABLE benchmark_run DROP COLUMN build_target_triple;
ALTER TABLE benchmark_run DROP COLUMN build_rustc_version;
ALTER TABLE benchmark_run DROP COLUMN git_branch;
ALTER TABLE benchmark_run DROP COLUMN git_dirty;
