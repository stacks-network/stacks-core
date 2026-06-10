-- Build provenance: which binary produced this run.
ALTER TABLE benchmark_run ADD COLUMN build_profile TEXT NOT NULL DEFAULT '';
ALTER TABLE benchmark_run ADD COLUMN build_opt_level TEXT NOT NULL DEFAULT '';
ALTER TABLE benchmark_run ADD COLUMN build_debug_assertions BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE benchmark_run ADD COLUMN build_overflow_checks BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE benchmark_run ADD COLUMN build_target_triple TEXT NOT NULL DEFAULT '';
ALTER TABLE benchmark_run ADD COLUMN build_rustc_version TEXT NOT NULL DEFAULT '';

-- Repository provenance: state of the source tree at run time.
-- Nullable because git may not be available (Docker, tarball, etc.).
ALTER TABLE benchmark_run ADD COLUMN git_branch TEXT;
ALTER TABLE benchmark_run ADD COLUMN git_dirty BOOLEAN;
