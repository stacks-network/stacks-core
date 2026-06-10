PRAGMA analysis_limit = 1000000;
ANALYZE profiler_record;

BEGIN;

-- Rebuild block summary for this run
DELETE FROM profiler_span_block_summary
WHERE benchmark_run_id = ?1;

INSERT INTO profiler_span_block_summary (
  benchmark_run_id,
  synthetic_block_id,
  profiler_span_id,
  record_count,
  call_count,
  sample_count,
  wall_time_us,
  self_wall_time_us,
  cpu_time_us,
  self_cpu_time_us
)
SELECT
  pr.benchmark_run_id,
  pr.synthetic_block_id,
  pr.profiler_span_id,
  COUNT(*)                AS record_count,
  SUM(pr.call_count)      AS call_count,
  SUM(pr.sample_count)    AS sample_count,
  SUM(pr.wall_time_us)    AS wall_time_us,
  SUM(pr.self_wall_time_us) AS self_wall_time_us,
  SUM(pr.cpu_time_us)     AS cpu_time_us,
  SUM(pr.self_cpu_time_us)  AS self_cpu_time_us
FROM profiler_record pr
WHERE pr.benchmark_run_id = ?1
GROUP BY
  pr.benchmark_run_id,
  pr.synthetic_block_id,
  pr.profiler_span_id;

-- Rebuild run-level summary from block summary
DELETE FROM profiler_span_summary
WHERE benchmark_run_id = ?1;

INSERT INTO profiler_span_summary (
  benchmark_run_id,
  profiler_span_id,
  record_count,
  call_count,
  sample_count,
  wall_time_us,
  self_wall_time_us,
  cpu_time_us,
  self_cpu_time_us
)
SELECT
  s.benchmark_run_id,
  s.profiler_span_id,
  SUM(s.record_count),
  SUM(s.call_count),
  SUM(s.sample_count),
  SUM(s.wall_time_us),
  SUM(s.self_wall_time_us),
  SUM(s.cpu_time_us),
  SUM(s.self_cpu_time_us)
FROM profiler_span_block_summary s
WHERE s.benchmark_run_id = ?1
GROUP BY s.benchmark_run_id, s.profiler_span_id;

COMMIT;

-- Refresh stats for query planner
PRAGMA analysis_limit = 0;
ANALYZE profiler_span_block_summary;
ANALYZE profiler_span_summary;
PRAGMA optimize;
