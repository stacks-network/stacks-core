PRAGMA foreign_keys = OFF;

-- Aggregate to a single row per profiler_record
DROP TABLE IF EXISTS _agg_profiler_clarity_costs;
CREATE TEMP TABLE _agg_profiler_clarity_costs AS
SELECT
  profiler_record_id,
  SUM(runtime) AS runtime,
  SUM(read_count) AS read_count,
  SUM(read_length) AS read_length,
  SUM(write_count) AS write_count,
  SUM(write_length) AS write_length,
  SUM(input_n) AS input_n
FROM _staged_profiler_record_clarity_costs
GROUP BY profiler_record_id;

-- Merge fact from reduced set
INSERT INTO profiler_record_clarity_costs (
  profiler_record_id,
  runtime,
  read_count,
  read_length,
  write_count,
  write_length,
  input_n
)
SELECT
  profiler_record_id,
  runtime,
  read_count,
  read_length,
  write_count,
  write_length,
  input_n
FROM _agg_profiler_clarity_costs
WHERE 1
ON CONFLICT (profiler_record_id) DO UPDATE SET
  runtime = excluded.runtime,
  read_count = excluded.read_count,
  read_length = excluded.read_length,
  write_count = excluded.write_count,
  write_length = excluded.write_length,
  input_n = excluded.input_n;

DROP TABLE _agg_profiler_clarity_costs;

DELETE FROM _staged_profiler_record_clarity_costs;

PRAGMA foreign_keys = ON;
