PRAGMA foreign_keys = OFF;

-- Build index to speed up aggregation
CREATE INDEX IF NOT EXISTS idx_staged_prkv_group
  ON _staged_profiler_record_kv(profiler_record_id, key, value_type_id, value);

-- Aggregate early to reduce all downstream work
DROP TABLE IF EXISTS _agg_profiler_kv;
CREATE TEMP TABLE _agg_profiler_kv AS
SELECT
  profiler_record_id,
  key,
  value_type_id,
  value,
  SUM(count) AS count
FROM _staged_profiler_record_kv
GROUP BY profiler_record_id, key, value_type_id, value;

-- Aggregation indexes
CREATE INDEX _agg_key_idx ON _agg_profiler_kv(key);
CREATE INDEX _agg_val_idx ON _agg_profiler_kv(value_type_id, value);

-- Merge dims from reduced set
INSERT INTO profiler_kv_key(key)
SELECT key FROM _agg_profiler_kv
GROUP BY key
ON CONFLICT(key) DO NOTHING;

INSERT INTO profiler_kv_value(profiler_kv_value_type_id, value)
SELECT value_type_id, value FROM _agg_profiler_kv
GROUP BY value_type_id, value
ON CONFLICT(value, profiler_kv_value_type_id) DO NOTHING;

-- Merge fact from reduced set
INSERT INTO profiler_record_kv (
  profiler_record_id, profiler_kv_key_id, profiler_kv_value_id, count
)
SELECT
  a.profiler_record_id,
  k.id,
  v.id,
  a.count
FROM _agg_profiler_kv a
JOIN profiler_kv_key k
  ON k.key = a.key
JOIN profiler_kv_value v
  ON v.profiler_kv_value_type_id = a.value_type_id
 AND v.value = a.value
ORDER BY a.profiler_record_id, k.id, v.id
ON CONFLICT (profiler_record_id, profiler_kv_key_id, profiler_kv_value_id)
DO UPDATE SET count = count + excluded.count;

DROP TABLE _agg_profiler_kv;

DELETE FROM _staged_profiler_record_kv;

DROP INDEX idx_staged_prkv_group;

PRAGMA foreign_keys = ON;
