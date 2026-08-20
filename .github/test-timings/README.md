# CI test timings

These files contain historical JUnit runtimes used to balance GitHub Actions
test jobs. Unknown tests receive `default_seconds`, so newly added tests still
run without requiring an immediate timing update.

The Bitcoin file records every integration test. The unit file records only
tests taking at least five seconds, which keeps the file small while
distributing the fast remainder evenly. Unknown tests use the observed 75th
percentile as a conservative default.

## Refreshing timings

Download the JUnit artifacts from a representative successful run, then invoke
the generator for the desired suite:

```bash
timing_dir=$(mktemp -d)
gh run download RUN_ID --pattern 'nextest-unit-tests-*' --dir "$timing_dir"
python3 .github/scripts/generate_test_timings.py \
  --input-dir "$timing_dir" \
  --source-run RUN_ID \
  --minimum-seconds 5 \
  --output .github/test-timings/unit.json
```

For Bitcoin integrations, use the artifact pattern
`nextest-batched-integration-tests-*`, omit `--minimum-seconds`, and output to
`bitcoin-integration.json`.
