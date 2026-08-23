# CI test timings

These files contain historical JUnit runtimes used to balance GitHub Actions
test jobs. Unknown tests receive `default_seconds`, so newly added tests still
run without requiring an immediate timing update. Retried attempts are included
in each test's runtime so flaky tests do not silently underweight a partition.
Concurrent named batches also use these weights to start their longest tests
first, reducing idle time near the end of each job.

The Bitcoin matrix balances effective execution-slot time: ordinary signer
tests use `SIGNER_TEST_THREADS_REQUIRED`, while exclusive stress tests use all
`BITCOIN_TEST_THREADS`. Keep those workflow values aligned with the
`threads-required` overrides in `ci-nextest.toml`. `BITCOIN_BATCH_COUNT`
controls the runner count independently from the `BATCH_SIZE` per-runner cap,
allowing heavyweight batches to contain fewer tests.

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

For a more stable estimate, download several representative runs into separate
directories and repeat `--input-dir` for each one. The generator uses each
test's 80th-percentile runtime across those runs; use `--test-percentile` to
override it and set `--source-run` to the newest included run.

For Bitcoin integrations, use the artifact pattern
`nextest-batched-integration-tests-*`, omit `--minimum-seconds`, and output to
`bitcoin-integration.json`.

For P2P integrations, use `nextest-p2p-*`, omit `--minimum-seconds`, and output
to `p2p.json`. Include multiple runs because topology convergence timings vary
substantially between otherwise identical runners.
