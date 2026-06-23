# `stacks-bench` structured output (wire contract)

Every `stacks-bench` command that produces machine-readable output — both
`--json` on the CLI and every successful MCP tool result — wraps its payload in a
single **versioned envelope**, `CommandResult`. (CLI failures are enveloped too,
with `success: false`; MCP failures use the protocol's native error channel —
see [CLI vs MCP](#cli-vs-mcp).) [`v1.json`](v1.json) is the machine-readable JSON
Schema for that envelope and for every payload it carries.

## Envelope

`--json` reserves stdout for one final [`CommandResult`](#envelope) object. Long
running commands may also emit newline-delimited progress events to stderr; see
[Progress JSONL](#progress-jsonl).

```json
{
  "schema_version": 1,
  "success": true,
  "result_type": "run",
  "result_version": 1,
  "duration_secs": 12.34,
  "result": { "...": "payload, shape per (result_type, result_version)" }
}
```

The **header** — every field except `result` — is a **frozen contract**:

| Field | Meaning |
| ---- | ---- |
| `schema_version` | Version of the envelope structure itself (this header). |
| `success` | `true` on success, `false` on error. |
| `result_type` | Discriminator for the `result` payload (e.g. `run`, `compare`, `run_list`); `error` on failure. |
| `result_version` | Schema version of the `result` payload contract; `0` on failure. |
| `duration_secs` | Command / tool-call wall time, measured at the dispatch boundary on both surfaces. |
| `error` | Error message; present only when `success` is `false` (CLI `--json` only — see below). |
| `result` | The version-specific payload; present only when `success` is `true`. |

For an enveloped result, a consumer can parse the header to learn status and,
via (`result_type`, `result_version`), exactly how to interpret `result` —
without inspecting the body, and regardless of which `stacks-bench` build
produced it.

## Progress JSONL

When `--json` is active, long-running CLI commands emit versioned progress
events to stderr as newline-delimited JSON. Stdout remains reserved for the
single final command envelope.

```json
{"schema_version":1,"event_type":"progress","event_version":1,"progress":{"phase":"replay","current":42.0,"total":100.0,"message":"Replaying measured entries"}}
```

| Field | Meaning |
| ---- | ---- |
| `schema_version` | Version of the CLI event envelope structure. |
| `event_type` | Event discriminator. Currently `progress`. |
| `event_version` | Schema version of this event type's payload. |
| `progress` | Progress payload, present when `event_type` is `progress`. |
| `progress.phase` | Stable phase label, e.g. `indexing`, `baseline`, `warmup`, `replay`, or `cleanup`. |
| `progress.current` | Phase-relative current progress value. |
| `progress.total` | Optional phase-relative total. |
| `progress.message` | Optional human-readable status text. |

The machine-readable schema lives under `cli_events.progress` in
[`v1.json`](v1.json). Consumers should treat stderr as JSONL, parsing one event
per line and ignoring unknown fields.

## Benchmark baseline fields

The `run` payload includes a `baseline` object describing how the empty-block
overhead baseline was handled for that benchmark:

- `mode: "inline"` means the run measured a new baseline before replay and
  saved it as a reusable calibration.
- `mode: "external"` means the run reused an existing calibration by id.
- `mode: "skipped"` means no empty-block baseline was measured or linked.

The CLI-only `baseline_calibration` payload is returned by
`bench baseline calibrate` and contains the saved calibration id plus the
measured empty-block averages. The payload schema is listed under
`cli_payloads.baseline_calibration` in [`v1.json`](v1.json).

By default, both inline `bench run` baseline measurement and standalone
`bench baseline calibrate` use the resolved chain tip as the calibration
anchor. `bench run --baseline-id` requires the saved calibration to belong to
the same indexed chainstate and tip anchor as the run.

## Evolution policy

- **The header is frozen.** Header fields are never renamed, removed, or
  repurposed. `schema_version` bumps only if the header structure ever changes.
- **Payloads evolve additively within a `result_version`.** Adding an optional
  field does **not** bump the version. Renaming, removing, or changing the
  **meaning** of a field **does** bump that payload's `result_version` —
  including semantic changes that leave the JSON shape identical (e.g. a metric
  whose definition changed).
- **Be a tolerant reader.** Parse the header strictly; parse the payload
  leniently (ignore unknown fields, treat missing fields as absent). Then
  additive producer changes never break you — only a `result_version` bump
  requires consumer work, and the bump is the signal that it does.

## CLI vs MCP

The **success** envelope is identical on both surfaces. Two notes:

- **Errors differ by surface.** On the CLI, a failure is still an envelope
  (`success: false`, `result_type: "error"`, populated `error`, no `result`) —
  it is the only structured channel `--json` has. On MCP, an application failure
  surfaces as a native MCP tool/protocol error, **not** a `success: false`
  envelope: only successful tool results are enveloped. MCP clients should use
  the protocol's error signal; the envelope describes the success body.
- A few `result_type`s exist on both surfaces with **different payload shapes**
  (`run_list`, `chainstate_list`): the CLI and MCP list commands predate this
  contract and emit different fields. They are documented separately under
  `cli_payloads` and `mcp_payloads` in [`v1.json`](v1.json). `run` and
  `chainstate_index` share one type across both surfaces.

## Excluded payloads

The `metabase` and `explorer` commands launch web UIs; their `--json` output is
a status blob tagged `result_type: "opaque"`, `result_version: 0`. These are
**not** stable contracts and are intentionally omitted from
[`v1.json`](v1.json).

## Regenerating `v1.json`

The schema is generated from the Rust types and guarded by a test
(`schema_gen::schema_v1_is_current`) that fails if the code drifts from the
checked-in file. After any wire change, regenerate with:

```text
UPDATE_SCHEMA=1 cargo test -p stacks-bench --bin stacks-bench schema_v1
```

and commit the updated `v1.json`. If the change is non-additive, also bump the
affected payload's `result_version` (in its `wire_payload!(...)` declaration)
and the entry in `src/schema_gen.rs`.
