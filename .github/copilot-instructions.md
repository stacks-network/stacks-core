# Copilot Instructions for stacks-core

## Project Overview
- **stacks-core** is a Rust-based blockchain implementation for the Stacks protocol, supporting smart contracts, consensus, and node operations.
- Major components:
  - `clarity/`: Smart contract VM and related logic
  - `stacks-node/`: Node runtime, networking, consensus
  - `stacks-common/`, `clarity-types/`: Shared types, utilities
  - `libsigner/`, `libstackerdb/`, `pox-locking/`: Specialized modules for signing, database, and PoX logic
  - `contrib/`: Test suites, boot contracts, integration helpers
  - `docs/`: Developer and protocol documentation

## Developer Workflows
- **Build:** Use `cargo build --release` at the repo root. Some sub-crates (e.g., `clarity/`, `stacks-node/`) can be built/tested independently.
- **Test:** Run `cargo test --workspace` for all Rust tests. For contract tests, use Clarinet (`clarinet test` in relevant `contrib/` folders).
- **Fuzzing:** Fuzz targets are in `clarity/fuzz/` and `stackslib/fuzz/`.
- **Debugging:** Use Rust debugging tools (e.g., `rust-gdb`, VS Code Rust extension). Node logs are verbose; check `stacks-node/src/` for logging patterns.

## Project-Specific Patterns
- **Smart Contracts:** Written in Clarity, tested via Clarinet in `contrib/`.
- **PoX Logic:** Implemented in `pox-locking/` and referenced by `stacks-node/`.
- **Shared Types:** Use `stacks-common/` and `clarity-types/` for cross-crate data structures.
- **Testing:** Rust unit/integration tests in `src/tests/` folders; contract tests in `contrib/*/tests/`.
- **Config:** Node config in `stacks-node/Stacks.toml`, contract config in `contrib/*/Clarinet.toml`.

## Integration Points
- **External Dependencies:**
  - Clarinet (for contract testing)
  - Docker (see `Dockerfile`, `deployment/`)
  - Python scripts for sidecar utilities (`side-cars/`, `miner-queries/`)
- **Cross-Component Communication:**
  - Node <-> VM: `stacks-node` calls into `clarity` for contract execution
  - Shared types/interfaces in `stacks-common/`, `clarity-types/`

## Conventions
- **Rust Style:** Follows standard Rust conventions, but shared types are centralized.
- **Testing:** Prefer workspace-wide tests; contract tests are run separately via Clarinet.
- **Docs:** Key developer docs in `docs/` (e.g., `release-process.md`, `profiling.md`)

## Examples
- To run all tests: `cargo test --workspace`
- To test contracts: `cd contrib/boot-contracts-unit-tests && clarinet test`
- To build node: `cargo build --release --package stacks-node`

## Key Files/Directories
- `clarity/`, `stacks-node/`, `stacks-common/`, `contrib/`, `docs/`, `deployment/`, `.github/`

---

_If any section is unclear or missing important project-specific details, please provide feedback to improve these instructions._
