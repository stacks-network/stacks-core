# Copilot Instructions for stacks-core

## Project Overview
**stacks-core** is a Rust-based blockchain implementation for the Stacks protocol, supporting smart contracts, consensus, and node operations. This is blockchain software where **there is no roll-back** from bad deployments, requiring extremely high rigor in development.

### Major Components
- `clarity/`: Smart contract VM and Clarity language implementation
- `stacks-node/`: Node runtime, networking, consensus logic
- `stackslib/`: Core blockchain logic, chainstate, and transaction processing
- `stacks-common/`, `clarity-types/`: Shared types and utilities across the codebase
- `libsigner/`: Signer implementation for the Stacks blockchain
- `libstackerdb/`: StackerDB database implementation
- `pox-locking/`: Proof of Transfer (PoX) consensus logic
- `stacks-signer/`: Signer binary for the Stacks blockchain
- `contrib/`: Test suites, boot contracts, tools, and integration helpers
- `docs/`: Developer and protocol documentation

### Workspace Structure
This is a Cargo workspace with 13 main crates (see `Cargo.toml`). Dependency versions are coordinated via `[workspace.dependencies]`.

## Build & Development

### Build Commands
```bash
# Full optimized release build
cargo build --release

# Faster build for low-RAM environments (16GB or less)
cargo build --profile release-lite

# Build specific packages
cargo build --release --package stacks-node
cargo build --release --package stacks-signer

# Build with native CPU optimizations (edit .cargo/config.toml)
RUSTFLAGS="-Ctarget-cpu=native" cargo build --release
```

### Testing
```bash
# Run all unit tests in parallel (recommended, uses nextest)
cargo nextest run

# Run workspace tests with standard cargo
cargo test --workspace

# Run specific test (single-threaded if needed)
cargo test testnet -- --test-threads=1

# Run tests with tags (using pinny-rs)
cargo test -- --tag slow
cargo nextest run --tags 'slow & bitcoind'
```

**Test Tagging**: Integration tests must be tagged using [pinny-rs](https://github.com/BitcoinL2-Labs/pinny-rs/):
- `slow`: Tests running over a minute
- `bitcoind`: Tests requiring Bitcoin daemon
- `flaky`: Tests with flaky behavior

Tests taking >1 minute or requiring `--test-threads 1` should be marked `#[ignore]`.

### Code Quality

**Formatting (REQUIRED)**:
```bash
# Check formatting (required for PR approval)
cargo fmt-stacks --check

# Auto-format code
cargo fmt-stacks
```

**Linting (REQUIRED)**:
```bash
# Check clippy warnings (required for PR approval)
cargo clippy-stacks
cargo clippy-stackslib
```

Both commands must pass with zero warnings before opening a PR.

### Contract Testing
```bash
# Test Clarity contracts with Clarinet
cd contrib/boot-contracts-unit-tests && clarinet test
cd contrib/core-contract-tests && clarinet test
```

## Architecture & Patterns

### Consensus-Critical Code
**CRITICAL**: Changes affecting block/transaction processing or state root hashes are consensus-breaking:
- Must be opened against `next` branch (never `develop` or `master`)
- Must be gated on Stacks epoch activation
- Requires a SIP (Stacks Improvement Proposal)
- Examples: changing wire formats, MARF storage, Clarity functions/costs, transaction validation

### Database Changes
- **Preserve schema when possible** - users shouldn't need to re-sync from genesis
- Schema changes require:
  - New schema version
  - Migration logic with test coverage
  - Indexed columns for all queries (no table scans - use `BLOCKSTACK_DB_TRACE` to verify)
- If no migration possible, verify genesis sync before submitting PR
- Database changes cannot be consensus-critical unless part of hard fork

### Code Organization
- **Business logic and I/O must be separated**: Use inner/outer function pattern
  - Inner functions: pure logic, no I/O
  - Outer functions: handle I/O, call inner functions
- **One subsystem per file** (except `mod.rs`)
- Directories represent collections of related subsystems

### Data Input Rules
- **Network/Bitcoin/config data is UNTRUSTED** - handle any byte sequence safely
- **Database data is TRUSTED** - can panic if corrupted
- All input processing must be:
  - Space-bound (maximum size limits)
  - Resource-bound (RAM/CPU limits for deserialization)
  - Time-bound (for network inputs)
- **Never panic on untrusted data** - use proper error handling

### Error Handling & Logging
- Use `Result` with proper `Error` types (define new types for new modules)
- Never use `println!()` or `eprintln!()` - use logging macros: `trace!()`, `debug!()`, `info!()`, `warn!()`, `error!()`
- Use structured logging: `info!("Block appended"; "block_id" => %block_id)`
- `test_debug!()` and `trace!()` only run in tests
- `debug!()` enabled via `BLOCKSTACK_DEBUG` env var

## Branching & Release

### Branch Strategy (Gitflow)
- `master`: Production-ready state
- `develop`: Latest development changes for next release
- `next`: Consensus-breaking changes for future hard forks
- `release/X.Y.Z.A.n`: Release branches
- Feature branches: `feat/`, `fix/`, `chore/`, `docs/`, `ci/`, `test/`, `refactor/`

### Versioning
Format: `X.Y.Z.A.n` (from `versions.toml`)
- X: Major version (e.g., Stacks 3.0)
- Y: Consensus-breaking changes
- Z: Non-consensus breaking, requires fresh chainstate
- A: Non-consensus breaking, new features
- n: Patches and hotfixes

### Release Process
- Avoid releases during PoX prepare phase (24h before cycle start)
- Block validation required before release
- CHANGELOG update required
- Release candidates tested on staging infrastructure
- See `docs/release-process.md` for full process

## PR Requirements

### Submission Checklist
- Answer: What problem? What solution? Why best solution? What alternatives?
- Reviewable in ≤2 hours (break into smaller PRs if needed)
- Pass `cargo fmt-stacks --check` and `cargo clippy-stacks`
- Include test coverage (unit + integration if consumer-visible)
- Update CHANGELOG for user-facing changes
- Update OpenAPI spec (`docs/rpc/openapi.yaml`) for RPC changes
- Document all public APIs with rustdoc comments
- Performance claims need reproducible benchmarks

### Documentation Standards
- Each file needs copyright statement
- Non-test modules need module-level documentation
- Public functions/structs/enums/traits need rustdoc comments
- Private non-trivial functions need comments
- Struct/enum fields need comment strings
- Don't restate names in comments - add new information only

### Code Conventions
- Simplicity over cleverness - reject complex implementations
- Stable Rust only (no nightly features)
- Minimal dependencies (case-by-case approval)
- Minimal `unsafe` code
- No compiler warnings (no warning-masking macros)

## Integration Points

### External Dependencies
- **Clarinet**: Contract testing framework (`contrib/*/Clarinet.toml`)
- **Docker**: Container builds (`Dockerfile`, `deployment/`)
- **nextest**: Parallel test runner (recommended)
- **pinny-rs**: Test tagging system
- **Bitcoin**: Burnchain integration (requires bitcoind for some tests)

### Cross-Component Communication
- Node → VM: `stacks-node` invokes `clarity` for contract execution
- Shared types: `stacks-common/` and `clarity-types/` provide cross-crate interfaces
- PoX: `pox-locking/` implements consensus, used by `stacks-node/`
- Signer: `libsigner/` provides signing interfaces

### Configuration Files
- `versions.toml`: Version numbers for releases
- `.cargo/config.toml`: Cargo aliases and build settings
- `Cargo.toml`: Workspace configuration and dependencies
- `contrib/*/Clarinet.toml`: Contract project configurations

## Important Policies

### AI Code Generation
**STRICTLY PROHIBITED**: The Stacks Foundation does not accept AI-generated code PRs due to licensing concerns. All code must be human-written.

### Review Expectations
- Reviews should complete in 2 business days
- Reviewers provide complete acceptance plan in one round
- Submitters incorporate clarifications into code comments
- Large refactorings must be in separate PRs

## Common Tasks

### Run the Node
```bash
# Start testnet follower
cargo stacks-node -- start --config ./sample/conf/testnet-follower-conf.toml

# Or with release build
./target/release/stacks-node start --config ./sample/conf/testnet-follower-conf.toml
```

### Performance Testing
- Use profiling tools (see `docs/profiling.md`)
- Provide reproducible benchmarks for performance improvement PRs
- Example: [PR #3075](https://github.com/stacks-network/stacks-core/pull/3075)

### Debugging
- Rust tools: `rust-gdb`, VS Code Rust extension
- Enable debug logs: `BLOCKSTACK_DEBUG=1`
- Database query tracing: `BLOCKSTACK_DB_TRACE=1`
- Check verbose node logs in `stacks-node/src/`

## Key Documentation
- `CONTRIBUTING.md`: Full contribution guidelines
- `docs/release-process.md`: Release procedures
- `docs/branching.md`: Git branching strategy
- `docs/ci-workflow.md`: CI/CD pipeline
- `docs/profiling.md`: Performance analysis
- `docs/rpc-endpoints.md`: RPC API documentation
- `docs/event-dispatcher.md`: Event system
- `docs/mining.md`: Mining documentation

## File Locations
- Main crates: `clarity/`, `stacks-node/`, `stackslib/`, `stacks-common/`, `clarity-types/`
- Supporting crates: `libsigner/`, `libstackerdb/`, `pox-locking/`, `stacks-signer/`
- Tests: `*/src/tests/`, `contrib/*/tests/`
- Fuzz targets: `clarity/fuzz/`, `stackslib/fuzz/`
- Docs: `docs/`, `README.md`, `CONTRIBUTING.md`
- CI: `.github/workflows/`

---

_These instructions prioritize safety, correctness, and maintainability for blockchain software. When in doubt, ask for clarification._
