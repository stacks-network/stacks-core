---
applyTo: "**/Cargo.toml,**/Cargo.lock,rust-toolchain.toml"
---

# Cargo and Rust toolchain review guidance

- For `Cargo.toml` changes, check feature unification, default and optional features, workspace inheritance, target-specific dependencies, and compatibility with CI and release builds.
- Verify new or changed dependencies use the intended version, features, source, and target scope, and flag avoidable supply-chain or maintenance risk when it has a concrete impact.
- For `Cargo.lock` changes, verify the diff follows from the manifest changes and flag unexplained dependency additions, source changes, or unexpectedly broad transitive updates.
- For `rust-toolchain.toml` changes, check compatibility with CI, release builds, repository tooling, and the minimum supported Rust version.
