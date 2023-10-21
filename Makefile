# Shortcuts for common commands

.PHONY: fmt fmt-check

# Run `cargo fmt` with CLI options not available in rustfmt.toml
fmt:
	cargo fmt -- --config group_imports=StdExternalCrate,imports_granularity=Module

# Run `cargo fmt` with CLI options not available in rustfmt.toml (check only)
fmt-check:
	cargo fmt -- --check --config group_imports=StdExternalCrate,imports_granularity=Module
