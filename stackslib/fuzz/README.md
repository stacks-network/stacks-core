# Fuzz Testing

This directory contains fuzz targets for the stackslib package using [libfuzzer-sys](https://docs.rs/libfuzzer-sys/).

## Requirements

- Rust nightly toolchain
- `cargo-fuzz` (installed automatically by the coverage script)
- `llvm-tools` component (installed automatically by the coverage script)

## Running Fuzz Tests

List available targets:

```bash
cargo +nightly fuzz list
```

Run a fuzz target:

```bash
cargo +nightly fuzz run <target_name>
```

## Coverage Reports

The `report-coverage.sh` script generates HTML/text coverage reports for fuzz targets.

### Basic Usage

```bash
bash report-coverage.sh <target_name>
```

### Options

Use `text` to show a console summary:

```bash
bash report-coverage.sh <target_name> text
```

### Output

The script creates:

- **HTML Report**: `coverage/<target>/html/index.html` - Interactive coverage view
- **Text Report**: Console summary (when using `text` option)

### File Locations

- Profile data: `coverage/<target>/coverage.profdata`
- HTML reports: `coverage/<target>/html/`
- Coverage binaries: `target/*/coverage/*/release/<target>`
