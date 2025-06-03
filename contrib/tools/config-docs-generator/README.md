# Configuration Documentation Generator

A tool that automatically generates comprehensive Markdown documentation for Stacks node TOML configuration options. The documentation is extracted directly from Rust source code comments and generates a complete configuration reference.

## Quick Start

### Using Docker (Recommended)

The easiest way to generate configuration documentation:

```bash
# Build the Docker image (one-time setup)
docker build -t config-docs-generator .

# Generate documentation
docker run --rm -v "$(pwd):/project_root" --user "$(id -u):$(id -g)" config-docs-generator
```

This approach:
- Uses a consistent nightly Rust environment
- Generates `docs/generated/configuration-reference.md`

### Using Local Setup (Alternative)

If you prefer to run without Docker:

```bash
# Install nightly toolchain if needed
rustup toolchain install nightly

# Generate documentation
./contrib/tools/config-docs-generator/generate-config-docs.sh
```

## What It Does

The tool processes these configuration structs from the Stacks codebase:
- `BurnchainConfig` → `[burnchain]` section
- `NodeConfig` → `[node]` section
- `MinerConfig` → `[miner]` section
- `ConnectionOptionsFile` → `[connection_options]` section
- `FeeEstimationConfigFile` → `[fee_estimation]` section
- `EventObserverConfigFile` → `[event_observer]` section
- `InitialBalanceFile` → `[initial_balances]` section

For each configuration field, it extracts:
- Field documentation from `///` comments
- Default values (including constant references)
- Usage notes and examples
- Deprecation warnings

## Output Files

- **Primary**: `docs/generated/configuration-reference.md` - Complete configuration reference
- **Intermediate**: `target/doc-generation/extracted-config-docs.json` - Raw extracted data

## Adding New Configuration Structs

### 1. Update the Target List

Edit `contrib/tools/config-docs-generator/generate-config-docs.sh`:

```bash
TARGET_STRUCTS="BurnchainConfig,NodeConfig,MinerConfig,YourNewConfig"
```

### 2. Document Your Struct

Add proper documentation to your Rust configuration struct:

```rust
/// Configuration for your new feature.
///
/// This controls how the feature operates and integrates
/// with the existing node functionality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YourNewConfig {
    /// Enable or disable the new feature.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - Requires restart to take effect
    ///   - May impact performance when enabled
    /// @toml_example: |
    ///   enabled = true
    pub enabled: bool,

    /// Timeout for feature operations in milliseconds.
    /// ---
    /// @default: [`DEFAULT_TIMEOUT`]
    pub timeout: u64,
}
```

### Supported Annotations

- **@default**: Default value (supports constant references like `[`CONSTANT_NAME`]`)
- **@notes**: Bullet-pointed usage notes
- **@deprecated**: Deprecation message
- **@toml_example**: Example TOML configuration

### 3. Add Section Mapping (Optional)

If you want a custom TOML section name, edit `src/generate_markdown.rs`:

```rust
fn struct_to_section_name(struct_name: &str) -> String {
    match struct_name {
        "YourNewConfig" => "[your_custom_section]".to_string(),
        // ... existing mappings
        _ => format!("[{}]", struct_name.to_lowercase()),
    }
}
```

### 4. Generate and Verify

```bash
# Using Docker (recommended)
docker run --rm -v "$(pwd):/project_root" --user "$(id -u):$(id -g)" config-docs-generator

# OR using local setup
./contrib/tools/config-docs-generator/generate-config-docs.sh

# Check that your struct appears
grep -A 5 "your_custom_section" docs/generated/configuration-reference.md
```

## How It Works

The tool uses a three-step process:

1. **Extract**: Uses `cargo +nightly rustdoc --output-format json` to generate documentation JSON
2. **Parse**: Extracts field information, resolves constant references across crates
3. **Generate**: Converts to Markdown with proper cross-references and formatting

The process is automated by the shell script which coordinates building the tools and running the extraction/generation pipeline.
