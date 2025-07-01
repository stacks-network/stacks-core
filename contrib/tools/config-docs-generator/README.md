# Configuration Documentation Generator

This tool automatically generates markdown documentation from Rust configuration structs by extracting specially formatted doc comments.

## Quick Start

### Using Docker (Recommended)

The easiest way to generate configuration documentation:

```bash
# Navigate to the config-docs-generator directory
cd contrib/tools/config-docs-generator

# Build the Docker image (one-time setup)
docker build -t config-docs-generator .

# Generate documentation
docker run --rm -v "$(pwd)/../../../:/project_root" config-docs-generator
```

This approach:
- Uses a consistent nightly Rust environment
- Generates `docs/generated/configuration-reference.md`

### Using Local Setup (Alternative)

If you prefer to run without Docker:

### Prerequisites

- Rust nightly toolchain (install with `rustup toolchain install nightly`)
- jq (install with `apt-get install jq`)

### Steps

```bash
# Install nightly toolchain if needed
rustup toolchain install nightly

# Navigate to the config-docs-generator directory
cd contrib/tools/config-docs-generator

# Generate documentation
./generate-config-docs.sh
```

## What It Does

The tool processes these configuration structs from the Stacks codebase:
- `BurnchainConfig` → `[burnchain]` section
- `NodeConfig` → `[node]` section
- `MinerConfig` → `[miner]` section
- `ConnectionOptionsFile` → `[connection_options]` section
- `FeeEstimationConfigFile` → `[fee_estimation]` section
- `EventObserverConfigFile` → `[[events_observer]]` section
- `InitialBalanceFile` → `[[ustx_balance]]` section

For each configuration field, it extracts:
- Field documentation from `///` comments
- Default values (including constant references)
- Usage notes and examples
- Deprecation warnings

## Output Files

- **Primary**: `docs/generated/configuration-reference.md` - Complete configuration reference
- **Intermediate**: `target/doc-generation/extracted-config-docs.json` - Raw extracted data

## Annotation Syntax Guide

### Overview

The generator processes doc comments with a structured annotation format:

```rust
/// [Description text in Markdown format]
/// ---
/// @annotation_name: value
/// @another_annotation: value
pub field_name: Type,
```

### General Structure

- **Description**: Standard Markdown text before the `---` separator
- **Separator**: Three dashes (`---`) separate description from annotations
- **Annotations**: Key-value pairs starting with `@`, each on its own line

### Supported Annotations

#### `@default: <value>`
Specifies the default value for the field.
- **Value Type**: String
- **Multiline Support**: Yes (all modes)
- **Examples**:
  ```rust
  /// @default: `None`
  /// @default: `"localhost:8080"`
  /// @default: |
  ///   Complex multi-line
  ///   default value
  ```

#### `@notes: <content>`
Additional notes or explanations, rendered as a bulleted list.
- **Value Type**: String (parsed into list items)
- **Multiline Support**: Yes (all modes)
- **List Processing**: Lines starting with `-`, `*`, or `•` become list items
- **Examples**:
  ```rust
  /// @notes: Single line note
  /// @notes:
  ///   - First bullet point
  ///   - Second bullet point
  /// @notes: |
  ///   Complex formatting with
  ///   preserved line breaks
  ```

#### `@deprecated: <message>`
Marks a field as deprecated with an optional message.
- **Value Type**: String
- **Multiline Support**: Yes (all modes)
- **Examples**:
  ```rust
  /// @deprecated: Use new_field instead
  /// @deprecated: |
  ///   This field will be removed in v3.0.
  ///   Migrate to the new configuration system.
  ```

#### `@toml_example: <example>`
Provides TOML configuration examples.
- **Value Type**: String
- **Multiline Support**: Yes (all modes)
- **Rendering**: Displayed in `<pre><code>` blocks in markdown tables
- **Examples**:
  ```rust
  /// @toml_example: key = "value"
  /// @toml_example: |
  ///   [section]
  ///   key = "value"
  ///   nested = { a = 1, b = 2 }
  ```

#### `@required: <boolean>`
Indicates whether the field is mandatory.
- **Value Type**: Boolean
- **Default**: If annotation is omitted, the field is considered *not required*.
- **Supported Values**:
  - ``true`
  - `false`
  - Invalid values default to `false`
- **Examples**:
  ```rust
  /// @required: true
  /// @required: false
  ```

#### `@units: <unit>`
Specifies the unit of measurement for the field.
- **Value Type**: String
- **Multiline Support**: Yes (all modes)
- **Constant References**: Supports `[`CONSTANT_NAME`]` syntax
- **Examples**:
  ```rust
  /// @units: milliseconds
  /// @units: sats/vByte
  ```

### Multiline Content Support

All annotations support three multiline modes:

#### Default Literal-like Mode
Content preserves newlines and relative indentation within the annotation block.

```rust
/// @notes:
///   First line with base indentation
///     Second line more indented
///   Third line back to base
///       Fourth line very indented
```

**Output preserves relative indentation**:
```
First line with base indentation
  Second line more indented
Third line back to base
    Fourth line very indented
```

#### Literal Block Style (`|`)
Exact preservation of newlines and relative indentation. Uses "clip" chomping (single trailing newline preserved).

```rust
/// @toml_example: |
///   [network]
///   bind = "0.0.0.0:20444"
///     # Indented comment
///   timeout = 30
```

**Output**:
```
[network]
bind = "0.0.0.0:20444"
  # Indented comment
timeout = 30
```

#### Folded Block Style (`>`)
Folds lines into paragraphs with intelligent spacing. More-indented lines preserved as literal blocks.

```rust
/// @notes: >
///   This is a long paragraph that will be
///   folded into a single line with spaces
///   between the original line breaks.
///
///   This is a second paragraph after a blank line.
///
///     This indented block will be preserved
///     exactly as written, like code.
///
///   Back to normal folded paragraph text.
```

**Output**:
```
This is a long paragraph that will be folded into a single line with spaces between the original line breaks.

This is a second paragraph after a blank line.

  This indented block will be preserved
  exactly as written, like code.

Back to normal folded paragraph text.
```

### Same-line Content

Content can start immediately after the colon for default multiline mode:

```rust
/// @default: immediate content
/// @notes: Content that starts immediately
///   and continues on the next line
```

For literal (`|`) and folded (`>`) modes, content must start on the next line:

```rust
/// @notes: |
///   Content starts here on the next line
///   All content must be indented on subsequent lines
/// @deprecated: >
///   Folded content also starts on the next line
///   and will be joined appropriately
```

### Complete Example

```rust
/// Timeout duration for network connections.
///
/// This setting controls how long the node will wait for network operations
/// to complete before timing out. Setting this too low may cause connection
/// failures on slow networks.
/// ---
/// @default: [`DEFAULT_NETWORK_TIMEOUT`]
/// @required: true
/// @units: milliseconds
/// @notes:
///   - Must be greater than 0
///   - Recommended range: 1000-30000
///   - Higher values needed for slow connections
/// @toml_example: |
///   [network]
///   timeout = 15000  # 15 seconds
/// @deprecated: >
///   Use the new `connection_timeout` setting instead.
///   This field will be removed in version 3.0.
pub timeout_ms: u64,
```

### Best Practices

1. **Choose the right multiline mode**:
   - Default mode: General text with preserved formatting
   - Literal (`|`): Code examples, exact formatting required
   - Folded (`>`): Documentation prose, automatic paragraph wrapping

2. **Use constant references in `@default` when appropriate**

### Integration with Rust Documentation

This system integrates with standard Rust documentation tools:
- Doc comments remain valid for `rustdoc`
- Annotations are ignored by standard documentation generators
- Full compatibility with existing documentation workflows

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

### 3. Generate

Override TOML section names using JSON configuration:

```bash
# Using Docker with custom mappings and template
cd contrib/tools/config-docs-generator
docker run --rm -v "$(pwd)/../../../:/project_root" \
  -e SECTION_MAPPINGS_PATH="/build/contrib/tools/config-docs-generator/custom_mappings.json" \
  -e TEMPLATE_PATH="/build/contrib/tools/config-docs-generator/templates/custom_template.md" \
  config-docs-generator

# OR using local setup
./generate-config-docs.sh --section-name-mappings custom_mappings.json --template custom_template.md
```

## How It Works

The tool uses a three-step process:

1. **Extract**: Uses `cargo +nightly rustdoc --output-format json` to generate documentation JSON
2. **Parse**: Extracts field information, resolves constant references across crates
3. **Generate**: Converts to Markdown with proper cross-references and formatting

The process is automated by the shell script which coordinates building the tools and running the extraction/generation pipeline.
