// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::collections::{HashMap, HashSet};
use std::fs;
use std::process::Command as StdCommand;

use anyhow::{Context, Result};
use clap::{Arg, Command as ClapCommand};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

// Static regex for finding constant references in documentation
static CONSTANT_REFERENCE_REGEX: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\[`([A-Z_][A-Z0-9_]*)`\]").unwrap());

#[derive(Debug, Serialize, Deserialize)]
pub struct FieldDoc {
    pub name: String,
    pub description: String,
    pub default_value: Option<String>,
    pub notes: Option<Vec<String>>,
    pub deprecated: Option<String>,
    pub toml_example: Option<String>,
    pub required: Option<bool>,
    pub units: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StructDoc {
    pub name: String,
    pub description: Option<String>,
    pub fields: Vec<FieldDoc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigDocs {
    structs: Vec<StructDoc>,
    referenced_constants: HashMap<String, Option<String>>, // Name -> Resolved Value (or None)
}

// JSON navigation helper functions
/// Navigate through nested JSON structure using an array of keys
/// Returns None if any part of the path doesn't exist
///
/// Example: get_json_path(value, &["inner", "struct", "kind"])
/// is equivalent to value.get("inner")?.get("struct")?.get("kind")
fn get_json_path<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;

    for &key in path {
        current = current.get(key)?;
    }

    Some(current)
}

/// Navigate to an array at the given JSON path
/// Returns None if the path doesn't exist or the value is not an array
fn get_json_array<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a Vec<serde_json::Value>> {
    get_json_path(value, path)?.as_array()
}

/// Navigate to an object at the given JSON path
/// Returns None if the path doesn't exist or the value is not an object
fn get_json_object<'a>(
    value: &'a serde_json::Value,
    path: &[&str],
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    get_json_path(value, path)?.as_object()
}

/// Navigate to a string at the given JSON path
/// Returns None if the path doesn't exist or the value is not a string
fn get_json_string<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    get_json_path(value, path)?.as_str()
}

fn main() -> Result<()> {
    let matches = ClapCommand::new("extract-docs")
        .about("Extract documentation from Rust source code using rustdoc JSON")
        .arg(
            Arg::new("package")
                .long("package")
                .short('p')
                .value_name("PACKAGE")
                .help("Package to extract docs for")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .value_name("FILE")
                .help("Output JSON file")
                .required(true),
        )
        .arg(
            Arg::new("structs")
                .long("structs")
                .value_name("NAMES")
                .help("Comma-separated list of struct names to extract")
                .required(true),
        )
        .get_matches();

    let package = matches.get_one::<String>("package").unwrap();
    let output_file = matches.get_one::<String>("output").unwrap();
    let target_structs: Option<Vec<String>> = matches
        .get_one::<String>("structs")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    // Generate rustdoc JSON
    let rustdoc_json = generate_rustdoc_json(package)?;

    // Extract configuration documentation from the rustdoc JSON
    let config_docs = extract_config_docs_from_rustdoc(&rustdoc_json, &target_structs)?;

    // Write the extracted docs to file
    fs::write(output_file, serde_json::to_string_pretty(&config_docs)?)?;

    println!("Successfully extracted documentation to {output_file}");
    println!(
        "Found {} structs with documentation",
        config_docs.structs.len()
    );
    Ok(())
}

fn generate_rustdoc_json(package: &str) -> Result<serde_json::Value> {
    // List of crates to generate rustdoc for (in addition to the main package)
    // These crates contain constants that might be referenced in documentation
    // NOTE: This list must be manually updated if new dependencies containing
    // constants referenced in doc comments are added to the project
    let additional_crates = ["stacks-common"];

    // Respect CARGO_TARGET_DIR environment variable for rustdoc output
    let rustdoc_target_dir = std::env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| "target".to_string())
        + "/rustdoc-json";

    // WARNING: This tool relies on nightly rustdoc JSON output (-Z unstable-options --output-format json)
    // The JSON format is subject to change with new Rust nightly versions and could break this tool.
    // Use cargo rustdoc with nightly to generate JSON for the main package
    let output = StdCommand::new("cargo")
        .args([
            "+nightly",
            "rustdoc",
            "--lib",
            "-p",
            package,
            "--target-dir",
            &rustdoc_target_dir,
            "--",
            "-Z",
            "unstable-options",
            "--output-format",
            "json",
            "--document-private-items",
        ])
        .output()
        .context("Failed to run cargo rustdoc command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("cargo rustdoc failed: {}", stderr);
    }

    // Generate rustdoc for additional crates that might contain referenced constants
    for additional_crate in &additional_crates {
        let error_msg = format!("Failed to run cargo rustdoc command for {additional_crate}");
        let output = StdCommand::new("cargo")
            .args([
                "+nightly",
                "rustdoc",
                "--lib",
                "-p",
                additional_crate,
                "--target-dir",
                &rustdoc_target_dir,
                "--",
                "-Z",
                "unstable-options",
                "--output-format",
                "json",
                "--document-private-items",
            ])
            .output()
            .context(error_msg)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: Failed to generate rustdoc for {additional_crate}: {stderr}");
        }
    }

    // Map package names to their library names if different
    // For most packages, the library name is the same as package name with hyphens replaced by underscores
    // But some packages have custom library names defined in Cargo.toml
    // NOTE: This mapping must be updated if new packages with different library names are processed
    let lib_name = match package {
        "stackslib" => "blockstack_lib".to_string(),
        _ => package.replace('-', "_"),
    };

    // Read the generated JSON file - rustdoc generates it based on library name
    let json_file_path = format!("{rustdoc_target_dir}/doc/{lib_name}.json");
    let json_content = std::fs::read_to_string(json_file_path)
        .context("Failed to read generated rustdoc JSON file")?;

    serde_json::from_str(&json_content).context("Failed to parse rustdoc JSON output")
}

fn extract_config_docs_from_rustdoc(
    rustdoc_json: &serde_json::Value,
    target_structs: &Option<Vec<String>>,
) -> Result<ConfigDocs> {
    let mut structs = Vec::new();
    let mut all_referenced_constants = std::collections::HashSet::new();

    // Access the main index containing all items from the rustdoc JSON output
    let index = get_json_object(rustdoc_json, &["index"])
        .context("Missing 'index' field in rustdoc JSON")?;

    for (_item_id, item) in index {
        // Extract the item's name from rustdoc JSON structure
        if let Some(name) = get_json_string(item, &["name"]) {
            // Check if this item is a struct by looking for the "struct" field
            if get_json_object(item, &["inner", "struct"]).is_some() {
                // Check if this struct is in our target list (if specified)
                if let Some(targets) = target_structs
                    && !targets.contains(&name.to_string())
                {
                    continue;
                }

                let (struct_doc_opt, referenced_constants) =
                    extract_struct_from_rustdoc_index(index, name, item)?;

                if let Some(struct_doc) = struct_doc_opt {
                    structs.push(struct_doc);
                }
                all_referenced_constants.extend(referenced_constants);
            }
        }
    }

    // Resolve all collected constant references
    let mut referenced_constants = HashMap::new();
    for constant_name in all_referenced_constants {
        let resolved_value = resolve_constant_reference(&constant_name, index);
        referenced_constants.insert(constant_name, resolved_value);
    }

    Ok(ConfigDocs {
        structs,
        referenced_constants,
    })
}

fn extract_struct_from_rustdoc_index(
    index: &serde_json::Map<String, serde_json::Value>,
    struct_name: &str,
    struct_item: &serde_json::Value,
) -> Result<(Option<StructDoc>, HashSet<String>)> {
    let mut all_referenced_constants = std::collections::HashSet::new();

    // Extract struct documentation
    let description = get_json_string(struct_item, &["docs"]).map(|s| s.to_string());

    // Collect constant references from struct description
    if let Some(desc) = &description {
        all_referenced_constants.extend(find_constant_references(desc));
    }

    // Extract fields
    let (fields, referenced_constants) = extract_struct_fields(index, struct_item)?;

    // Extend referenced constants
    all_referenced_constants.extend(referenced_constants);

    if !fields.is_empty() || description.is_some() {
        let struct_doc = StructDoc {
            name: struct_name.to_string(),
            description,
            fields,
        };
        Ok((Some(struct_doc), all_referenced_constants))
    } else {
        Ok((None, all_referenced_constants))
    }
}

fn extract_struct_fields(
    index: &serde_json::Map<String, serde_json::Value>,
    struct_item: &serde_json::Value,
) -> Result<(Vec<FieldDoc>, std::collections::HashSet<String>)> {
    let mut fields = Vec::new();
    let mut all_referenced_constants = std::collections::HashSet::new();

    // Navigate through rustdoc JSON structure to access struct fields
    // Path: item.inner.struct.kind.plain.fields[]
    if let Some(field_ids) =
        get_json_array(struct_item, &["inner", "struct", "kind", "plain", "fields"])
    {
        for field_id in field_ids {
            // Field IDs can be either integers or strings in rustdoc JSON, try both formats
            let field_item = if let Some(field_id_num) = field_id.as_u64() {
                // Numeric field ID - convert to string for index lookup
                index.get(&field_id_num.to_string())
            } else if let Some(field_id_str) = field_id.as_str() {
                // String field ID - use directly for index lookup
                index.get(field_id_str)
            } else {
                None
            };

            if let Some(field_item) = field_item {
                // Extract the field's name from the rustdoc item
                let field_name = get_json_string(field_item, &["name"])
                    .unwrap_or("unknown")
                    .to_string();

                // Extract the field's documentation text from rustdoc
                let field_docs = get_json_string(field_item, &["docs"])
                    .unwrap_or("")
                    .to_string();

                // Parse the structured documentation
                let (field_doc, referenced_constants) =
                    parse_field_documentation(&field_docs, &field_name)?;

                // Only include fields that have documentation
                if !field_doc.description.is_empty() || field_doc.default_value.is_some() {
                    fields.push(field_doc);
                }

                // Extend referenced constants
                all_referenced_constants.extend(referenced_constants);
            }
        }
    }

    Ok((fields, all_referenced_constants))
}

fn parse_field_documentation(
    doc_text: &str,
    field_name: &str,
) -> Result<(FieldDoc, std::collections::HashSet<String>)> {
    let mut default_value = None;
    let mut notes = None;
    let mut deprecated = None;
    let mut toml_example = None;
    let mut required = None;
    let mut units = None;
    let mut referenced_constants = std::collections::HashSet::new();

    // Split on --- separator if present
    let parts: Vec<&str> = doc_text.split("---").collect();

    let description = parts[0].trim().to_string();

    // Collect constant references from description
    referenced_constants.extend(find_constant_references(&description));

    // Parse metadata section if present
    if parts.len() >= 2 {
        let metadata_section = parts[1];

        // Parse @default: annotations
        if let Some(default_match) = extract_annotation(metadata_section, "default") {
            // Collect constant references from default value
            referenced_constants.extend(find_constant_references(&default_match));
            default_value = Some(default_match);
        }

        // Parse @notes: annotations
        if let Some(notes_text) = extract_annotation(metadata_section, "notes") {
            // Collect constant references from notes
            referenced_constants.extend(find_constant_references(&notes_text));

            let mut note_items: Vec<String> = Vec::new();
            let mut current_note = String::new();
            let mut in_note = false;

            for line in notes_text.lines() {
                let trimmed = line.trim();

                // Skip empty lines
                if trimmed.is_empty() {
                    continue;
                }

                // Check if this line starts a new note (bullet point)
                if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
                    // If we were building a previous note, save it
                    if in_note && !current_note.trim().is_empty() {
                        note_items.push(current_note.trim().to_string());
                    }

                    // Start a new note (remove the bullet point)
                    current_note = trimmed[2..].trim().to_string();
                    in_note = true;
                } else if in_note {
                    // This is a continuation line for the current note
                    if !current_note.is_empty() {
                        current_note.push(' ');
                    }
                    current_note.push_str(trimmed);
                }
                // If not in_note and doesn't start with bullet, ignore the line
            }

            // Don't forget the last note
            if in_note && !current_note.trim().is_empty() {
                note_items.push(current_note.trim().to_string());
            }

            if !note_items.is_empty() {
                notes = Some(note_items);
            }
        }

        // Parse @deprecated: annotations
        if let Some(deprecated_text) = extract_annotation(metadata_section, "deprecated") {
            // Collect constant references from deprecated text
            referenced_constants.extend(find_constant_references(&deprecated_text));
            deprecated = Some(deprecated_text);
        }

        // Parse @toml_example: annotations
        if let Some(example_text) = extract_annotation(metadata_section, "toml_example") {
            // Note: We typically don't expect constant references in TOML examples,
            // but we'll check anyway for completeness
            referenced_constants.extend(find_constant_references(&example_text));
            toml_example = Some(example_text);
        }

        // Parse @required: annotations
        if let Some(required_text) = extract_annotation(metadata_section, "required") {
            let required_bool = match required_text.trim() {
                "" => false, // Empty string defaults to false
                text => text.parse::<bool>().unwrap_or_else(|_| {
                    eprintln!(
                        "Warning: Invalid @required value '{text}' for field '{field_name}', defaulting to false"
                    );
                    false
                }),
            };
            required = Some(required_bool);
        }

        // Parse @units: annotations
        if let Some(units_text) = extract_annotation(metadata_section, "units") {
            // Collect constant references from units text
            referenced_constants.extend(find_constant_references(&units_text));
            units = Some(units_text);
        }
    }

    let field_doc = FieldDoc {
        name: field_name.to_string(),
        description,
        default_value,
        notes,
        deprecated,
        toml_example,
        required,
        units,
    };

    Ok((field_doc, referenced_constants))
}

/// Parse a YAML-style literal block scalar (|) from comment lines
/// Preserves newlines and internal indentation relative to the block base indentation
fn parse_literal_block_scalar(lines: &[&str], _base_indent: usize) -> String {
    if lines.is_empty() {
        return String::new();
    }

    // Find the first non-empty content line to determine block indentation
    let content_lines: Vec<&str> = lines
        .iter()
        .skip_while(|line| line.trim().is_empty())
        .copied()
        .collect();

    if content_lines.is_empty() {
        return String::new();
    }

    // Determine block indentation from the first content line
    let block_indent = content_lines[0].len() - content_lines[0].trim_start().len();

    // Process all lines, preserving relative indentation within the block
    let mut result_lines = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            // Preserve empty lines
            result_lines.push(String::new());
        } else {
            let line_indent = line.len() - line.trim_start().len();
            if line_indent >= block_indent {
                // Remove only the common block indentation, preserving relative indentation
                let content = &line[block_indent.min(line.len())..];
                result_lines.push(content.to_string());
            } else {
                // Line is less indented than block base - should not happen in well-formed blocks
                result_lines.push(line.trim_start().to_string());
            }
        }
    }

    // Remove trailing empty lines (clip chomping style)
    while let Some(last) = result_lines.last() {
        if last.is_empty() {
            result_lines.pop();
        } else {
            break;
        }
    }

    result_lines.join("\n")
}

/// Parse a YAML-style folded block scalar (>)
/// Folds lines into paragraphs, preserving more-indented lines as literal blocks
fn parse_folded_block_scalar(lines: &[&str], _base_indent: usize) -> String {
    if lines.is_empty() {
        return String::new();
    }

    // Find the first non-empty content line to determine block indentation
    let content_lines: Vec<&str> = lines
        .iter()
        .skip_while(|line| line.trim().is_empty())
        .copied()
        .collect();

    if content_lines.is_empty() {
        return String::new();
    }

    // Determine block indentation from the first content line
    let block_indent = content_lines[0].len() - content_lines[0].trim_start().len();

    let mut result = String::new();
    let mut current_paragraph = Vec::new();
    let mut in_literal_block = false;

    for line in lines {
        if line.trim().is_empty() {
            if in_literal_block {
                // Empty line in literal block - preserve it
                result.push('\n');
            } else if !current_paragraph.is_empty() {
                // End current paragraph
                result.push_str(&current_paragraph.join(" "));
                result.push_str("\n\n");
                current_paragraph.clear();
            }
            continue;
        }

        let line_indent = line.len() - line.trim_start().len();
        let content = if line_indent >= block_indent {
            &line[block_indent.min(line.len())..]
        } else {
            line.trim_start()
        };

        let relative_indent = line_indent.saturating_sub(block_indent);

        if relative_indent > 0 {
            // More indented line - start or continue literal block
            if !in_literal_block {
                // Finish current paragraph before starting literal block
                if !current_paragraph.is_empty() {
                    result.push_str(&current_paragraph.join(" "));
                    result.push('\n');
                    current_paragraph.clear();
                }
                in_literal_block = true;
            }
            // Add literal line with preserved indentation
            result.push_str(content);
            result.push('\n');
        } else {
            // Normal indentation - folded content
            if in_literal_block {
                // Exit literal block
                in_literal_block = false;
                if !result.is_empty() && !result.ends_with('\n') {
                    result.push('\n');
                }
            }
            // Add to current paragraph
            current_paragraph.push(content);
        }
    }

    // Finish any remaining paragraph
    if !current_paragraph.is_empty() {
        result.push_str(&current_paragraph.join(" "));
    }

    // Apply "clip" chomping style (consistent with literal parser)
    // Remove trailing empty lines but preserve a single trailing newline if content exists
    let trimmed = result.trim_end_matches('\n');
    if !trimmed.is_empty() && result.ends_with('\n') {
        format!("{trimmed}\n")
    } else {
        trimmed.to_string()
    }
}

fn extract_annotation(metadata_section: &str, annotation_name: &str) -> Option<String> {
    let annotation_pattern = format!("@{annotation_name}:");

    if let Some(_start_pos) = metadata_section.find(&annotation_pattern) {
        // Split the metadata section into lines for processing
        let all_lines: Vec<&str> = metadata_section.lines().collect();

        // Find which line contains our annotation
        let mut annotation_line_idx = None;
        for (idx, line) in all_lines.iter().enumerate() {
            if line.contains(&annotation_pattern) {
                annotation_line_idx = Some(idx);
                break;
            }
        }

        let annotation_line_idx = annotation_line_idx?;
        let annotation_line = all_lines[annotation_line_idx];

        // Find the position of the annotation pattern within this line
        let pattern_pos = annotation_line.find(&annotation_pattern)?;
        let after_colon = &annotation_line[pattern_pos + annotation_pattern.len()..];

        // Check for multiline indicators immediately after the colon
        let trimmed_after_colon = after_colon.trim_start();

        if trimmed_after_colon.starts_with('|') {
            // Literal block scalar mode (|)
            // Content starts from the next line, ignoring any text after | on the same line
            let block_lines = collect_annotation_block_lines(
                &all_lines,
                annotation_line_idx + 1,
                annotation_line,
            );

            // Convert to owned strings for the parser
            let owned_lines: Vec<String> = block_lines.iter().map(|s| s.to_string()).collect();

            // Convert back to string slices for the parser
            let string_refs: Vec<&str> = owned_lines.iter().map(|s| s.as_str()).collect();
            let base_indent = annotation_line.len() - annotation_line.trim_start().len();
            let result = parse_literal_block_scalar(&string_refs, base_indent);
            if result.trim().is_empty() {
                return None;
            } else {
                return Some(result);
            }
        } else if trimmed_after_colon.starts_with('>') {
            // Folded block scalar mode (>)
            // Content starts from the next line, ignoring any text after > on the same line
            let block_lines = collect_annotation_block_lines(
                &all_lines,
                annotation_line_idx + 1,
                annotation_line,
            );

            // Convert to owned strings for the parser
            let owned_lines: Vec<String> = block_lines.iter().map(|s| s.to_string()).collect();

            // Convert back to string slices for the parser
            let string_refs: Vec<&str> = owned_lines.iter().map(|s| s.as_str()).collect();
            let base_indent = annotation_line.len() - annotation_line.trim_start().len();
            let result = parse_folded_block_scalar(&string_refs, base_indent);
            if result.trim().is_empty() {
                return None;
            } else {
                return Some(result);
            }
        } else {
            // Default literal-like multiline mode
            // Content can start on the same line or the next line
            let mut content_lines = Vec::new();

            // Check if there's content on the same line after the colon
            if !trimmed_after_colon.is_empty() {
                content_lines.push(trimmed_after_colon);
            }

            // Collect subsequent lines that belong to this annotation
            let block_lines = collect_annotation_block_lines(
                &all_lines,
                annotation_line_idx + 1,
                annotation_line,
            );

            // For default mode, preserve relative indentation within the block
            if !block_lines.is_empty() {
                // Find the base indentation from the first non-empty content line
                let mut base_indent = None;
                for line in &block_lines {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        base_indent = Some(line.len() - line.trim_start().len());
                        break;
                    }
                }

                // Process lines preserving relative indentation
                for line in block_lines {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        if let Some(base) = base_indent {
                            let line_indent = line.len() - line.trim_start().len();
                            if line_indent >= base {
                                // Remove only the common base indentation, preserving relative indentation
                                let content = &line[base.min(line.len())..];
                                content_lines.push(content);
                            } else {
                                // Line is less indented than base - use trimmed content
                                content_lines.push(trimmed);
                            }
                        } else {
                            content_lines.push(trimmed);
                        }
                    }
                }
            }

            if content_lines.is_empty() {
                return None;
            }

            // Join lines preserving the structure - this maintains internal newlines and relative indentation
            let result = content_lines.join("\n");

            // Apply standard trimming and return if not empty
            let cleaned = result.trim();
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
    }

    None
}

/// Collect lines that belong to an annotation block, stopping at the next annotation or end
fn collect_annotation_block_lines<'a>(
    all_lines: &[&'a str],
    start_idx: usize,
    annotation_line: &str,
) -> Vec<&'a str> {
    let mut block_lines = Vec::new();
    let annotation_indent = annotation_line.len() - annotation_line.trim_start().len();

    for &line in all_lines.iter().skip(start_idx) {
        let trimmed = line.trim();

        // Stop if we hit another annotation at the same or lesser indentation level
        if trimmed.starts_with('@') && trimmed.contains(':') {
            let line_indent = line.len() - line.trim_start().len();
            if line_indent <= annotation_indent {
                break;
            }
        }

        // Stop if we hit a line that's clearly not part of the comment block
        // (very different indentation or structure)
        let line_indent = line.len() - line.trim_start().len();
        if !trimmed.is_empty() && line_indent < annotation_indent {
            break;
        }

        block_lines.push(line);
    }

    block_lines
}

fn resolve_constant_reference(
    name: &str,
    rustdoc_index: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    // First, try to find the constant in the main rustdoc index
    if let Some(value) = resolve_constant_in_index(name, rustdoc_index) {
        return Some(value);
    }

    // If not found in main index, try additional crates
    let additional_crate_libs = ["stacks_common"]; // Library names for additional crates

    for lib_name in &additional_crate_libs {
        let json_file_path = format!("target/rustdoc-json/doc/{lib_name}.json");
        if let Ok(json_content) = std::fs::read_to_string(&json_file_path)
            && let Ok(rustdoc_json) = serde_json::from_str::<serde_json::Value>(&json_content)
            && let Some(index) = get_json_object(&rustdoc_json, &["index"])
            && let Some(value) = resolve_constant_in_index(name, index)
        {
            return Some(value);
        }
    }

    None
}

fn resolve_constant_in_index(
    name: &str,
    rustdoc_index: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    // Look for a constant with the given name in the rustdoc index
    for (_item_id, item) in rustdoc_index {
        // Check if this item's name matches the constant we're looking for
        if let Some(item_name) = get_json_string(item, &["name"])
            && item_name == name
        {
            // Check if this item is a constant by looking for the "constant" field
            if let Some(constant_data) = get_json_object(item, &["inner", "constant"]) {
                // Try newer rustdoc JSON structure first (with nested 'const' field)
                let constant_data_value = serde_json::Value::Object(constant_data.clone());
                if get_json_object(&constant_data_value, &["const"]).is_some() {
                    // For literal constants, prefer expr which doesn't have type suffix
                    if get_json_path(&constant_data_value, &["const", "is_literal"])
                        .and_then(|v| v.as_bool())
                        == Some(true)
                    {
                        // Access the expression field for literal constant values
                        if let Some(expr) =
                            get_json_string(&constant_data_value, &["const", "expr"])
                            && expr != "_"
                        {
                            return Some(expr.to_string());
                        }
                    }

                    // For computed constants or when expr is "_", use value but strip type suffix
                    if let Some(value) = get_json_string(&constant_data_value, &["const", "value"])
                    {
                        return Some(strip_type_suffix(value));
                    }

                    // Fallback to expr if value is not available
                    if let Some(expr) = get_json_string(&constant_data_value, &["const", "expr"])
                        && expr != "_"
                    {
                        return Some(expr.to_string());
                    }
                }

                // Fall back to older rustdoc JSON structure for compatibility
                if let Some(value) = get_json_string(&constant_data_value, &["value"]) {
                    return Some(strip_type_suffix(value));
                }
                if let Some(expr) = get_json_string(&constant_data_value, &["expr"])
                    && expr != "_"
                {
                    return Some(expr.to_string());
                }

                // For some constants, the value might be in the type field if it's a simple literal
                if let Some(type_str) = get_json_string(&constant_data_value, &["type"]) {
                    // Handle simple numeric or string literals embedded in type
                    return Some(type_str.to_string());
                }
            }
        }
    }
    None
}

/// Strip type suffixes from rustdoc constant values (e.g., "50u64" -> "50", "402_653_196u32" -> "402_653_196")
fn strip_type_suffix(value: &str) -> String {
    // Common Rust integer type suffixes
    let suffixes = [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
        "f32", "f64",
    ];

    for suffix in &suffixes {
        if let Some(without_suffix) = value.strip_suffix(suffix) {
            // Only strip if the remaining part looks like a numeric literal
            // (contains only digits, underscores, dots, minus signs, or quotes for string literals)
            if !without_suffix.is_empty()
                && (without_suffix
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '_' || c == '.' || c == '-')
                    || (without_suffix.starts_with('"') && without_suffix.ends_with('"')))
            {
                return without_suffix.to_string();
            }
        }
    }

    // If no valid suffix found, return as-is
    value.to_string()
}

fn find_constant_references(text: &str) -> std::collections::HashSet<String> {
    let mut constants = std::collections::HashSet::new();

    for captures in CONSTANT_REFERENCE_REGEX.captures_iter(text) {
        if let Some(constant_name) = captures.get(1) {
            constants.insert(constant_name.as_str().to_string());
        }
    }

    constants
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_parse_field_documentation_basic() {
        let doc_text = "This is a basic field description.";
        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        assert_eq!(result.0.name, "test_field");
        assert_eq!(result.0.description, "This is a basic field description.");
        assert_eq!(result.0.default_value, None);
        assert_eq!(result.0.notes, None);
        assert_eq!(result.0.deprecated, None);
        assert_eq!(result.0.toml_example, None);
    }

    #[test]
    fn test_parse_field_documentation_with_metadata() {
        let doc_text = r#"This is a field with metadata.
---
@default: `"test_value"`
@notes:
  - This is a note.
  - This is another note.
@deprecated: This field is deprecated.
@toml_example: |
  key = "value"
  other = 123"#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        assert_eq!(result.0.name, "test_field");
        assert_eq!(result.0.description, "This is a field with metadata.");
        assert_eq!(result.0.default_value, Some("`\"test_value\"`".to_string()));
        assert_eq!(
            result.0.notes,
            Some(vec![
                "This is a note.".to_string(),
                "This is another note.".to_string()
            ])
        );
        assert_eq!(
            result.0.deprecated,
            Some("This field is deprecated.".to_string())
        );
        assert_eq!(
            result.0.toml_example,
            Some("key = \"value\"\nother = 123".to_string())
        );
    }

    #[test]
    fn test_parse_field_documentation_multiline_default() {
        let doc_text = r#"Multi-line field description.
---
@default: Derived from [`BurnchainConfig::mode`] ([`CHAIN_ID_MAINNET`] for `mainnet`,
  [`CHAIN_ID_TESTNET`] otherwise).
@notes:
  - Warning: Do not modify this unless you really know what you're doing."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        assert_eq!(result.0.name, "test_field");
        assert_eq!(result.0.description, "Multi-line field description.");
        assert!(result.0.default_value.is_some());
        let default_val = result.0.default_value.unwrap();
        assert!(default_val.contains("Derived from"));
        assert!(default_val.contains("CHAIN_ID_MAINNET"));
        assert_eq!(
            result.0.notes,
            Some(vec![
                "Warning: Do not modify this unless you really know what you're doing.".to_string()
            ])
        );
    }

    #[test]
    fn test_parse_field_documentation_multiline_notes() {
        let doc_text = r#"Field with multi-line notes.
---
@notes:
  - This is a single line note.
  - This is a multi-line note that
    spans across multiple lines
    and should be treated as one note.
  - Another single line note.
  - Final multi-line note that also
    continues on the next line."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        let (field_doc, _) = result;

        assert_eq!(field_doc.name, "test_field");
        assert_eq!(field_doc.description, "Field with multi-line notes.");

        let notes = field_doc.notes.expect("Should have notes");
        assert_eq!(notes.len(), 4);
        assert_eq!(notes[0], "This is a single line note.");
        assert_eq!(
            notes[1],
            "This is a multi-line note that spans across multiple lines and should be treated as one note."
        );
        assert_eq!(notes[2], "Another single line note.");
        assert_eq!(
            notes[3],
            "Final multi-line note that also continues on the next line."
        );
    }

    #[test]
    fn test_parse_field_documentation_multiline_notes_mixed_bullets() {
        let doc_text = r#"Field with mixed bullet styles.
---
@notes:
  - First note with dash.
  * Second note with asterisk
    that continues.
  - Third note with dash again
    and multiple continuation lines
    should all be joined together."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        let (field_doc, _) = result;

        let notes = field_doc.notes.expect("Should have notes");
        assert_eq!(notes.len(), 3);
        assert_eq!(notes[0], "First note with dash.");
        assert_eq!(notes[1], "Second note with asterisk that continues.");
        assert_eq!(
            notes[2],
            "Third note with dash again and multiple continuation lines should all be joined together."
        );
    }

    #[test]
    fn test_parse_field_documentation_notes_with_empty_lines() {
        let doc_text = r#"Field with notes that have empty lines.
---
@notes:
  - First note.

  - Second note after empty line
    with continuation.

  - Third note after another empty line."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        let (field_doc, _) = result;

        let notes = field_doc.notes.expect("Should have notes");
        assert_eq!(notes.len(), 3);
        assert_eq!(notes[0], "First note.");
        assert_eq!(notes[1], "Second note after empty line with continuation.");
        assert_eq!(notes[2], "Third note after another empty line.");
    }

    #[test]
    fn test_parse_field_documentation_notes_with_intralinks() {
        let doc_text = r#"Field with notes containing intralinks.
---
@notes:
  - If [`SomeConfig::field`] is `true`, the node will
    use the default estimator.
  - See [`CONSTANT_VALUE`] for details."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        let (field_doc, referenced_constants) = result;

        let notes = field_doc.notes.expect("Should have notes");
        assert_eq!(notes.len(), 2);
        assert_eq!(
            notes[0],
            "If [`SomeConfig::field`] is `true`, the node will use the default estimator."
        );
        assert_eq!(notes[1], "See [`CONSTANT_VALUE`] for details.");

        // Check that constants were collected
        assert!(referenced_constants.contains("CONSTANT_VALUE"));
    }

    #[test]
    fn test_extract_annotation_basic() {
        let metadata = "@default: `\"test\"`\n@notes: Some notes here.";

        let default = extract_annotation(metadata, "default");
        let notes = extract_annotation(metadata, "notes");
        let missing = extract_annotation(metadata, "missing");

        assert_eq!(default, Some("`\"test\"`".to_string()));
        assert_eq!(notes, Some("Some notes here.".to_string()));
        assert_eq!(missing, None);
    }

    #[test]
    fn test_extract_annotation_toml_example() {
        let metadata = r#"@toml_example: |
  key = "value"
  number = 42
  nested = { a = 1, b = 2 }"#;

        let result = extract_annotation(metadata, "toml_example");
        assert!(result.is_some());
        let toml = result.unwrap();
        assert!(toml.contains("key = \"value\""));
        assert!(toml.contains("number = 42"));
        assert!(toml.contains("nested = { a = 1, b = 2 }"));
    }

    #[test]
    fn test_extract_annotation_multiline() {
        let metadata = r#"@notes:
  - First note with important details.
  - Second note with more info.
@default: `None`"#;

        let notes = extract_annotation(metadata, "notes");
        let default = extract_annotation(metadata, "default");

        assert!(notes.is_some());
        let notes_text = notes.unwrap();
        assert!(notes_text.contains("First note"));
        assert!(notes_text.contains("Second note"));
        assert_eq!(default, Some("`None`".to_string()));
    }

    #[test]
    fn test_extract_struct_fields_from_mock_data() {
        let mock_index = json!({
            "struct_1": {
                "name": "TestStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": ["field_1", "field_2"]
                            }
                        }
                    }
                }
            },
            "field_1": {
                "name": "test_field",
                "docs": "A test field.\n---\n@default: `42`"
            },
            "field_2": {
                "name": "another_field",
                "docs": "Another field with notes.\n---\n@default: `\"hello\"`\n@notes:\n  - This is a note."
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let (fields, _referenced_constants) = extract_struct_fields(index, struct_item).unwrap();

        assert_eq!(fields.len(), 2);

        let first_field = &fields[0];
        assert_eq!(first_field.name, "test_field");
        assert_eq!(first_field.description, "A test field.");
        assert_eq!(first_field.default_value, Some("`42`".to_string()));

        let second_field = &fields[1];
        assert_eq!(second_field.name, "another_field");
        assert_eq!(second_field.description, "Another field with notes.");
        assert_eq!(second_field.default_value, Some("`\"hello\"`".to_string()));
        assert_eq!(
            second_field.notes,
            Some(vec!["This is a note.".to_string()])
        );
    }

    #[test]
    fn test_extract_struct_from_rustdoc_index() {
        let mock_index = json!({
            "struct_1": {
                "name": "TestStruct",
                "docs": "This is a test struct for configuration.",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": ["field_1"]
                            }
                        }
                    }
                }
            },
            "field_1": {
                "name": "config_field",
                "docs": "Configuration field.\n---\n@default: `\"default\"`"
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let result = extract_struct_from_rustdoc_index(index, "TestStruct", struct_item).unwrap();

        assert!(result.0.is_some());
        let struct_doc = result.0.unwrap();
        assert_eq!(struct_doc.name, "TestStruct");
        assert_eq!(
            struct_doc.description,
            Some("This is a test struct for configuration.".to_string())
        );
        assert_eq!(struct_doc.fields.len(), 1);
        assert_eq!(struct_doc.fields[0].name, "config_field");
    }

    #[test]
    fn test_extract_config_docs_from_rustdoc() {
        let mock_rustdoc = json!({
            "index": {
                "item_1": {
                    "name": "ConfigStruct",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": ["field_1"]
                                }
                            }
                        }
                    },
                    "docs": "A configuration struct."
                },
                "item_2": {
                    "name": "NonStruct",
                    "inner": {
                        "function": {}
                    }
                },
                "field_1": {
                    "name": "setting",
                    "docs": "A configuration setting.\n---\n@default: `true`"
                }
            }
        });

        let target_structs = Some(vec!["ConfigStruct".to_string()]);
        let result = extract_config_docs_from_rustdoc(&mock_rustdoc, &target_structs).unwrap();

        assert_eq!(result.structs.len(), 1);
        let struct_doc = &result.structs[0];
        assert_eq!(struct_doc.name, "ConfigStruct");
        assert_eq!(
            struct_doc.description,
            Some("A configuration struct.".to_string())
        );
        assert_eq!(struct_doc.fields.len(), 1);
    }

    #[test]
    fn test_extract_config_docs_filter_by_target() {
        let mock_rustdoc = json!({
            "index": {
                "item_1": {
                    "name": "WantedStruct",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": []
                                }
                            }
                        }
                    },
                    "docs": "Wanted struct."
                },
                "item_2": {
                    "name": "UnwantedStruct",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": []
                                }
                            }
                        }
                    },
                    "docs": "Unwanted struct."
                }
            }
        });

        let target_structs = Some(vec!["WantedStruct".to_string()]);
        let result = extract_config_docs_from_rustdoc(&mock_rustdoc, &target_structs).unwrap();

        assert_eq!(result.structs.len(), 1);
        assert_eq!(result.structs[0].name, "WantedStruct");
    }

    #[test]
    fn test_extract_config_docs_no_filter() {
        let mock_rustdoc = json!({
            "index": {
                "item_1": {
                    "name": "Struct1",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": []
                                }
                            }
                        }
                    },
                    "docs": "First struct."
                },
                "item_2": {
                    "name": "Struct2",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": []
                                }
                            }
                        }
                    },
                    "docs": "Second struct."
                }
            }
        });

        let result = extract_config_docs_from_rustdoc(&mock_rustdoc, &None).unwrap();

        assert_eq!(result.structs.len(), 2);
        let names: Vec<&str> = result.structs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Struct1"));
        assert!(names.contains(&"Struct2"));
    }

    #[test]
    fn test_parse_field_documentation_empty_notes() {
        let doc_text = r#"Field with empty notes.
---
@default: `None`
@notes:


@deprecated: Old field"#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        assert_eq!(result.0.name, "test_field");
        assert_eq!(result.0.description, "Field with empty notes.");
        assert_eq!(result.0.default_value, Some("`None`".to_string()));
        assert_eq!(result.0.notes, None); // Empty notes should result in None
        assert_eq!(result.0.deprecated, Some("Old field".to_string()));
    }

    #[test]
    fn test_parse_field_documentation_bullet_points_cleanup() {
        let doc_text = r#"Field with bullet notes.
---
@notes:
  - First bullet point
  * Second bullet point
  - Third bullet point"#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        assert_eq!(
            result.0.notes,
            Some(vec![
                "First bullet point".to_string(),
                "Second bullet point".to_string(),
                "Third bullet point".to_string()
            ])
        );
    }

    #[test]
    fn test_extract_annotation_edge_cases() {
        // Test with annotation at the end
        let metadata1 = "@default: `value`";
        assert_eq!(
            extract_annotation(metadata1, "default"),
            Some("`value`".to_string())
        );

        // Test with empty annotation
        let metadata2 = "@default:\n@notes: something";
        assert_eq!(extract_annotation(metadata2, "default"), None);

        // Test with annotation containing colons
        let metadata3 = "@notes: URL: https://example.com:8080/path";
        let notes = extract_annotation(metadata3, "notes");
        assert_eq!(
            notes,
            Some("URL: https://example.com:8080/path".to_string())
        );

        // Test with whitespace-only annotation
        let metadata_whitespace = "@default:      \n@notes: something";
        assert_eq!(
            extract_annotation(metadata_whitespace, "default"),
            None,
            "Annotation with only whitespace should be None"
        );

        // Test with annotation containing only newline
        let metadata_newline = "@default:\n@notes: something";
        assert_eq!(
            extract_annotation(metadata_newline, "default"),
            None,
            "Annotation with only newline should be None"
        );
    }

    #[test]
    fn test_extract_struct_fields_numeric_field_ids() {
        let mock_index = json!({
            "struct_1": {
                "name": "TestStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": [123, 456] // Numeric field IDs
                            }
                        }
                    }
                }
            },
            "123": {
                "name": "numeric_field",
                "docs": "Field with numeric ID.\n---\n@default: `0`"
            },
            "456": {
                "name": "another_numeric",
                "docs": "Another numeric field."
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let (fields, _referenced_constants) = extract_struct_fields(index, struct_item).unwrap();

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "numeric_field");
        assert_eq!(fields[1].name, "another_numeric");
    }

    #[test]
    fn test_extract_struct_fields_missing_field_data() {
        let mock_index = json!({
            "struct_1": {
                "name": "TestStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": ["missing_field", "present_field"]
                            }
                        }
                    }
                }
            },
            "present_field": {
                "name": "present",
                "docs": "This field exists."
            }
            // "missing_field" is intentionally not in the index
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let (fields, _referenced_constants) = extract_struct_fields(index, struct_item).unwrap();

        // Should only include the present field
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "present");
    }

    #[test]
    fn test_extract_config_docs_missing_index() {
        let invalid_rustdoc = json!({
            "not_index": {}
        });

        let result = extract_config_docs_from_rustdoc(&invalid_rustdoc, &None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing 'index' field")
        );
    }

    #[test]
    fn test_extract_struct_fields_no_documentation() {
        let mock_index = json!({
            "struct_1": {
                "name": "TestStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": ["field_1"]
                            }
                        }
                    }
                }
            },
            "field_1": {
                "name": "undocumented_field",
                "docs": ""  // Empty documentation
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let (fields, _referenced_constants) = extract_struct_fields(index, struct_item).unwrap();

        // Fields without documentation should be excluded
        assert_eq!(fields.len(), 0);
    }

    #[test]
    fn test_extract_struct_fields_malformed_structure() {
        let mock_index = json!({
            "struct_1": {
                "name": "TestStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "tuple": {}  // Not a "plain" struct
                        }
                    }
                }
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let (fields, _referenced_constants) = extract_struct_fields(index, struct_item).unwrap();

        // Should handle malformed structures gracefully
        assert_eq!(fields.len(), 0);
    }

    #[test]
    fn test_parse_field_documentation_complex_annotations() {
        let doc_text = r#"Complex field with all annotation types and edge cases.

This description spans multiple lines
and includes various formatting.
---
@default: Dynamically determined.
  - If the `[miner]` section *is present* in the config file, the [`NodeConfig::seed`] is used.
  - If the `[miner]` section *is not present*, this is `None`, and mining operations will fail.
@notes:
  - **Warning:** This field requires careful configuration.
  - Only relevant if [`NodeConfig::miner`] is `true`.
  - Units: milliseconds.
@deprecated: Use `new_field` instead. This will be removed in version 2.0.
@toml_example: |
  # This is a comment
  [section]
  field = "value"

  # Another section
  [other_section]
  number = 42
  array = ["a", "b", "c"]"#;

        let result = parse_field_documentation(doc_text, "complex_field").unwrap();

        assert_eq!(result.0.name, "complex_field");
        assert!(result.0.description.contains("Complex field"));
        assert!(result.0.description.contains("multiple lines"));

        let default_val = result.0.default_value.unwrap();
        assert!(default_val.contains("Dynamically determined"));
        assert!(default_val.contains("NodeConfig::seed"));

        let notes = result.0.notes.unwrap();
        assert_eq!(notes.len(), 3);
        assert!(notes[0].contains("Warning"));
        assert!(notes[1].contains("Only relevant"));
        assert!(notes[2].contains("Units: milliseconds"));

        assert!(
            result
                .0
                .deprecated
                .unwrap()
                .contains("Use `new_field` instead")
        );

        let toml_example = result.0.toml_example.unwrap();
        assert!(toml_example.contains("# This is a comment"));
        assert!(toml_example.contains("[section]"));
        assert!(toml_example.contains("array = [\"a\", \"b\", \"c\"]"));
    }

    #[test]
    fn test_extract_annotation_overlapping_patterns() {
        let metadata = r#"@config_value: `"not_default"`
@default: `"actual_default"`
@notes_info: Some other annotation
@notes: Actual notes here
@deprecated_old: Old deprecation
@deprecated: Current deprecation"#;

        // Should extract the correct annotations, not get confused by similar names
        assert_eq!(
            extract_annotation(metadata, "default"),
            Some("`\"actual_default\"`".to_string())
        );
        assert_eq!(
            extract_annotation(metadata, "notes"),
            Some("Actual notes here".to_string())
        );
        assert_eq!(
            extract_annotation(metadata, "deprecated"),
            Some("Current deprecation".to_string())
        );

        // Should not find non-existent annotations
        assert_eq!(extract_annotation(metadata, "nonexistent"), None);
        assert_eq!(extract_annotation(metadata, "missing"), None);
    }

    #[test]
    fn test_extract_struct_from_rustdoc_index_no_fields_no_description() {
        let mock_index = json!({
            "struct_1": {
                "name": "EmptyStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": []
                            }
                        }
                    }
                }
                // No "docs" field
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];

        let result = extract_struct_from_rustdoc_index(index, "EmptyStruct", struct_item).unwrap();

        // Should return None for structs with no fields and no description
        assert!(result.0.is_none());
    }

    #[test]
    fn test_parse_field_documentation_only_description() {
        let doc_text = "Just a simple description with no metadata separator.";
        let result = parse_field_documentation(doc_text, "simple_field").unwrap();

        assert_eq!(result.0.name, "simple_field");
        assert_eq!(
            result.0.description,
            "Just a simple description with no metadata separator."
        );
        assert_eq!(result.0.default_value, None);
        assert_eq!(result.0.notes, None);
        assert_eq!(result.0.deprecated, None);
        assert_eq!(result.0.toml_example, None);
    }

    #[test]
    fn test_package_to_library_name_mapping() {
        // Test the logic inside generate_rustdoc_json for mapping package names to library names
        // We can't easily test generate_rustdoc_json directly since it runs external commands,
        // but we can test the mapping logic

        // Test the special case for stackslib
        let lib_name = match "stackslib" {
            "stackslib" => "blockstack_lib".to_string(),
            pkg => pkg.replace('-', "_"),
        };
        assert_eq!(lib_name, "blockstack_lib");

        // Test normal package names with hyphens
        let lib_name = match "config-docs-generator" {
            "stackslib" => "blockstack_lib".to_string(),
            pkg => pkg.replace('-', "_"),
        };
        assert_eq!(lib_name, "config_docs_generator");

        // Test package name without hyphens
        let lib_name = match "normalpackage" {
            "stackslib" => "blockstack_lib".to_string(),
            pkg => pkg.replace('-', "_"),
        };
        assert_eq!(lib_name, "normalpackage");
    }

    #[test]
    fn test_find_constant_references() {
        // Test finding constant references in text
        let text1 = "This field uses [`DEFAULT_VALUE`] as default.";
        let constants1 = find_constant_references(text1);
        assert_eq!(constants1.len(), 1);
        assert!(constants1.contains("DEFAULT_VALUE"));

        // Test multiple constants
        let text2 = "Uses [`CONST_A`] and [`CONST_B`] values.";
        let constants2 = find_constant_references(text2);
        assert_eq!(constants2.len(), 2);
        assert!(constants2.contains("CONST_A"));
        assert!(constants2.contains("CONST_B"));

        // Test no constants
        let text3 = "This text has no constant references.";
        let constants3 = find_constant_references(text3);
        assert_eq!(constants3.len(), 0);

        // Test mixed content
        let text4 =
            "Field uses [`MY_CONSTANT`] and links to [`SomeStruct::field`] but not `lowercase`.";
        let constants4 = find_constant_references(text4);
        assert_eq!(constants4.len(), 1);
        assert!(constants4.contains("MY_CONSTANT"));
        assert!(!constants4.contains("SomeStruct::field")); // Should not match struct::field patterns
        assert!(!constants4.contains("lowercase")); // Should not match lowercase
    }

    #[test]
    fn test_resolve_constant_reference() {
        // Create mock rustdoc index with a constant
        let mock_index = serde_json::json!({
            "const_1": {
                "name": "TEST_CONSTANT",
                "inner": {
                    "constant": {
                        "expr": "42",
                        "type": "u32"
                    }
                }
            },
            "const_2": {
                "name": "STRING_CONST",
                "inner": {
                    "constant": {
                        "value": "\"hello\"",
                        "type": "&str"
                    }
                }
            },
            "not_const": {
                "name": "NotAConstant",
                "inner": {
                    "function": {}
                }
            }
        });

        let index = mock_index.as_object().unwrap();

        // Test resolving existing constant with expr field
        let result1 = resolve_constant_reference("TEST_CONSTANT", index);
        assert_eq!(result1, Some("42".to_string()));

        // Test resolving existing constant with value field
        let result2 = resolve_constant_reference("STRING_CONST", index);
        assert_eq!(result2, Some("\"hello\"".to_string()));

        // Test resolving non-existent constant
        let result3 = resolve_constant_reference("NONEXISTENT", index);
        assert_eq!(result3, None);

        // Test resolving non-constant item
        let result4 = resolve_constant_reference("NotAConstant", index);
        assert_eq!(result4, None);
    }

    #[test]
    fn test_resolve_computed_constant() {
        // Test computed constants that have "_" in expr and actual value in value field
        let mock_index = serde_json::json!({
            "computed_const": {
                "name": "COMPUTED_CONSTANT",
                "inner": {
                    "constant": {
                        "const": {
                            "expr": "_",
                            "value": "402_653_196u32",
                            "is_literal": false
                        },
                        "type": {
                            "primitive": "u32"
                        }
                    }
                }
            },
            "literal_const": {
                "name": "LITERAL_CONSTANT",
                "inner": {
                    "constant": {
                        "const": {
                            "expr": "100",
                            "value": "100u32",
                            "is_literal": true
                        },
                        "type": {
                            "primitive": "u32"
                        }
                    }
                }
            }
        });

        let index = mock_index.as_object().unwrap();

        // Test resolving computed constant - should get the value without type suffix
        let result1 = resolve_constant_in_index("COMPUTED_CONSTANT", index);
        assert_eq!(result1, Some("402_653_196".to_string()));

        // Test resolving literal constant - should get expr which is clean
        let result2 = resolve_constant_in_index("LITERAL_CONSTANT", index);
        assert_eq!(result2, Some("100".to_string()));
    }

    #[test]
    fn test_parse_field_documentation_with_constants() {
        let doc_text = r#"This field uses [`DEFAULT_TIMEOUT`] milliseconds.
---
@default: [`DEFAULT_VALUE`]
@notes:
  - See [`MAX_RETRIES`] for retry limit.
  - Warning about [`DEPRECATED_CONST`]."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        // Check that constants were collected
        assert_eq!(result.1.len(), 4);
        assert!(result.1.contains("DEFAULT_TIMEOUT"));
        assert!(result.1.contains("DEFAULT_VALUE"));
        assert!(result.1.contains("MAX_RETRIES"));
        assert!(result.1.contains("DEPRECATED_CONST"));

        // Check that normal parsing still works
        assert_eq!(result.0.name, "test_field");
        assert!(result.0.description.contains("DEFAULT_TIMEOUT"));
        assert!(result.0.default_value.is_some());
        assert!(result.0.notes.is_some());
    }

    #[test]
    fn test_extract_config_docs_with_constants() {
        let mock_rustdoc = serde_json::json!({
            "index": {
                "struct_1": {
                    "name": "TestStruct",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": ["field_1"]
                                }
                            }
                        }
                    },
                    "docs": "Struct that uses [`STRUCT_CONSTANT`]."
                },
                "field_1": {
                    "name": "test_field",
                    "docs": "Field using [`FIELD_CONSTANT`].\n---\n@default: [`DEFAULT_CONST`]"
                },
                "const_1": {
                    "name": "STRUCT_CONSTANT",
                    "inner": {
                        "constant": {
                            "expr": "100"
                        }
                    }
                },
                "const_2": {
                    "name": "FIELD_CONSTANT",
                    "inner": {
                        "constant": {
                            "value": "\"test\""
                        }
                    }
                },
                "const_3": {
                    "name": "DEFAULT_CONST",
                    "inner": {
                        "constant": {
                            "expr": "42"
                        }
                    }
                }
            }
        });

        let result = extract_config_docs_from_rustdoc(&mock_rustdoc, &None).unwrap();

        // Check that constants were resolved
        assert_eq!(result.referenced_constants.len(), 3);
        assert_eq!(
            result.referenced_constants.get("STRUCT_CONSTANT"),
            Some(&Some("100".to_string()))
        );
        assert_eq!(
            result.referenced_constants.get("FIELD_CONSTANT"),
            Some(&Some("\"test\"".to_string()))
        );
        assert_eq!(
            result.referenced_constants.get("DEFAULT_CONST"),
            Some(&Some("42".to_string()))
        );

        // Check that struct was extracted normally
        assert_eq!(result.structs.len(), 1);
        assert_eq!(result.structs[0].name, "TestStruct");
    }

    #[test]
    fn test_extract_config_docs_with_unresolvable_constants() {
        let mock_rustdoc = serde_json::json!({
            "index": {
                "struct_1": {
                    "name": "TestStruct",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": ["field_1"]
                                }
                            }
                        }
                    },
                    "docs": "Struct that references [`MISSING_CONSTANT`]."
                },
                "field_1": {
                    "name": "test_field",
                    "docs": "Field description."
                }
            }
        });

        let result = extract_config_docs_from_rustdoc(&mock_rustdoc, &None).unwrap();

        // Check that unresolvable constant is recorded with None value
        assert_eq!(result.referenced_constants.len(), 1);
        assert_eq!(
            result.referenced_constants.get("MISSING_CONSTANT"),
            Some(&None)
        );
    }

    #[test]
    fn test_private_items_included_in_rustdoc() {
        // This test verifies that our fix for including private items in rustdoc generation
        // allows us to resolve private constants that were previously inaccessible

        // Simulate a rustdoc JSON that includes both public and private constants
        // (which should happen with --document-private-items flag)
        let mock_rustdoc = serde_json::json!({
            "index": {
                "struct_1": {
                    "name": "TestStruct",
                    "inner": {
                        "struct": {
                            "kind": {
                                "plain": {
                                    "fields": ["field_1"]
                                }
                            }
                        }
                    },
                    "docs": "Struct description."
                },
                "field_1": {
                    "name": "test_field",
                    "docs": "Field that uses [`PRIVATE_CONSTANT`] and [`PUBLIC_CONSTANT`]."
                },
                // Public constant (would be included without --document-private-items)
                "const_public": {
                    "name": "PUBLIC_CONSTANT",
                    "inner": {
                        "constant": {
                            "const": {
                                "expr": "100",
                                "type": "u32"
                            }
                        }
                    },
                    "visibility": "public"
                },
                // Private constant (only included with --document-private-items)
                "const_private": {
                    "name": "PRIVATE_CONSTANT",
                    "inner": {
                        "constant": {
                            "const": {
                                "expr": "200",
                                "type": "u32"
                            }
                        }
                    },
                    "visibility": "crate"
                }
            }
        });

        let result = extract_config_docs_from_rustdoc(&mock_rustdoc, &None).unwrap();

        // Both constants should be resolved now
        assert_eq!(result.referenced_constants.len(), 2);
        assert_eq!(
            result.referenced_constants.get("PUBLIC_CONSTANT"),
            Some(&Some("100".to_string()))
        );
        assert_eq!(
            result.referenced_constants.get("PRIVATE_CONSTANT"),
            Some(&Some("200".to_string()))
        );
    }

    #[test]
    fn test_multi_crate_constant_resolution() {
        // This test verifies that our multi-crate constant resolution works
        // It simulates the case where constants are defined in different crates

        // Create a mock rustdoc index for the main crate (without the target constant)
        let main_index = serde_json::json!({
            "const_main": {
                "name": "MAIN_CONSTANT",
                "inner": {
                    "constant": {
                        "const": {
                            "expr": "100",
                            "type": "u32"
                        }
                    }
                }
            }
        });

        let main_index_obj = main_index.as_object().unwrap();

        // Test resolving a constant that exists in main index
        let result1 = resolve_constant_in_index("MAIN_CONSTANT", main_index_obj);
        assert_eq!(result1, Some("100".to_string()));

        // Test resolving a constant that doesn't exist in main index
        let result2 = resolve_constant_in_index("EXTERNAL_CONSTANT", main_index_obj);
        assert_eq!(result2, None);

        // Note: Testing the full resolve_constant_reference function that reads from files
        // would require setting up actual rustdoc JSON files, which is complex for unit tests.
        // The integration test via the full pipeline covers this functionality.
    }

    #[test]
    fn test_strip_type_suffix() {
        // Test various type suffixes
        assert_eq!(strip_type_suffix("50u64"), "50");
        assert_eq!(strip_type_suffix("402_653_196u32"), "402_653_196");
        assert_eq!(strip_type_suffix("100i32"), "100");
        assert_eq!(strip_type_suffix("255u8"), "255");
        assert_eq!(strip_type_suffix("3.14f32"), "3.14");
        assert_eq!(strip_type_suffix("2.718f64"), "2.718");
        assert_eq!(strip_type_suffix("1000usize"), "1000");
        assert_eq!(strip_type_suffix("-42i64"), "-42");

        // Test values without type suffixes (should remain unchanged)
        assert_eq!(strip_type_suffix("42"), "42");
        assert_eq!(strip_type_suffix("3.14"), "3.14");
        assert_eq!(strip_type_suffix("hello"), "hello");
        assert_eq!(strip_type_suffix("\"string\""), "\"string\"");

        // Test edge cases
        assert_eq!(strip_type_suffix(""), "");
        assert_eq!(strip_type_suffix("u32"), "u32"); // Just the type name, not a suffixed value
        assert_eq!(strip_type_suffix("value_u32_test"), "value_u32_test"); // Contains but doesn't end with type
    }

    #[test]
    fn test_parse_field_documentation_with_required_and_units() {
        let doc_text = r#"Field with required and units annotations.
---
@default: `5000`
@required: true
@units: milliseconds
@notes:
  - This field has all new features."#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();

        assert_eq!(result.0.name, "test_field");
        assert_eq!(
            result.0.description,
            "Field with required and units annotations."
        );
        assert_eq!(result.0.default_value, Some("`5000`".to_string()));
        assert_eq!(result.0.required, Some(true));
        assert_eq!(result.0.units, Some("milliseconds".to_string()));
        assert_eq!(
            result.0.notes,
            Some(vec!["This field has all new features.".to_string()])
        );
    }

    #[test]
    fn test_parse_field_documentation_required_variants() {
        // Test "true" variant
        let doc_text1 = r#"Required field.
---
@required: true"#;
        let result1 = parse_field_documentation(doc_text1, "field1").unwrap();
        assert_eq!(result1.0.required, Some(true));

        // Test "false" variant
        let doc_text2 = r#"Optional field.
---
@required: false"#;
        let result2 = parse_field_documentation(doc_text2, "field2").unwrap();
        assert_eq!(result2.0.required, Some(false));

        // Test "TRUE" variant
        let doc_text3 = r#"Required field.
---
@required: TRUE"#; // Needs to be lowercase, will default to false, but will log a warning
        let result3 = parse_field_documentation(doc_text3, "field3").unwrap();
        assert_eq!(result3.0.required, Some(false));

        // Test "FALSE" variant
        let doc_text4 = r#"Optional field.
---
@required: FALSE"#; // Needs to be lowercase, will default to false, but will log a warning
        let result4 = parse_field_documentation(doc_text4, "field4").unwrap();
        assert_eq!(result4.0.required, Some(false));

        // Test invalid variant (should default to false with warning)
        let doc_text5 = r#"Invalid required field.
---
@required: maybe"#;
        let result5 = parse_field_documentation(doc_text5, "field5").unwrap();
        assert_eq!(result5.0.required, Some(false));
    }

    #[test]
    fn test_extract_annotation_literal_block_mode() {
        let metadata = r#"@notes: |
  This is a literal block
    with preserved indentation
  and multiple lines."#;

        let result = extract_annotation(metadata, "notes");
        assert!(result.is_some());
        let notes = result.unwrap();
        assert!(notes.contains("This is a literal block"));
        assert!(notes.contains("  with preserved indentation"));
        assert!(notes.contains("and multiple lines"));
        // Should preserve newlines
        assert!(notes.contains('\n'));
    }

    #[test]
    fn test_extract_annotation_folded_block_mode() {
        let metadata = r#"@default: >
  This is a folded block
  that should join lines
  together.

  But preserve paragraph breaks."#;

        let result = extract_annotation(metadata, "default");
        assert!(result.is_some());
        let default = result.unwrap();
        // Folded blocks should join lines with spaces
        assert!(default.contains("This is a folded block that should join lines together."));
        // But preserve paragraph breaks
        assert!(default.contains("But preserve paragraph breaks."));
    }

    #[test]
    fn test_extract_annotation_default_multiline_mode() {
        let metadata = r#"@notes:
  - First bullet point
  - Second bullet point with
    continuation on next line
  - Third bullet point"#;

        let result = extract_annotation(metadata, "notes");
        assert!(result.is_some());
        let notes = result.unwrap();
        assert!(notes.contains("First bullet point"));
        assert!(notes.contains("Second bullet point with"));
        assert!(notes.contains("continuation on next line"));
        assert!(notes.contains("Third bullet point"));
    }

    #[test]
    fn test_extract_annotation_literal_block_with_same_line_content() {
        let metadata = r#"@toml_example: | This content is on the same line
  And this content is on the next line
  With proper indentation preserved"#;

        let result = extract_annotation(metadata, "toml_example");
        assert!(result.is_some());
        let toml = result.unwrap();
        // Should only include content from subsequent lines, ignoring same-line content
        assert!(!toml.contains("This content is on the same line"));
        assert!(toml.contains("And this content is on the next line"));
        assert!(toml.contains("With proper indentation preserved"));
    }

    #[test]
    fn test_units_with_constant_references() {
        let doc_text = r#"Field with units containing constant references.
---
@units: [`DEFAULT_TIMEOUT_MS`] milliseconds"#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        let (field_doc, referenced_constants) = result;

        assert_eq!(
            field_doc.units,
            Some("[`DEFAULT_TIMEOUT_MS`] milliseconds".to_string())
        );
        // Check that constants were collected from units
        assert!(referenced_constants.contains("DEFAULT_TIMEOUT_MS"));
    }

    #[test]
    fn test_extract_annotation_default_mode_preserves_relative_indent() {
        let metadata = r#"@notes:
  - Main item 1
    - Sub item 1a
      - Sub-sub item 1a1
    - Sub item 1b
  - Main item 2"#;

        let result = extract_annotation(metadata, "notes");
        assert!(result.is_some());
        let notes = result.unwrap();

        // Should preserve relative indentation within the block
        assert!(notes.contains("- Main item 1"));
        assert!(notes.contains("  - Sub item 1a")); // 2 spaces more indented
        assert!(notes.contains("    - Sub-sub item 1a1")); // 4 spaces more indented
        assert!(notes.contains("  - Sub item 1b")); // Back to 2 spaces
        assert!(notes.contains("- Main item 2")); // Back to base level
    }

    #[test]
    fn test_extract_annotation_default_mode_mixed_indentation() {
        let metadata = r#"@default:
  First line with base indentation
    Second line more indented
  Third line back to base
      Fourth line very indented"#;

        let result = extract_annotation(metadata, "default");
        assert!(result.is_some());
        let default_val = result.unwrap();

        // Should preserve relative spacing
        let lines: Vec<&str> = default_val.lines().collect();
        assert_eq!(lines[0], "First line with base indentation");
        assert_eq!(lines[1], "  Second line more indented"); // 2 extra spaces
        assert_eq!(lines[2], "Third line back to base");
        assert_eq!(lines[3], "    Fourth line very indented"); // 4 extra spaces
    }

    #[test]
    fn test_extract_annotation_toml_example_consistency() {
        // Test that @toml_example now uses standard parsing (no special handling)
        let metadata = r#"@toml_example: |
  key = "value"
    indented_key = "nested"
  other = 123"#;

        let result = extract_annotation(metadata, "toml_example");
        assert!(result.is_some());
        let toml = result.unwrap();

        // Should use standard literal block parsing
        assert!(toml.contains("key = \"value\""));
        assert!(toml.contains("  indented_key = \"nested\"")); // Preserved relative indent
        assert!(toml.contains("other = 123"));
    }

    #[test]
    fn test_parse_folded_block_scalar_clip_chomping() {
        // Test that folded blocks use "clip" chomping (consistent with literal)
        let lines = vec![
            "    First paragraph line",
            "    continues here.",
            "",
            "    Second paragraph",
            "    also continues.",
            "",
            "", // Extra empty lines at end
        ];

        let result = parse_folded_block_scalar(&lines, 0);

        // Should fold lines within paragraphs but preserve paragraph breaks
        assert!(result.contains("First paragraph line continues here."));
        assert!(result.contains("Second paragraph also continues."));

        // Should use clip chomping - preserve single trailing newline if content ends with one
        // But since we're folding, the exact behavior depends on implementation
        assert!(!result.ends_with("\n\n")); // Should not have multiple trailing newlines
    }

    #[test]
    fn test_extract_annotation_edge_cases_empty_and_whitespace() {
        // Test annotations with only whitespace or empty content
        let metadata1 = "@default: |";
        let metadata2 = "@notes:\n    \n    \n"; // Only whitespace lines
        let metadata3 = "@deprecated: >\n"; // Folded with no content

        assert_eq!(extract_annotation(metadata1, "default"), None);
        assert_eq!(extract_annotation(metadata2, "notes"), None);
        assert_eq!(extract_annotation(metadata3, "deprecated"), None);
    }

    #[test]
    fn test_required_field_validation_comprehensive() {
        // Test all supported boolean representations for @required
        let test_cases = vec![
            ("true", Some(true)),
            ("True", Some(false)), // Need to be lowercase
            ("TRUE", Some(false)), // Need to be lowercase
            ("false", Some(false)),
            ("False", Some(false)), // Will default to false, but will log a warning
            ("FALSE", Some(false)), // Will default to false, but will log a warning
            ("maybe", Some(false)), // Invalid defaults to false
            ("invalid", Some(false)),
        ];

        for (input, expected) in test_cases {
            let doc_text = format!("Test field.\n---\n@required: {}", input);
            let result = parse_field_documentation(&doc_text, "test_field").unwrap();
            assert_eq!(result.0.required, expected, "Failed for input: '{}'", input);
        }

        // Test empty @required annotation (should return None, not Some(false))
        let doc_text_empty = "Test field.\n---\n@required:";
        let result_empty = parse_field_documentation(doc_text_empty, "test_field").unwrap();
        assert_eq!(
            result_empty.0.required, None,
            "Empty @required should not be parsed"
        );
    }

    #[test]
    fn test_units_with_multiline_content() {
        // Test units annotation with multiline content
        let doc_text = r#"Field with multiline units.
---
@units: |
  seconds (range: 1-3600)
  Default: [`DEFAULT_TIMEOUT`] seconds
@required: true"#;

        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        let (field_doc, referenced_constants) = result;

        assert!(field_doc.units.is_some());
        let units = field_doc.units.unwrap();
        assert!(units.contains("seconds (range: 1-3600)"));
        assert!(units.contains("Default: [`DEFAULT_TIMEOUT`] seconds"));
        assert_eq!(field_doc.required, Some(true));
        assert!(referenced_constants.contains("DEFAULT_TIMEOUT"));
    }

    #[test]
    fn test_extract_annotation_literal_and_folded_ignore_same_line_content() {
        // Test that same-line content is ignored for both | and >
        let metadata_literal = r#"@notes: | Ignored same line content
  Next line content
  Another line"#;

        let metadata_folded = r#"@default: > Ignored same line content
  Next line content
  Another line"#;

        let literal_result = extract_annotation(metadata_literal, "notes").unwrap();
        let folded_result = extract_annotation(metadata_folded, "default").unwrap();

        // Same-line content should be ignored
        assert!(!literal_result.contains("Ignored same line content"));
        assert!(!folded_result.contains("Ignored same line content"));

        // Literal mode should preserve all content from subsequent lines
        assert!(literal_result.contains("Next line content"));
        assert!(literal_result.contains("Another line"));

        let literal_lines: Vec<&str> = literal_result.lines().collect();
        assert_eq!(literal_lines.len(), 2);
        assert_eq!(literal_lines[0], "Next line content");
        assert_eq!(literal_lines[1], "Another line");

        // Folded mode should fold the subsequent lines
        assert!(folded_result.contains("Next line content"));
        assert!(folded_result.contains("Another line"));

        // In folded mode, lines at same indentation get joined with spaces
        let expected_folded = "Next line content Another line";
        assert_eq!(folded_result.trim(), expected_folded);
    }

    #[test]
    fn test_json_navigation_helpers() {
        let test_json = json!({
            "level1": {
                "level2": {
                    "level3": "value",
                    "array": ["item1", "item2"],
                    "object": {
                        "key": "value"
                    }
                },
                "string_field": "test_string"
            }
        });

        // Test get_json_path - valid paths
        assert!(get_json_path(&test_json, &["level1"]).is_some());
        assert!(get_json_path(&test_json, &["level1", "level2"]).is_some());
        assert!(get_json_path(&test_json, &["level1", "level2", "level3"]).is_some());

        // Test get_json_path - invalid paths
        assert!(get_json_path(&test_json, &["nonexistent"]).is_none());
        assert!(get_json_path(&test_json, &["level1", "nonexistent"]).is_none());
        assert!(get_json_path(&test_json, &["level1", "level2", "level3", "too_deep"]).is_none());

        // Test get_json_string
        assert_eq!(
            get_json_string(&test_json, &["level1", "level2", "level3"]),
            Some("value")
        );
        assert_eq!(
            get_json_string(&test_json, &["level1", "string_field"]),
            Some("test_string")
        );
        assert!(get_json_string(&test_json, &["level1", "level2", "array"]).is_none()); // not a string

        // Test get_json_array
        let array_result = get_json_array(&test_json, &["level1", "level2", "array"]);
        assert!(array_result.is_some());
        assert_eq!(array_result.unwrap().len(), 2);
        assert!(get_json_array(&test_json, &["level1", "string_field"]).is_none()); // not an array

        // Test get_json_object
        assert!(get_json_object(&test_json, &["level1"]).is_some());
        assert!(get_json_object(&test_json, &["level1", "level2"]).is_some());
        assert!(get_json_object(&test_json, &["level1", "level2", "object"]).is_some());
        assert!(get_json_object(&test_json, &["level1", "string_field"]).is_none()); // not an object
    }

    #[test]
    fn test_resolve_constant_in_index_edge_cases() {
        // Test with empty index
        let empty_index = serde_json::Map::new();
        let result = resolve_constant_in_index("ANY_CONSTANT", &empty_index);
        assert_eq!(result, None);

        // Test with index containing non-constant items
        let mock_index = serde_json::json!({
            "item_1": {
                "name": "NotAConstant",
                "inner": {
                    "function": {}
                }
            }
        });
        let index = mock_index.as_object().unwrap();
        let result = resolve_constant_in_index("NotAConstant", index);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_constant_in_index_malformed_constant() {
        // Test constant without value or expr - falls back to type field
        let mock_index = serde_json::json!({
            "const_1": {
                "name": "MALFORMED_CONSTANT",
                "inner": {
                    "constant": {
                        "type": "u32"
                        // Missing value and expr fields
                    }
                }
            }
        });
        let index = mock_index.as_object().unwrap();
        let result = resolve_constant_in_index("MALFORMED_CONSTANT", index);
        assert_eq!(result, Some("u32".to_string()));
    }

    #[test]
    fn test_resolve_constant_in_index_underscore_expr() {
        // Test constant with "_" expr and no value - falls back to type field
        let mock_index = serde_json::json!({
            "const_1": {
                "name": "COMPUTED_CONSTANT",
                "inner": {
                    "constant": {
                        "expr": "_",
                        "type": "u32"
                        // No value field
                    }
                }
            }
        });
        let index = mock_index.as_object().unwrap();
        let result = resolve_constant_in_index("COMPUTED_CONSTANT", index);
        assert_eq!(result, Some("u32".to_string()));
    }

    #[test]
    fn test_strip_type_suffix_edge_cases() {
        // Test with invalid suffixes that shouldn't be stripped
        assert_eq!(strip_type_suffix("123abc"), "123abc");
        assert_eq!(
            strip_type_suffix("value_with_u32_in_middle"),
            "value_with_u32_in_middle"
        );

        // Test with partial type names
        assert_eq!(strip_type_suffix("u"), "u");
        assert_eq!(strip_type_suffix("u3"), "u3");

        // Test with non-numeric values before type suffix
        assert_eq!(strip_type_suffix("abcu32"), "abcu32");

        // Test string literals with type suffixes inside
        assert_eq!(strip_type_suffix("\"value_u32\""), "\"value_u32\"");
    }

    #[test]
    fn test_get_json_navigation_edge_cases() {
        let test_json = serde_json::json!({
            "level1": {
                "string": "value",
                "number": 42,
                "boolean": true,
                "null_value": null
            }
        });

        // Test getting wrong types
        assert!(get_json_string(&test_json, &["level1", "number"]).is_none());
        assert!(get_json_array(&test_json, &["level1", "string"]).is_none());
        assert!(get_json_object(&test_json, &["level1", "boolean"]).is_none());

        // Test deep paths that don't exist
        assert!(get_json_path(&test_json, &["level1", "string", "deeper"]).is_none());
        assert!(get_json_path(&test_json, &["nonexistent", "path"]).is_none());

        // Test null values
        assert!(get_json_string(&test_json, &["level1", "null_value"]).is_none());
    }

    #[test]
    fn test_parse_field_documentation_edge_cases() {
        // Test with only separator, no content
        let doc_text = "Description\n---\n";
        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        assert_eq!(result.0.description, "Description");
        assert_eq!(result.0.default_value, None);

        // Test with multiple separators
        let doc_text = "Description\n---\n@default: value\n---\nIgnored section";
        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        assert_eq!(result.0.description, "Description");
        assert_eq!(result.0.default_value, Some("value".to_string()));

        // Test with empty description
        let doc_text = "\n---\n@default: value";
        let result = parse_field_documentation(doc_text, "test_field").unwrap();
        assert_eq!(result.0.description, "");
        assert_eq!(result.0.default_value, Some("value".to_string()));
    }

    #[test]
    fn test_extract_annotation_malformed_input() {
        // Test with annotation without colon
        let metadata = "@default no_colon_here\n@notes: valid";
        assert_eq!(extract_annotation(metadata, "default"), None);
        assert_eq!(
            extract_annotation(metadata, "notes"),
            Some("valid".to_string())
        );

        // Test with nested annotations - this will actually find "inside" because the function
        // looks for the pattern anywhere in a line, not necessarily at the start
        let metadata = "text with @default: inside\n@actual: real_value";
        assert_eq!(
            extract_annotation(metadata, "default"),
            Some("inside".to_string())
        );
        assert_eq!(
            extract_annotation(metadata, "actual"),
            Some("real_value".to_string())
        );
    }

    #[test]
    fn test_parse_literal_block_scalar_edge_cases() {
        // Test with empty input
        let result = parse_literal_block_scalar(&[], 0);
        assert_eq!(result, "");

        // Test with only empty lines
        let lines = vec!["", "  ", "\t", ""];
        let result = parse_literal_block_scalar(&lines, 0);
        assert_eq!(result, "");

        // Test with mixed indentation
        let lines = vec!["  line1", "    line2", "line3", "      line4"];
        let result = parse_literal_block_scalar(&lines, 0);
        assert!(result.contains("line1"));
        assert!(result.contains("  line2")); // Preserved relative indent
        assert!(result.contains("line3"));
        assert!(result.contains("    line4")); // Preserved relative indent
    }

    #[test]
    fn test_parse_folded_block_scalar_edge_cases() {
        // Test with empty input
        let result = parse_folded_block_scalar(&[], 0);
        assert_eq!(result, "");

        // Test with only empty lines
        let lines = vec!["", "  ", "\t"];
        let result = parse_folded_block_scalar(&lines, 0);
        assert_eq!(result, "");

        // Test paragraph separation
        let lines = vec![
            "  First paragraph line",
            "  continues here",
            "",
            "  Second paragraph",
            "  also continues",
        ];
        let result = parse_folded_block_scalar(&lines, 0);
        assert!(result.contains("First paragraph line continues here"));
        assert!(result.contains("Second paragraph also continues"));
        // Should have paragraph separation
        assert!(result.matches('\n').count() >= 1);
    }

    #[test]
    fn test_collect_annotation_block_lines_edge_cases() {
        let lines = vec![
            "@first: value1",
            "  content line 1",
            "  content line 2",
            "@second: value2",
            "  different content",
        ];

        // Test collecting until next annotation
        let result = collect_annotation_block_lines(&lines, 1, "@first: value1");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "  content line 1");
        assert_eq!(result[1], "  content line 2");

        // Test collecting from end
        let result = collect_annotation_block_lines(&lines, 4, "@second: value2");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "  different content");
    }

    #[test]
    fn test_find_constant_references_edge_cases() {
        // Test with malformed brackets
        let text = "[INCOMPLETE or [`VALID_CONSTANT`] and `not_constant`";
        let constants = find_constant_references(text);
        assert_eq!(constants.len(), 1);
        assert!(constants.contains("VALID_CONSTANT"));

        // Test with nested brackets - this won't match because [ in the middle breaks the pattern
        let text = "[`OUTER_[INNER]_CONSTANT`]";
        let constants = find_constant_references(text);
        assert_eq!(constants.len(), 0);

        // Test with empty brackets
        let text = "[``] and [`VALID`]";
        let constants = find_constant_references(text);
        assert_eq!(constants.len(), 1);
        assert!(constants.contains("VALID"));
    }

    #[test]
    fn test_extract_struct_fields_complex_scenarios() {
        // Test struct with no fields array
        let mock_index = serde_json::json!({
            "struct_1": {
                "name": "EmptyStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                // No fields array
                            }
                        }
                    }
                }
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];
        let (fields, _) = extract_struct_fields(index, struct_item).unwrap();
        assert_eq!(fields.len(), 0);

        // Test struct with empty fields array
        let mock_index = serde_json::json!({
            "struct_1": {
                "name": "EmptyFieldsStruct",
                "inner": {
                    "struct": {
                        "kind": {
                            "plain": {
                                "fields": []
                            }
                        }
                    }
                }
            }
        });

        let index = mock_index.as_object().unwrap();
        let struct_item = &mock_index["struct_1"];
        let (fields, _) = extract_struct_fields(index, struct_item).unwrap();
        assert_eq!(fields.len(), 0);
    }
}
