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
use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use clap::{Arg, Command};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FieldDoc {
    name: String,
    description: String,
    default_value: Option<String>,
    notes: Option<Vec<String>>,
    deprecated: Option<String>,
    toml_example: Option<String>,
    required: Option<bool>,
    units: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StructDoc {
    name: String,
    description: Option<String>,
    fields: Vec<FieldDoc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigDocs {
    structs: Vec<StructDoc>,
    referenced_constants: HashMap<String, Option<String>>, // Name -> Resolved Value (or None)
}

// Global context for cross-references
struct GlobalContext {
    // Map from struct name to markdown section anchor
    struct_to_anchor: HashMap<String, String>,
    // Map from field name to (struct_name, anchor) for finding cross-references
    field_to_struct: HashMap<String, (String, String)>,
    // Map from constant name to value (if we can extract them)
    constants: HashMap<String, String>,
    // Custom section name mappings
    custom_mappings: HashMap<String, String>,
}

// Static regex for finding intra-documentation links - compiled once at startup
static LINK_REGEX_BACKTICKS: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\[`([A-Za-z0-9_:]+)`\]").unwrap());

fn main() -> Result<()> {
    let matches = Command::new("generate-markdown")
        .about("Generate Markdown documentation from extracted config docs JSON")
        .arg(
            Arg::new("input")
                .long("input")
                .value_name("FILE")
                .help("Input JSON file with extracted documentation")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("FILE")
                .help("Output Markdown file")
                .required(true),
        )
        .arg(
            Arg::new("template")
                .long("template")
                .value_name("FILE")
                .help(
                    "Optional markdown template file (defaults to templates/reference_template.md)",
                )
                .required(true),
        )
        .arg(
            Arg::new("mappings")
                .long("section-name-mappings")
                .value_name("FILE")
                .help("Optional JSON file for struct name to TOML section name mappings")
                .required(true),
        )
        .get_matches();

    let input_path = matches.get_one::<String>("input").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let template_path = matches.get_one::<String>("template").unwrap();
    let mappings_path = matches.get_one::<String>("mappings").unwrap();

    let input_content = fs::read_to_string(input_path)
        .with_context(|| format!("Failed to read input JSON file: {input_path}"))?;

    let config_docs: ConfigDocs =
        serde_json::from_str(&input_content).with_context(|| "Failed to parse input JSON")?;

    let custom_mappings = load_section_name_mappings(mappings_path)?;

    let markdown = generate_markdown(&config_docs, template_path, &custom_mappings)?;

    fs::write(output_path, markdown)
        .with_context(|| format!("Failed to write output file: {output_path}"))?;

    println!("Successfully generated Markdown documentation at {output_path}");
    Ok(())
}

fn load_section_name_mappings(mappings_file: &str) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(mappings_file)
        .with_context(|| format!("Failed to read section name mappings file: {mappings_file}"))?;

    let mappings: HashMap<String, String> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse section name mappings JSON: {mappings_file}"))?;

    Ok(mappings)
}

fn load_template(template_path: &str) -> Result<String> {
    fs::read_to_string(template_path)
        .with_context(|| format!("Failed to read template file: {template_path}"))
}

fn render_template(template: &str, variables: HashMap<String, String>) -> String {
    let mut result = template.to_string();

    for (key, value) in variables {
        let placeholder = format!("{{{{{key}}}}}");
        result = result.replace(&placeholder, &value);
    }

    result
}

fn generate_markdown(
    config_docs: &ConfigDocs,
    template_path: &str,
    custom_mappings: &HashMap<String, String>,
) -> Result<String> {
    // Load template
    let template = load_template(template_path)?;

    // Build global context for cross-references
    let global_context = build_global_context(config_docs, custom_mappings);

    // Build table of contents
    let mut toc_content = String::new();
    for struct_doc in &config_docs.structs {
        let section_name = struct_to_section_name(&struct_doc.name, custom_mappings);
        toc_content.push_str(&format!(
            "- [{}]({})\n",
            section_name,
            section_anchor(&section_name)
        ));
    }

    // Generate sections for each struct
    let mut struct_sections = String::new();
    for struct_doc in &config_docs.structs {
        generate_struct_section(
            &mut struct_sections,
            struct_doc,
            &global_context,
            custom_mappings,
        )?;
        struct_sections.push('\n');
    }

    // Prepare template variables
    let mut template_vars = HashMap::new();
    template_vars.insert("toc_content".to_string(), toc_content);
    template_vars.insert("struct_sections".to_string(), struct_sections);

    // Render template with variables
    let output = render_template(&template, template_vars);

    Ok(output)
}

fn build_global_context(
    config_docs: &ConfigDocs,
    custom_mappings: &HashMap<String, String>,
) -> GlobalContext {
    let mut struct_to_anchor = HashMap::new();
    let mut field_to_struct = HashMap::new();
    let mut resolved_constants_map = HashMap::new();

    // Build mappings
    for struct_doc in &config_docs.structs {
        let section_name = struct_to_section_name(&struct_doc.name, custom_mappings);
        let anchor = section_anchor(&section_name);
        struct_to_anchor.insert(struct_doc.name.clone(), anchor.clone());

        for field in &struct_doc.fields {
            field_to_struct.insert(
                field.name.clone(),
                (struct_doc.name.clone(), anchor.clone()),
            );
        }
    }

    // Populate constants from the parsed ConfigDocs.referenced_constants
    for (name, opt_value) in &config_docs.referenced_constants {
        if let Some(value) = opt_value {
            resolved_constants_map.insert(name.clone(), value.clone());
        }
    }

    GlobalContext {
        struct_to_anchor,
        field_to_struct,
        constants: resolved_constants_map,
        custom_mappings: custom_mappings.clone(),
    }
}

fn generate_struct_section(
    output: &mut String,
    struct_doc: &StructDoc,
    global_context: &GlobalContext,
    custom_mappings: &HashMap<String, String>,
) -> Result<()> {
    let section_name = struct_to_section_name(&struct_doc.name, custom_mappings);
    output.push_str(&format!("## {section_name}\n\n"));

    // Add struct description if available
    if let Some(description) = &struct_doc.description {
        output.push_str(&format!(
            "{}\n\n",
            process_intralinks_with_context(description, global_context, &struct_doc.name)
        ));
    }

    // Only create table if there are fields
    if struct_doc.fields.is_empty() {
        output.push_str("*No configurable parameters documented.*\n\n");
        return Ok(());
    }

    // Sort fields: non-deprecated first, then deprecated
    let mut sorted_fields = struct_doc.fields.clone();
    sorted_fields.sort_by(|a, b| {
        let a_deprecated = is_deprecated(a);
        let b_deprecated = is_deprecated(b);

        match (a_deprecated, b_deprecated) {
            (false, true) => std::cmp::Ordering::Less, // non-deprecated first
            (true, false) => std::cmp::Ordering::Greater, // deprecated last
            _ => a.name.cmp(&b.name),                  // alphabetical within groups
        }
    });

    // Parameter table header
    output.push_str("| Parameter | Description | Default |\n");
    output.push_str("|-----------|-------------|----------|\n");

    // Generate table rows for each field
    for field in &sorted_fields {
        generate_field_row(output, field, &struct_doc.name, global_context)?;
    }

    output.push('\n');
    Ok(())
}

fn generate_field_row(
    output: &mut String,
    field: &FieldDoc,
    struct_name: &str,
    global_context: &GlobalContext,
) -> Result<()> {
    // Create proper anchor ID
    let section_name = struct_to_section_name_with_context(struct_name, global_context);
    let anchor_id = format!(
        "{}-{}",
        section_name.trim_start_matches('[').trim_end_matches(']'),
        field.name
    );

    // Use HTML span with id for proper anchoring
    let field_name = if is_deprecated(field) {
        format!(
            "~~[<span id=\"{}\">{}</span>](#{})~~",
            anchor_id,
            escape_markdown(&field.name),
            anchor_id
        )
    } else {
        format!(
            "[<span id=\"{}\">{}</span>](#{})",
            anchor_id,
            escape_markdown(&field.name),
            anchor_id
        )
    };

    // Build comprehensive description column with struct context
    let mut description_parts = Vec::new();

    // Main description
    if !field.description.is_empty() {
        let main_desc = if let Some(separator_pos) = field.description.find("---") {
            field.description[..separator_pos].trim()
        } else {
            &field.description
        };

        if !main_desc.is_empty() {
            // Check if this description contains hierarchical lists (indented bullet points)
            let has_hierarchical_lists = main_desc.lines().any(|line| {
                let trimmed = line.trim();
                let leading_spaces = line.len() - line.trim_start().len();
                trimmed.starts_with("- ") && leading_spaces > 0
            });

            let processed_desc = if has_hierarchical_lists {
                // Use hierarchical list processing to preserve indentation
                process_hierarchical_lists(main_desc, global_context, struct_name)
            } else {
                // Use regular processing with intra-links
                process_intralinks_with_context(main_desc, global_context, struct_name)
                    .replace('\n', "<br>")
            };

            description_parts.push(processed_desc);
        }
    }

    // Add notes if present
    if let Some(notes) = &field.notes {
        let mut notes_section = String::new();
        notes_section.push_str("<br><br>**Notes:**");
        for note in notes {
            notes_section.push_str(&format!(
                "<br>- {}",
                process_intralinks_with_context(note, global_context, struct_name)
            ));
        }
        description_parts.push(notes_section);
    }

    // Add deprecation warning if present
    if let Some(deprecated) = &field.deprecated {
        description_parts.push(format!("<br><br>**⚠️ DEPRECATED:** {deprecated}"));
    }

    // Add TOML example if present
    if let Some(toml_example) = &field.toml_example {
        let clean_example = if toml_example.starts_with('|') {
            toml_example.trim_start_matches('|').trim_start()
        } else {
            toml_example
        };

        // Use HTML pre/code formatting that works properly in markdown tables
        // instead of markdown fenced code blocks which get mangled by br tag conversion
        let escaped_example = clean_example
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\n', "&#10;"); // Use HTML entity for newline to avoid <br> conversion

        let example_section = format!(
            "<br><br>**Example:**<br><pre><code>{escaped_example}</code></pre>" // HTML entities will be rendered as newlines by <pre>
        );
        description_parts.push(example_section);
    }

    // Add units information if present
    if let Some(units) = &field.units {
        let units_text = process_intralinks_with_context(units, global_context, struct_name);
        description_parts.push(format!("<br><br>**Units:** {units_text}"));
    }

    let description = if description_parts.is_empty() {
        "*No description available*".to_string()
    } else {
        description_parts.join("")
    };

    // Default value column - handle required fields
    let default_value = match (&field.required, &field.default_value) {
        // If explicitly marked as required=true, show as required regardless of default
        (Some(true), _) => "**Required**".to_string(),
        // If explicitly marked as required=false and has default, show the default
        (Some(false), Some(default)) => {
            process_intralinks_with_context(default, global_context, struct_name)
        }
        // If explicitly marked as required=false but no default, show as optional
        (Some(false), None) => "*Optional*".to_string(),
        // If required field is not specified, use default behavior (backward compatibility)
        (None, Some(default)) => {
            process_intralinks_with_context(default, global_context, struct_name)
        }
        (None, None) => "**Required**".to_string(),
    };

    output.push_str(&format!(
        "| {} | {} | {} |\n",
        field_name,
        escape_markdown_table(&description),
        escape_markdown_table(&default_value)
    ));

    Ok(())
}

fn escape_markdown_table(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', "<br>")
}

fn is_deprecated(field: &FieldDoc) -> bool {
    field.deprecated.is_some()
}

fn struct_to_section_name(struct_name: &str, custom_mappings: &HashMap<String, String>) -> String {
    // Check custom mappings first
    if let Some(section_name) = custom_mappings.get(struct_name) {
        return section_name.clone();
    }
    format!("[{}]", struct_name.to_lowercase())
}

fn struct_to_section_name_with_context(
    struct_name: &str,
    global_context: &GlobalContext,
) -> String {
    struct_to_section_name(struct_name, &global_context.custom_mappings)
}

fn escape_markdown(text: &str) -> String {
    text.replace('|', "\\|")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn section_anchor(section: &str) -> String {
    format!(
        "#{}",
        section
            .to_lowercase()
            .replace(' ', "-")
            .replace("[", "")
            .replace("]", "")
    )
}

fn process_intralinks_with_context(
    text: &str,
    global_context: &GlobalContext,
    current_struct_name: &str,
) -> String {
    // Process cross-references in both formats:
    // 1. [`StructName::field`] or [`CONSTANT_NAME`] (with backticks)
    LINK_REGEX_BACKTICKS
        .replace_all(text, |caps: &regex::Captures| {
            process_reference(&caps[1], global_context, current_struct_name)
        })
        .to_string()
}

fn process_reference(
    reference: &str,
    global_context: &GlobalContext,
    current_struct_name: &str,
) -> String {
    if reference.contains("::") {
        // This is a struct::field reference
        let parts: Vec<&str> = reference.split("::").collect();
        if parts.len() == 2 {
            let ref_struct_name = parts[0];
            let field_name = parts[1];

            // Check if the referenced struct exists in our docs
            if global_context
                .struct_to_anchor
                .contains_key(ref_struct_name)
            {
                // Create proper anchor ID
                let section_name =
                    struct_to_section_name_with_context(ref_struct_name, global_context);
                let anchor_id = format!(
                    "{}-{}",
                    section_name.trim_start_matches('[').trim_end_matches(']'),
                    field_name
                );

                // Check if it's the same struct or different struct
                if ref_struct_name == current_struct_name {
                    // Same struct: just show field name
                    return format!("[{field_name}](#{anchor_id}) ");
                } else {
                    // Different struct: show [config_section].field_name as a link
                    let config_section = section_name.trim_start_matches('[').trim_end_matches(']');
                    return format!("[[{config_section}].{field_name}](#{anchor_id}) ");
                }
            }
        }
    } else {
        // This might be a constant reference
        if let Some(value) = global_context.constants.get(reference) {
            return format!("`{value}`");
        }

        // Check if it's a standalone field name (without struct prefix)
        if let Some((field_struct_name, _anchor)) = global_context.field_to_struct.get(reference) {
            let section_name =
                struct_to_section_name_with_context(field_struct_name, global_context);
            let anchor_id = format!(
                "{}-{}",
                section_name.trim_start_matches('[').trim_end_matches(']'),
                reference
            );

            // Check if it's the same struct or different struct
            if field_struct_name == current_struct_name {
                // Same struct: just show field name
                return format!("[{reference}](#{anchor_id}) ");
            } else {
                // Different struct: show [config_section].field_name as a link
                let config_section = section_name.trim_start_matches('[').trim_end_matches(']');
                return format!("[[{config_section}].{reference}](#{anchor_id}) ");
            }
        }
    }

    // If we can't resolve the reference, keep the text
    format!("`{reference}`")
}

/// Process text to preserve hierarchical list indentation
/// Converts markdown-style indented lists to HTML that preserves indentation in table cells
fn process_hierarchical_lists(
    text: &str,
    global_context: &GlobalContext,
    struct_name: &str,
) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut result = Vec::new();

    for line in lines {
        if line.trim().starts_with("- ") {
            // Count leading spaces to determine indentation level
            let leading_spaces = line.len() - line.trim_start().len();

            // Convert spaces to non-breaking spaces for HTML preservation
            // Every 2 spaces becomes 2 &nbsp; entities for visual indentation
            let indent_html = "&nbsp;".repeat(leading_spaces);

            // Process intra-links in the content
            let content = line.trim();
            let processed_content =
                process_intralinks_with_context(content, global_context, struct_name);

            result.push(format!("{indent_html}{processed_content}"));
        } else {
            // Process intra-links in non-bullet lines too
            let processed_line = process_intralinks_with_context(line, global_context, struct_name);
            result.push(processed_line);
        }
    }

    result.join("<br>")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a basic FieldDoc for testing
    fn create_field_doc(name: &str, description: &str) -> FieldDoc {
        FieldDoc {
            name: name.to_string(),
            description: description.to_string(),
            default_value: None,
            notes: None,
            deprecated: None,
            toml_example: None,
            required: None,
            units: None,
        }
    }

    // Helper function to create a basic StructDoc for testing
    fn create_struct_doc(
        name: &str,
        description: Option<&str>,
        fields: Vec<FieldDoc>,
    ) -> StructDoc {
        StructDoc {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            fields,
        }
    }

    // Helper function to create a basic ConfigDocs for testing
    fn create_config_docs(structs: Vec<StructDoc>) -> ConfigDocs {
        ConfigDocs {
            structs,
            referenced_constants: HashMap::new(),
        }
    }

    // Helper function to create a mock GlobalContext for testing
    fn create_mock_global_context() -> GlobalContext {
        let mut struct_to_anchor = HashMap::new();
        let mut field_to_struct = HashMap::new();
        let mut constants = HashMap::new();
        let mut custom_mappings = HashMap::new();

        // Add custom mappings like the real ones
        custom_mappings.insert("NodeConfig".to_string(), "[node]".to_string());
        custom_mappings.insert("MinerConfig".to_string(), "[miner]".to_string());

        // Add some test structs and fields
        struct_to_anchor.insert("NodeConfig".to_string(), "#node".to_string());
        struct_to_anchor.insert("MinerConfig".to_string(), "#miner".to_string());

        field_to_struct.insert(
            "test_field".to_string(),
            ("NodeConfig".to_string(), "#node".to_string()),
        );
        field_to_struct.insert(
            "other_field".to_string(),
            ("MinerConfig".to_string(), "#miner".to_string()),
        );

        constants.insert("TEST_CONSTANT".to_string(), "42".to_string());
        constants.insert("ANOTHER_CONSTANT".to_string(), "true".to_string());

        GlobalContext {
            struct_to_anchor,
            field_to_struct,
            constants,
            custom_mappings,
        }
    }

    // I. Basic Markdown Generation Tests

    #[test]
    fn test_generate_markdown_empty_config() {
        let config_docs = create_config_docs(vec![]);
        let template_path = "templates/reference_template.md";
        let result = generate_markdown(&config_docs, template_path, &HashMap::new()).unwrap();

        assert!(result.contains("# Stacks Node Configuration Reference"));
        assert!(result.contains("## Table of Contents"));
        // Should not contain any specific struct sections
        assert!(!result.contains("## ["));
    }

    #[test]
    fn test_generate_markdown_with_one_struct_no_fields() {
        let struct_doc = create_struct_doc("TestStruct", Some("A test struct"), vec![]);
        let config_docs = create_config_docs(vec![struct_doc]);
        let template_path = "templates/reference_template.md";
        let result = generate_markdown(&config_docs, template_path, &HashMap::new()).unwrap();

        assert!(result.contains("# Stacks Node Configuration Reference"));
        assert!(result.contains("- [[teststruct]](#teststruct)"));
        assert!(result.contains("## [teststruct]"));
        assert!(result.contains("A test struct"));
        assert!(result.contains("*No configurable parameters documented.*"));
    }

    #[test]
    fn test_generate_markdown_with_one_struct_with_fields() {
        let field = create_field_doc("test_field", "A test field");
        let struct_doc = create_struct_doc("TestStruct", Some("A test struct"), vec![field]);
        let config_docs = create_config_docs(vec![struct_doc]);
        let template_path = "templates/reference_template.md";
        let result = generate_markdown(&config_docs, template_path, &HashMap::new()).unwrap();

        assert!(result.contains("# Stacks Node Configuration Reference"));
        assert!(result.contains("- [[teststruct]](#teststruct)"));
        assert!(result.contains("## [teststruct]"));
        assert!(result.contains("A test struct"));
        assert!(result.contains("| Parameter | Description | Default |"));
        assert!(result.contains("test_field"));
        assert!(result.contains("A test field"));
    }

    // II. Section & Anchor Generation Tests

    #[test]
    fn test_struct_to_section_name_known_structs() {
        let mut mappings = HashMap::new();
        // Load the expected mappings based on section_name_mappings.json
        mappings.insert("BurnchainConfig".to_string(), "[burnchain]".to_string());
        mappings.insert("NodeConfig".to_string(), "[node]".to_string());
        mappings.insert("MinerConfig".to_string(), "[miner]".to_string());
        mappings.insert(
            "ConnectionOptionsFile".to_string(),
            "[connection_options]".to_string(),
        );
        mappings.insert(
            "FeeEstimationConfigFile".to_string(),
            "[fee_estimation]".to_string(),
        );
        mappings.insert(
            "EventObserverConfigFile".to_string(),
            "[[events_observer]]".to_string(),
        );
        mappings.insert(
            "InitialBalanceFile".to_string(),
            "[[ustx_balance]]".to_string(),
        );

        assert_eq!(
            struct_to_section_name("BurnchainConfig", &mappings),
            "[burnchain]"
        );
        assert_eq!(struct_to_section_name("NodeConfig", &mappings), "[node]");
        assert_eq!(struct_to_section_name("MinerConfig", &mappings), "[miner]");
        assert_eq!(
            struct_to_section_name("ConnectionOptionsFile", &mappings),
            "[connection_options]"
        );
        assert_eq!(
            struct_to_section_name("FeeEstimationConfigFile", &mappings),
            "[fee_estimation]"
        );
        assert_eq!(
            struct_to_section_name("EventObserverConfigFile", &mappings),
            "[[events_observer]]"
        );
        assert_eq!(
            struct_to_section_name("InitialBalanceFile", &mappings),
            "[[ustx_balance]]"
        );
    }

    #[test]
    fn test_struct_to_section_name_unknown_struct() {
        let mappings = HashMap::new();
        assert_eq!(
            struct_to_section_name("MyCustomConfig", &mappings),
            "[mycustomconfig]"
        );
        assert_eq!(
            struct_to_section_name("UnknownStruct", &mappings),
            "[unknownstruct]"
        );
    }

    #[test]
    fn test_section_anchor_generation() {
        assert_eq!(section_anchor("[node]"), "#node");
        assert_eq!(section_anchor("[burnchain]"), "#burnchain");
        assert_eq!(section_anchor("[my custom section]"), "#my-custom-section");
        assert_eq!(
            section_anchor("[connection_options]"),
            "#connection_options"
        );
    }

    // III. Field Row Generation Tests

    #[test]
    fn test_generate_field_row_basic_field() {
        let field = create_field_doc("basic_field", "A basic field description");
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("basic_field"));
        assert!(output.contains("A basic field description"));
        assert!(output.contains("**Required**"));
        assert!(output.contains("<span id=\"teststruct-basic_field\">"));
    }

    #[test]
    fn test_generate_field_row_with_default_value() {
        let mut field = create_field_doc("field_with_default", "Field with default value");
        field.default_value = Some("`42`".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("field_with_default"));
        assert!(output.contains("Field with default value"));
        assert!(output.contains("`42`"));
        assert!(!output.contains("**Required**"));
    }

    #[test]
    fn test_generate_field_row_without_default_value() {
        let field = create_field_doc("required_field", "A required field");
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("required_field"));
        assert!(output.contains("**Required**"));
    }

    #[test]
    fn test_generate_field_row_with_notes() {
        let mut field = create_field_doc("field_with_notes", "Field with notes");
        field.notes = Some(vec!["First note".to_string(), "Second note".to_string()]);
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("**Notes:**"));
        assert!(output.contains("- First note"));
        assert!(output.contains("- Second note"));
    }

    #[test]
    fn test_generate_field_row_deprecated_field() {
        let mut field = create_field_doc("old_field", "An old field");
        field.deprecated = Some("Use new_field instead".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("~~"));
        assert!(output.contains("**⚠️ DEPRECATED:**"));
        assert!(output.contains("Use new_field instead"));
    }

    #[test]
    fn test_generate_field_row_with_toml_example() {
        let mut field = create_field_doc("field_with_example", "Field with TOML example");
        field.toml_example = Some("key = \"value\"\nnumber = 42".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("**Example:**"));
        assert!(output.contains("<pre><code>"));
        assert!(output.contains("key = \"value\""));
        assert!(output.contains("number = 42"));
        assert!(output.contains("</code></pre>"));
    }

    #[test]
    fn test_generate_field_row_toml_example_preserves_newlines() {
        let mut field = create_field_doc("multiline_example", "Field with multiline TOML example");
        field.toml_example =
            Some("key = \"value\"\nnested = {\n  sub_key = \"sub_value\"\n}".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("**Example:**"));
        assert!(output.contains("<pre><code>"));
        assert!(output.contains("</code></pre>"));

        // Find the code block content
        let pre_start = output.find("<pre><code>").unwrap();
        let pre_end = output.find("</code></pre>").unwrap();
        let code_content = &output[pre_start..pre_end + "</code></pre>".len()];

        // Should NOT contain <br> tags inside the code block
        assert!(
            !code_content.contains("<br>"),
            "Code block should not contain <br> tags"
        );

        // Should contain HTML entities for newlines instead
        assert!(
            code_content.contains("&#10;"),
            "Code block should contain HTML entities for newlines"
        );

        // Should contain the key-value pairs
        assert!(code_content.contains("key = \"value\""));
        assert!(code_content.contains("sub_key = \"sub_value\""));

        // Should contain the actual newline characters in the original TOML
        assert!(field.toml_example.as_ref().unwrap().contains('\n'));
    }

    #[test]
    fn test_generate_field_row_hierarchical_lists() {
        let field = create_field_doc(
            "complex_list_field",
            r"Field with hierarchical lists:
- Main item 1
  - Sub item 1a
    - Sub-sub item 1a1
  - Sub item 1b
- Main item 2
  - Sub item 2a",
        );
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        // Verify that indentation is preserved with &nbsp; entities
        assert!(output.contains("- Main item 1"));
        assert!(output.contains("&nbsp;&nbsp;- Sub item 1a"));
        assert!(output.contains("&nbsp;&nbsp;&nbsp;&nbsp;- Sub-sub item 1a1"));
        assert!(output.contains("&nbsp;&nbsp;- Sub item 1b"));
        assert!(output.contains("- Main item 2"));
        assert!(output.contains("&nbsp;&nbsp;- Sub item 2a"));
    }

    #[test]
    fn test_generate_field_row_hierarchical_lists_with_intralinks() {
        let field = create_field_doc(
            "list_with_links",
            r"Field with links in hierarchical lists:
- Main item with [`TEST_CONSTANT`]
  - Sub item with [`NodeConfig::test_field`]
    - Sub-sub item with [`other_field`]",
        );
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        // Verify that indentation is preserved AND intra-links are processed
        assert!(output.contains("- Main item with `42`")); // constant resolved
        assert!(
            output.contains("&nbsp;&nbsp;- Sub item with [[node].test_field](#node-test_field)")
        ); // field link with indentation
        assert!(output.contains(
            "&nbsp;&nbsp;&nbsp;&nbsp;- Sub-sub item with [[miner].other_field](#miner-other_field)"
        )); // cross-struct field link with indentation
    }

    #[test]
    fn test_generate_field_row_with_required_true() {
        let mut field = create_field_doc("required_field", "A required field");
        field.required = Some(true);
        field.default_value = Some("`default_value`".to_string()); // Even with default, should show as required
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("required_field"));
        assert!(output.contains("A required field"));
        assert!(output.contains("**Required**"));
        assert!(!output.contains("`default_value`")); // Should not show default when required=true
    }

    #[test]
    fn test_generate_field_row_with_required_false_and_default() {
        let mut field = create_field_doc("optional_field", "An optional field");
        field.required = Some(false);
        field.default_value = Some("`42`".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("optional_field"));
        assert!(output.contains("An optional field"));
        assert!(output.contains("`42`"));
        assert!(!output.contains("**Required**"));
    }

    #[test]
    fn test_generate_field_row_with_required_false_no_default() {
        let mut field = create_field_doc("optional_field", "An optional field");
        field.required = Some(false);
        field.default_value = None;
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("optional_field"));
        assert!(output.contains("An optional field"));
        assert!(output.contains("*Optional*"));
        assert!(!output.contains("**Required**"));
    }

    #[test]
    fn test_generate_field_row_with_units() {
        let mut field = create_field_doc("timeout_field", "A timeout field");
        field.units = Some("milliseconds".to_string());
        field.default_value = Some("`5000`".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("timeout_field"));
        assert!(output.contains("A timeout field"));
        assert!(output.contains("**Units:** milliseconds"));
        assert!(output.contains("`5000`"));
    }

    #[test]
    fn test_generate_field_row_with_units_and_constants() {
        let mut field = create_field_doc("timeout_field", "A timeout field");
        field.units = Some("[`TEST_CONSTANT`] milliseconds".to_string());
        field.default_value = Some("`5000`".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("timeout_field"));
        assert!(output.contains("A timeout field"));
        assert!(output.contains("**Units:** `42` milliseconds")); // Constant should be resolved
        assert!(output.contains("`5000`"));
    }

    #[test]
    fn test_generate_field_row_all_new_features() {
        let mut field = create_field_doc("complex_field", "A field with all new features");
        field.required = Some(true);
        field.units = Some("seconds".to_string());
        field.notes = Some(vec!["Important note".to_string()]);
        field.toml_example = Some("field = 30".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("complex_field"));
        assert!(output.contains("A field with all new features"));
        assert!(output.contains("**Required**"));
        assert!(output.contains("**Units:** seconds"));
        assert!(output.contains("**Notes:**"));
        assert!(output.contains("- Important note"));
        assert!(output.contains("**Example:**"));
        assert!(output.contains("field = 30"));
    }

    #[test]
    fn test_generate_field_row_units_with_constants_and_intralinks() {
        let mut field = create_field_doc("timeout_field", "A timeout field");
        field.units =
            Some("[`TEST_CONSTANT`] seconds (see [`NodeConfig::test_field`])".to_string());
        field.default_value = Some("`30`".to_string());
        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "TestStruct", &global_context).unwrap();

        assert!(output.contains("timeout_field"));
        assert!(output.contains("**Units:**"));
        // Constants should be resolved and intralinks processed
        assert!(output.contains("`42`")); // TEST_CONSTANT resolved
        assert!(output.contains("[[node].test_field](#node-test_field)")); // Cross-struct reference format
    }

    #[test]
    fn test_generate_field_row_required_field_combinations() {
        let global_context = create_mock_global_context();

        // Test required=true with default (should show Required, not default)
        let mut field1 = create_field_doc("req_with_default", "Required with default");
        field1.required = Some(true);
        field1.default_value = Some("`ignored`".to_string());
        let mut output1 = String::new();
        generate_field_row(&mut output1, &field1, "TestStruct", &global_context).unwrap();
        assert!(output1.contains("**Required**"));
        assert!(!output1.contains("`ignored`"));

        // Test required=false with default (should show default)
        let mut field2 = create_field_doc("opt_with_default", "Optional with default");
        field2.required = Some(false);
        field2.default_value = Some("`42`".to_string());
        let mut output2 = String::new();
        generate_field_row(&mut output2, &field2, "TestStruct", &global_context).unwrap();
        assert!(output2.contains("`42`"));
        assert!(!output2.contains("**Required**"));
        assert!(!output2.contains("*Optional*"));

        // Test required=false without default (should show Optional)
        let mut field3 = create_field_doc("opt_no_default", "Optional without default");
        field3.required = Some(false);
        field3.default_value = None;
        let mut output3 = String::new();
        generate_field_row(&mut output3, &field3, "TestStruct", &global_context).unwrap();
        assert!(output3.contains("*Optional*"));
        assert!(!output3.contains("**Required**"));

        // Test no required field specified (backward compatibility)
        let mut field4 = create_field_doc("legacy_field", "Legacy field");
        field4.required = None;
        field4.default_value = Some("`legacy`".to_string());
        let mut output4 = String::new();
        generate_field_row(&mut output4, &field4, "TestStruct", &global_context).unwrap();
        assert!(output4.contains("`legacy`"));
        assert!(!output4.contains("**Required**"));
    }

    #[test]
    fn test_generate_field_row_comprehensive_integration() {
        // Test a field with all possible attributes
        let mut field = create_field_doc(
            "comprehensive_field",
            "A comprehensive field demonstrating all features.\n\nThis includes multiple paragraphs.",
        );
        field.default_value = Some("`[\"default\", \"values\"]`".to_string());
        field.required = Some(false);
        field.units = Some("milliseconds (range: 100-5000)".to_string());
        field.notes = Some(vec![
            "This is the first note with [`TEST_CONSTANT`]".to_string(),
            "This is the second note referencing [`NodeConfig::test_field`]".to_string(),
        ]);
        field.deprecated =
            Some("Use new_comprehensive_field instead. Will be removed in v3.0.".to_string());
        field.toml_example =
            Some("comprehensive_field = [\n  \"value1\",\n  \"value2\"\n]".to_string());

        let global_context = create_mock_global_context();
        let mut output = String::new();

        generate_field_row(&mut output, &field, "NodeConfig", &global_context).unwrap();

        // Verify field name with deprecation strikethrough
        assert!(output.contains("~~"));
        assert!(output.contains("comprehensive_field"));

        // Verify description processing
        assert!(output.contains("A comprehensive field"));
        assert!(output.contains("This includes multiple paragraphs"));

        // Verify default value (since required=false and has default)
        assert!(output.contains("`[\"default\", \"values\"]`"));
        assert!(!output.contains("**Required**"));
        assert!(!output.contains("*Optional*"));

        // Verify units
        assert!(output.contains("**Units:** milliseconds (range: 100-5000)"));

        // Verify notes with intralink processing
        assert!(output.contains("**Notes:**"));
        assert!(output.contains("- This is the first note with `42`")); // Constant resolved
        assert!(
            output.contains("- This is the second note referencing [test_field](#node-test_field)")
        ); // Intralink

        // Verify deprecation warning
        assert!(output.contains("**⚠️ DEPRECATED:**"));
        assert!(output.contains("Use new_comprehensive_field instead"));

        // Verify TOML example with proper formatting
        assert!(output.contains("**Example:**"));
        assert!(output.contains("<pre><code>"));
        assert!(output.contains("comprehensive_field = ["));
        assert!(output.contains("\"value1\","));
        assert!(output.contains("\"value2\""));
        assert!(output.contains("</code></pre>"));
    }

    #[test]
    fn test_load_section_name_mappings_file_not_found() {
        let result = load_section_name_mappings("nonexistent.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_load_section_name_mappings_invalid_json() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "invalid json content").unwrap();

        let result = load_section_name_mappings(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse section name mappings JSON")
        );
    }

    #[test]
    fn test_load_template_file_not_found() {
        let result = load_template("nonexistent_template.md");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to read template file")
        );
    }

    #[test]
    fn test_render_template_complex_substitutions() {
        let template = "Hello {{name}}! Your score is {{score}}. {{missing}} should stay as is.";
        let mut variables = HashMap::new();
        variables.insert("name".to_string(), "Alice".to_string());
        variables.insert("score".to_string(), "100".to_string());

        let result = render_template(template, variables);
        assert_eq!(
            result,
            "Hello Alice! Your score is 100. {{missing}} should stay as is."
        );
    }

    #[test]
    fn test_render_template_empty_variables() {
        let template = "Template with {{variable}} that won't be replaced";
        let result = render_template(template, HashMap::new());
        assert_eq!(result, "Template with {{variable}} that won't be replaced");
    }

    #[test]
    fn test_render_template_multiple_same_variable() {
        let template = "{{name}} said hello to {{name}} twice";
        let mut variables = HashMap::new();
        variables.insert("name".to_string(), "Bob".to_string());

        let result = render_template(template, variables);
        assert_eq!(result, "Bob said hello to Bob twice");
    }

    #[test]
    fn test_generate_markdown_error_paths() {
        // Test with invalid template path
        let config_docs = create_config_docs(vec![]);
        let custom_mappings = HashMap::new();

        let result = generate_markdown(&config_docs, "nonexistent_template.md", &custom_mappings);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to read template file")
        );
    }

    #[test]
    fn test_escape_markdown_edge_cases() {
        assert_eq!(escape_markdown(""), "");
        assert_eq!(escape_markdown("normal text"), "normal text");
        assert_eq!(escape_markdown("[text]"), "\\[text\\]");
        assert_eq!(escape_markdown("table|cell"), "table\\|cell");
        assert_eq!(escape_markdown("[table|cell]"), "\\[table\\|cell\\]");
    }

    #[test]
    fn test_escape_markdown_table_edge_cases() {
        assert_eq!(escape_markdown_table(""), "");
        assert_eq!(escape_markdown_table("normal text"), "normal text");
        assert_eq!(escape_markdown_table("table|cell"), "table\\|cell");
        assert_eq!(escape_markdown_table("line\nbreak"), "line<br>break");
        assert_eq!(
            escape_markdown_table("both|pipe\nand newline"),
            "both\\|pipe<br>and newline"
        );
    }

    #[test]
    fn test_section_anchor_edge_cases() {
        assert_eq!(section_anchor(""), "#");
        assert_eq!(section_anchor("UPPERCASE"), "#uppercase");
        assert_eq!(
            section_anchor("[complex section name]"),
            "#complex-section-name"
        );
        assert_eq!(section_anchor("Multiple   Spaces"), "#multiple---spaces");
        assert_eq!(
            section_anchor("[section_with_underscores]"),
            "#section_with_underscores"
        );
    }

    #[test]
    fn test_process_reference_edge_cases() {
        let global_context = create_mock_global_context();

        // Test unknown reference
        let result = process_reference("UNKNOWN_CONSTANT", &global_context, "TestStruct");
        assert_eq!(result, "`UNKNOWN_CONSTANT`");

        // Test malformed struct::field reference
        let result = process_reference("OnlyStruct::", &global_context, "TestStruct");
        assert_eq!(result, "`OnlyStruct::`");

        // Test empty reference
        let result = process_reference("", &global_context, "TestStruct");
        assert_eq!(result, "``");
    }

    #[test]
    fn test_struct_to_section_name_edge_cases() {
        let mappings = HashMap::new();

        // Test empty struct name
        assert_eq!(struct_to_section_name("", &mappings), "[]");

        // Test struct name with special characters
        assert_eq!(
            struct_to_section_name("Struct_With_Underscores", &mappings),
            "[struct_with_underscores]"
        );

        // Test very long struct name
        let long_name = "A".repeat(100);
        let expected = format!("[{}]", "a".repeat(100));
        assert_eq!(struct_to_section_name(&long_name, &mappings), expected);
    }
}
