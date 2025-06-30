use std::fs;

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;

#[test]
fn test_extract_docs_missing_arguments() {
    let mut cmd = Command::cargo_bin("extract-docs").unwrap();
    let output = cmd.output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required arguments were not provided"));
}

#[test]
fn test_extract_docs_help() {
    let mut cmd = Command::cargo_bin("extract-docs").unwrap();
    cmd.arg("--help");
    let output = cmd.output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Extract documentation from Rust source code"));
}

#[test]
fn test_extract_docs_invalid_package() {
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("output.json");

    let mut cmd = Command::cargo_bin("extract-docs").unwrap();
    cmd.args([
        "--package",
        "nonexistent-package",
        "--output",
        output_file.to_str().unwrap(),
        "--structs",
        "TestStruct",
    ]);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cargo rustdoc failed"));
}

#[test]
fn test_generate_markdown_missing_arguments() {
    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    let output = cmd.output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required arguments were not provided"));
}

#[test]
fn test_generate_markdown_help() {
    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.arg("--help");
    let output = cmd.output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Generate Markdown documentation"));
}

#[test]
fn test_generate_markdown_missing_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create valid template and mappings files
    fs::write(
        &template_file,
        "# Test\n{{toc_content}}\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, "{}").unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        "nonexistent.json",
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to read input JSON file"));
}

#[test]
fn test_generate_markdown_invalid_input_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create invalid JSON input
    fs::write(&input_file, "invalid json").unwrap();
    fs::write(
        &template_file,
        "# Test\n{{toc_content}}\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, "{}").unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to parse input JSON"));
}

#[test]
fn test_generate_markdown_missing_template_file() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create valid input and mappings
    let config_docs = json!({
        "structs": [],
        "referenced_constants": {}
    });
    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(&mappings_file, "{}").unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        "nonexistent_template.md",
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to read template file"));
}

#[test]
fn test_generate_markdown_invalid_mappings_json() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create valid input and template, invalid mappings
    let config_docs = json!({
        "structs": [],
        "referenced_constants": {}
    });
    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# Test\n{{toc_content}}\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, "invalid json").unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to parse section name mappings JSON"));
}

#[test]
fn test_generate_markdown_successful_execution() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create valid test data
    let config_docs = json!({
        "structs": [{
            "name": "TestStruct",
            "description": "A test configuration struct",
            "fields": [{
                "name": "test_field",
                "description": "A test field",
                "default_value": "`42`",
                "notes": null,
                "deprecated": null,
                "toml_example": null,
                "required": null,
                "units": null
            }]
        }],
        "referenced_constants": {}
    });

    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# Configuration Reference\n\n{{toc_content}}\n\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, r#"{"TestStruct": "[test]"}"#).unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Successfully generated Markdown documentation"));

    // Verify output file was created and contains expected content
    let output_content = fs::read_to_string(&output_file).unwrap();
    assert!(output_content.contains("Configuration Reference"));
    assert!(output_content.contains("[test]"));
    assert!(output_content.contains("test_field"));
    assert!(output_content.contains("A test field"));
}

#[test]
fn test_generate_markdown_file_write_permission_error() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create valid input files
    let config_docs = json!({
        "structs": [],
        "referenced_constants": {}
    });
    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# Test\n{{toc_content}}\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, "{}").unwrap();

    // Try to write to a directory that doesn't exist (should fail)
    let invalid_output = "/nonexistent/path/output.md";

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        invalid_output,
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to write output file"));
}

// New comprehensive integration tests using real fixture data

#[test]
fn test_generate_markdown_with_real_fixture_data() {
    let temp_dir = TempDir::new().unwrap();
    let output_file = temp_dir.path().join("output.md");

    // Use the fixture files we created
    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        "tests/fixtures/minimal_config.json",
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        "tests/fixtures/test_template.md",
        "--section-name-mappings",
        "tests/fixtures/test_mappings.json",
    ]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Successfully generated Markdown documentation"));

    // Verify output file was created and contains expected realistic content
    let output_content = fs::read_to_string(&output_file).unwrap();
    assert!(output_content.contains("Test Configuration Reference"));
    assert!(output_content.contains("[node]"));
    assert!(output_content.contains("Configuration settings for a Stacks node"));
    assert!(output_content.contains("seed"));
    assert!(output_content.contains("rpc_bind"));
    assert!(output_content.contains("MinerConfig::mining_key"));
    assert!(output_content.contains("DEPRECATED"));
    assert!(output_content.contains("Units"));
    assert!(output_content.contains("milliseconds"));
    assert!(output_content.contains("Example:"));
    assert!(output_content.contains("bootstrap_node"));
}

#[test]
fn test_generate_markdown_with_complex_field_features() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create test data with all field features
    let config_docs = json!({
        "structs": [{
            "name": "ComplexStruct",
            "description": "A struct with all possible field features",
            "fields": [
                {
                    "name": "basic_field",
                    "description": "A basic field with description",
                    "default_value": "`42`",
                    "notes": null,
                    "deprecated": null,
                    "toml_example": null,
                    "required": null,
                    "units": null
                },
                {
                    "name": "field_with_notes",
                    "description": "A field with multiple notes",
                    "default_value": "`\"default\"`",
                    "notes": [
                        "First note about this field",
                        "Second note with more details"
                    ],
                    "deprecated": null,
                    "toml_example": null,
                    "required": null,
                    "units": null
                },
                {
                    "name": "deprecated_field",
                    "description": "A deprecated field",
                    "default_value": "`false`",
                    "notes": null,
                    "deprecated": "This field is deprecated since version 2.0",
                    "toml_example": null,
                    "required": null,
                    "units": null
                },
                {
                    "name": "field_with_toml_example",
                    "description": "A field with TOML example",
                    "default_value": "`{}`",
                    "notes": null,
                    "deprecated": null,
                    "toml_example": "field_with_toml_example = { key = \"value\", number = 123 }",
                    "required": null,
                    "units": null
                },
                {
                    "name": "required_field",
                    "description": "A required field",
                    "default_value": null,
                    "notes": null,
                    "deprecated": null,
                    "toml_example": null,
                    "required": true,
                    "units": null
                },
                {
                    "name": "field_with_units",
                    "description": "A field with units",
                    "default_value": "`30_000`",
                    "notes": null,
                    "deprecated": null,
                    "toml_example": null,
                    "required": null,
                    "units": "milliseconds"
                }
            ]
        }],
        "referenced_constants": {}
    });

    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# Complex Test\n\n{{toc_content}}\n\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, r#"{}"#).unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Successfully generated Markdown documentation"));

    // Verify all field features are properly rendered
    let output_content = fs::read_to_string(&output_file).unwrap();
    assert!(output_content.contains("Complex Test"));
    assert!(output_content.contains("[complexstruct]"));
    assert!(output_content.contains("basic_field"));
    assert!(output_content.contains("field_with_notes"));
    assert!(output_content.contains("First note about this field"));
    assert!(output_content.contains("Second note with more details"));
    assert!(output_content.contains("deprecated_field"));
    assert!(output_content.contains("**⚠️ DEPRECATED:**"));
    assert!(output_content.contains("deprecated since version 2.0"));
    assert!(output_content.contains("field_with_toml_example"));
    assert!(output_content.contains("required_field"));
    assert!(output_content.contains("**Required**"));
    assert!(output_content.contains("field_with_units"));
    assert!(output_content.contains("milliseconds"));
}

#[test]
fn test_generate_markdown_with_constant_references() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create test data with constant references
    let config_docs = json!({
        "structs": [{
            "name": "ConfigWithConstants",
            "description": "A struct with constant references",
            "fields": [{
                "name": "timeout",
                "description": "Connection timeout using [`DEFAULT_TIMEOUT`] constant",
                "default_value": "[`DEFAULT_TIMEOUT`]",
                "notes": ["See [`MAX_RETRIES`] for retry logic"],
                "deprecated": null,
                "toml_example": null,
                "required": null,
                "units": "seconds"
            }]
        }],
        "referenced_constants": {
            "DEFAULT_TIMEOUT": "30",
            "MAX_RETRIES": "3"
        }
    });

    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# Constants Test\n\n{{toc_content}}\n\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, r#"{}"#).unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Successfully generated Markdown documentation"));

    // Verify constant references are properly processed
    let output_content = fs::read_to_string(&output_file).unwrap();
    assert!(output_content.contains("Constants Test"));
    assert!(output_content.contains("[configwithconstants]"));
    assert!(output_content.contains("timeout"));
    assert!(output_content.contains("30")); // DEFAULT_TIMEOUT resolved
    assert!(output_content.contains("3")); // MAX_RETRIES resolved
}

#[test]
fn test_generate_markdown_empty_struct_description() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create test data with null struct description
    let config_docs = json!({
        "structs": [{
            "name": "NoDescStruct",
            "description": null,
            "fields": [{
                "name": "field",
                "description": "A field in a struct with no description",
                "default_value": "`value`",
                "notes": null,
                "deprecated": null,
                "toml_example": null,
                "required": null,
                "units": null
            }]
        }],
        "referenced_constants": {}
    });

    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# No Description Test\n\n{{toc_content}}\n\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, r#"{}"#).unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Successfully generated Markdown documentation"));

    // Verify struct with null description is handled properly
    let output_content = fs::read_to_string(&output_file).unwrap();
    assert!(output_content.contains("No Description Test"));
    assert!(output_content.contains("[nodescstruct]"));
    assert!(output_content.contains("field"));
}

#[test]
fn test_generate_markdown_multiple_structs() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let output_file = temp_dir.path().join("output.md");
    let template_file = temp_dir.path().join("template.md");
    let mappings_file = temp_dir.path().join("mappings.json");

    // Create test data with multiple structs
    let config_docs = json!({
        "structs": [
            {
                "name": "FirstStruct",
                "description": "The first configuration struct",
                "fields": [{
                    "name": "first_field",
                    "description": "Field in first struct",
                    "default_value": "`1`",
                    "notes": null,
                    "deprecated": null,
                    "toml_example": null,
                    "required": null,
                    "units": null
                }]
            },
            {
                "name": "SecondStruct",
                "description": "The second configuration struct",
                "fields": [{
                    "name": "second_field",
                    "description": "Field in second struct",
                    "default_value": "`2`",
                    "notes": null,
                    "deprecated": null,
                    "toml_example": null,
                    "required": null,
                    "units": null
                }]
            }
        ],
        "referenced_constants": {}
    });

    fs::write(
        &input_file,
        serde_json::to_string_pretty(&config_docs).unwrap(),
    )
    .unwrap();
    fs::write(
        &template_file,
        "# Multiple Structs Test\n\n{{toc_content}}\n\n{{struct_sections}}",
    )
    .unwrap();
    fs::write(&mappings_file, r#"{}"#).unwrap();

    let mut cmd = Command::cargo_bin("generate-markdown").unwrap();
    cmd.args([
        "--input",
        input_file.to_str().unwrap(),
        "--output",
        output_file.to_str().unwrap(),
        "--template",
        template_file.to_str().unwrap(),
        "--section-name-mappings",
        mappings_file.to_str().unwrap(),
    ]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Successfully generated Markdown documentation"));

    // Verify both structs are properly rendered
    let output_content = fs::read_to_string(&output_file).unwrap();
    assert!(output_content.contains("Multiple Structs Test"));
    assert!(output_content.contains("[firststruct]"));
    assert!(output_content.contains("[secondstruct]"));
    assert!(output_content.contains("first_field"));
    assert!(output_content.contains("second_field"));
    assert!(output_content.contains("The first configuration struct"));
    assert!(output_content.contains("The second configuration struct"));
}
