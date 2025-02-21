use std::path::Path;
use std::process::Command;
use std::{env, fs};

use toml::Value;

/// Given a [Command], run it and return the output as a string,
/// returning `None` if the command fails.
fn run_git_command(command: &mut Command) -> Option<String> {
    command
        .output()
        .map(|output| String::from_utf8(output.stdout).ok())
        .unwrap_or(None)
        .map(|s| s.trim().to_string())
}

fn current_git_hash() -> Option<String> {
    option_env!("GIT_COMMIT").map(String::from).or_else(|| {
        run_git_command(
            Command::new("git")
                .arg("log")
                .arg("-1")
                .arg("--pretty=format:%h")
                .current_dir(env!("CARGO_MANIFEST_DIR")),
        )
    })
}

fn current_git_branch() -> Option<String> {
    option_env!("GIT_BRANCH").map(String::from).or_else(|| {
        run_git_command(
            Command::new("git")
                .arg("rev-parse")
                .arg("--abbrev-ref")
                .arg("HEAD"),
        )
    })
}

fn is_working_tree_clean() -> bool {
    Command::new("git")
        .arg("diff")
        .arg("--quiet")
        .arg("--exit-code")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .map(|status| status.code() == Some(0))
        .unwrap_or(true)
}

fn main() {
    let toml_file = "../versions.toml";
    let toml_content = fs::read_to_string(toml_file).expect("Failed to read versions.toml");

    let config: Value = toml::from_str(&toml_content).expect("Failed to parse TOML");

    let mut rust_code = String::from("// Auto-generated code from versions.toml\n\n");

    let Value::Table(table) = config else {
        panic!("Invalid value type in versions.toml: {config:?}");
    };
    for (key, val) in table {
        let Value::String(s) = val else {
            panic!("Invalid value type in versions.toml: {val:?}");
        };
        rust_code.push_str(&format!(
            "pub const {}: &str = {s:?};\n",
            key.to_uppercase()
        ));
    }

    let git_commit = current_git_hash();
    rust_code.push_str(&format!(
        "pub const GIT_COMMIT: Option<&'static str> = {git_commit:?};\n",
    ));
    if let Some(git_commit) = git_commit {
        println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    }

    let git_branch = current_git_branch();
    rust_code.push_str(&format!(
        "pub const GIT_BRANCH: Option<&'static str> = {git_branch:?};\n",
    ));
    if let Some(git_branch) = git_branch {
        println!("cargo:rustc-env=GIT_BRANCH={}", git_branch);
    }

    let is_clean = if is_working_tree_clean() { "" } else { "+" };
    rust_code.push_str(&format!(
        "pub const GIT_TREE_CLEAN: Option<&'static str> = Some(\"{}\");\n",
        is_clean
    ));
    println!("cargo:rustc-env=GIT_TREE_CLEAN={}", is_clean);

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("versions.rs");
    fs::write(&dest_path, rust_code).expect("Failed to write generated code");

    // Tell Cargo to rerun this script if the TOML file changes
    println!("cargo:rerun-if-changed={toml_file}");
}
