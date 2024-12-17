use std::path::Path;
use std::process::Command;
use std::{env, fs};

use toml::Value;

fn current_git_hash() -> Option<String> {
    if option_env!("GIT_COMMIT") == None {
        let commit = Command::new("git")
            .arg("log")
            .arg("-1")
            .arg("--pretty=format:%h") // Abbreviated commit hash
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output();

        if let Ok(commit) = commit {
            if let Ok(commit) = String::from_utf8(commit.stdout) {
                return Some(commit.trim().to_string());
            }
        }
    } else {
        return option_env!("GIT_COMMIT").map(String::from);
    }

    None
}

fn current_git_branch() -> Option<String> {
    if option_env!("GIT_BRANCH") == None {
        let commit = Command::new("git")
            .arg("rev-parse")
            .arg("--abbrev-ref")
            .arg("HEAD")
            .output();
        if let Ok(commit) = commit {
            if let Ok(commit) = String::from_utf8(commit.stdout) {
                return Some(commit.trim().to_string());
            }
        }
    } else {
        return option_env!("GIT_BRANCH").map(String::from);
    }

    None
}

fn is_working_tree_clean() -> bool {
    let status = Command::new("git")
        .arg("diff")
        .arg("--quiet")
        .arg("--exit-code")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status();

    if let Ok(status) = status {
        status.code() == Some(0)
    } else {
        true
    }
}

fn main() {
    let toml_content =
        fs::read_to_string("../versions.toml").expect("Failed to read versions.toml");

    let config: Value = toml::from_str(&toml_content).expect("Failed to parse TOML");

    let mut rust_code = String::from("// Auto-generated code from versions.toml\n\n");

    match config {
        Value::Table(table) => {
            for (key, val) in table {
                match val {
                    Value::String(s) => {
                        let const_value = format!("\"{}\"", s);
                        rust_code.push_str(&format!(
                            "pub const {}: &str = {};\n",
                            key.to_uppercase(),
                            const_value
                        ));
                    }
                    _ => {
                        panic!("Invalid value type in versions.toml: {:?}", val);
                    }
                };
            }
        }
        _ => {
            panic!("Invalid value type in versions.toml: {:?}", config);
        }
    }

    if let Some(git) = current_git_hash() {
        // println!("git commit: {}", git);
        rust_code.push_str(&format!(
            "pub const GIT_COMMIT: Option<&'static str> = Some(\"{}\");\n",
            git
        ));
        println!("cargo:rustc-env=GIT_COMMIT={}", git);
    } else {
        rust_code.push_str(&format!(
            "pub const GIT_COMMIT: Option<&'static str> = None;\n"
        ));
    }
    if let Some(git) = current_git_branch() {
        rust_code.push_str(&format!(
            "pub const GIT_BRANCH: Option<&'static str> = Some(\"{}\");\n",
            git
        ));
        println!("cargo:rustc-env=GIT_BRANCH={}", git);
    } else {
        rust_code.push_str(&format!(
            "pub const GIT_BRANCH: Option<&'static str> = None;\n"
        ));
    }
    if !is_working_tree_clean() {
        rust_code.push_str(&format!(
            "pub const GIT_TREE_CLEAN: Option<&'static str> = Some(\"\");\n"
        ));
        println!("cargo:rustc-env=GIT_TREE_CLEAN=+");
    } else {
        rust_code.push_str(&format!(
            "pub const GIT_TREE_CLEAN: Option<&'static str> = Some(\"+\");\n"
        ));
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("versions.rs");
    fs::write(&dest_path, rust_code).expect("Failed to write generated code");

    // Tell Cargo to rerun this script if the TOML file changes
    println!("cargo:rerun-if-changed=../versions.toml");
}
