use std::path::Path;
use std::{env, fs};

use toml::Value;

fn main() {
    let toml_content =
        fs::read_to_string("../versions.toml").expect("Failed to read versions.toml");

    let config: Value = toml::from_str(&toml_content).expect("Failed to parse TOML");

    let mut rust_code = String::from("// Auto-generated code from versions.toml\n\n");

    fn generate_constants(value: &Value, prefix: &str, code: &mut String) {
        match value {
            Value::Table(table) => {
                for (key, val) in table {
                    let new_prefix = if prefix.is_empty() {
                        key.to_string()
                    } else {
                        format!("{}_{}", prefix, key)
                    };
                    generate_constants(val, &new_prefix, code);
                }
            }
            Value::Array(arr) => {
                code.push_str(&format!(
                    "pub const {}: &[&str] = &[{}];\n",
                    prefix.to_uppercase(),
                    arr.iter()
                        .map(|v| format!("\"{}\"", v.as_str().unwrap_or("")))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            _ => {
                let const_value = match value {
                    Value::String(s) => format!("\"{}\"", s),
                    Value::Integer(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Boolean(b) => b.to_string(),
                    _ => "\"\"".to_string(),
                };
                code.push_str(&format!(
                    "pub const {}: {} = {};\n",
                    prefix.to_uppercase(),
                    if value.is_str() {
                        "&str"
                    } else if value.is_integer() {
                        "i64"
                    } else if value.is_float() {
                        "f64"
                    } else if value.is_bool() {
                        "bool"
                    } else {
                        "&str"
                    },
                    const_value
                ));
            }
        }
    }

    generate_constants(&config, "", &mut rust_code);

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("versions.rs");
    fs::write(&dest_path, rust_code).expect("Failed to write generated code");

    // Tell Cargo to rerun this script if the TOML file changes
    println!("cargo:rerun-if-changed=../versions.toml");
}
