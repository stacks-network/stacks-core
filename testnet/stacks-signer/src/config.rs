use serde::Deserialize;
use std::fs;
use toml;

#[derive(Clone, Deserialize, Default, Debug)]
pub struct Config {}

impl Config {
    pub fn from_file(path: &str) -> Result<Config, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Invalid path: {}", &e))?;
        Self::from_str(&content)
    }
    pub fn from_str(content: &str) -> Result<Config, String> {
        let config: Config = toml::from_str(content).map_err(|e| format!("Invalid toml: {}", e))?;
        Ok(config)
    }
}
