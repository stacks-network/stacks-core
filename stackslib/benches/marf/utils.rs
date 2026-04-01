// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::str::FromStr;

use stacks_common::types::chainstate::{StacksBlockId, TrieHash};

/// Return true if CLI args include `-h` or `--help`.
pub fn has_help_flag(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "-h" || arg == "--help")
}

/// Parse usize env var or return default value.
pub fn parse_usize_env(name: &str, default: usize) -> usize {
    parse_env_or_default(name, default)
}

/// Parse u32 env var or return default value.
pub fn parse_u32_env(name: &str, default: u32) -> u32 {
    parse_env_or_default(name, default)
}

/// Parse comma-separated u32 values from env or return defaults.
pub fn parse_csv_u32_env(name: &str, default: &[u32]) -> Vec<u32> {
    parse_csv_env(name, default, "integer")
}

/// Parse comma-separated usize values from env or return defaults.
pub fn parse_csv_usize_env(name: &str, default: &[usize]) -> Vec<usize> {
    parse_csv_env(name, default, "integer")
}

/// Parse comma-separated string tokens, lowercasing and trimming each entry.
pub fn parse_csv_lowercase_tokens_env(name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(name).ok()?;
    let tokens: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect();

    assert!(!tokens.is_empty(), "{name} must contain at least one value");
    Some(tokens)
}

/// Build a deterministic block id from a numeric seed.
pub fn block_id(seed: u32) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&seed.to_be_bytes());
    StacksBlockId::from(bytes)
}

/// Build a deterministic trie path hash from a one-byte seed.
pub fn path_from_seed(seed: u8) -> TrieHash {
    let bytes: [u8; 32] = std::array::from_fn(|i| seed.wrapping_mul(17).wrapping_add(i as u8));
    TrieHash::from_bytes(&bytes).expect("failed to build trie path")
}

/// Build a deterministic missing-path hash used by insertion tests.
pub fn missing_path_hash() -> TrieHash {
    let bytes: [u8; 32] = std::array::from_fn(|i| 255u8.wrapping_sub(i as u8));
    TrieHash::from_bytes(&bytes).expect("failed to build missing trie path")
}

/// Parse scalar env value with fallback default.
fn parse_env_or_default<T>(name: &str, default: T) -> T
where
    T: FromStr,
{
    parse_env(name).unwrap_or(default)
}

/// Parse scalar env value into target type.
fn parse_env<T>(name: &str) -> Option<T>
where
    T: FromStr,
{
    std::env::var(name).ok().and_then(|s| s.parse::<T>().ok())
}

/// Parse comma-separated env values with validation and fallback.
fn parse_csv_env<T>(name: &str, default: &[T], value_kind: &str) -> Vec<T>
where
    T: FromStr + Clone,
{
    let Some(raw) = std::env::var(name).ok() else {
        return default.to_vec();
    };

    let parsed: Vec<T> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<T>()
                .unwrap_or_else(|_| panic!("invalid {name} {value_kind} entry: '{s}'"))
        })
        .collect();

    assert!(!parsed.is_empty(), "{name} must contain at least one value");
    parsed
}
