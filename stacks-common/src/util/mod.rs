// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

#[macro_use]
pub mod log;
#[macro_use]
pub mod macros;
pub mod chunked_encoding;
#[cfg(feature = "rusqlite")]
pub mod db;
pub mod hash;
pub mod lru_cache;
pub mod pair;
pub mod pipe;
pub mod retry;
pub mod secp256k1;
pub mod serde_serializers;
pub mod uint;
pub mod vrf;

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::time::{self, SystemTime, UNIX_EPOCH};
use std::{error, fmt, thread};

/// Given a relative path inside the Cargo workspace, return the absolute path
#[cfg(any(test, feature = "testing"))]
pub fn cargo_workspace<P>(relative_path: P) -> std::path::PathBuf
where
    P: AsRef<Path>,
{
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .expect("Failed to run command");
    let cargo_toml = std::str::from_utf8(&output.stdout)
        .expect("Failed to parse utf8")
        .trim();
    Path::new(cargo_toml)
        .parent()
        .expect("Failed to get parent directory")
        .join(relative_path)
}

#[cfg(any(test, feature = "testing"))]
pub mod tests;

pub fn get_epoch_time_secs() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs()
}

pub fn get_epoch_time_ms() -> u128 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_millis()
}

#[cfg(any(test, feature = "testing"))]
pub fn get_epoch_time_nanos() -> u128 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_nanos()
}

pub fn sleep_ms(millis: u64) {
    let t = time::Duration::from_millis(millis);
    thread::sleep(t);
}

/// Hex deserialization error
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HexError {
    /// Length was not 64 characters
    BadLength(usize),
    /// Non-hex character in string
    BadCharacter(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HexError::BadLength(n) => write!(f, "bad length {n} for hex string"),
            HexError::BadCharacter(c) => write!(f, "bad character {c} for hex string"),
        }
    }
}

impl error::Error for HexError {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
    fn description(&self) -> &str {
        match *self {
            HexError::BadLength(_) => "hex string non-64 length",
            HexError::BadCharacter(_) => "bad hex character",
        }
    }
}

pub trait HexDeser: Sized {
    fn try_from_hex(hex: &str) -> Result<Self, HexError>;
}

/// Write any `serde_json` object directly to a file
pub fn serialize_json_to_file<J, P>(json: &J, path: P) -> Result<(), std::io::Error>
where
    J: ?Sized + serde::Serialize,
    P: AsRef<Path>,
{
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, json)?;
    writer.flush()
}

/// Read any `serde_json` object directly from a file
pub fn deserialize_json_from_file<J, P>(path: P) -> Result<J, std::io::Error>
where
    J: serde::de::DeserializeOwned,
    P: AsRef<Path>,
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    serde_json::from_reader::<_, J>(reader).map_err(std::io::Error::from)
}
#[cfg(all(feature = "rusqlite", target_family = "wasm"))]
compile_error!("The `rusqlite` feature is not supported for wasm targets");

// The threshold of weighted votes to reach consensus in Nakamoto.
// This is out of 100, so 70 means "70%".
pub const NAKAMOTO_SIGNER_APPROVAL_THRESHOLD: u32 = 70;

/// Determines the signer approval threshold percentage for Nakamoto block approval.
///
/// By default, this uses the constant [`NAKAMOTO_SIGNER_APPROVAL_THRESHOLD`].
/// If the `SIGNER_APPROVAL_THRESHOLD` environment variable is set, its value (in percent)
/// will be used instead—unless `mainnet` is `true`, in which case overriding via the
/// environment variable is not allowed.
///
/// The environment variable value must be an integer between 1 and 100 (inclusive).
///
/// # Panics
/// - If `mainnet` is `true` and `SIGNER_APPROVAL_THRESHOLD` is set.
/// - If `SIGNER_APPROVAL_THRESHOLD` cannot be parsed as a `u32`.
/// - If the parsed threshold is not in the range `1..=100`.
///
/// # Parameters
/// - `mainnet`: Whether the network is Mainnet.
///
/// # Returns
/// The approval threshold percentage as a `u32`.
pub fn determine_signer_approval_threshold_percentage(mainnet: bool) -> u32 {
    let mut threshold = NAKAMOTO_SIGNER_APPROVAL_THRESHOLD;
    if let Ok(env_threshold) = std::env::var("SIGNER_APPROVAL_THRESHOLD") {
        assert!(
            !mainnet,
            "Cannot use SIGNER_APPROVAL_THRESHOLD env variable with Mainnet."
        );
        match env_threshold.parse::<u32>() {
            Ok(env_threshold) => {
                assert!(
                    env_threshold > 0 && env_threshold <= 100,
                    "Invalid SIGNER_APPROVAL_THRESHOLD. Must be > 0 and <= 100"
                );
                threshold = env_threshold;
            }
            Err(e) => panic!("Failed to parse SIGNER_APPROVAL_THRESHOLD as a u32: {e}"),
        }
    }
    threshold
}

/// Computes the minimum voting weight required to reach consensus.
///
/// The threshold is determined as a percentage of `total_weight`, using
/// [`determine_signer_approval_threshold_percentage`]. The percentage is
/// applied, and any remainder from integer division is rounded up by adding 1
/// if there is a non-zero remainder.
///
/// # Parameters
/// - `total_weight`: The total combined voting weight of all signers.
/// - `mainnet`: Whether the network is Mainnet (affects threshold calculation).
///
/// # Returns
/// The minimum voting weight (rounded up) required for consensus.
pub fn compute_voting_weight_threshold(total_weight: u32, mainnet: bool) -> u32 {
    let threshold = determine_signer_approval_threshold_percentage(mainnet);
    let ceil = if (total_weight * threshold) % 100 == 0 {
        0
    } else {
        1
    };
    (total_weight * threshold / 100).saturating_add(ceil)
}

#[test]
pub fn test_compute_voting_weight_threshold_no_env() {
    // We are purposefully testing ONLY compute_voting_weight_threshold without SIGNER_APPROVAL_THRESHOLD
    // see following tests for env SIGNER_APPROVAL_THRESHOLD specific tests.
    use crate::util::compute_voting_weight_threshold;
    std::env::remove_var("SIGNER_APPROVAL_THRESHOLD");
    assert_eq!(compute_voting_weight_threshold(100_u32, false), 70_u32,);

    assert_eq!(compute_voting_weight_threshold(10_u32, false), 7_u32,);

    assert_eq!(compute_voting_weight_threshold(3000_u32, false), 2100_u32,);

    assert_eq!(compute_voting_weight_threshold(4000_u32, false), 2800_u32,);

    // Round-up check
    assert_eq!(compute_voting_weight_threshold(511_u32, false), 358_u32,);
}

#[test]
#[serial_test::serial]
fn returns_default_when_env_not_set() {
    std::env::remove_var("SIGNER_APPROVAL_THRESHOLD");
    let result = determine_signer_approval_threshold_percentage(false);
    assert_eq!(result, 70);
}

#[test]
#[serial_test::serial]
fn uses_env_when_not_mainnet() {
    std::env::set_var("SIGNER_APPROVAL_THRESHOLD", "75");
    let result = determine_signer_approval_threshold_percentage(false);
    assert_eq!(result, 75);
}

#[test]
#[serial_test::serial]
#[should_panic(expected = "Cannot use SIGNER_APPROVAL_THRESHOLD env variable with Mainnet")]
fn panics_if_env_set_on_mainnet() {
    std::env::set_var("SIGNER_APPROVAL_THRESHOLD", "50");
    let _ = determine_signer_approval_threshold_percentage(true);
}

#[test]
#[serial_test::serial]
#[should_panic(expected = "Failed to parse SIGNER_APPROVAL_THRESHOLD as a u32")]
fn panics_if_env_not_u32() {
    std::env::set_var("SIGNER_APPROVAL_THRESHOLD", "not-a-number");
    let _ = determine_signer_approval_threshold_percentage(false);
}

#[test]
#[serial_test::serial]
#[should_panic(expected = "Invalid SIGNER_APPROVAL_THRESHOLD. Must be > 0 and <= 100")]
fn panics_if_env_is_zero() {
    std::env::set_var("SIGNER_APPROVAL_THRESHOLD", "0");
    let _ = determine_signer_approval_threshold_percentage(false);
}

#[test]
#[serial_test::serial]
#[should_panic(expected = "Invalid SIGNER_APPROVAL_THRESHOLD. Must be > 0 and <= 100")]
fn panics_if_env_over_100() {
    std::env::set_var("SIGNER_APPROVAL_THRESHOLD", "101");
    let _ = determine_signer_approval_threshold_percentage(false);
}
