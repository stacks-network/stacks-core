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

//! Node-config loading: PoX constants, config-TOML overrides, and the
//! minimum-tenure-height policy.

use std::path::Path;

use stacks_common::types::StacksEpochId;
use stackslib::burnchains::PoxConstants;
use stackslib::config::{Config, ConfigFile};

/// Mainnet minimum: the first tenure of epoch 3.4. 3.4 activated at Bitcoin height
/// 943333, but that block had no sortition, so the first 3.4 tenure is 943334.
const MAINNET_MIN_TENURE_HEIGHT: u64 = 943_334;

/// Enforce that `bitcoin_height` selects a tenure in epoch 3.4 or later.
///
/// A squashed snapshot is only usable from epoch 3.4 onwards, and the squash anchors
/// at the selected tenure's first Nakamoto block, so that block must already be in
/// epoch 3.4.
///
/// * Mainnet: [`MAINNET_MIN_TENURE_HEIGHT`].
/// * non-mainnet: epoch 3.4's `start_height`, from the node config TOML.
pub fn enforce_minimum_tenure_height(
    bitcoin_height: u32,
    mainnet: bool,
    config_path: Option<&Path>,
) {
    let bitcoin_height = u64::from(bitcoin_height);
    let min = if mainnet {
        MAINNET_MIN_TENURE_HEIGHT
    } else {
        let config_path = config_path
            .expect("enforce_minimum_tenure_height called for non-mainnet without --config");
        let config_file =
            ConfigFile::from_path(config_path.to_str().unwrap()).unwrap_or_else(|e| {
                eprintln!(
                    "Failed to parse config file '{}': {e}",
                    config_path.display()
                );
                std::process::exit(1);
            });
        let config = Config::from_config_file(config_file, false).unwrap_or_else(|e| {
            eprintln!("Failed to load config '{}': {e}", config_path.display());
            std::process::exit(1);
        });
        let epochs = config.burnchain.get_epoch_list();
        let epoch_34 = epochs.get(StacksEpochId::Epoch34).unwrap_or_else(|| {
            eprintln!(
                "Error: config '{}' does not define epoch 3.4.\n\
                 Epoch 3.4 activation height is required to validate \
                 --tenure-start-bitcoin-height.",
                config_path.display()
            );
            std::process::exit(1);
        });
        if epoch_34.start_height == 0 {
            eprintln!(
                "Error: config '{}' defines epoch 3.4 starting at height 0; \
                 a real network activates 3.4 well after genesis.",
                config_path.display()
            );
            std::process::exit(1);
        }
        epoch_34.start_height
    };

    if bitcoin_height < min {
        eprintln!(
            "Error: --tenure-start-bitcoin-height {bitcoin_height} is below the minimum \
             acceptable height {min}.\n\
             A squashed snapshot can only be used from epoch 3.4 onwards, and the squash \
             anchors at the tenure's first Nakamoto block, so the tenure must start at or \
             after the first tenure of epoch 3.4 (height {min})."
        );
        std::process::exit(1);
    }
}

/// Build PoxConstants. For mainnet the built-in constants are canonical.
/// For any other network, the node config TOML is required because each
/// testnet has its own PoX parameters.
pub fn build_pox_constants(mainnet: bool, config_path: Option<&Path>) -> PoxConstants {
    if mainnet {
        let mut pox = PoxConstants::mainnet_default();
        if let Some(p) = config_path {
            apply_config_overrides(p, &mut pox);
        }
        pox
    } else {
        let config_path = config_path.unwrap_or_else(|| {
            eprintln!(
                "Error: --config is required for non-mainnet networks.\n\
                 Each testnet has its own PoX parameters (reward cycle length, \
                 prepare phase length, etc.) that cannot be inferred from the \
                 database. Pass the node config TOML with --config."
            );
            std::process::exit(1);
        });
        // Start from nakamoto_testnet_default as a baseline, then apply
        // overrides from the config file.
        let mut pox = PoxConstants::nakamoto_testnet_default();
        apply_config_overrides(config_path, &mut pox);
        pox
    }
}

/// Apply PoX overrides from a node config TOML file to the given PoxConstants.
/// Reads the [burnchain] section and applies any pox_reward_length,
/// pox_prepare_length, sunset_start, and sunset_end overrides.
pub fn apply_config_overrides(config_path: &Path, pox: &mut PoxConstants) {
    let config = ConfigFile::from_path(config_path.to_str().unwrap()).unwrap_or_else(|e| {
        eprintln!(
            "Failed to parse config file '{}': {e}",
            config_path.display()
        );
        std::process::exit(1);
    });
    let bc = match config.burnchain {
        Some(bc) => bc,
        None => return,
    };
    if let Some(v) = bc.pox_reward_length {
        eprintln!("Config override: pox_reward_length = {v}");
        pox.reward_cycle_length = v;
    }
    if let Some(v) = bc.pox_prepare_length {
        eprintln!("Config override: pox_prepare_length = {v}");
        pox.prepare_length = v;
    }
    if let Some(v) = bc.sunset_start {
        pox.sunset_start = v as u64;
    }
    if let Some(v) = bc.sunset_end {
        pox.sunset_end = v as u64;
    }
    if let Some(v) = bc.pox_2_activation {
        pox.v1_unlock_height = v;
    }
}
