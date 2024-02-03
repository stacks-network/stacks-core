// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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
use std::time::Duration;

use slog::slog_debug;
use stacks_common::debug;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::types::PrivateKey;
use wsts::curve::ecdsa;
use wsts::curve::scalar::Scalar;

use crate::config::Network;

/// Helper function for building a signer config for each provided signer private key
pub fn build_signer_config_tomls(
    stacks_private_keys: &[StacksPrivateKey],
    num_keys: u32,
    node_host: &str,
    stackerdb_contract_id: &str,
    timeout: Option<Duration>,
    network: &Network,
) -> Vec<String> {
    let num_signers = stacks_private_keys.len() as u32;
    let keys_per_signer = num_keys / num_signers;
    let mut key_id: u32 = 1;
    let mut key_ids = Vec::new();
    for i in 0..num_signers {
        let mut ids = Vec::new();
        for _ in 0..keys_per_signer {
            ids.push(format!("{key_id}"));
            key_id += 1;
        }
        if i + 1 == num_signers {
            for _ in 0..num_keys % num_signers {
                // We have requested a number of keys that cannot fit evenly into the number of signers
                // Append the remaining keys to the last signer
                ids.push(format!("{key_id}"));
                key_id += 1;
                debug!("Appending extra key to last signer...");
            }
        }
        key_ids.push(ids.join(", "));
    }

    let mut signer_config_tomls = vec![];
    let mut signers_array = String::new();

    signers_array += "signers = [";
    for (i, stacks_private_key) in stacks_private_keys.iter().enumerate() {
        let scalar = Scalar::try_from(&stacks_private_key.to_bytes()[..32])
            .expect("BUG: failed to convert the StacksPrivateKey to a Scalar");
        let ecdsa_public_key = ecdsa::PublicKey::new(&scalar)
            .expect("BUG: failed to get a ecdsa::PublicKey from the provided Scalar")
            .to_string();
        let ids = key_ids[i].clone();
        signers_array += &format!(
            r#"
    {{public_key = "{ecdsa_public_key}", key_ids = [{ids}]}}"#
        );
        if i != stacks_private_keys.len() - 1 {
            signers_array += ",";
        }
    }
    signers_array += "\n]";

    let mut port = 30000;
    for (i, stacks_private_key) in stacks_private_keys.iter().enumerate() {
        let endpoint = format!("localhost:{}", port);
        port += 1;
        let id = i;
        let stacks_private_key = stacks_private_key.to_hex();
        let mut signer_config_toml = format!(
            r#"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{endpoint}"
network = "{network}"
stackerdb_contract_id = "{stackerdb_contract_id}"
signer_id = {id}
{signers_array}
"#
        );

        if let Some(timeout) = timeout {
            let event_timeout_ms = timeout.as_millis();
            signer_config_toml = format!(
                r#"
{signer_config_toml}
event_timeout = {event_timeout_ms}   
"#
            )
        }

        signer_config_tomls.push(signer_config_toml);
    }

    signer_config_tomls
}

/// Helper function for building a stackerdb contract from the provided signer stacks addresses
pub fn build_stackerdb_contract(
    signer_stacks_addresses: &[StacksAddress],
    slots_per_user: u32,
) -> String {
    let mut stackerdb_contract = String::new(); // "
    stackerdb_contract += "        ;; stacker DB\n";
    stackerdb_contract += "        (define-read-only (stackerdb-get-signer-slots)\n";
    stackerdb_contract += "            (ok (list\n";
    for signer_stacks_address in signer_stacks_addresses {
        stackerdb_contract += "                {\n";
        stackerdb_contract +=
            format!("                    signer: '{},\n", signer_stacks_address).as_str();
        stackerdb_contract +=
            format!("                    num-slots: u{}\n", slots_per_user).as_str();
        stackerdb_contract += "                }\n";
    }
    stackerdb_contract += "                )))\n";
    stackerdb_contract += "\n";
    stackerdb_contract += "        (define-read-only (stackerdb-get-config)\n";
    stackerdb_contract += "            (ok {\n";
    stackerdb_contract += "                chunk-size: u4096,\n";
    stackerdb_contract += "                write-freq: u0,\n";
    stackerdb_contract += "                max-writes: u4096,\n";
    stackerdb_contract += "                max-neighbors: u32,\n";
    stackerdb_contract += "                hint-replicas: (list )\n";
    stackerdb_contract += "            }))\n";
    stackerdb_contract += "    ";
    stackerdb_contract
}

/// Helper function to convert a private key to a Stacks address
pub fn to_addr(stacks_private_key: &StacksPrivateKey, network: &Network) -> StacksAddress {
    StacksAddress::p2pkh(
        network.is_mainnet(),
        &StacksPublicKey::from_private(stacks_private_key),
    )
}
