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

use std::net::SocketAddrV4;
use std::ops::RangeInclusive;
use std::time::Duration;

use crate::config::Network;
use rand_core::OsRng;
use slog::slog_debug;
use stacks_common::debug;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks_common::util::hash::Sha256Sum;
use wsts::curve::ecdsa;
use wsts::curve::scalar::Scalar;

fn key_ids_per_signer(signer_id: u32, num_signers: u32, num_keys: u32) -> RangeInclusive<u32> {
    if signer_id >= num_signers {
        panic!("Signer id {signer_id} out of bounds");
    }
    if num_signers > num_keys {
        panic!("More signers than keys.")
    }
    let keys_per_signer = num_keys / num_signers;
    if signer_id + 1 == num_signers {
        (keys_per_signer * signer_id + 1)..=num_keys
    } else {
        (keys_per_signer * signer_id + 1)..=(keys_per_signer * (signer_id + 1))
    }
}

fn scalar_from_seed(seed: &str, index: u32) -> Scalar {
    let array = Sha256Sum::from_data(format!("{index}{}", seed).as_bytes()).0;
    Scalar::from(array)
}

fn signers_array(num_keys: u32, num_signers: u32, seed: &str) -> String {
    let mut signers_array = String::from("signers = [");
    for i in 0..num_signers {
        let ecdsa_private_key = scalar_from_seed(seed, i);
        let ecdsa_public_key = ecdsa::PublicKey::new(&ecdsa_private_key)
            .unwrap()
            .to_string();
        let ids = key_ids_per_signer(i, num_signers, num_keys).collect::<Vec<_>>();
        let ids = ids.as_slice();

        signers_array += &format!(
            r#"
            {{public_key = "{ecdsa_public_key}", key_ids = {ids:?}}}"#
        );

        if i != num_signers - 1 {
            signers_array += ",";
        }
    }
    signers_array += "\n          ]";
    signers_array
}

/// Helper function for building a signer config for each provided signer private key
pub fn build_signer_config_toml(
    signer_stacks_private_key: &StacksPrivateKey,
    num_keys: u32,
    signer_id: u32,
    num_signers: u32,
    node_host: &str,
    stackerdb_contract_id: &str,
    timeout: Option<Duration>,
    observer_socket_addr: SocketAddrV4,
    seed: &str,
    network: Network,
) -> String {
    let signers_array = signers_array(num_keys, num_signers, seed);

    let message_private_key = scalar_from_seed(seed, signer_id);
    let stacks_private_key = signer_stacks_private_key.to_hex();
    let network = match network {
        Network::Mainnet => "mainnet",
        Network::Testnet | Network::Mocknet => "testnet",
    };
    let mut signer_config_toml = format!(
        r#"
message_private_key = "{message_private_key}"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{observer_socket_addr}"
network = "{network}"
stackerdb_contract_id = "{stackerdb_contract_id}"
signer_id = {signer_id}
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
    signer_config_toml
}

/// Helper function for building a signer config for each provided signer private key
pub fn build_signer_config_tomls(
    signer_stacks_private_keys: &[StacksPrivateKey],
    num_keys: u32,
    node_host: &str,
    stackerdb_contract_id: &str,
    timeout: Option<Duration>,
) -> Vec<String> {
    let num_signers = signer_stacks_private_keys.len() as u32;
    let mut rng = OsRng;
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
    let signer_ecdsa_private_keys = (0..num_signers)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();

    let mut signer_config_tomls = vec![];
    let mut signers_array = String::new();
    signers_array += "signers = [";
    for (i, private_key) in signer_ecdsa_private_keys.iter().enumerate() {
        let ecdsa_public_key = ecdsa::PublicKey::new(private_key).unwrap().to_string();
        let ids = key_ids[i].clone();
        signers_array += &format!(
            r#"
            {{public_key = "{ecdsa_public_key}", key_ids = [{ids}]}}
        "#
        );
        if i != signer_ecdsa_private_keys.len() - 1 {
            signers_array += ",";
        }
    }
    signers_array += "]";
    let mut port = 30000;
    for (i, stacks_private_key) in signer_stacks_private_keys.iter().enumerate() {
        let endpoint = format!("localhost:{}", port);
        port += 1;
        let id = i;
        let message_private_key = signer_ecdsa_private_keys[i].to_string();
        let stacks_private_key = stacks_private_key.to_hex();
        let mut signer_config_toml = format!(
            r#"
message_private_key = "{message_private_key}"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{endpoint}"
network = "testnet"
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
    chunk_size: u32,
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
    stackerdb_contract += format!("                chunk-size: u{chunk_size},\n").as_str();
    stackerdb_contract += "                write-freq: u0,\n";
    stackerdb_contract += "                max-writes: u4096,\n";
    stackerdb_contract += "                max-neighbors: u32,\n";
    stackerdb_contract += "                hint-replicas: (list )\n";
    stackerdb_contract += "            }))\n";
    stackerdb_contract += "    ";
    stackerdb_contract
}

#[cfg(test)]
mod test {
    use crate::config::Config;
    use clarity::vm::types::PrincipalData;

    use libsigner::SIGNER_SLOTS_PER_USER;

    use super::*;

    #[test]
    fn build_stackerdb_contract_parses_chunk_size() {
        let address: StacksAddress =
            PrincipalData::parse_standard_principal("SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
                .unwrap()
                .into();

        let contract =
            build_stackerdb_contract(vec![address].as_slice(), SIGNER_SLOTS_PER_USER, 1024);
        assert!(contract.contains("chunk-size: u1024"));
    }

    #[test]
    fn valid_signer_toml() {
        let config = build_signer_config_toml(
            &StacksPrivateKey::new(),
            10,
            0,
            3,
            "127.0.0.1:20443",
            "ST1EMWQSAEZ3VSD5TR9VY5M26E7FA52FWPS6EW59Q.hello-world",
            Some(Duration::from_millis(1000)),
            "127.0.0.1:3000".parse().unwrap(),
            "secret-seed",
            Network::Mocknet,
        );
        Config::load_from_str(config.as_str()).unwrap();
    }

    #[test]
    #[should_panic = "Signer id 1 out of bounds"]
    fn key_ids_per_signer_signer_out_of_bounds() {
        key_ids_per_signer(1, 1, 1);
    }

    #[test]
    #[should_panic = "More signers than keys."]
    fn key_ids_per_signer_signer_without_key() {
        key_ids_per_signer(0, 2, 1);
    }

    #[test]
    fn sane_key_ids_per_signer() {
        assert_eq!(key_ids_per_signer(0, 1, 1), 1..=1);
        assert_eq!(key_ids_per_signer(0, 2, 2), 1..=1);
        assert_eq!(key_ids_per_signer(1, 2, 2), 2..=2);
        assert_eq!(key_ids_per_signer(0, 2, 4), 1..=2);
        assert_eq!(key_ids_per_signer(1, 2, 4), 3..=4);
        assert_eq!(key_ids_per_signer(0, 2, 5), 1..=2);
        assert_eq!(key_ids_per_signer(1, 2, 5), 3..=5);
    }

    #[test]
    fn sane_signers_array() {
        let array = signers_array(5, 2, "seed");
        assert_eq!(
            array,
            r#"signers = [
            {public_key = "26kWKQi79qissWsxUSJPqTtPLMY9qewdw8VTPoNpBBpDJ", key_ids = [1, 2]},
            {public_key = "22YQ9XoDcPxRKMcJGormjPz98VTkpn6ZTRGUywoBjC4A7", key_ids = [3, 4, 5]}
          ]"#
        );
    }
}
