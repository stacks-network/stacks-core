use p256k1::ecdsa;
use rand_core::OsRng;
use slog::slog_debug;
use stacks_common::{
    debug,
    types::chainstate::{StacksAddress, StacksPrivateKey},
};
use wsts::Scalar;

use crate::stacks_client::SLOTS_PER_USER;

/// Helper function for building a signer config for each provided signer private key
pub fn build_signer_config_tomls(
    signer_stacks_private_keys: &[StacksPrivateKey],
    num_keys: u32,
    node_host: &str,
    contract_id: &str,
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
        let signer_config_toml = format!(
            r#"
message_private_key = "{message_private_key}"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{endpoint}"
network = "testnet"
stackerdb_contract_id = "{contract_id}"
signer_id = {id}
{signers_array}
"#
        );
        signer_config_tomls.push(signer_config_toml);
    }
    signer_config_tomls
}

/// Helper function for building a stackerdb contract from the provided signer stacks addresses
pub fn build_stackerdb_contract(signer_stacks_addresses: &[StacksAddress]) -> String {
    let mut stackerdb_contract = String::new(); // "
    stackerdb_contract += "        ;; stacker DB\n";
    stackerdb_contract += "        (define-read-only (stackerdb-get-signer-slots)\n";
    stackerdb_contract += "            (ok (list\n";
    for signer_stacks_address in signer_stacks_addresses {
        stackerdb_contract += "                {\n";
        stackerdb_contract +=
            format!("                    signer: '{},\n", signer_stacks_address).as_str();
        stackerdb_contract +=
            format!("                    num-slots: u{}\n", SLOTS_PER_USER).as_str();
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
