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

//! Ping utils
use std::fs::File;
use std::io::Read;
use std::io::Write as WriteT;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use crate::cli::parse_contract;
use crate::cli::StackerDBArgs;
use crate::client::{ClientError, StacksClient};
use crate::utils::build_signer_config_toml;
use crate::{config::Network, utils::build_stackerdb_contract};
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::StacksTransactionSigner;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::{
    chainstate::stacks::{TransactionPayload, TransactionSmartContract},
    util_lib::strings::StacksString,
};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use clarity::vm::ContractName;
use libsigner::SIGNER_SLOTS_PER_USER;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use stacks_common::{
    address::AddressHashMode,
    types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey},
};
use stacks_node::{ConfigFile, EventObserverConfigFile};

#[derive(clap::Subcommand, Debug)]

/// Ping subcommands
pub enum PingSubcommands {
    /// Generate a simple stackerDB contract.
    /// This command can be used to generate a simple stackerDB contract.
    /// A shared seed can be used to generate keys deterministically.
    /// DO NOT USE this in production.
    /// Don't hold funds on this accounts. Anyone with the shared seed can deterministically generate the signer's secret keys.
    GenerateContract(GenerateContractArgs),
    /// Publish a stackerDB contract,
    PublishContract(PublishContractArgs),
    /// This command can be used to generate a signer.toml used by a signer runloop.
    GenerateSignerConfig(GenerateSignerConfigArgs),
    /// Add an observer and a stackerdb replica to the node's config.
    ExtendNodeConfig(ExtendNodeConfigArgs),
}

impl PingSubcommands {
    /// Handle any subcommand
    pub fn handle(&self) {
        match self {
            PingSubcommands::GenerateContract(args) => args.handle(),
            PingSubcommands::PublishContract(args) => args.handle(),
            PingSubcommands::GenerateSignerConfig(args) => args.handle(),
            PingSubcommands::ExtendNodeConfig(args) => args.handle(),
        }
    }
}

#[derive(clap::Args, Debug)]
/// You can provide either existing [signers] addresses or generate new ones based on a [seed]
/// and the specified number of signers [num_signers].
pub struct GenerateContractArgs {
    // output file e.g. ./stackerDB.clar
    save_to_file: PathBuf,
    #[clap(value_parser = PrincipalData::parse_standard_principal, long, value_delimiter= ',',conflicts_with_all=["seed","num_signers","network"])]
    /// A list of signers' addresses e.g. SP2E7G2V8QAJ9KS1DMHYNMBWFWY2EHGGYTGRTH12B,SP1NHW9S3XP1937EX5WTJSF599YPZRB0H85W1WCP0
    signers: Vec<StandardPrincipalData>,
    /// chunk-size for the contract
    #[clap(short, long, default_value = "4096")]
    chunk_size: u32,
    #[clap(long, requires_all = ["num_signers","network"])]
    seed: Option<String>,
    #[clap(long, requires_all = ["seed","network"])]
    num_signers: Option<u32>,
    #[clap(long, requires_all = ["seed","num_signers"])]
    network: Option<Network>,
}

impl GenerateContractArgs {
    fn handle(&self) {
        let mut file = File::create(&self.save_to_file).unwrap();
        let addresses: Vec<StacksAddress> =
        // Use the signers provided
        if !self.signers.is_empty() {
            self.signers
                .clone()
                .into_iter()
                .map(StacksAddress::from)
                .collect()
        } else
        //generate new signers from a seed, expect all signers' conflicting options to be Some()
        {
            (0..self.num_signers.unwrap()).map(|i|
            to_stacks_address(self.network.as_ref().unwrap(), &private_key_from_seed(self.seed.as_ref().unwrap(), i))
            ).collect()
        };

        let contract =
            build_stackerdb_contract(addresses.as_slice(), SIGNER_SLOTS_PER_USER, self.chunk_size);
        file.write_all(contract.as_bytes()).unwrap();
        println!("New stackerdb contract written to {:?}", self.save_to_file);
    }
}

fn to_stacks_address(network: &Network, pkey: &StacksPrivateKey) -> StacksAddress {
    let address_version = network.to_address_version();
    StacksAddress::from_public_keys(
        address_version,
        &AddressHashMode::from_version(address_version),
        1,
        &vec![StacksPublicKey::from_private(pkey)],
    )
    .unwrap()
}

fn private_key_from_seed(seed: &str, signer_id: u32) -> StacksPrivateKey {
    StacksPrivateKey::from_seed(format!("{signer_id}{}", seed).as_bytes())
}

#[derive(clap::Args, Debug)]
/// Once you have generated a contract, publish it.
pub struct PublishContractArgs {
    #[clap(long)]
    source_file: PathBuf,
    #[clap(long, short)]
    contract_name: String,
    #[clap(value_enum, long)]
    network: Network,
    #[clap(long, short)]
    stacks_private_key: String,
    #[clap(long, short)]
    nonce: u64,
    #[clap(long, short)]
    fee: u64,
    #[clap(long)]
    /// e.g. http://localhost:20443
    host: String,
}

impl PublishContractArgs {
    fn handle(&self) {
        let pkey = StacksPrivateKey::from_hex(&self.stacks_private_key).unwrap();
        let contract_name = ContractName::try_from(self.contract_name.clone()).unwrap();

        let tx = {
            let payload = {
                let code_body = {
                    let mut contract = String::new();
                    File::open(&self.source_file)
                        .unwrap()
                        .read_to_string(&mut contract)
                        .unwrap();

                    StacksString::from_str(contract.as_str()).unwrap()
                };

                TransactionPayload::SmartContract(
                    TransactionSmartContract {
                        name: contract_name.clone(),
                        code_body,
                    },
                    None,
                )
            };

            let auth = {
                let mut auth = TransactionAuth::from_p2pkh(&pkey).unwrap();
                auth.set_origin_nonce(self.nonce);
                auth.set_tx_fee(self.fee);
                auth
            };

            let mut unsinged_tx =
                StacksTransaction::new(self.network.to_transaction_version(), auth, payload);
            unsinged_tx.chain_id = self.network.to_chain_id();
            unsinged_tx.post_condition_mode = TransactionPostConditionMode::Allow;
            unsinged_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

            let mut signer = StacksTransactionSigner::new(&unsinged_tx);

            signer.sign_origin(&pkey).unwrap();
            signer.get_tx().unwrap()
        };

        let client = Client::new();

        let tx_id = StacksClient::submit_tx(&tx, &client, &self.host).unwrap();

        let principal = {
            let address = to_stacks_address(&self.network, &pkey);
            StandardPrincipalData::from(address)
        };

        println!("Waiting on tx:{tx_id:?}");

        while matches!(
            StacksClient::get_contract_source(
                &self.host,
                &principal.clone(),
                &self.contract_name,
                &client,
            )
            .map(|_| {
                println!(
                    "Contract {} published successfully",
                    QualifiedContractIdentifier::new(principal.clone(), contract_name.clone())
                )
            }),
            Err(ClientError::RequestFailure(StatusCode::NOT_FOUND))
        ) {
            thread::sleep(Duration::from_millis(500));
        }
    }
}

#[derive(clap::Args, Debug)]
/// Generate testing signer configs
pub struct GenerateSignerConfigArgs {
    /// output file e.g. ./signer.toml
    #[clap(long)]
    save_to_file: PathBuf,
    #[clap(short, long)]
    seed: String,
    #[clap(long)]
    signer_id: u32,
    #[clap(short, long)]
    network: Network,
    #[clap(flatten)]
    stacker_db_args: StackerDBArgs,
    #[clap(short, long)]
    /// to what socket address is the observer binding. e.g. 127.0.0.1:3000
    observer_socket_address: SocketAddrV4,
    #[clap(long)]
    num_keys: u32,
    #[clap(long)]
    num_signers: u32,
    #[clap(long)]
    timeout: Option<u64>,
}

impl GenerateSignerConfigArgs {
    fn handle(&self) {
        let pkey = private_key_from_seed(&self.seed, self.signer_id);
        let config = build_signer_config_toml(
            &pkey,
            self.num_keys,
            self.signer_id,
            self.num_signers,
            self.stacker_db_args.host.to_string().as_str(),
            self.stacker_db_args.contract.to_string().as_str(),
            self.timeout.map(Duration::from_millis),
            self.observer_socket_address,
            self.seed.as_str(),
            self.network.clone(),
        );
        println!("Wrote signer config to {:?}", self.save_to_file);
        File::create(&self.save_to_file)
            .unwrap()
            .write_all(config.as_bytes())
            .unwrap();
    }
}

#[derive(Debug, clap::Args)]
/// Generate a new node file to use with the stackerdb contract
pub struct ExtendNodeConfigArgs {
    /// output file e.g. ./Devnet.toml
    output_file: PathBuf,
    /// load from file e.g. ./Devnet.toml
    input_file: PathBuf,
    /// A stackerdb replica
    #[clap(long, value_parser = parse_contract )]
    contract: QualifiedContractIdentifier,
    /// A signer's socket address to listen to stackerdb update events
    observer_socket_address: SocketAddrV4,
}

impl ExtendNodeConfigArgs {
    fn handle(&self) {
        let mut cfg = ConfigFile::from_path(self.input_file.to_str().unwrap()).unwrap();
        let mut observers = cfg.events_observer.unwrap_or_default();
        let observer_cfg = EventObserverConfigFile {
            endpoint: self.observer_socket_address.clone().to_string(),
            events_keys: vec!["stackerdb".to_string()],
        };
        observers.insert(observer_cfg);
        cfg.events_observer = Some(observers);

        let mut node_cfg = cfg
            .node
            .expect("Node Config is missing. Add '[node]' to the file.");
        let mut replicas = node_cfg.stacker_dbs.unwrap_or_default();
        let contract_string = self.contract.to_string();
        if !replicas.contains(&contract_string) {
            replicas.push(contract_string)
        }
        node_cfg.stacker_dbs = Some(replicas);
        cfg.node = Some(node_cfg);

        let content = toml::to_vec(&cfg).unwrap();
        let mut output_file = File::create(self.output_file.clone()).unwrap();
        output_file.write_all(&content).unwrap();
    }
}

#[cfg(test)]
mod test {
    use stacks_common::types::Address;
    use std::{env::temp_dir, str::FromStr};

    use super::*;

    #[test]
    fn sane_to_stacks_address() {
        let address = to_stacks_address(
            &Network::Mainnet,
            &StacksPrivateKey::from_hex(
                "d06a21eb4127872d0a96a3261437f5f932f3cdb98cd651396892f026b8a7542c01",
            )
            .unwrap(),
        );
        assert_eq!(
            address,
            StacksAddress::from_string("SP23M92VQE6452BXRGDMEBRM1WPDCJXAA5T3WYE17").unwrap()
        )
    }

    #[test]
    fn different_private_key_per_signer() {
        let seed = "secret";
        let a = private_key_from_seed(seed, 0);
        let b = private_key_from_seed(seed, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn sane_extend_config() {
        let tmp_dir = temp_dir();
        let output_file = tmp_dir.join("output.toml");
        let cfg_args = ExtendNodeConfigArgs {
            output_file: output_file.clone(),
            input_file: PathBuf::from_str("../testnet/stacks-node/conf/regtest-follower-conf.toml")
                .unwrap(),
            contract: QualifiedContractIdentifier::parse(
                "ST1EMWQSAEZ3VSD5TR9VY5M26E7FA52FWPS6EW59Q.hello-world",
            )
            .unwrap(),
            observer_socket_address: "127.0.0.1:30000".parse().unwrap(),
        };
        cfg_args.handle();

        let _ = ConfigFile::from_path(output_file.to_str().unwrap()).unwrap();
    }
}
