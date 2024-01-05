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
use std::io::Write as WriteT;
use std::path::PathBuf;

use crate::{config::Network, utils::build_stackerdb_contract};
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use libsigner::SIGNER_SLOTS_PER_USER;
use stacks_common::{
    address::AddressHashMode,
    types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey},
};

#[derive(clap::Subcommand, Debug)]

/// Ping subcommands
pub enum PingSubcommands {
    /// Generate a simple stackerDB contract.
    /// This command can be used to generate a simple stackerDB contract.
    /// A shared seed can be used to generate keys deterministically.
    /// DO NOT USE this in production.
    /// Don't hold funds on this accounts. Anyone with the shared seed can deterministically generate the signer's secret keys.
    GenerateContract(GenerateContractArgs),
}

impl PingSubcommands {
    /// Handle any subcommand
    pub fn handle(&self) {
        match self {
            PingSubcommands::GenerateContract(args) => args.handle(),
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

#[cfg(test)]
mod test {
    use stacks_common::types::Address;

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
}
