// Copyright (C) 2024 Stacks Open Internet Foundation
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

use std::collections::{BTreeMap, HashMap};

use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};

/// A reward set parsed into relevant structures
#[derive(Debug, Clone)]
pub struct SignerEntries {
    /// The signer addresses mapped to signer ID
    pub signer_addr_to_id: HashMap<StacksAddress, u32>,
    /// The signer IDs mapped to addresses. Uses a BTreeMap to ensure *reward cycle order*
    pub signer_id_to_addr: BTreeMap<u32, StacksAddress>,
    /// signer ID mapped to public key
    pub signer_id_to_pk: HashMap<u32, StacksPublicKey>,
    /// public_key mapped to signer ID
    pub signer_pk_to_id: HashMap<StacksPublicKey, u32>,
    /// The signer public keys
    pub signer_pks: Vec<StacksPublicKey>,
    /// The signer addresses
    pub signer_addresses: Vec<StacksAddress>,
    /// The signer address mapped to signing weight
    pub signer_addr_to_weight: HashMap<StacksAddress, u32>,
}

/// Parsing errors for `SignerEntries`
#[derive(Debug)]
pub enum Error {
    /// A member of the signing set has a signing key buffer
    ///  which does not represent a valid Stacks public key
    BadSignerPublicKey(String),
    /// The number of signers was greater than u32::MAX
    SignerCountOverflow,
}

impl SignerEntries {
    /// Try to parse the reward set defined by `NakamotoSignEntry` into the SignerEntries struct
    pub fn parse(is_mainnet: bool, reward_set: &[NakamotoSignerEntry]) -> Result<Self, Error> {
        let mut signer_pk_to_id = HashMap::with_capacity(reward_set.len());
        let mut signer_id_to_pk = HashMap::with_capacity(reward_set.len());
        let mut signer_addr_to_id = HashMap::with_capacity(reward_set.len());
        let mut signer_pks = Vec::with_capacity(reward_set.len());
        let mut signer_id_to_addr = BTreeMap::new();
        let mut signer_addr_to_weight = HashMap::new();
        let mut signer_addresses = Vec::with_capacity(reward_set.len());
        for (i, entry) in reward_set.iter().enumerate() {
            let signer_id = u32::try_from(i).map_err(|_| Error::SignerCountOverflow)?;
            let signer_public_key = StacksPublicKey::from_slice(entry.signing_key.as_slice())
                .map_err(|e| {
                    Error::BadSignerPublicKey(format!(
                        "Failed to convert signing key to StacksPublicKey: {e}"
                    ))
                })?;

            let stacks_address = StacksAddress::p2pkh(is_mainnet, &signer_public_key);
            signer_addr_to_id.insert(stacks_address.clone(), signer_id);
            signer_id_to_pk.insert(signer_id, signer_public_key.clone());
            signer_pk_to_id.insert(signer_public_key.clone(), signer_id);
            signer_pks.push(signer_public_key);
            signer_id_to_addr.insert(signer_id, stacks_address.clone());
            signer_addr_to_weight.insert(stacks_address.clone(), entry.weight);
            signer_addresses.push(stacks_address);
        }

        Ok(Self {
            signer_addr_to_id,
            signer_id_to_pk,
            signer_pk_to_id,
            signer_pks,
            signer_id_to_addr,
            signer_addr_to_weight,
            signer_addresses,
        })
    }
}
