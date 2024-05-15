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

use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
use hashbrown::{HashMap, HashSet};
use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};
use wsts::curve::ecdsa;
use wsts::curve::point::{Compressed, Point};
use wsts::state_machine::PublicKeys;

/// A reward set parsed into the structures required by WSTS party members and coordinators.
#[derive(Debug, Clone)]
pub struct SignerEntries {
    /// The signer addresses mapped to signer id
    pub signer_ids: HashMap<StacksAddress, u32>,
    /// The signer ids mapped to public key and key ids mapped to public keys
    pub public_keys: PublicKeys,
    /// The signer ids mapped to key ids
    pub signer_key_ids: HashMap<u32, Vec<u32>>,
    /// The signer ids mapped to wsts public keys
    pub signer_public_keys: HashMap<u32, Point>,
    /// The signer ids mapped to a hash set of key ids
    /// The wsts coordinator uses a hash set for each signer since it needs to do lots of lookups
    pub coordinator_key_ids: HashMap<u32, HashSet<u32>>,
}

/// Parsing errors for `SignerEntries`
#[derive(Debug)]
pub enum Error {
    /// A member of the signing set has a signing key buffer
    ///  which does not represent a ecdsa public key.
    BadSignerPublicKey(String),
    /// The number of signers was greater than u32::MAX
    SignerCountOverflow,
}

impl SignerEntries {
    /// Try to parse the reward set defined by `NakamotoSignEntry` into the structures required
    ///  by WSTS party members and coordinators.
    pub fn parse(is_mainnet: bool, reward_set: &[NakamotoSignerEntry]) -> Result<Self, Error> {
        let mut weight_end = 1;
        let mut signer_key_ids = HashMap::with_capacity(reward_set.len());
        let mut signer_public_keys = HashMap::with_capacity(reward_set.len());
        let mut coordinator_key_ids = HashMap::with_capacity(4000);
        let mut signer_ids = HashMap::with_capacity(reward_set.len());
        let mut wsts_signers = HashMap::new();
        let mut wsts_key_ids = HashMap::new();
        for (i, entry) in reward_set.iter().enumerate() {
            let signer_id = u32::try_from(i).map_err(|_| Error::SignerCountOverflow)?;
            let ecdsa_pk =
                ecdsa::PublicKey::try_from(entry.signing_key.as_slice()).map_err(|e| {
                    Error::BadSignerPublicKey(format!(
                        "Failed to convert signing key to ecdsa::PublicKey: {e}"
                    ))
                })?;
            let signer_public_key = Point::try_from(&Compressed::from(ecdsa_pk.to_bytes()))
                .map_err(|e| {
                    Error::BadSignerPublicKey(format!(
                        "Failed to convert signing key to wsts::Point: {e}"
                    ))
                })?;
            let stacks_public_key = StacksPublicKey::from_slice(entry.signing_key.as_slice())
                .map_err(|e| {
                    Error::BadSignerPublicKey(format!(
                        "Failed to convert signing key to StacksPublicKey: {e}"
                    ))
                })?;

            let stacks_address = StacksAddress::p2pkh(is_mainnet, &stacks_public_key);
            signer_ids.insert(stacks_address, signer_id);

            signer_public_keys.insert(signer_id, signer_public_key);
            let weight_start = weight_end;
            weight_end = weight_start + entry.weight;
            let key_ids: HashSet<u32> = (weight_start..weight_end).collect();
            for key_id in key_ids.iter() {
                wsts_key_ids.insert(*key_id, ecdsa_pk);
            }
            signer_key_ids.insert(signer_id, (weight_start..weight_end).collect());
            coordinator_key_ids.insert(signer_id, key_ids);
            wsts_signers.insert(signer_id, ecdsa_pk);
        }

        Ok(Self {
            signer_ids,
            public_keys: PublicKeys {
                signers: wsts_signers,
                key_ids: wsts_key_ids,
            },
            signer_key_ids,
            signer_public_keys,
            coordinator_key_ids,
        })
    }

    /// Return the number of Key IDs in the WSTS group signature
    pub fn count_keys(&self) -> Result<u32, Error> {
        self.public_keys
            .key_ids
            .len()
            .try_into()
            .map_err(|_| Error::SignerCountOverflow)
    }

    /// Return the number of Key IDs in the WSTS group signature
    pub fn count_signers(&self) -> Result<u32, Error> {
        self.public_keys
            .signers
            .len()
            .try_into()
            .map_err(|_| Error::SignerCountOverflow)
    }

    /// Return the number of Key IDs required to sign a message with the WSTS group signature
    pub fn get_signing_threshold(&self) -> Result<u32, Error> {
        let num_keys = self.count_keys()?;
        Ok((num_keys as f64 * 7_f64 / 10_f64).ceil() as u32)
    }

    /// Return the number of Key IDs required to sign a message with the WSTS group signature
    pub fn get_dkg_threshold(&self) -> Result<u32, Error> {
        let num_keys = self.count_keys()?;
        Ok((num_keys as f64 * 9_f64 / 10_f64).ceil() as u32)
    }
}
