// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::fs;

use crate::net::stackerdb::{SlotMetadata, StackerDBSet};
use crate::net::StackerDBChunkData;

use clarity::vm::ContractName;
use stacks_common::types::chainstate::StacksAddress;

use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
use stacks_common::types::chainstate::{ConsensusHash, StacksPrivateKey, StacksPublicKey};
use stacks_common::types::PrivateKey;

#[test]
fn test_stackerdb_slot_metadata_sign_verify() {
    let pk = StacksPrivateKey::new();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&pk)],
    )
    .unwrap();
    let bad_addr = StacksAddress {
        version: 0x01,
        bytes: Hash160([0x01; 20]),
    };

    let chunk_data = StackerDBChunkData {
        slot_id: 0,
        slot_version: 1,
        sig: MessageSignature::empty(),
        data: vec![0x1; 128],
    };

    let mut slot_metadata = chunk_data.get_slot_metadata();
    slot_metadata.sign(&pk).unwrap();

    assert!(slot_metadata.verify(&addr).unwrap());

    // fails with wrong address
    assert!(!slot_metadata.verify(&bad_addr).unwrap());

    // fails with corrupted data
    let mut bad_slot_metadata = chunk_data.get_slot_metadata();
    bad_slot_metadata.sign(&pk).unwrap();
    bad_slot_metadata.slot_id += 1;
    assert!(!bad_slot_metadata.verify(&addr).unwrap());

    let mut bad_slot_metadata = chunk_data.get_slot_metadata();
    bad_slot_metadata.sign(&pk).unwrap();
    bad_slot_metadata.slot_version += 1;
    assert!(!bad_slot_metadata.verify(&addr).unwrap());

    let mut bad_slot_metadata = chunk_data.get_slot_metadata();
    bad_slot_metadata.sign(&pk).unwrap();
    bad_slot_metadata.data_hash = Sha512Trunc256Sum([0x20; 32]);
    assert!(!bad_slot_metadata.verify(&addr).unwrap());
}
