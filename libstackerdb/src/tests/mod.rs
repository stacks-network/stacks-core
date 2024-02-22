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

use clarity::vm::types::QualifiedContractIdentifier;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;

use crate::*;

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

#[test]
fn test_stackerdb_paths() {
    let pk = StacksPrivateKey::from_hex(
        "4bbe4e7dc879afedf4bf258a7385cf78ccf3a68a77f9cfc624f433d009f812f901",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&pk)],
    )
    .unwrap();

    let contract_id = QualifiedContractIdentifier::new(addr.into(), "hello-world".into());

    assert_eq!(
        stackerdb_get_metadata_path(contract_id.clone()),
        "/v2/stackerdb/SP1Y0NECNCJ6YDVM7GQ594FF065NN3NT72FASBXB8/hello-world".to_string()
    );

    assert_eq!(
        stackerdb_get_chunk_path(contract_id.clone(), 1, Some(2)),
        "/v2/stackerdb/SP1Y0NECNCJ6YDVM7GQ594FF065NN3NT72FASBXB8/hello-world/1/2".to_string()
    );

    assert_eq!(
        stackerdb_get_chunk_path(contract_id.clone(), 1, None),
        "/v2/stackerdb/SP1Y0NECNCJ6YDVM7GQ594FF065NN3NT72FASBXB8/hello-world/1".to_string()
    );

    assert_eq!(
        stackerdb_post_chunk_path(contract_id),
        "/v2/stackerdb/SP1Y0NECNCJ6YDVM7GQ594FF065NN3NT72FASBXB8/hello-world/chunks".to_string()
    );
}
