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

use crate::net::stackerdb::{db::ChunkValidation, ChunkMetadata, StackerDB, StackerDBConfig};

use crate::net::Error as net_error;
use crate::net::StackerDBChunkData;

use clarity::vm::ContractName;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksAddress;

use stacks_common::util::hash::Hash160;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use stacks_common::address::{
    AddressHashMode, C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
};
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};

#[test]
fn test_stackerdb_connect() {
    let path = "/tmp/test_stackerdb_connect.sqlite";
    if fs::metadata(path).is_ok() {
        fs::remove_file(path).unwrap();
    }

    let _ = StackerDB::connect(path, true).unwrap();
}

#[test]
fn test_stackerdb_create_list_delete() {
    let path = "/tmp/test_stackerdb_create_list_delete.sqlite";
    if fs::metadata(path).is_ok() {
        fs::remove_file(path).unwrap();
    }

    let mut db = StackerDB::connect(path, true).unwrap();
    let tx = db.tx_begin(StackerDBConfig::noop()).unwrap();

    tx.create_stackerdb((
        &StacksAddress {
            version: 0x01,
            bytes: Hash160([0x01; 20]),
        },
        &ContractName::try_from("db1").unwrap(),
    ))
    .unwrap();
    tx.create_stackerdb((
        &StacksAddress {
            version: 0x02,
            bytes: Hash160([0x02; 20]),
        },
        &ContractName::try_from("db2").unwrap(),
    ))
    .unwrap();
    tx.create_stackerdb((
        &StacksAddress {
            version: 0x03,
            bytes: Hash160([0x03; 20]),
        },
        &ContractName::try_from("db3").unwrap(),
    ))
    .unwrap();

    tx.commit().unwrap();

    let mut dbs = db.get_stackerdbs().unwrap();
    dbs.sort();

    assert_eq!(
        dbs,
        vec![
            (
                StacksAddress {
                    version: 0x01,
                    bytes: Hash160([0x01; 20])
                },
                ContractName::try_from("db1").unwrap()
            ),
            (
                StacksAddress {
                    version: 0x02,
                    bytes: Hash160([0x02; 20])
                },
                ContractName::try_from("db2").unwrap()
            ),
            (
                StacksAddress {
                    version: 0x03,
                    bytes: Hash160([0x03; 20])
                },
                ContractName::try_from("db3").unwrap()
            ),
        ]
    );

    // adding the same DB is idempotent
    let tx = db.tx_begin(StackerDBConfig::noop()).unwrap();
    tx.create_stackerdb((
        &StacksAddress {
            version: 0x01,
            bytes: Hash160([0x01; 20]),
        },
        &ContractName::try_from("db1").unwrap(),
    ))
    .unwrap();
    tx.commit().unwrap();

    let mut dbs = db.get_stackerdbs().unwrap();
    dbs.sort();

    assert_eq!(
        dbs,
        vec![
            (
                StacksAddress {
                    version: 0x01,
                    bytes: Hash160([0x01; 20])
                },
                ContractName::try_from("db1").unwrap()
            ),
            (
                StacksAddress {
                    version: 0x02,
                    bytes: Hash160([0x02; 20])
                },
                ContractName::try_from("db2").unwrap()
            ),
            (
                StacksAddress {
                    version: 0x03,
                    bytes: Hash160([0x03; 20])
                },
                ContractName::try_from("db3").unwrap()
            ),
        ]
    );

    // remove a db
    let tx = db.tx_begin(StackerDBConfig::noop()).unwrap();
    tx.delete_stackerdb((
        &StacksAddress {
            version: 0x01,
            bytes: Hash160([0x01; 20]),
        },
        &ContractName::try_from("db1").unwrap(),
    ))
    .unwrap();
    tx.commit().unwrap();

    let mut dbs = db.get_stackerdbs().unwrap();
    dbs.sort();

    assert_eq!(
        dbs,
        vec![
            (
                StacksAddress {
                    version: 0x02,
                    bytes: Hash160([0x02; 20])
                },
                ContractName::try_from("db2").unwrap()
            ),
            (
                StacksAddress {
                    version: 0x03,
                    bytes: Hash160([0x03; 20])
                },
                ContractName::try_from("db3").unwrap()
            ),
        ]
    );

    // deletion is idempotent
    let tx = db.tx_begin(StackerDBConfig::noop()).unwrap();
    tx.delete_stackerdb((
        &StacksAddress {
            version: 0x01,
            bytes: Hash160([0x01; 20]),
        },
        &ContractName::try_from("db1").unwrap(),
    ))
    .unwrap();
    tx.commit().unwrap();

    let mut dbs = db.get_stackerdbs().unwrap();
    dbs.sort();

    assert_eq!(
        dbs,
        vec![
            (
                StacksAddress {
                    version: 0x02,
                    bytes: Hash160([0x02; 20])
                },
                ContractName::try_from("db2").unwrap()
            ),
            (
                StacksAddress {
                    version: 0x03,
                    bytes: Hash160([0x03; 20])
                },
                ContractName::try_from("db3").unwrap()
            ),
        ]
    );
}

#[test]
fn test_stackerdb_prepare_clear_slots() {
    let path = "/tmp/test_stackerdb_prepare_clear_slots.sqlite";
    if fs::metadata(path).is_ok() {
        fs::remove_file(path).unwrap();
    }

    let sc = (
        StacksAddress {
            version: 0x01,
            bytes: Hash160([0x01; 20]),
        },
        ContractName::try_from("db1").unwrap(),
    );

    let mut db = StackerDB::connect(path, true).unwrap();
    let tx = db.tx_begin(StackerDBConfig::noop()).unwrap();

    tx.create_stackerdb((&sc.0, &sc.1)).unwrap();
    tx.prepare_stackerdb_slots(
        (&sc.0, &sc.1),
        &ConsensusHash([0x01; 20]),
        &vec![
            (
                StacksAddress {
                    version: 0x02,
                    bytes: Hash160([0x02; 20]),
                },
                2,
            ),
            (
                StacksAddress {
                    version: 0x03,
                    bytes: Hash160([0x03; 20]),
                },
                3,
            ),
            (
                StacksAddress {
                    version: 0x04,
                    bytes: Hash160([0x04; 20]),
                },
                4,
            ),
        ],
    )
    .unwrap();

    tx.commit().unwrap();

    // slots must all be inserted in the right places and quantities
    for chunk_id in 0..(2 + 3 + 4) {
        let chunk_metadata = db
            .get_chunk_metadata((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), chunk_id)
            .unwrap()
            .unwrap();
        let chunk_validation = db
            .get_chunk_validation((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), chunk_id)
            .unwrap()
            .unwrap();

        if chunk_id < 2 {
            // belongs to 0x02
            assert_eq!(
                chunk_validation.stacker,
                StacksAddress {
                    version: 0x02,
                    bytes: Hash160([0x02; 20])
                }
            );
        } else if chunk_id >= 2 && chunk_id < 2 + 3 {
            // belongs to 0x03
            assert_eq!(
                chunk_validation.stacker,
                StacksAddress {
                    version: 0x03,
                    bytes: Hash160([0x03; 20])
                }
            );
        } else if chunk_id >= 2 + 3 && chunk_id < 2 + 3 + 4 {
            // belongs to 0x03
            assert_eq!(
                chunk_validation.stacker,
                StacksAddress {
                    version: 0x04,
                    bytes: Hash160([0x04; 20])
                }
            );
        } else {
            unreachable!()
        }

        assert_eq!(chunk_metadata.rc_consensus_hash, ConsensusHash([0x01; 20]));
        assert_eq!(chunk_metadata.chunk_id, chunk_id);
        assert_eq!(chunk_metadata.chunk_version, 0);
        assert_eq!(chunk_metadata.data_hash, Sha512Trunc256Sum([0x00; 32]));
        assert_eq!(chunk_metadata.signature, MessageSignature::empty());

        assert_eq!(chunk_validation.version, 0);
        assert_eq!(chunk_validation.write_time, 0);
    }

    let tx = db.tx_begin(StackerDBConfig::noop()).unwrap();
    tx.clear_stackerdb_slots((&sc.0, &sc.1), &ConsensusHash([0x01; 20]))
        .unwrap();
    tx.commit().unwrap();

    // no more slots
    for chunk_id in 0..(2 + 3 + 4) {
        let chunk_metadata = db
            .get_chunk_metadata((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), chunk_id)
            .unwrap();
        assert!(chunk_metadata.is_none());

        let chunk_validation = db
            .get_chunk_validation((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), chunk_id)
            .unwrap();
        assert!(chunk_validation.is_none());
    }
}

#[test]
fn test_stackerdb_insert_query_chunks() {
    let path = "/tmp/test_stackerdb_insert_query_chunks.sqlite";
    if fs::metadata(path).is_ok() {
        fs::remove_file(path).unwrap();
    }

    let sc = (
        StacksAddress {
            version: 0x01,
            bytes: Hash160([0x01; 20]),
        },
        ContractName::try_from("db1").unwrap(),
    );

    let mut db = StackerDB::connect(path, true).unwrap();

    let mut db_config = StackerDBConfig::noop();
    db_config.max_writes = 3;
    db_config.write_freq = 120;

    let tx = db.tx_begin(db_config.clone()).unwrap();

    tx.create_stackerdb((&sc.0, &sc.1)).unwrap();

    let pks: Vec<_> = (0..10).map(|_| StacksPrivateKey::new()).collect();
    let addrs: Vec<_> = pks
        .iter()
        .map(|pk| {
            StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&pk)],
            )
            .unwrap()
        })
        .collect();

    tx.prepare_stackerdb_slots(
        (&sc.0, &sc.1),
        &ConsensusHash([0x01; 20]),
        &addrs
            .clone()
            .into_iter()
            .map(|addr| (addr, 1))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    // store some data
    for (i, pk) in pks.iter().enumerate() {
        let mut chunk_data = StackerDBChunkData {
            chunk_id: i as u32,
            chunk_version: 1,
            sig: MessageSignature::empty(),
            data: vec![i as u8; 128],
        };

        chunk_data.sign(ConsensusHash([0x01; 20]), &pk).unwrap();

        let chunk_metadata = tx
            .get_chunk_metadata((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32)
            .unwrap()
            .unwrap();
        assert_eq!(chunk_metadata.rc_consensus_hash, ConsensusHash([0x01; 20]));
        assert_eq!(chunk_metadata.chunk_id, i as u32);
        assert_eq!(chunk_metadata.chunk_version, 0);
        assert_eq!(chunk_metadata.data_hash, Sha512Trunc256Sum([0x00; 32]));
        assert_eq!(chunk_metadata.signature, MessageSignature::empty());

        // should succeed
        tx.try_replace_chunk(
            (&sc.0, &sc.1),
            &chunk_data.get_chunk_metadata(ConsensusHash([0x01; 20])),
            &chunk_data.data,
        )
        .unwrap();

        let chunk_metadata = tx
            .get_chunk_metadata((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32)
            .unwrap()
            .unwrap();
        assert_eq!(chunk_metadata.rc_consensus_hash, ConsensusHash([0x01; 20]));
        assert_eq!(chunk_metadata.chunk_id, i as u32);
        assert_eq!(chunk_metadata.chunk_version, chunk_data.chunk_version);
        assert_eq!(chunk_metadata.data_hash, chunk_data.data_hash());
        assert_eq!(chunk_metadata.signature, chunk_data.sig);

        // should fail -- stale version
        if let Err(net_error::StaleChunk(db_version, given_version)) = tx.try_replace_chunk(
            (&sc.0, &sc.1),
            &chunk_data.get_chunk_metadata(ConsensusHash([0x01; 20])),
            &chunk_data.data,
        ) {
            assert_eq!(db_version, 1);
            assert_eq!(given_version, 1);
        } else {
            panic!("Did not get StaleChunk");
        }

        // should fail -- too many writes version
        chunk_data.chunk_version = db_config.max_writes + 1;
        chunk_data.sign(ConsensusHash([0x01; 20]), &pk).unwrap();
        if let Err(net_error::TooManyChunkWrites(db_max, cur_version)) = tx.try_replace_chunk(
            (&sc.0, &sc.1),
            &chunk_data.get_chunk_metadata(ConsensusHash([0x01; 20])),
            &chunk_data.data,
        ) {
            assert_eq!(db_max, db_config.max_writes);
            assert_eq!(cur_version, 1);
        } else {
            panic!("Did not get TooManyChunkWrites");
        }

        // should fail -- bad signature
        chunk_data.chunk_version = 2;
        if let Err(net_error::BadChunkSigner(stacker, chunk_id)) = tx.try_replace_chunk(
            (&sc.0, &sc.1),
            &chunk_data.get_chunk_metadata(ConsensusHash([0x01; 20])),
            &chunk_data.data,
        ) {
            assert_eq!(stacker, addrs[i]);
            assert_eq!(chunk_id, i as u32);
        } else {
            eprintln!(
                "{}",
                tx.try_replace_chunk(
                    (&sc.0, &sc.1),
                    &chunk_data.get_chunk_metadata(ConsensusHash([0x01; 20])),
                    &chunk_data.data
                )
                .unwrap_err()
            );
            panic!("Did not get BadChunkSigner");
        }

        // should fail -- throttled
        chunk_data.sign(ConsensusHash([0x01; 20]), &pk).unwrap();
        if let Err(net_error::TooFrequentChunkWrites(..)) = tx.try_replace_chunk(
            (&sc.0, &sc.1),
            &chunk_data.get_chunk_metadata(ConsensusHash([0x01; 20])),
            &chunk_data.data,
        ) {
            chunk_data.chunk_version -= 1;
        } else {
            panic!("Did not get TooFrequentChunkWrites");
        }
    }

    tx.commit().unwrap();

    // test queries against the data
    for (i, addr) in addrs.iter().enumerate() {
        let signer = db
            .get_chunk_signer((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32)
            .unwrap()
            .unwrap();
        assert_eq!(signer, *addr);

        let chunk = db
            .get_latest_chunk((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32)
            .unwrap();
        assert_eq!(chunk, vec![i as u8; 128]);

        // correct version
        let chunk = db
            .get_chunk((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32, 1)
            .unwrap()
            .unwrap();
        assert_eq!(chunk.data, vec![i as u8; 128]);
        assert_eq!(chunk.chunk_version, 1);
        assert_eq!(chunk.chunk_id, i as u32);
        assert!(chunk.verify(ConsensusHash([0x01; 20]), &addr).unwrap());

        // incorrect version
        let chunk = db
            .get_chunk((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32, 0)
            .unwrap();
        assert!(chunk.is_none());

        // incorrect version
        let chunk = db
            .get_chunk((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32, 2)
            .unwrap();
        assert!(chunk.is_none());

        let chunk_metadata = db
            .get_chunk_metadata((&sc.0, &sc.1), &ConsensusHash([0x01; 20]), i as u32)
            .unwrap()
            .unwrap();
        assert!(chunk_metadata.verify(&addr).unwrap());
    }

    let versions = db
        .get_chunk_versions((&sc.0, &sc.1), &ConsensusHash([0x01; 20]))
        .unwrap();
    assert_eq!(versions, vec![1; 10]);

    let timestamps = db
        .get_chunk_write_timestamps((&sc.0, &sc.1), &ConsensusHash([0x01; 20]))
        .unwrap();
    for ts in timestamps {
        assert!(ts > 0);
    }
}
