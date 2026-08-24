// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::io::{Read, Write};

use clarity::codec::{
    read_next, read_next_at_most, write_next, Error as CodecError, StacksMessageCodec,
};
use clarity::types::chainstate::{BurnchainHeaderHash, ConsensusHash};
use clarity::types::{MinerDiagnosticData, MiningReason};
use serde::{Deserialize, Serialize};

use crate::v0::messages::BLOCK_RESPONSE_DATA_MAX_SIZE;
use crate::BlockProposalData;

pub const BLOCK_PROPOSAL_DATA_VERSION_V2: u8 = 2;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct BlockProposalData_v2 {
    pub version: u8,
    pub server_version: String,
    pub unknown_bytes: Vec<u8>,
}

impl BlockProposalData_v2 {
    pub fn new(server_version: String) -> Self {
        Self {
            version: BLOCK_PROPOSAL_DATA_VERSION_V2,
            server_version,
            unknown_bytes: vec![],
        }
    }

    pub fn empty() -> Self {
        Self::new(String::new())
    }

    fn inner_consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.server_version.as_bytes().to_vec())?;
        fd.write_all(&self.unknown_bytes)
            .map_err(CodecError::WriteError)?;
        Ok(())
    }
}

impl StacksMessageCodec for BlockProposalData_v2 {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        let mut inner_bytes = vec![];
        self.inner_consensus_serialize(&mut inner_bytes)?;
        write_next(fd, &inner_bytes)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, CodecError> {
        let Ok(version) = read_next(fd) else {
            return Ok(Self::empty());
        };
        let inner_bytes: Vec<u8> = read_next_at_most(fd, BLOCK_RESPONSE_DATA_MAX_SIZE)?;
        let mut inner_reader = inner_bytes.as_slice();
        let server_version: Vec<u8> = read_next(&mut inner_reader)?;
        let server_version = String::from_utf8(server_version).map_err(|e| {
            CodecError::DeserializeError(format!("Failed to decode server version: {:?}", &e))
        })?;
        Ok(Self {
            version,
            server_version,
            unknown_bytes: inner_reader.to_vec(),
        })
    }
}

/// Asserts that current version BlockProposalData can be deserialized and reserialized
/// by an older version without losing any information.
#[test]
fn block_proposal_data_serialization_roundtrip_v2() {
    let original_data = BlockProposalData::new(
        "myversion".into(),
        MinerDiagnosticData {
            burnchain_tip_height: 67,
            burnchain_tip_consensus_hash: ConsensusHash::from_bytes(&[0xabu8; 20]).unwrap(),
            burnchain_tip_header_hash: BurnchainHeaderHash::from_bytes(&[99u8; 32]).unwrap(),
            read_count_extend_timestamp: 1764576000,
            tenure_extend_time_stamp: 1804989566,
            mining_reason: MiningReason::Extended,
        },
    );

    let serialized = original_data.serialize_to_vec();

    let v2_deserialized = BlockProposalData_v2::consensus_deserialize(&mut &serialized[..])
        .expect("BlockProposalData v2 should deserialize v3 data without error");

    assert_eq!(v2_deserialized.server_version, "myversion");
    assert_eq!(v2_deserialized.version, original_data.version);
    assert!(!v2_deserialized.unknown_bytes.is_empty());

    let v2_serialized = v2_deserialized.serialize_to_vec();

    let roundtripped = BlockProposalData::consensus_deserialize(&mut &v2_serialized[..]).expect(
        "current BlockProposalData should deserialize data from older serializers without error",
    );

    assert_eq!(original_data, roundtripped);
}

/// Asserts that we can successfully deserialize block proposal data that was serialized
/// by an older version, and re-serialize it identically.
#[test]
fn block_proposal_data_backwards_compatible() {
    let original_data = BlockProposalData_v2::new("1.2.3.4".into());

    let serialized = original_data.serialize_to_vec();

    let deserialized = BlockProposalData::consensus_deserialize(&mut &serialized[..])
        .expect("current BlockProposalData should deserialize v2 data without error");

    assert_eq!(deserialized.server_version, "1.2.3.4");
    assert_eq!(deserialized.version, original_data.version);
    assert!(deserialized.unknown_bytes.is_empty());
    assert!(deserialized.miner_diagnostic_data.is_none());

    let re_serialized = deserialized.serialize_to_vec();

    assert_eq!(serialized, re_serialized);

    let roundtripped = BlockProposalData_v2::consensus_deserialize(&mut &re_serialized[..])
        .expect("BlockProposalData v2 should deserialize round-tripped data without error");

    assert_eq!(original_data, roundtripped);
}
