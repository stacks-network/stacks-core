use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, VRFSeed,
};
use crate::util::hash::{hex_bytes, to_hex, Hash160};
use serde::{Deserialize, Serialize};

/// This file contains functions used for custom serde serializations and deserializations.

pub fn burn_hh_serialize<S: serde::Serializer>(
    bhh: &BurnchainHeaderHash,
    s: S,
) -> Result<S::Ok, S::Error> {
    let inst = bhh.to_hex();
    s.serialize_str(inst.as_str())
}

pub fn burn_hh_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BurnchainHeaderHash, D::Error> {
    let inst_str = String::deserialize(d)?;
    BurnchainHeaderHash::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

pub fn block_hh_serialize<S: serde::Serializer>(
    bhh: &BlockHeaderHash,
    s: S,
) -> Result<S::Ok, S::Error> {
    let inst = bhh.to_hex();
    s.serialize_str(inst.as_str())
}

pub fn block_hh_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BlockHeaderHash, D::Error> {
    let inst_str = String::deserialize(d)?;
    BlockHeaderHash::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

pub fn vrf_seed_serialize<S: serde::Serializer>(seed: &VRFSeed, s: S) -> Result<S::Ok, S::Error> {
    let inst = seed.to_hex();
    s.serialize_str(inst.as_str())
}

pub fn vrf_seed_deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<VRFSeed, D::Error> {
    let inst_str = String::deserialize(d)?;
    VRFSeed::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

pub fn consensus_hash_serialize<S: serde::Serializer>(
    ch: &ConsensusHash,
    s: S,
) -> Result<S::Ok, S::Error> {
    let inst = ch.to_hex();
    s.serialize_str(inst.as_str())
}

pub fn consensus_hash_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<ConsensusHash, D::Error> {
    let inst_str = String::deserialize(d)?;
    ConsensusHash::from_hex(&inst_str).map_err(serde::de::Error::custom)
}

pub fn memo_serialize<S: serde::Serializer>(memo: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let hex_inst = to_hex(memo);
    let byte_str = format!("0x{}", hex_inst);
    s.serialize_str(byte_str.as_str())
}

pub fn memo_deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let bytes_str = String::deserialize(d)?;
    let hex_inst = &bytes_str[2..];

    hex_bytes(&hex_inst).map_err(serde::de::Error::custom)
}

#[derive(Serialize, Deserialize)]
struct StacksAddrJsonDisplay {
    address: String,
    #[serde(
        deserialize_with = "hash_160_deserialize",
        serialize_with = "hash_160_serialize"
    )]
    address_hash_bytes: Hash160,
    address_version: u8,
}

fn hash_160_serialize<S: serde::Serializer>(hash: &Hash160, s: S) -> Result<S::Ok, S::Error> {
    let hex_inst = to_hex(&hash.0);
    let byte_str = format!("0x{}", hex_inst);
    s.serialize_str(byte_str.as_str())
}

fn hash_160_deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Hash160, D::Error> {
    let bytes_str = String::deserialize(d)?;
    let hex_inst = &bytes_str[2..];
    Hash160::from_hex(&hex_inst).map_err(serde::de::Error::custom)
}

pub fn stacks_addr_serialize<S: serde::Serializer>(
    addr: &StacksAddress,
    s: S,
) -> Result<S::Ok, S::Error> {
    let addr_str = addr.to_string();
    let addr_display = StacksAddrJsonDisplay {
        address: addr_str,
        address_hash_bytes: addr.bytes,
        address_version: addr.version,
    };
    addr_display.serialize(s)
}

pub fn stacks_addr_deserialize<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<StacksAddress, D::Error> {
    let addr_display = StacksAddrJsonDisplay::deserialize(d)?;
    Ok(StacksAddress {
        version: addr_display.address_version,
        bytes: addr_display.address_hash_bytes,
    })
}
