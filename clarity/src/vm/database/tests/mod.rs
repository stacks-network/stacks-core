use rand::{Rng, RngCore};
use randomizer::Randomizer;
use stacks_common::types::chainstate::StacksBlockId;

use super::structures::ContractData;
use crate::vm::types::QualifiedContractIdentifier;

mod db;
mod kv;
mod sqlite;
mod store;

fn random_bhh() -> [u8; 32] {
    let mut bhh = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bhh);
    bhh
}

fn random_stacks_block_id() -> StacksBlockId {
    StacksBlockId::from_bytes(&random_bhh()).expect("failed to create random StacksBlockId")
}

fn random_bytes_random_len(min_len: usize, max_len: usize) -> Vec<u8> {
    let len = rand::thread_rng().gen_range(min_len..max_len);
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn random_u32(min: usize, max: usize) -> u32 {
    rand::thread_rng().gen_range(min..max) as u32
}

fn random_height() -> u32 {
    random_u32(0, 100_000)
}

fn random_string(len: usize) -> String {
    let result = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(len)
        .collect();

    String::from_utf8(result).unwrap()
}

fn assert_contract_eq(left: ContractData, right: ContractData) {
    assert_eq!(left.issuer, right.issuer);
    assert_eq!(left.name, right.name);
    assert_eq!(left.source, right.source);
    assert_eq!(left.source_size, right.source_size);
    assert_eq!(left.contract, right.contract);
    assert_eq!(left.contract_size, right.contract_size);
    assert_eq!(left.data_size, right.data_size);
}

fn random_contract_data() -> (QualifiedContractIdentifier, ContractData) {
    let src_bytes = random_bytes_random_len(100, 1000);
    let src_len = src_bytes.len() as u32;
    let contract_bytes = random_bytes_random_len(100, 1000);
    let contract_len = contract_bytes.len() as u32;
    let data_size = random_u32(100, 1000);

    let identifier =
        QualifiedContractIdentifier::local(&Randomizer::ALPHABETICAL(10).string().unwrap())
            .unwrap();

    (
        identifier.clone(),
        ContractData {
            id: 0,
            issuer: identifier.issuer.to_string(),
            name: identifier.name.to_string(),
            source: src_bytes.clone(),
            source_size: src_len as u32,
            contract: contract_bytes,
            contract_size: contract_len,
            data_size,
            contract_hash: random_bhh().to_vec(),
        },
    )
}
