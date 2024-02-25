use rand::{Rng, RngCore};
use randomizer::Randomizer;
use stacks_common::types::{chainstate::StacksBlockId, StacksEpochId};

use super::structures::ContractData;
use crate::vm::{analysis::ContractAnalysis, ast::build_ast, costs::LimitedCostTracker, types::QualifiedContractIdentifier, ClarityVersion, ContractContext};

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

fn random_contract_id() -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::local(&Randomizer::ALPHABETICAL(10).string().unwrap())
        .unwrap()
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

fn random_contract_and_analysis() -> (ContractContext, ContractAnalysis) {
    let contract_id = random_contract_id();
    
    let parsed = build_ast(
        &contract_id,
        CONTRACT_SRC,
        &mut (),
        ClarityVersion::latest(),
        StacksEpochId::latest(),
    ).expect("failed to parse contract");

    let contract_context = ContractContext::new(contract_id.clone(), ClarityVersion::latest());

    let analysis = ContractAnalysis::new(
        contract_id.clone(),
        parsed.expressions.clone(),
        LimitedCostTracker::new_free(),
        StacksEpochId::latest(),
        ClarityVersion::latest());

    (contract_context, analysis)
}

const CONTRACT_SRC: &str = "(define-map tokens { account: principal } { balance: uint })
         (define-read-only (my-get-token-balance (account principal))
            (default-to u0 (get balance (map-get? tokens (tuple (account account))))))
         (define-read-only (explode (account principal))
             (map-delete tokens (tuple (account account))))
         (define-private (token-credit! (account principal) (amount uint))
            (if (<= amount u0)
                (err \"must be positive\")
                (let ((current-amount (my-get-token-balance account)))
                  (begin
                    (map-set tokens (tuple (account account))
                                       (tuple (balance (+ amount current-amount))))
                    (ok 0)))))
         (define-public (token-transfer (to principal) (amount uint))
          (let ((balance (my-get-token-balance tx-sender)))
             (if (or (> amount balance) (<= amount u0))
                 (err \"not enough balance\")
                 (begin
                   (map-set tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (print (token-transfer (print original-sender) u1)))))                     
         (define-public (mint-after (block-to-release uint))
           (if (>= block-height block-to-release)
               (faucet)
               (err \"must be in the future\")))
         (begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR u10000)
                (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G u200)
                (token-credit! .tokens u4))";