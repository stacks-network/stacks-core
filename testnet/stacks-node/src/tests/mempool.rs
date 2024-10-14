use std::sync::Mutex;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::NULL_BURN_STATE_DB;
use clarity::vm::representations::ContractName;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::Value;
use lazy_static::lazy_static;
use stacks::chainstate::stacks::db::blocks::MemPoolRejection;
use stacks::chainstate::stacks::{
    Error as ChainstateError, StacksBlockHeader, StacksMicroblockHeader, StacksPrivateKey,
    StacksPublicKey, StacksTransaction, StacksTransactionSigner, TokenTransferMemo,
    TransactionAnchorMode, TransactionAuth, TransactionPayload, TransactionSpendingCondition,
    TransactionVersion, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::mempool::MemPoolDB;
use stacks::core::{StacksEpochId, CHAIN_ID_TESTNET};
use stacks::cost_estimates::metrics::UnitMetric;
use stacks::cost_estimates::UnitEstimator;
use stacks::net::Error as NetError;
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksAddress};
use stacks_common::util::hash::*;
use stacks_common::util::secp256k1::*;

use super::{
    make_coinbase, make_contract_call, make_contract_publish, make_poison, make_stacks_transfer,
    serialize_sign_standard_single_sig_tx_anchor_mode_version, to_addr, SK_1, SK_2,
};
use crate::helium::RunLoop;
use crate::Keychain;

const FOO_CONTRACT: &'static str = "(define-public (foo) (ok 1))
                                    (define-public (bar (x uint)) (ok x))";
const TRAIT_CONTRACT: &'static str = "(define-trait tr ((value () (response uint uint))))";
const USE_TRAIT_CONTRACT: &'static str = "(use-trait tr-trait .trait-contract.tr)
                                         (define-public (baz (abc <tr-trait>)) (ok (contract-of abc)))";
const IMPLEMENT_TRAIT_CONTRACT: &'static str = "(define-public (value) (ok u1))";
const BAD_TRAIT_CONTRACT: &'static str = "(define-public (foo-bar) (ok u1))";

pub fn make_bad_stacks_transfer(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));

    let mut spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(spending_condition);

    let mut unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
    unsigned_tx.chain_id = CHAIN_ID_TESTNET;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);

    tx_signer.sign_origin(&StacksPrivateKey::new()).unwrap();

    let mut buf = vec![];
    tx_signer
        .get_tx()
        .unwrap()
        .consensus_serialize(&mut buf)
        .unwrap();
    buf
}

lazy_static! {
    static ref CHAINSTATE_PATH: Mutex<Option<String>> = Mutex::new(None);
}

#[test]
fn mempool_setup_chainstate() {
    let mut conf = super::new_test_conf();

    // force seeds to be the same
    conf.node.seed = vec![0x00];

    conf.burnchain.commit_anchor_block_within = 1500;

    let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let contract_addr = to_addr(&contract_sk);
    conf.add_initial_balance(contract_addr.to_string(), 100000);

    {
        CHAINSTATE_PATH
            .lock()
            .unwrap()
            .replace(conf.get_chainstate_path_str());
    }

    let num_rounds = 4;

    let mut run_loop = RunLoop::new(conf.clone());

    run_loop
        .callbacks
        .on_new_tenure(|round, _burnchain_tip, chain_tip, tenure| {
            let mut chainstate_copy = tenure.open_chainstate();
            let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
            let header_hash = chain_tip.block.block_hash();
            let consensus_hash = chain_tip.metadata.consensus_hash;
            let sortdb = tenure.open_fake_sortdb();

            if round == 1 {
                eprintln!("Tenure in 1 started!");

                let publish_tx1 =
                    make_contract_publish(&contract_sk, 0, 100, "foo_contract", FOO_CONTRACT);
                tenure
                    .mem_pool
                    .submit_raw(
                        &mut chainstate_copy,
                        &sortdb,
                        &consensus_hash,
                        &header_hash,
                        publish_tx1,
                        &ExecutionCost::max_value(),
                        &StacksEpochId::Epoch20,
                    )
                    .unwrap();

                let publish_tx2 =
                    make_contract_publish(&contract_sk, 1, 100, "trait-contract", TRAIT_CONTRACT);
                tenure
                    .mem_pool
                    .submit_raw(
                        &mut chainstate_copy,
                        &sortdb,
                        &consensus_hash,
                        &header_hash,
                        publish_tx2,
                        &ExecutionCost::max_value(),
                        &StacksEpochId::Epoch20,
                    )
                    .unwrap();

                let publish_tx3 = make_contract_publish(
                    &contract_sk,
                    2,
                    100,
                    "use-trait-contract",
                    USE_TRAIT_CONTRACT,
                );
                tenure
                    .mem_pool
                    .submit_raw(
                        &mut chainstate_copy,
                        &sortdb,
                        &consensus_hash,
                        &header_hash,
                        publish_tx3,
                        &ExecutionCost::max_value(),
                        &StacksEpochId::Epoch20,
                    )
                    .unwrap();

                let publish_tx4 = make_contract_publish(
                    &contract_sk,
                    3,
                    100,
                    "implement-trait-contract",
                    IMPLEMENT_TRAIT_CONTRACT,
                );
                tenure
                    .mem_pool
                    .submit_raw(
                        &mut chainstate_copy,
                        &sortdb,
                        &consensus_hash,
                        &header_hash,
                        publish_tx4,
                        &ExecutionCost::max_value(),
                        &StacksEpochId::Epoch20,
                    )
                    .unwrap();

                let publish_tx4 = make_contract_publish(
                    &contract_sk,
                    4,
                    100,
                    "bad-trait-contract",
                    BAD_TRAIT_CONTRACT,
                );
                tenure
                    .mem_pool
                    .submit_raw(
                        &mut chainstate_copy,
                        &sortdb,
                        &consensus_hash,
                        &header_hash,
                        publish_tx4,
                        &ExecutionCost::max_value(),
                        &StacksEpochId::Epoch20,
                    )
                    .unwrap();
            }
        });

    run_loop.callbacks.on_new_stacks_chain_state(
        |round, _burnchain_tip, chain_tip, chain_state, _burn_dbconn| {
            let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
            let contract_addr = to_addr(&contract_sk);

            let other_sk = StacksPrivateKey::from_hex(SK_2).unwrap();
            let other_addr = to_addr(&other_sk).into();

            let chainstate_path = { CHAINSTATE_PATH.lock().unwrap().clone().unwrap() };

            let estimator = Box::new(UnitEstimator);
            let metric = Box::new(UnitMetric);

            let _mempool =
                MemPoolDB::open(false, CHAIN_ID_TESTNET, &chainstate_path, estimator, metric)
                    .unwrap();

            if round == 3 {
                let block_header = chain_tip.metadata.clone();
                let consensus_hash = &block_header.consensus_hash;
                let block_hash = &block_header.anchored_header.block_hash();

                let micro_pubkh = &block_header
                    .anchored_header
                    .as_stacks_epoch2()
                    .unwrap()
                    .microblock_pubkey_hash;

                // let's throw some transactions at it.
                // first a couple valid ones:
                let tx_bytes =
                    make_contract_publish(&contract_sk, 5, 1000, "bar_contract", FOO_CONTRACT);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap();

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    200,
                    &contract_addr,
                    "foo_contract",
                    "bar",
                    &[Value::UInt(1)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap();

                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 200, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap();

                // bad signature
                let tx_bytes = make_bad_stacks_transfer(&contract_sk, 5, 200, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(
                    if let MemPoolRejection::FailedToValidate(ChainstateError::NetError(
                        NetError::VerifyingError(_),
                    )) = e
                    {
                        true
                    } else {
                        false
                    }
                );

                // mismatched network on contract-call!
                let bad_addr = StacksAddress::from_public_keys(
                    88,
                    &AddressHashMode::SerializeP2PKH,
                    1,
                    &vec![StacksPublicKey::from_private(&other_sk)],
                )
                .unwrap()
                .into();

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    200,
                    &bad_addr,
                    "foo_contract",
                    "bar",
                    &[Value::UInt(1), Value::Int(2)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();

                assert!(if let MemPoolRejection::BadAddressVersionByte = e {
                    true
                } else {
                    false
                });

                // mismatched network on transfer!
                let bad_addr = StacksAddress::from_public_keys(
                    C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                    &AddressHashMode::SerializeP2PKH,
                    1,
                    &vec![StacksPublicKey::from_private(&other_sk)],
                )
                .unwrap()
                .into();

                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 200, &bad_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                assert!(if let MemPoolRejection::BadAddressVersionByte = e {
                    true
                } else {
                    false
                });

                // bad fees
                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 0, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::FeeTooLow(0, _) = e {
                    true
                } else {
                    false
                });

                // bad nonce
                let tx_bytes = make_stacks_transfer(&contract_sk, 0, 200, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::BadNonces(_) = e {
                    true
                } else {
                    false
                });

                // not enough funds
                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 110000, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NotEnoughFunds(111000, 99500) = e {
                    true
                } else {
                    false
                });

                // sender == recipient
                let contract_princ = PrincipalData::from(contract_addr.clone());
                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 300, &contract_princ, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::TransferRecipientIsSender(r) = e {
                    r == contract_princ
                } else {
                    false
                });

                // recipient must be testnet
                let mut mainnet_recipient = to_addr(&other_sk);
                mainnet_recipient.version = C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
                let mainnet_princ = mainnet_recipient.into();
                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 300, &mainnet_princ, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::BadAddressVersionByte = e {
                    true
                } else {
                    false
                });

                // tx version must be testnet
                let contract_princ = PrincipalData::from(contract_addr.clone());
                let payload = TransactionPayload::TokenTransfer(
                    contract_princ.clone(),
                    1000,
                    TokenTransferMemo([0; 34]),
                );
                let tx_bytes = serialize_sign_standard_single_sig_tx_anchor_mode_version(
                    payload,
                    &contract_sk,
                    5,
                    300,
                    TransactionAnchorMode::OnChainOnly,
                    TransactionVersion::Mainnet,
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::BadTransactionVersion = e {
                    true
                } else {
                    false
                });

                // send amount must be positive
                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 300, &other_addr, 0);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::TransferAmountMustBePositive = e {
                    true
                } else {
                    false
                });

                // not enough funds
                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 110000, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NotEnoughFunds(111000, 99500) = e {
                    true
                } else {
                    false
                });

                let tx_bytes = make_stacks_transfer(&contract_sk, 5, 99700, &other_addr, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NotEnoughFunds(100700, 99500) = e {
                    true
                } else {
                    false
                });

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    200,
                    &contract_addr,
                    "bar_contract",
                    "bar",
                    &[Value::UInt(1)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoSuchContract = e {
                    true
                } else {
                    false
                });

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    200,
                    &contract_addr,
                    "foo_contract",
                    "foobar",
                    &[Value::UInt(1)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoSuchPublicFunction = e {
                    true
                } else {
                    false
                });

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    200,
                    &contract_addr,
                    "foo_contract",
                    "bar",
                    &[Value::UInt(1), Value::Int(2)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::BadFunctionArgument(_) = e {
                    true
                } else {
                    false
                });

                let tx_bytes =
                    make_contract_publish(&contract_sk, 5, 1000, "foo_contract", FOO_CONTRACT);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::ContractAlreadyExists(_) = e {
                    true
                } else {
                    false
                });

                let microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([1; 65]),
                };

                let microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 1,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([1; 65]),
                };

                let tx_bytes = make_poison(&contract_sk, 5, 1000, microblock_1, microblock_2);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(matches!(e, MemPoolRejection::Other(_)));

                let microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: block_hash.clone(),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65]),
                };

                let microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: block_hash.clone(),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[1, 2, 3]),
                    signature: MessageSignature([0; 65]),
                };

                let tx_bytes = make_poison(&contract_sk, 5, 1000, microblock_1, microblock_2);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(matches!(e, MemPoolRejection::Other(_)));

                let mut microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65]),
                };

                let mut microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[1, 2, 3]),
                    signature: MessageSignature([0; 65]),
                };

                microblock_1.sign(&other_sk).unwrap();
                microblock_2.sign(&other_sk).unwrap();

                let tx_bytes = make_poison(&contract_sk, 5, 1000, microblock_1, microblock_2);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(matches!(e, MemPoolRejection::Other(_)));

                let tx_bytes = make_coinbase(&contract_sk, 5, 1000);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoCoinbaseViaMempool = e {
                    true
                } else {
                    false
                });

                // find the correct priv-key
                let mut secret_key = None;
                let mut conf = super::new_test_conf();
                conf.node.seed = vec![0x00];

                let keychain = Keychain::default(conf.node.seed.clone());
                for i in 0..4 {
                    let microblock_secret_key = keychain.get_microblock_key(1 + i);
                    let mut microblock_pubkey =
                        Secp256k1PublicKey::from_private(&microblock_secret_key);
                    microblock_pubkey.set_compressed(true);
                    let pubkey_hash = StacksBlockHeader::pubkey_hash(&microblock_pubkey);
                    if pubkey_hash == *micro_pubkh {
                        secret_key = Some(microblock_secret_key);
                        break;
                    }
                }

                let secret_key = secret_key.expect("Failed to find the microblock secret key");

                let mut microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65]),
                };

                let mut microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[1, 2, 3]),
                    signature: MessageSignature([0; 65]),
                };

                microblock_1.sign(&secret_key).unwrap();
                microblock_2.sign(&secret_key).unwrap();

                let tx_bytes = make_poison(&contract_sk, 5, 1000, microblock_1, microblock_2);
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(matches!(e, MemPoolRejection::Other(_)));

                let contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(contract_addr.clone()),
                    ContractName::try_from("implement-trait-contract").unwrap(),
                );
                let contract_principal = PrincipalData::Contract(contract_id.clone());

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    250,
                    &contract_addr,
                    "use-trait-contract",
                    "baz",
                    &[Value::Principal(contract_principal)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap();

                let contract_id = QualifiedContractIdentifier::new(
                    StandardPrincipalData::from(contract_addr.clone()),
                    ContractName::try_from("bad-trait-contract").unwrap(),
                );
                let contract_principal = PrincipalData::Contract(contract_id.clone());

                let tx_bytes = make_contract_call(
                    &contract_sk,
                    5,
                    250,
                    &contract_addr,
                    "use-trait-contract",
                    "baz",
                    &[Value::Principal(contract_principal)],
                );
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                let e = chain_state
                    .will_admit_mempool_tx(
                        &NULL_BURN_STATE_DB,
                        consensus_hash,
                        block_hash,
                        &tx,
                        tx_bytes.len() as u64,
                    )
                    .unwrap_err();
                assert!(if let MemPoolRejection::BadFunctionArgument(_) = e {
                    true
                } else {
                    false
                });
            }
        },
    );

    run_loop.start(num_rounds).unwrap();
}
