use std::{env, path::PathBuf};
use time::Instant;

use rand::seq::SliceRandom;
use rand::Rng;

use cost_estimates::metrics::CostMetric;
use cost_estimates::{EstimatorError, FeeEstimator};
use vm::costs::ExecutionCost;

use chainstate::burn::ConsensusHash;
use chainstate::stacks::db::{StacksEpochReceipt, StacksHeaderInfo};
use chainstate::stacks::events::StacksTransactionReceipt;
use types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksBlockHeader, StacksWorkScore};
use types::proof::TrieHash;
use util::hash::{to_hex, Hash160, Sha512Trunc256Sum};
use util::vrf::VRFProof;

use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, TokenTransferMemo, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use crate::cost_estimates::CostEstimator;
use crate::cost_estimates::FeeRateEstimate;
use crate::cost_estimates::PessimisticEstimator;
use crate::types::chainstate::StacksAddress;
use crate::vm::types::{PrincipalData, StandardPrincipalData};
use crate::vm::Value;

fn instantiate_test_db() -> PessimisticEstimator {
    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(&format!("fee_db_{}.sqlite", &to_hex(&random_bytes)[0..8]));

    PessimisticEstimator::open(&path).expect("Test failure: could not open fee rate DB")
}

/// This struct implements a simple metric used for unit testing the
/// the fee rate estimator. It always returns a cost of 1, making the
/// fee rate of a transaction always equal to the paid fee.
struct TestCostMetric;

impl CostMetric for TestCostMetric {
    fn from_cost_and_len(&self, _cost: &ExecutionCost, _tx_len: u64) -> u64 {
        1
    }

    fn from_len(&self, _tx_len: u64) -> u64 {
        1
    }
}

#[test]
fn test_empty_pessimistic_estimator() {
    let estimator = instantiate_test_db();
    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_transfer_payload())
            .expect_err("Empty pessimistic estimator should error."),
        EstimatorError::NoEstimateAvailable
    );
}

fn make_block_receipt(tx_receipts: Vec<StacksTransactionReceipt>) -> StacksEpochReceipt {
    StacksEpochReceipt {
        header: StacksHeaderInfo {
            anchored_header: StacksBlockHeader {
                version: 1,
                total_work: StacksWorkScore { burn: 1, work: 1 },
                proof: VRFProof::empty(),
                parent_block: BlockHeaderHash([0; 32]),
                parent_microblock: BlockHeaderHash([0; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                microblock_pubkey_hash: Hash160([0; 20]),
            },
            microblock_tail: None,
            block_height: 1,
            index_root: TrieHash([0; 32]),
            consensus_hash: ConsensusHash([2; 20]),
            burn_header_hash: BurnchainHeaderHash([1; 32]),
            burn_header_height: 2,
            burn_header_timestamp: 2,
            anchored_block_size: 1,
        },
        tx_receipts,
        matured_rewards: vec![],
        matured_rewards_info: None,
        parent_microblocks_cost: ExecutionCost::zero(),
        anchored_block_cost: ExecutionCost::zero(),
        parent_burn_block_hash: BurnchainHeaderHash([0; 32]),
        parent_burn_block_height: 1,
        parent_burn_block_timestamp: 1,
    }
}

fn make_dummy_coinbase_tx() -> StacksTransaction {
    StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::Coinbase(CoinbasePayload([0; 32])),
    )
}

fn make_dummy_transfer_payload() -> TransactionPayload {
    TransactionPayload::TokenTransfer(
        PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
        1,
        TokenTransferMemo([0; 34]),
    )
}

fn make_dummy_transfer_tx(fee: u64) -> StacksTransactionReceipt {
    let mut tx = StacksTransaction::new(
        TransactionVersion::Mainnet,
        TransactionAuth::Standard(TransactionSpendingCondition::new_initial_sighash()),
        TransactionPayload::TokenTransfer(
            PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
            1,
            TokenTransferMemo([0; 34]),
        ),
    );
    tx.set_tx_fee(fee);

    StacksTransactionReceipt::from_stx_transfer(
        tx,
        vec![],
        Value::okay(Value::Bool(true)).unwrap(),
        ExecutionCost::zero(),
    )
}

fn make_dummy_cc_payload(contract_name: &str, function_name: &str) -> TransactionPayload {
    TransactionPayload::ContractCall(TransactionContractCall {
        address: StacksAddress::new(0, Hash160([0; 20])),
        contract_name: contract_name.into(),
        function_name: function_name.into(),
        function_args: vec![],
    })
}

#[test]
/// This tests the PessimisticEstimator as a unit (i.e., separate
/// from the trait auto-impl method) by providing payload inputs
/// to produce the expected pessimistic result (i.e., mean over a 10-sample
/// window, where the window only updates if the new entry would make a dimension
/// worse).
fn test_pessimistic_cost_estimator() {
    let mut estimator = instantiate_test_db();
    estimator.notify_event(
        &make_dummy_cc_payload("contract-1", "func1"),
        &ExecutionCost {
            write_length: 1,
            write_count: 1,
            read_length: 1,
            read_count: 1,
            runtime: 1,
        },
    );

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 1,
            write_count: 1,
            read_length: 1,
            read_count: 1,
            runtime: 1,
        }
    );

    estimator.notify_event(
        &make_dummy_cc_payload("contract-1", "func1"),
        &ExecutionCost {
            write_length: 9,
            write_count: 5,
            read_length: 3,
            read_count: 1,
            runtime: 1,
        },
    );

    assert_eq!(
        estimator
            .estimate_cost(&make_dummy_cc_payload("contract-1", "func1"))
            .expect("Should be able to provide cost estimate now"),
        ExecutionCost {
            write_length: 5,
            write_count: 3,
            read_length: 2,
            read_count: 1,
            runtime: 1,
        }
    );
}
