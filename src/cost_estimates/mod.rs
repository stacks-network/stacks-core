use std::collections::HashMap;
use std::iter::FromIterator;
use std::{error::Error, fmt::Display};

use chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use chainstate::stacks::{StacksBlock, TransactionPayload};
use vm::costs::ExecutionCost;

use crate::burnchains::Txid;

pub mod pessimistic;
pub use self::pessimistic::PessimisticEstimator;

pub trait CostEstimator {
    /// This method is invoked by the `stacks-node` to update the cost estimator with a new
    ///  cost measurement. The given `tx` had a measured cost of `actual_cost`.
    fn notify_event(
        &mut self,
        tx: &TransactionPayload,
        actual_cost: &ExecutionCost,
    ) -> Result<(), EstimatorError>;
    /// This method is used by a stacks-node to obtain an estimate for a given transaction payload.
    /// If the estimator cannot provide an accurate estimate for a given payload, it should return
    /// `EstimatorError::NoEstimateAvailable`
    fn estimate_cost(&self, tx: &TransactionPayload) -> Result<ExecutionCost, EstimatorError>;
    fn notify_block(&mut self, block: &StacksBlock, receipts: &[StacksTransactionReceipt]) {
        // create a Map from txid -> index in block
        let tx_index: HashMap<Txid, usize> = HashMap::from_iter(
            block
                .txs
                .iter()
                .enumerate()
                .map(|(tx_ix, tx)| (tx.txid(), tx_ix)),
        );
        // iterate over receipts, and for all the tx receipts, notify the event
        for current_receipt in receipts.iter() {
            let current_txid = match current_receipt.transaction {
                TransactionOrigin::Burn(_) => continue,
                TransactionOrigin::Stacks(ref tx) => tx.txid(),
            };
            let tx_payload = match tx_index.get(&current_txid) {
                Some(block_index) => &block.txs[*block_index].payload,
                None => continue,
            };

            if let Err(e) = self.notify_event(tx_payload, &current_receipt.execution_cost) {
                info!("CostEstimator failed to process event";
                      "txid" => %current_txid,
                      "stacks_block" => %block.header.block_hash(),
                      "error" => %e,
                      "execution_cost" => %current_receipt.execution_cost);
            }
        }
    }
}

#[derive(Debug)]
pub enum EstimatorError {
    NoEstimateAvailable,
}

impl Error for EstimatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for EstimatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EstimatorError::NoEstimateAvailable => {
                write!(f, "No estimate available for the provided payload.")
            }
        }
    }
}

struct LogEstimator;

impl CostEstimator for LogEstimator {
    fn notify_event(
        &mut self,
        tx: &TransactionPayload,
        actual_cost: &ExecutionCost,
    ) -> Result<(), EstimatorError> {
        let (tx_descriptor, arg_size) = match tx {
            TransactionPayload::TokenTransfer(..) => ("stx-transfer".to_string(), 1),
            TransactionPayload::ContractCall(cc) => (
                format!("cc:{}.{}", cc.contract_name, cc.function_name),
                cc.function_args
                    .iter()
                    .fold(0, |acc, value| acc + value.size() as usize),
            ),
            TransactionPayload::SmartContract(sc) => {
                ("contract-publish".to_string(), sc.code_body.len())
            }
            // ignore poison microblock and coinbase events
            TransactionPayload::PoisonMicroblock(_, _) | TransactionPayload::Coinbase(_) => {
                return Ok(())
            }
        };
        info!(
            "{}, {}, {}, {}, {}, {}, {}",
            tx_descriptor,
            arg_size,
            actual_cost.runtime,
            actual_cost.write_count,
            actual_cost.write_length,
            actual_cost.read_length,
            actual_cost.read_count
        );
        Ok(())
    }

    fn estimate_cost(&self, _tx: &TransactionPayload) -> Result<ExecutionCost, EstimatorError> {
        todo!()
    }
}
