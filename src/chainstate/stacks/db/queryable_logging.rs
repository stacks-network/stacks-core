//! The methods in this file implement a "queryable" form for logging the outcomes of transactions.
//!
//! Each processed transaction should be logged if it succeeds, logged if it fails with an error,
//! and should be logged each time it is skipped.
//!
//! This way, when debugging a miner, we can run a standard query, and see what happened to the
//! transaction.
//!
/// Logs a queryable message for the case where `txid` has succeeded.
use chainstate::stacks::StacksTransaction;

fn create_transaction_key(tx: &StacksTransaction) {
    format!("Transaction outcome {}:", &tx.txid())
}

/// Logs a queryable message for the case where `txid` has succeeded.
pub fn log_transaction_success(tx: &StacksTransaction) {
    info!("{} successfully processed.", create_transaction_key(tx));
}

/// Logs a queryable message for the case where `txid` has failed
/// with error `err`.
pub fn log_transaction_error(tx: &StacksTransaction, err: &Error) {
    warn!("{} failed with error: ", create_transaction_key(tx), err);
}

/// Logs a queryable message for the case where `tx` has been skipped
/// for reason `reason`.
pub fn log_transaction_skipped(tx: &StacksTransaction, reason: str) {
    info!(
        "{} skipped for reason: ",
        create_transaction_key(tx),
        reason
    );
}
