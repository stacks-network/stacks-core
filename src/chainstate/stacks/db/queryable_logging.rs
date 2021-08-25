//! The methods in this file implement a "queryable" form for logging the outcomes of transactions.
//!
//! Each processed transaction should be logged if it succeeds, logged if it fails with an error,
//! and should be logged each time it is skipped.
//!
//! This way, when debugging a miner, we can run a standard query, and see what happened to the
//! transaction.
//!
use chainstate::stacks::Error;
/// Logs a queryable message for the case where `txid` has succeeded.
use chainstate::stacks::StacksTransaction;

/// Returns a prefix for a "queryable logging" statement. This is the "queryable" part, which is to
/// say that the prefix will be the same no matter what the outcome is, so that a fixed regex will
/// match this part for any transaction.
///
/// Format looks like this:
/// "Transaction outcome for tx=491493d01fc8c0f21f0891ad7c378bfb9c7b83142524f3320ea609e6b5cffa90: "
fn create_transaction_key(tx: &StacksTransaction) -> String {
    format!("Transaction outcome for tx={}:", &tx.txid())
}

/// Logs a queryable message for the case where `txid` has succeeded.
pub fn log_transaction_success(tx: &StacksTransaction) {
    info!("{} successfully processed.", create_transaction_key(tx));
}

/// Logs a queryable message for the case where `txid` has failed
/// with error `err`.
pub fn log_transaction_error(tx: &StacksTransaction, err: &Error) {
    warn!("{} failed with error: {}", create_transaction_key(tx), err);
}

/// Logs a queryable message for the case where `tx` has been skipped
/// for reason `reason`.
pub fn log_transaction_skipped(tx: &StacksTransaction, reason: String) {
    info!(
        "{} skipped for reason: {}",
        create_transaction_key(tx),
        reason
    );
}
