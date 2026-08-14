// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Typestate-based orchestration for complete and payload-only Stacks transaction processing.

use clarity::vm::hooks::EvalHook;
use clarity::vm::ClarityVersion;

use super::TransactionNonceMismatch;
use crate::burnchains::Txid;
use crate::chainstate::stacks::db::{ClarityTx, DBConfig, StacksAccount, StacksChainState};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::miner::TransactionResourceBudgets;
use crate::chainstate::stacks::{
    Error, StacksTransaction, TransactionAuthVerificationMode, TransactionPayload,
};
use crate::clarity_vm::clarity::{ClarityConnection, ClarityTransactionConnection};
use crate::core::StacksEpochId;

mod accounts;
mod payload;
pub mod poison_microblock;
mod post_conditions;
#[cfg(any(test, doctest))]
mod tests;
mod validation;

#[cfg(test)]
pub use post_conditions::check as check_transaction_postconditions_for_test;

fn noop_transaction_check(_receipt: &StacksTransactionReceipt) -> Result<(), Error> {
    Ok(())
}

/// Receipt-check function used by a newly configured [`TransactionProcessor`].
pub type DefaultReceiptCheck = fn(&StacksTransactionReceipt) -> Result<(), Error>;

/// Indicates that a [`TransactionProcessor`] still requires a resource policy.
#[doc(hidden)]
pub struct NeedsResourcePolicy;

/// Contains the resource policy selected for a [`TransactionProcessor`].
#[doc(hidden)]
pub struct Ready {
    resource_budgets: TransactionResourceBudgets,
}

/// A transaction selected for admission checks, full processing, or payload-only processing.
#[doc(hidden)]
pub struct SelectedTransaction<'tx> {
    tx: &'tx StacksTransaction,
}

/// A transaction paired with its full-processing disposition.
#[doc(hidden)]
pub struct FullTransaction<'tx> {
    tx: &'tx StacksTransaction,
    skip_problematic: Option<u8>,
}

/// Complete transaction-processing state backed by an open Clarity block.
#[doc(hidden)]
pub struct FullContext<'tx, 'clarity, 'block, 'conn> {
    tx: &'tx StacksTransaction,
    skip_problematic: Option<u8>,
    clarity_tx: &'clarity mut ClarityTx<'block, 'conn>,
}

/// Payload-only state backed by a caller-owned Clarity transaction.
#[doc(hidden)]
pub struct PayloadContext<'tx, 'clarity, 'store, 'db, 'origin> {
    tx: &'tx StacksTransaction,
    clarity_tx: &'clarity mut ClarityTransactionConnection<'store, 'db>,
    origin_account: &'origin StacksAccount,
}

/// A transaction paired with the disposition required during full processing.
///
/// Passing this value directly into [`TransactionProcessor`] prevents replay callers from
/// accidentally discarding a known skip disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxToProcess<'tx> {
    /// Execute the transaction's payload normally.
    Execute(&'tx StacksTransaction),
    /// Charge fees and advance nonces without executing the payload.
    Skip {
        /// Transaction being processed.
        tx: &'tx StacksTransaction,
        /// Opaque category recorded in the resulting receipt.
        category: u8,
    },
}

impl<'tx> TxToProcess<'tx> {
    /// Wraps a transaction list with the ordinary execute disposition.
    pub fn all_execute(
        txs: &'tx [StacksTransaction],
    ) -> impl Iterator<Item = TxToProcess<'tx>> + 'tx {
        txs.iter().map(TxToProcess::Execute)
    }

    /// Returns the transaction ID without discarding its disposition.
    pub fn txid(&self) -> Txid {
        match self {
            Self::Execute(tx) | Self::Skip { tx, .. } => tx.txid(),
        }
    }

    /// Returns the payload without discarding its disposition.
    pub fn payload(&self) -> &'tx TransactionPayload {
        match self {
            Self::Execute(tx) | Self::Skip { tx, .. } => &tx.payload,
        }
    }

    /// Returns whether payload execution must be skipped.
    pub fn is_problematic(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }

    /// Returns the raw transaction, deliberately ignoring its disposition.
    ///
    /// Do not use this on a processing path; convert the complete value into a
    /// [`TransactionProcessor`] so the disposition is preserved.
    pub fn tx_ignoring_problematic_state(&self) -> &'tx StacksTransaction {
        match self {
            Self::Execute(tx) | Self::Skip { tx, .. } => tx,
        }
    }
}

/// Configures and processes one Stacks transaction.
///
/// The lifecycle state proves which transaction and Clarity context are
/// available. An independent resource typestate requires an explicit limited or
/// unlimited policy before either terminal operation is available.
pub struct TransactionProcessor<
    'hooks,
    State,
    Resources = NeedsResourcePolicy,
    Check = DefaultReceiptCheck,
> {
    state: State,
    resources: Resources,
    quiet: bool,
    check: Check,
    eval_hook: Option<&'hooks mut dyn EvalHook>,
}

/// Constructs a processor in the [`SelectedTransaction`] typestate with no resource policy yet.
impl<'tx> From<&'tx StacksTransaction> for TransactionProcessor<'static, SelectedTransaction<'tx>> {
    fn from(tx: &'tx StacksTransaction) -> Self {
        Self {
            state: SelectedTransaction { tx },
            resources: NeedsResourcePolicy,
            quiet: false,
            check: noop_transaction_check,
            eval_hook: None,
        }
    }
}

/// Constructs a processor in the [`FullTransaction`] typestate, preserving whether the selected
/// transaction should execute or be skipped, with no resource policy yet.
impl<'tx> From<TxToProcess<'tx>> for TransactionProcessor<'static, FullTransaction<'tx>> {
    fn from(tx_to_process: TxToProcess<'tx>) -> Self {
        match tx_to_process {
            TxToProcess::Execute(tx) => TransactionProcessor::from(tx).execute(),
            TxToProcess::Skip { tx, category } => TransactionProcessor::from(tx).skipped(category),
        }
    }
}

/// Transitions any processor awaiting a resource policy from [`NeedsResourcePolicy`] to [`Ready`].
impl<'hooks, State, Check> TransactionProcessor<'hooks, State, NeedsResourcePolicy, Check> {
    /// Selects deterministic transaction processing without resource limits
    /// ([`TransactionResourceBudgets::unlimited`]).
    pub fn with_unlimited_resource_policy(
        self,
    ) -> TransactionProcessor<'hooks, State, Ready, Check> {
        self.with_budgets(TransactionResourceBudgets::unlimited())
    }

    /// Selects the caller-supplied resource policy for transaction processing.
    pub fn with_resource_policy(
        self,
        resource_budgets: TransactionResourceBudgets,
    ) -> TransactionProcessor<'hooks, State, Ready, Check> {
        self.with_budgets(resource_budgets)
    }

    fn with_budgets(
        self,
        resource_budgets: TransactionResourceBudgets,
    ) -> TransactionProcessor<'hooks, State, Ready, Check> {
        TransactionProcessor {
            state: self.state,
            resources: Ready { resource_budgets },
            quiet: self.quiet,
            check: self.check,
            eval_hook: self.eval_hook,
        }
    }
}

/// Provides validation, disposition, and payload-context selection for [`SelectedTransaction`].
impl<'tx, Resources> TransactionProcessor<'static, SelectedTransaction<'tx>, Resources> {
    /// Checks transaction properties that do not require mutable chainstate.
    pub fn precheck(
        &self,
        config: &DBConfig,
        epoch_id: StacksEpochId,
        auth_verification_mode_override: Option<TransactionAuthVerificationMode>,
    ) -> Result<(), Error> {
        validation::precheck_transaction(
            config,
            self.state.tx,
            epoch_id,
            auth_verification_mode_override,
        )
    }

    /// Checks the transaction's origin and payer nonces against chainstate.
    pub fn check_nonces<T: ClarityConnection>(
        &self,
        clarity_tx: &mut T,
        quiet: bool,
    ) -> Result<
        (StacksAccount, StacksAccount),
        (TransactionNonceMismatch, (StacksAccount, StacksAccount)),
    > {
        accounts::check_transaction_nonces(clarity_tx, self.state.tx, quiet)
    }

    /// Selects the Clarity version for this transaction at `epoch_id`.
    pub fn clarity_version(&self, epoch_id: StacksEpochId) -> ClarityVersion {
        match &self.state.tx.payload {
            TransactionPayload::SmartContract(_, version) => {
                version.unwrap_or(ClarityVersion::default_for_epoch(epoch_id))
            }
            _ => ClarityVersion::default_for_epoch(epoch_id),
        }
    }

    /// Selects full execution, asserting that no problematic marker applies and the transaction
    /// payload must run.
    ///
    /// Use [`Self::skipped`] when the transaction carries a problematic marker.
    pub fn execute(self) -> TransactionProcessor<'static, FullTransaction<'tx>, Resources> {
        TransactionProcessor {
            state: FullTransaction {
                tx: self.state.tx,
                skip_problematic: None,
            },
            resources: self.resources,
            quiet: self.quiet,
            check: self.check,
            eval_hook: self.eval_hook,
        }
    }

    /// Marks this transaction as problematic so full processing skips its payload.
    pub fn skipped(
        self,
        category: u8,
    ) -> TransactionProcessor<'static, FullTransaction<'tx>, Resources> {
        TransactionProcessor {
            state: FullTransaction {
                tx: self.state.tx,
                skip_problematic: Some(category),
            },
            resources: self.resources,
            quiet: self.quiet,
            check: self.check,
            eval_hook: self.eval_hook,
        }
    }

    /// Supplies an existing Clarity transaction for payload-only processing.
    pub fn using_clarity_transaction<'clarity, 'store, 'db, 'origin>(
        self,
        clarity_tx: &'clarity mut ClarityTransactionConnection<'store, 'db>,
        origin_account: &'origin StacksAccount,
    ) -> TransactionProcessor<'static, PayloadContext<'tx, 'clarity, 'store, 'db, 'origin>, Resources>
    {
        TransactionProcessor {
            state: PayloadContext {
                tx: self.state.tx,
                clarity_tx,
                origin_account,
            },
            resources: self.resources,
            quiet: self.quiet,
            check: self.check,
            eval_hook: self.eval_hook,
        }
    }
}

/// Binds a transaction with an execute-or-skip disposition to the [`FullContext`] typestate.
impl<'tx, Resources> TransactionProcessor<'static, FullTransaction<'tx>, Resources> {
    /// Supplies the context for complete transaction processing.
    pub fn using_clarity_tx<'clarity, 'block, 'conn>(
        self,
        clarity_tx: &'clarity mut ClarityTx<'block, 'conn>,
    ) -> TransactionProcessor<'static, FullContext<'tx, 'clarity, 'block, 'conn>, Resources> {
        TransactionProcessor {
            state: FullContext {
                tx: self.state.tx,
                skip_problematic: self.state.skip_problematic,
                clarity_tx,
            },
            resources: self.resources,
            quiet: self.quiet,
            check: self.check,
            eval_hook: self.eval_hook,
        }
    }
}

/// Provides final configuration and processing only for a [`FullContext`] with a [`Ready`]
/// resource policy.
impl<'tx, 'clarity, 'block, 'conn, 'hooks, Check>
    TransactionProcessor<'hooks, FullContext<'tx, 'clarity, 'block, 'conn>, Ready, Check>
where
    Check: FnMut(&StacksTransactionReceipt) -> Result<(), Error>,
{
    /// Controls whether transaction-processing logs should be quiet.
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Adds a receipt validation callback that runs before commit.
    pub fn with_check<C>(
        self,
        check: C,
    ) -> TransactionProcessor<'hooks, FullContext<'tx, 'clarity, 'block, 'conn>, Ready, C>
    where
        C: FnMut(&StacksTransactionReceipt) -> Result<(), Error>,
    {
        TransactionProcessor {
            state: self.state,
            resources: self.resources,
            quiet: self.quiet,
            check,
            eval_hook: self.eval_hook,
        }
    }

    /// Attaches a Clarity evaluation hook to this transaction.
    pub fn with_eval_hook<'new_hooks>(
        self,
        eval_hook: &'new_hooks mut dyn EvalHook,
    ) -> TransactionProcessor<'new_hooks, FullContext<'tx, 'clarity, 'block, 'conn>, Ready, Check>
    {
        TransactionProcessor {
            state: self.state,
            resources: self.resources,
            quiet: self.quiet,
            check: self.check,
            eval_hook: Some(eval_hook),
        }
    }

    /// Processes the transaction and commits its state changes on success.
    pub fn process(mut self) -> Result<(u64, StacksTransactionReceipt), Error> {
        let tx = self.state.tx;
        let skip_problematic = self.state.skip_problematic;
        debug!("Process transaction {} ({})", tx.txid(), tx.payload.name());
        let epoch = self.state.clarity_tx.get_epoch();

        if skip_problematic.is_some() && epoch < StacksEpochId::Epoch40 {
            return Err(Error::InvalidStacksTransaction(
                format!(
                    "problematic_txs markers are not allowed before Epoch 4.0 (got epoch {epoch})"
                ),
                false,
            ));
        }

        validation::precheck_transaction(&self.state.clarity_tx.config, tx, epoch, None)?;

        let mut transaction = self
            .state
            .clarity_tx
            .connection()
            .start_transaction_processing();
        if let Some(eval_hook) = self.eval_hook.take() {
            transaction.set_eval_hook(eval_hook);
        }

        let fee = tx.get_tx_fee();
        let tx_receipt = if epoch >= StacksEpochId::Epoch21 {
            // 2.1 and later: pay tx fee, then process transaction
            let (_origin_account, payer_account) =
                accounts::check_transaction_nonces(&mut transaction, tx, self.quiet)?;

            let payer_address = payer_account.principal.clone();
            let payer_nonce = payer_account.nonce;
            accounts::pay_transaction_fee(&mut transaction, fee, payer_account)?;

            // origin balance may have changed (e.g. if the origin paid the tx fee), so reload the account
            let origin_account =
                StacksChainState::get_account(&mut transaction, &tx.origin_address().into());

            let tx_receipt = match skip_problematic {
                Some(category) => {
                    debug!(
                        "Skip-execute problematic transaction {} ({}) category={}",
                        tx.txid(),
                        tx.payload.name(),
                        category,
                    );
                    StacksTransactionReceipt::from_problematic_skipped(tx.clone(), category)
                }
                None => payload::process(
                    &mut transaction,
                    tx,
                    &origin_account,
                    &self.resources.resource_budgets,
                )?,
            };

            // update the account nonces
            StacksChainState::update_account_nonce(
                &mut transaction,
                &origin_account.principal,
                origin_account.nonce,
            );
            if origin_account.principal != payer_address {
                // payer is a different account, so update its nonce too
                StacksChainState::update_account_nonce(
                    &mut transaction,
                    &payer_address,
                    payer_nonce,
                );
            }

            tx_receipt
        } else {
            debug_assert!(
                skip_problematic.is_none(),
                "problematic transaction reached pre-2.1 processing"
            );

            // pre-2.1: process transaction, then pay tx fee
            let (origin_account, payer_account) =
                accounts::check_transaction_nonces(&mut transaction, tx, self.quiet)?;

            let tx_receipt = payload::process(
                &mut transaction,
                tx,
                &origin_account,
                &TransactionResourceBudgets::unlimited(),
            )?;

            let new_payer_account = accounts::get_payer_account(&mut transaction, tx);
            accounts::pay_transaction_fee(&mut transaction, fee, new_payer_account)?;

            // update the account nonces
            StacksChainState::update_account_nonce(
                &mut transaction,
                &origin_account.principal,
                origin_account.nonce,
            );
            if origin_account != payer_account {
                StacksChainState::update_account_nonce(
                    &mut transaction,
                    &payer_account.principal,
                    payer_account.nonce,
                );
            }

            tx_receipt
        };
        // The legacy skipped-transaction path did not run receipt checks.
        if skip_problematic.is_none() {
            (self.check)(&tx_receipt)?;
        }

        transaction
            .commit()
            .map_err(|e| Error::InvalidStacksTransaction(e.to_string(), false))?;

        Ok((fee, tx_receipt))
    }
}

/// Provides payload-only processing for a [`PayloadContext`] with a [`Ready`] resource policy.
impl<'tx, 'clarity, 'store, 'db, 'origin>
    TransactionProcessor<'static, PayloadContext<'tx, 'clarity, 'store, 'db, 'origin>, Ready>
{
    /// Processes only the payload inside the caller-owned Clarity transaction.
    ///
    /// Payload-only callers that need tracing attach the hook directly to their
    /// caller-owned [`ClarityTransactionConnection`] before processing.
    pub fn process_payload(self) -> Result<StacksTransactionReceipt, Error> {
        payload::process(
            self.state.clarity_tx,
            self.state.tx,
            self.state.origin_account,
            &self.resources.resource_budgets,
        )
    }
}
