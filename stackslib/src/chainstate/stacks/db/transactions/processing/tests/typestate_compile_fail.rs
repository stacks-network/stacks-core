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

//! Compile-fail coverage for invalid [`TransactionProcessor`](super::TransactionProcessor)
//! typestate transitions.

/// Full processing requires an explicit resource policy.
///
/// ```compile_fail,E0599
/// use blockstack_lib::chainstate::stacks::db::transactions::TransactionProcessor;
/// use blockstack_lib::chainstate::stacks::db::ClarityTx;
/// use blockstack_lib::chainstate::stacks::StacksTransaction;
///
/// fn process_without_a_resource_policy(
///     clarity_tx: &mut ClarityTx<'_, '_>,
///     tx: &StacksTransaction,
/// ) {
///     TransactionProcessor::from(tx)
///         .execute()
///         .using_clarity_tx(clarity_tx)
///         .process();
/// }
/// ```
struct ProcessRequiresResourcePolicy;

/// Complete processing requires an explicit execute-or-skip disposition.
///
/// ```compile_fail,E0599
/// use blockstack_lib::chainstate::stacks::db::transactions::TransactionProcessor;
/// use blockstack_lib::chainstate::stacks::db::ClarityTx;
/// use blockstack_lib::chainstate::stacks::StacksTransaction;
///
/// fn bind_full_context_without_a_disposition(
///     clarity_tx: &mut ClarityTx<'_, '_>,
///     tx: &StacksTransaction,
/// ) {
///     TransactionProcessor::from(tx).using_clarity_tx(clarity_tx);
/// }
/// ```
struct FullContextRequiresDisposition;

/// Full processing requires a complete Clarity context.
///
/// ```compile_fail,E0599
/// use blockstack_lib::chainstate::stacks::db::transactions::TransactionProcessor;
/// use blockstack_lib::chainstate::stacks::StacksTransaction;
///
/// fn process_without_a_clarity_context(tx: &StacksTransaction) {
///     TransactionProcessor::from(tx)
///         .execute()
///         .with_unlimited_resource_policy()
///         .process();
/// }
/// ```
struct ProcessRequiresClarityContext;

/// Payload-only context cannot perform complete transaction processing.
///
/// ```compile_fail,E0599
/// use blockstack_lib::chainstate::stacks::db::transactions::TransactionProcessor;
/// use blockstack_lib::chainstate::stacks::{StacksAccount, StacksTransaction};
/// use blockstack_lib::clarity_vm::clarity::ClarityTransactionConnection;
///
/// fn fully_process_with_a_payload_context(
///     clarity_tx: &mut ClarityTransactionConnection<'_, '_>,
///     tx: &StacksTransaction,
///     origin_account: &StacksAccount,
/// ) {
///     TransactionProcessor::from(tx)
///         .using_clarity_transaction(clarity_tx, origin_account)
///         .with_unlimited_resource_policy()
///         .process();
/// }
/// ```
struct FullProcessingRequiresFullContext;

/// Full context cannot invoke the payload-only terminal operation.
///
/// ```compile_fail,E0599
/// use blockstack_lib::chainstate::stacks::db::transactions::TransactionProcessor;
/// use blockstack_lib::chainstate::stacks::db::ClarityTx;
/// use blockstack_lib::chainstate::stacks::StacksTransaction;
///
/// fn process_only_the_payload_with_a_full_context(
///     clarity_tx: &mut ClarityTx<'_, '_>,
///     tx: &StacksTransaction,
/// ) {
///     TransactionProcessor::from(tx)
///         .execute()
///         .using_clarity_tx(clarity_tx)
///         .with_unlimited_resource_policy()
///         .process_payload();
/// }
/// ```
struct PayloadProcessingRequiresPayloadContext;
