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

//! Account and fee operations used during transaction processing.

use crate::chainstate::stacks::db::transactions::TransactionNonceMismatch;
use crate::chainstate::stacks::db::{StacksAccount, StacksChainState};
use crate::chainstate::stacks::{Error, StacksTransaction};
use crate::clarity_vm::clarity::{ClarityConnection, ClarityTransactionConnection};

/// Get the payer account
pub fn get_payer_account<T: ClarityConnection>(
    clarity_tx: &mut T,
    tx: &StacksTransaction,
) -> StacksAccount {
    // who's paying the fee?
    let payer_account = if let Some(sponsor_address) = tx.sponsor_address() {
        let payer_account = StacksChainState::get_account(clarity_tx, &sponsor_address.into());
        payer_account
    } else {
        let origin_account = StacksChainState::get_account(clarity_tx, &tx.origin_address().into());
        origin_account
    };

    payer_account
}

/// Check the account nonces for the supplied stacks transaction,
///   returning the origin and payer accounts if valid.
pub fn check_transaction_nonces<T: ClarityConnection>(
    clarity_tx: &mut T,
    tx: &StacksTransaction,
    quiet: bool,
) -> Result<
    (StacksAccount, StacksAccount),
    (TransactionNonceMismatch, (StacksAccount, StacksAccount)),
> {
    // who's sending it?
    let origin = tx.get_origin();
    let origin_account = StacksChainState::get_account(clarity_tx, &tx.origin_address().into());

    // who's paying the fee?
    let payer_account = if let Some(sponsor_address) = tx.sponsor_address() {
        let payer = tx.get_payer();
        let payer_account = StacksChainState::get_account(clarity_tx, &sponsor_address.into());

        if payer.nonce() != payer_account.nonce {
            let e = TransactionNonceMismatch {
                expected: payer_account.nonce,
                actual: payer.nonce(),
                txid: tx.txid(),
                principal: payer_account.principal.clone(),
                is_origin: false,
                quiet,
            };
            if !quiet {
                warn!("{e}");
            }
            return Err((e, (origin_account, payer_account)));
        }

        payer_account
    } else {
        origin_account.clone()
    };

    // check nonces
    if origin.nonce() != origin_account.nonce {
        let e = TransactionNonceMismatch {
            expected: origin_account.nonce,
            actual: origin.nonce(),
            txid: tx.txid(),
            principal: origin_account.principal.clone(),
            is_origin: true,
            quiet,
        };
        if !quiet {
            warn!("{e}");
        }
        return Err((e, (origin_account, payer_account)));
    }

    Ok((origin_account, payer_account))
}

/// Pay the transaction fee (but don't credit it to the miner yet).
///
/// - Does not touch the account nonce.
/// - Consumes the account object, since it invalidates it.
pub fn pay_transaction_fee(
    clarity_tx: &mut ClarityTransactionConnection,
    fee: u64,
    payer_account: StacksAccount,
) -> Result<u64, Error> {
    let (cur_burn_block_height, v1_unlock_ht, v2_unlock_ht, v3_unlock_ht, v4_unlock_ht) =
        clarity_tx.with_clarity_db_readonly(|ref mut db| {
            let res: Result<_, Error> = Ok((
                db.get_current_burnchain_block_height()?,
                db.get_v1_unlock_height(),
                db.get_v2_unlock_height()?,
                db.get_v3_unlock_height()?,
                db.get_v4_unlock_height()?,
            ));
            res
        })?;

    let consolidated_balance = payer_account
        .stx_balance
        .get_available_balance_at_burn_block(
            u64::from(cur_burn_block_height),
            v1_unlock_ht,
            v2_unlock_ht,
            v3_unlock_ht,
            v4_unlock_ht,
        )?;

    if consolidated_balance < u128::from(fee) {
        return Err(Error::InvalidFee);
    }

    StacksChainState::account_debit(clarity_tx, &payer_account.principal, fee);
    Ok(fee)
}
