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

//! Static validation performed before transaction execution.

use crate::chainstate::stacks::db::DBConfig;
use crate::chainstate::stacks::{
    Error, StacksTransaction, TransactionAuthVerificationMode, TransactionPayload,
    TransactionVersion,
};
use crate::core::StacksEpochId;

/// Pre-check a transaction -- make sure it's well-formed.
pub fn precheck_transaction(
    config: &DBConfig,
    tx: &StacksTransaction,
    epoch_id: StacksEpochId,
) -> Result<(), Error> {
    // valid auth?
    if !tx.auth.is_supported_in_epoch(epoch_id) {
        let msg = format!(
            "Invalid tx {}: authentication mode not supported in Epoch {epoch_id}",
            tx.txid()
        );
        warn!("{msg}");

        return Err(Error::InvalidStacksTransaction(msg, false));
    }
    let verification_mode = if epoch_id.allows_tx_signatures_with_high_s() {
        TransactionAuthVerificationMode::AllowHighS
    } else {
        TransactionAuthVerificationMode::EnforceLowS
    };

    tx.verify(verification_mode)?;

    // destined for us?
    if config.chain_id != tx.chain_id {
        let msg = format!(
            "Invalid tx {}: invalid chain ID {} (expected {})",
            tx.txid(),
            tx.chain_id,
            config.chain_id
        );
        warn!("{}", &msg);

        return Err(Error::InvalidStacksTransaction(msg, false));
    }

    match tx.version {
        TransactionVersion::Mainnet => {
            if !config.mainnet {
                let msg = format!("Invalid tx {}: on testnet; got mainnet", tx.txid());
                warn!("{}", &msg);

                return Err(Error::InvalidStacksTransaction(msg, false));
            }
        }
        TransactionVersion::Testnet => {
            if config.mainnet {
                let msg = format!("Invalid tx {}: on mainnet; got testnet", tx.txid());
                warn!("{}", &msg);

                return Err(Error::InvalidStacksTransaction(msg, false));
            }
        }
    }

    stacks_transactions::check_post_conditions_supported_in_epoch(
        &tx.post_conditions,
        &tx.post_condition_mode,
        epoch_id,
    )
    .map_err(|reason| {
        let msg = format!("Invalid Stacks transaction: {reason}");
        info!("{}", &msg; "txid" => %tx.txid());
        Error::InvalidStacksTransaction(msg, false)
    })?;

    // Same rule as static block validation, so a block that would fail
    // here is never staged.
    if let TransactionPayload::SmartContract(_, Some(clarity_version)) = &tx.payload {
        stacks_transactions::check_versioned_deploy_supported_in_epoch(*clarity_version, epoch_id)
            .map_err(|reason| {
                let msg = format!("Invalid transaction {}: {reason}", tx.txid());
                info!("{msg}");
                Error::InvalidStacksTransaction(msg, false)
            })?;
    }

    // Same rule as static block validation, so a block that would fail
    // there is never mined or staged.
    stacks_transactions::check_contract_names_supported_in_epoch(
        &tx.payload,
        &tx.post_conditions,
        epoch_id,
    )
    .map_err(|reason| {
        let msg = format!("Invalid transaction {}: {reason}", tx.txid());
        info!("{msg}");
        Error::InvalidStacksTransaction(msg, false)
    })?;

    Ok(())
}
