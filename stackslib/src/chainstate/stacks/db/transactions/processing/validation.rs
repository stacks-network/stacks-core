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

use clarity::vm::ClarityVersion;

use crate::chainstate::stacks::db::DBConfig;
use crate::chainstate::stacks::{
    Error, NonfungibleConditionCode, StacksTransaction, TransactionAuthVerificationMode,
    TransactionPayload, TransactionPostCondition, TransactionPostConditionMode, TransactionVersion,
};
use crate::core::StacksEpochId;

/// Pre-check a transaction -- make sure it's well-formed.
///
/// If `auth_verification_mode_override` is `Some(_)`, it specifies whether transaction signatures
/// should be verified to be the low-S variant, or if high-S is allowed. If it's `None`, this
/// decision is made based on consensus rules for the specified epoch.
pub fn precheck_transaction(
    config: &DBConfig,
    tx: &StacksTransaction,
    epoch_id: StacksEpochId,
    auth_verification_mode_override: Option<TransactionAuthVerificationMode>,
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
    let verification_mode = auth_verification_mode_override.unwrap_or_else(|| {
        if epoch_id.allows_tx_signatures_with_high_s() {
            TransactionAuthVerificationMode::AllowHighS
        } else {
            TransactionAuthVerificationMode::EnforceLowS
        }
    });

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

    // check if post-condition mode is supported in this epoch
    if tx.post_condition_mode == TransactionPostConditionMode::Originator
        && !epoch_id.supports_sip040_post_conditions()
    {
        let msg = "Invalid Stacks transaction: Originator post-condition mode is not supported before Stacks 3.4".to_string();
        info!("{}", &msg; "txid" => %tx.txid());
        return Err(Error::InvalidStacksTransaction(msg, false));
    }
    // check if MaybeSent NFT post-conditions are supported in this epoch
    if !epoch_id.supports_sip040_post_conditions() {
        for post_condition in tx.post_conditions.iter() {
            if let TransactionPostCondition::Nonfungible(_, _, _, condition_code) = post_condition {
                if *condition_code == NonfungibleConditionCode::MaybeSent {
                    let msg = "Invalid Stacks transaction: NFT MaybeSent post-condition is not supported before Stacks 3.4".to_string();
                    info!("{}", &msg; "txid" => %tx.txid());
                    return Err(Error::InvalidStacksTransaction(msg, false));
                }
            }
        }
    }
    // check if Staking/Pox post-conditions are supported in this epoch
    if !epoch_id.supports_staking_post_conditions() {
        for post_condition in tx.post_conditions.iter() {
            if matches!(
                post_condition,
                TransactionPostCondition::Staking(..) | TransactionPostCondition::Pox(..)
            ) {
                let msg = "Invalid Stacks transaction: Staking/Pox post-condition is not supported before Stacks 4.0".to_string();
                info!("{}", &msg; "txid" => %tx.txid());
                return Err(Error::InvalidStacksTransaction(msg, false));
            }
        }
    }

    // check that the requested Clarity version is supported in this epoch.
    // Only a versioned smart-contract deploy can pin a specific version;
    // every other transaction implicitly uses the epoch default. A version
    // newer than the epoch allows is statically invalid, so reject it
    // here.
    if let TransactionPayload::SmartContract(_, Some(clarity_version)) = &tx.payload {
        let max_version = ClarityVersion::default_for_epoch(epoch_id);
        if *clarity_version > max_version {
            let msg = format!(
                "Invalid transaction {}: asks for {clarity_version}, but current epoch {epoch_id} only supports up to {max_version}",
                tx.txid()
            );
            info!("{msg}");
            return Err(Error::InvalidStacksTransaction(msg, false));
        }
    }

    Ok(())
}
