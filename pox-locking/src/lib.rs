// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use clarity::boot_util::boot_code_id;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::errors::{Error as ClarityError, RuntimeErrorType};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::Value;
use slog::slog_warn;
use stacks_common::types::StacksEpochId;
use stacks_common::warn;

mod events;
mod pox_1;
mod pox_2;
mod pox_3;

#[derive(Debug)]
pub enum LockingError {
    DefunctPoxContract,
    PoxAlreadyLocked,
    PoxInsufficientBalance,
    PoxExtendNotLocked,
    PoxIncreaseOnV1,
    PoxInvalidIncrease,
}

pub const POX_1_NAME: &'static str = "pox";
pub const POX_2_NAME: &'static str = "pox-2";
pub const POX_3_NAME: &'static str = "pox-3";

/// Handle special cases of contract-calls -- namely, those into PoX that should lock up STX
pub fn handle_contract_call_special_cases(
    global_context: &mut GlobalContext,
    sender: Option<&PrincipalData>,
    _sponsor: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    result: &Value,
) -> Result<(), ClarityError> {
    if *contract_id == boot_code_id(POX_1_NAME, global_context.mainnet) {
        if !pox_1::is_read_only(function_name)
            && global_context.database.get_v1_unlock_height()
                <= global_context.database.get_current_burnchain_block_height()
        {
            // NOTE: get-pox-info is read-only, so it can call old pox v1 stuff
            warn!("PoX-1 function call attempted on an account after v1 unlock height";
                  "v1_unlock_ht" => global_context.database.get_v1_unlock_height(),
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height(),
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(ClarityError::Runtime(
                RuntimeErrorType::DefunctPoxContract,
                None,
            ));
        }
        return pox_1::handle_contract_call(global_context, sender, function_name, result);
    } else if *contract_id == boot_code_id(POX_2_NAME, global_context.mainnet) {
        if !pox_2::is_read_only(function_name) && global_context.epoch_id >= StacksEpochId::Epoch22
        {
            warn!("PoX-2 function call attempted on an account after Epoch 2.2";
                  "v2_unlock_ht" => global_context.database.get_v2_unlock_height(),
                  "current_burn_ht" => global_context.database.get_current_burnchain_block_height(),
                  "function_name" => function_name,
                  "contract_id" => %contract_id
            );
            return Err(ClarityError::Runtime(
                RuntimeErrorType::DefunctPoxContract,
                None,
            ));
        }

        return pox_2::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        );
    } else if *contract_id == boot_code_id(POX_3_NAME, global_context.mainnet) {
        return pox_3::handle_contract_call(
            global_context,
            sender,
            contract_id,
            function_name,
            args,
            result,
        );
    }

    Ok(())
}
