// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;

use util::boot::boot_code_id;
use vm::callables::FunctionIdentifier;
use vm::contexts::{Environment, LocalContext};
use vm::database::{
    ClarityDatabase, DataMapMetadata, DataVariableMetadata, FungibleTokenMetadata,
    NonFungibleTokenMetadata,
};
use vm::errors::{CheckErrors, InterpreterError, InterpreterResult as Result, RuntimeErrorType};
use vm::representations::ClarityName;
use vm::types::{QualifiedContractIdentifier, Value};

use core::StacksEpochId;

pub type ExtensionFunctionBody = &'static dyn Fn(&mut Environment, &LocalContext) -> Result<Value>;

/// Native function implementation that does the actual work if a publicly-defined contract
/// function.  Used for both Stacks 2.1 extension contracts, as well as native replacements for any
/// existing function.
#[derive(Clone)]
pub struct ExtensionImplementation {
    body: ExtensionFunctionBody,
}

impl ExtensionImplementation {
    pub fn new(body: ExtensionFunctionBody) -> ExtensionImplementation {
        ExtensionImplementation { body }
    }

    pub fn run(&self, env: &mut Environment, context: &LocalContext) -> Result<Value> {
        (self.body)(env, context)
    }
}

/// Really simple no-op native implementation, to prove that this works.
/// (define-public (get-epoch-id) (ok u513)) ;; 0x0201 little-endian
fn extension_get_epoch_id(_env: &mut Environment, _context: &LocalContext) -> Result<Value> {
    Value::okay(Value::UInt(0x0201))
}

/// Load up the set of native function body replacements.
/// For now, they're all loaded into the boot address.
pub fn load_extension_function_implementations(
    mainnet: bool,
    epoch_id: StacksEpochId,
) -> HashMap<FunctionIdentifier, ExtensionImplementation> {
    match epoch_id {
        StacksEpochId::Epoch10 => HashMap::new(),
        StacksEpochId::Epoch20 => HashMap::new(),
        StacksEpochId::Epoch21 => {
            let mut ret = HashMap::new();
            add_native_extension_function_implementations(mainnet, epoch_id, &mut ret);
            ret
        }
    }
}

fn add_native_extension_function_implementations(
    mainnet: bool,
    epoch_id: StacksEpochId,
    ret: &mut HashMap<FunctionIdentifier, ExtensionImplementation>,
) {
    match epoch_id {
        StacksEpochId::Epoch10 => (),
        StacksEpochId::Epoch20 => (),
        StacksEpochId::Epoch21 => {
            let extension_contract_id = boot_code_id("ext-2_1", mainnet);
            for (function_name, native_body) in STACKS_2_1_NATIVE_EXTENSION_FUNCTIONS.iter() {
                let function_id = FunctionIdentifier::new_contract_function(
                    &extension_contract_id,
                    function_name,
                );
                ret.insert(function_id, ExtensionImplementation::new(native_body));
            }
        }
    }
}

pub const STACKS_2_1_NATIVE_EXTENSION_FUNCTIONS: &[(&'static str, ExtensionFunctionBody)] =
    &[("get-epoch-id", &extension_get_epoch_id)];
