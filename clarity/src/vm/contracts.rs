// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::ops::Deref;
use std::sync::Arc;

use super::analysis::ContractAnalysis;
use crate::vm::ast::ContractAST;
#[cfg(feature = "clarity-wasm")]
use crate::vm::clarity_wasm::initialize_contract;
use crate::vm::contexts::{ContractContext, GlobalContext};
use crate::vm::errors::VmExecutionError;
use crate::vm::eval_all;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::version::ClarityVersion;

/// A parsed, shared contract.
// TODO: We could clean this up more; maybe rename to `SharedContract` to make the inner `Arc` more
// explicit, move the `initialize_from_ast` logic to a constructor on `ContractContext` and locate
// this type in the `contexts` module, etc.
#[derive(Clone)]
pub struct Contract {
    contract_context: Arc<ContractContext>,
}

impl Deref for Contract {
    type Target = ContractContext;

    fn deref(&self) -> &ContractContext {
        &self.contract_context
    }
}

impl Contract {
    pub fn initialize_from_ast(
        contract_identifier: QualifiedContractIdentifier,
        contract: &mut ContractAST,
        contract_analysis: &ContractAnalysis,
        sponsor: Option<PrincipalData>,
        global_context: &mut GlobalContext,
        version: ClarityVersion,
    ) -> Result<Contract, VmExecutionError> {
        let mut contract_context = ContractContext::new(contract_identifier, version);
        contract_context.is_deploying = true;

        #[cfg(feature = "clarity-wasm")]
        if let Some(wasm_module) = contract.wasm_module.take() {
            contract_context.set_wasm_module(wasm_module);

            // Initialize the contract via the compiled Wasm module
            global_context.execute(|global_context| {
                initialize_contract(
                    global_context,
                    &mut contract_context,
                    sponsor,
                    contract_analysis,
                )
            })?;
        } else {
            // Interpret the contract
            eval_all(
                &contract.expressions,
                &mut contract_context,
                global_context,
                sponsor,
            )?;
        }

        #[cfg(not(feature = "clarity-wasm"))]
        eval_all(
            &contract.expressions,
            &mut contract_context,
            global_context,
            sponsor,
        )?;

        contract_context.is_deploying = false;
        Ok(Contract {
            contract_context: Arc::new(contract_context),
        })
    }
}

impl From<ContractContext> for Contract {
    fn from(contract_context: ContractContext) -> Self {
        Self {
            contract_context: Arc::new(contract_context),
        }
    }
}
