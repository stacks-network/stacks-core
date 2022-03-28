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

use crate::vm::ast::ContractAST;
use crate::vm::callables::CallableType;
use crate::vm::contexts::{ContractContext, Environment, GlobalContext, LocalContext};
use crate::vm::errors::InterpreterResult as Result;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{apply, eval_all, Value};
use std::convert::TryInto;

#[derive(Serialize, Deserialize)]
pub struct Contract {
    pub contract_context: ContractContext,
}

// AARON: this is an increasingly useless wrapper around a ContractContext struct.
//          will probably be removed soon.
impl Contract {
    pub fn initialize_from_ast(
        contract_identifier: QualifiedContractIdentifier,
        contract: &ContractAST,
        global_context: &mut GlobalContext,
    ) -> Result<Contract> {
        let mut contract_context = ContractContext::new(contract_identifier);

        eval_all(&contract.expressions, &mut contract_context, global_context)?;

        Ok(Contract {
            contract_context: contract_context,
        })
    }
}
