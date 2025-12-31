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

pub use clarity::vm::analysis::errors::RuntimeAnalysisError;
use clarity::vm::contracts::Contract;
use clarity::vm::errors::VmExecutionError;
use clarity::vm::types::{QualifiedContractIdentifier, Value};

use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::{Error, *};
use crate::clarity_vm::clarity::ClarityConnection;

impl StacksChainState {
    pub fn get_contract<T: ClarityConnection>(
        clarity_tx: &mut T,
        contract_id: &QualifiedContractIdentifier,
    ) -> Result<Option<Contract>, Error> {
        clarity_tx
            .with_clarity_db_readonly(|ref mut db| match db.get_contract(contract_id) {
                Ok(c) => Ok(Some(c)),
                Err(VmExecutionError::RuntimeCheck(RuntimeAnalysisError::NoSuchContract(_))) => {
                    Ok(None)
                }
                Err(e) => Err(ClarityError::Interpreter(e)),
            })
            .map_err(Error::ClarityError)
    }

    pub fn get_data_var<T: ClarityConnection>(
        clarity_tx: &mut T,
        contract_id: &QualifiedContractIdentifier,
        data_var: &str,
    ) -> Result<Option<Value>, Error> {
        let epoch = clarity_tx.get_epoch();
        clarity_tx
            .with_clarity_db_readonly(|ref mut db| {
                match db.lookup_variable_unknown_descriptor(contract_id, data_var, &epoch) {
                    Ok(c) => Ok(Some(c)),
                    Err(VmExecutionError::RuntimeCheck(RuntimeAnalysisError::NoSuchDataVariable(
                        _,
                    ))) => Ok(None),
                    Err(e) => Err(ClarityError::Interpreter(e)),
                }
            })
            .map_err(Error::ClarityError)
    }
}
