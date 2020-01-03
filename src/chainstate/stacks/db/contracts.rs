/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;
use std::collections::{HashSet, HashMap};

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::*;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    query_rows,
    query_count
};

use util::strings::StacksString;

use util::hash::to_hex;

use chainstate::burn::db::burndb::*;

use net::Error as net_error;

use vm::types::{
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::contexts::{
    OwnedEnvironment,
    AssetMap
};

use vm::ast::build_ast;
use vm::analysis::run_analysis;
use vm::types::{
    Value,
    AssetIdentifier
};

use vm::clarity::{
    ClarityBlockConnection,
    ClarityInstance
};

pub use vm::analysis::errors::CheckErrors;
use vm::errors::Error as clarity_vm_error;

use vm::database::ClarityDatabase;

use vm::contracts::Contract;

impl StacksChainState {
    pub fn get_contract<'a>(clarity_tx: &mut ClarityTx<'a>, contract_id: &QualifiedContractIdentifier) -> Result<Option<Contract>, Error> {
        clarity_tx.block.with_clarity_db_readonly(|ref mut db| {
            match db.get_contract(contract_id) {
                Ok(c) => {
                    return Ok(Some(c));
                },
                Err(e) => {
                    match e {
                        clarity_vm_error::Unchecked(ref ce) => {
                            match ce {
                                CheckErrors::NoSuchContract(_) => {
                                    return Ok(None);
                                },
                                _ => {}
                            }
                        },
                        _ => {}
                    }
                    return Err(clarity_error::Interpreter(e));
                }
            }
        }).map_err(Error::ClarityError)
    }
    
    pub fn get_data_var<'a>(clarity_tx: &mut ClarityTx<'a>, contract_id: &QualifiedContractIdentifier, data_var: &str) -> Result<Option<Value>, Error> {
        clarity_tx.block.with_clarity_db_readonly(|ref mut db| {
            match db.lookup_variable(contract_id, data_var) {
                Ok(v) => {
                    return Ok(Some(v));
                },
                Err(e) => {
                    match e {
                        clarity_vm_error::Unchecked(ref ce) => {
                            match ce {
                                CheckErrors::NoSuchDataVariable(_) => {
                                    return Ok(None);
                                },
                                _ => {}
                            }
                        },
                        _ => {}
                    }
                    return Err(clarity_error::Interpreter(e));
                }
            }
        }).map_err(Error::ClarityError)
    }
}

