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

//! The VM calls the contract-call special-case handler for exactly the callees the
//! backing store supplies it for.

use std::cell::RefCell;

use rstest::rstest;
use rusqlite::Connection;
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::Sha512Trunc256Sum;

use super::top_level_env;
use crate::vm::ClarityVersion;
use crate::vm::contexts::GlobalContext;
use crate::vm::database::{
    ClarityBackingStore, ClarityDatabase, MemoryBackingStore, NULL_BURN_STATE_DB, NULL_HEADER_DB,
    SpecialCaseHandler,
};
use crate::vm::errors::VmExecutionError;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value};

/// A handler call: the called contract and function, its arguments and its result.
type HandlerCall = (QualifiedContractIdentifier, String, Vec<Value>, Value);

thread_local! {
    static HANDLER_CALLS: RefCell<Vec<HandlerCall>> = const { RefCell::new(Vec::new()) };
}

fn record_handler_call(
    _global_context: &mut GlobalContext,
    _sender: Option<&PrincipalData>,
    _sponsor: Option<&PrincipalData>,
    contract: &QualifiedContractIdentifier,
    function: &str,
    args: &[Value],
    result: &Value,
) -> Result<(), VmExecutionError> {
    HANDLER_CALLS.with_borrow_mut(|calls| {
        calls.push((
            contract.clone(),
            function.to_string(),
            args.to_vec(),
            result.clone(),
        ))
    });
    Ok(())
}

/// A [`MemoryBackingStore`] that supplies [`record_handler_call`] for calls into
/// `handler_for` only.
struct RecordingStore {
    store: MemoryBackingStore,
    handler_for: Option<QualifiedContractIdentifier>,
}

impl ClarityBackingStore for RecordingStore {
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<(), VmExecutionError> {
        self.store.put_all_data(items)
    }
    fn get_data(&mut self, key: &str) -> Result<Option<String>, VmExecutionError> {
        self.store.get_data(key)
    }
    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>, VmExecutionError> {
        self.store.get_data_from_path(hash)
    }
    fn get_data_with_proof(
        &mut self,
        key: &str,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        self.store.get_data_with_proof(key)
    }
    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        self.store.get_data_with_proof_from_path(hash)
    }
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId, VmExecutionError> {
        self.store.set_block_hash(bhh)
    }
    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        self.store.get_block_at_height(height)
    }
    fn get_current_block_height(&mut self) -> u32 {
        self.store.get_current_block_height()
    }
    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.store.get_open_chain_tip_height()
    }
    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        self.store.get_open_chain_tip()
    }
    fn get_side_store(&mut self) -> &Connection {
        self.store.get_side_store()
    }
    fn get_cc_special_cases_handler(
        &self,
        contract: &QualifiedContractIdentifier,
    ) -> Option<SpecialCaseHandler> {
        if self.handler_for.as_ref() == Some(contract) {
            Some(&record_handler_call)
        } else {
            None
        }
    }
    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum), VmExecutionError> {
        self.store.get_contract_hash(contract)
    }
    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<(), VmExecutionError> {
        self.store.insert_metadata(contract, key, value)
    }
    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        self.store.get_metadata(contract, key)
    }
    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        self.store.get_metadata_manual(at_height, contract, key)
    }
}

const CALLEE: &str = "(define-public (succeed (n uint)) (ok n))
     (define-public (fail (n uint)) (err n))
     (define-public (abort (n uint)) (ok (- u0 n)))";

/// Deploys the callee and a caller that forwards to it, then runs the callee's
/// `function` with `u5`, either as the transaction itself or through the caller's
/// `contract-call?`. Returns the result and the handler calls it made.
fn run_call(
    handler_supplied: bool,
    function: &str,
    via_contract_call: bool,
) -> (Result<Value, VmExecutionError>, Vec<HandlerCall>) {
    HANDLER_CALLS.with_borrow_mut(Vec::clear);
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    let caller_source =
        format!("(define-public (call (n uint)) (contract-call? '{callee} {function} n))");

    let mut store = RecordingStore {
        store: MemoryBackingStore::new(),
        handler_for: handler_supplied.then(|| callee.clone()),
    };
    let db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);
    let mut env = top_level_env(db, StacksEpochId::latest());
    for (contract, source) in [(&callee, CALLEE), (&caller, caller_source.as_str())] {
        env.initialize_versioned_contract(contract.clone(), ClarityVersion::Clarity2, source, None)
            .unwrap();
    }
    let (target, target_function) = if via_contract_call {
        (caller, "call")
    } else {
        (callee, function)
    };
    let result = env
        .execute_transaction(
            StandardPrincipalData::transient().into(),
            None,
            target,
            target_function,
            vec![Value::UInt(5)],
        )
        .map(|(result, ..)| result);
    (result, HANDLER_CALLS.take())
}

/// A callee the store supplies the handler for reaches it once, with its arguments and
/// its result, including an `err` response, whether the call is the transaction itself
/// or a `contract-call?`. Other callees never reach it.
#[rstest]
fn test_special_case_handler_only_when_supplied(
    #[values(true, false)] handler_supplied: bool,
    #[values("succeed", "fail")] function: &str,
    #[values(false, true)] via_contract_call: bool,
) {
    let (result, handler_calls) = run_call(handler_supplied, function, via_contract_call);

    let expected_result = if function == "succeed" {
        Value::okay(Value::UInt(5))
    } else {
        Value::error(Value::UInt(5))
    }
    .unwrap();
    assert_eq!(result.unwrap(), expected_result);
    let expected_calls = if handler_supplied {
        vec![(
            QualifiedContractIdentifier::local("callee").unwrap(),
            function.to_string(),
            vec![Value::UInt(5)],
            expected_result,
        )]
    } else {
        vec![]
    };
    assert_eq!(handler_calls, expected_calls);
}

/// A call that fails at runtime does not reach the handler, since it returned no value.
#[rstest]
fn test_special_case_handler_not_called_when_call_fails(
    #[values(false, true)] via_contract_call: bool,
) {
    let (result, handler_calls) = run_call(true, "abort", via_contract_call);
    assert!(result.is_err());
    assert!(handler_calls.is_empty());
}
