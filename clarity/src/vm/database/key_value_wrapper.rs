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

use std::hash::Hash;

use rand::{thread_rng, Rng};
use hashbrown::HashMap;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Sha512Trunc256Sum;

use super::clarity_store::{ContractCommitment, SpecialCaseHandler};
use super::structures::{
    ContractAnalysisData, ContractData, GetContractResult, PendingContract, StoredContract,
};
use super::{ClarityBackingStore, ClarityDeserializable};
use crate::vm::analysis::{CheckErrors, ContractAnalysis};
use crate::vm::ast::ContractAST;
use crate::vm::contracts::Contract;
use crate::vm::database::cache::with_clarity_cache;
use crate::vm::database::clarity_store::make_contract_hash_key;
use crate::vm::database::structures::ContractId;
use crate::vm::errors::{InterpreterError, InterpreterResult};
use crate::vm::types::serialization::SerializationError;
use crate::vm::types::{
    QualifiedContractIdentifier, SequenceData, SequenceSubtype, TupleData, TypeSignature,
};
use crate::vm::{ContractContext, StacksEpoch, Value};

#[cfg(rollback_value_check)]
type RollbackValueCheck = String;
#[cfg(not(rollback_value_check))]
type RollbackValueCheck = ();

#[cfg(not(rollback_value_check))]
fn rollback_value_check(_value: &str, _check: &RollbackValueCheck) {}

#[cfg(not(rollback_value_check))]
fn rollback_edits_push<T>(edits: &mut Vec<(T, RollbackValueCheck)>, key: T, _value: &str) {
    edits.push((key, ()));
}
/// This function is used to check the lookup map when committing at the "bottom" 
/// of the wrapper -- i.e., when committing to the underlying store. for the 
/// _unchecked_ implementation this is used to get the edit _value_ out of the
/// lookupmap, for used in the subsequent `put_all_data` command.
#[cfg(not(rollback_value_check))]
fn rollback_check_pre_bottom_commit<T>(
    edits: Vec<(T, RollbackValueCheck)>,
    lookup_map: &mut HashMap<T, Vec<String>>,
) -> Result<Vec<(T, String)>, InterpreterError>
where
    T: Eq + Hash + Clone,
{
    for (_, edit_history) in lookup_map.iter_mut() {
        edit_history.reverse();
    }

    let output = edits
        .into_iter()
        .map(|(key, _)| {
            let value = rollback_lookup_map(&key, &(), lookup_map)?;
            Ok((key, value))
        })
        .collect();

    assert!(lookup_map.is_empty());
    output
}

#[cfg(rollback_value_check)]
fn rollback_value_check(value: &String, check: &RollbackValueCheck) {
    assert_eq!(value, check)
}
#[cfg(rollback_value_check)]
fn rollback_edits_push<T>(edits: &mut Vec<(T, RollbackValueCheck)>, key: T, value: &String)
where
    T: Eq + Hash + Clone,
{
    edits.push((key, value.clone()));
}
/// This function is used to check the lookup map when committing at the "bottom" 
/// of the wrapper -- i.e., when committing to the underlying store.
#[cfg(rollback_value_check)]
fn rollback_check_pre_bottom_commit<T>(
    edits: Vec<(T, RollbackValueCheck)>,
    lookup_map: &mut HashMap<T, Vec<String>>,
) -> Vec<(T, String)>
where
    T: Eq + Hash + Clone,
{
    for (_, edit_history) in lookup_map.iter_mut() {
        edit_history.reverse();
    }
    for (key, value) in edits.iter() {
        rollback_lookup_map(key, &value, lookup_map);
    }
    assert!(lookup_map.is_empty());
    edits
}

/// Result structure for fetched values from the underlying store.
#[derive(Debug)]
pub struct ValueResult {
    pub value: Value,
    pub serialized_byte_len: u64,
}

/// The [RollbackContext] represents a single "frame" of the rollback stack and
/// contains all of the modifications made during its lifetime. This structure
/// is used by the [RollbackWrapper], which employs a stack of these contexts,
/// to track and manage the changes made to both consensus-critical data (`edits`)
/// as well as non-consensus data (`metadata_edits`, `pending_contracts`, and
/// `contract_analyses`).
#[derive(Debug, Default)]
pub struct RollbackContext {
    /// Edits to consensus-critical key-value data.
    edits: Vec<(String, RollbackValueCheck)>,
    /// Edits to non-consensus-critical key-value data.
    metadata_edits: Vec<((QualifiedContractIdentifier, String), RollbackValueCheck)>,
    /// Edits to pending contract data. "Pending" in this context refers to
    /// contracts which have been created but not yet committed to the underlying
    /// store. This data is not consensus-critical as it is locally-generated
    /// representations of Clarity contracts.
    pending_contracts: Vec<PendingContract>,
    /// Edits to pending contract analysis data. "Pending" in this context refers
    /// to contract analyses which have been created but not yet committed to the
    /// underlying store. This data is not consensus-critical as it is locally-generated
    /// representations of Clarity contract analyses.
    contract_analyses: Vec<ContractAnalysis>,
}

pub struct RollbackWrapper<'a> {
    /// Unique id of this [RollbackWrapper] instance.
    id: u32,
    /// Reference to the underlying Clarity backing store.
    store: &'a mut dyn ClarityBackingStore,
    /// Maintains a history of edits for a given key in order of least-recent to 
    /// most-recent at the tail. This allows ~ O(1) lookups, and ~ O(1) commits & 
    /// roll-backs (amortized by # of PUTs).
    lookup_map: HashMap<String, Vec<String>>,
    /// Maintains a history of metadata-edits for a given key in order of least-recent
    /// to most-recent at the tail. This allows ~ O(1) lookups, and ~ O(1) commits &
    /// roll-backs (amortized by # of PUTs). This is used for non-consensus-critical
    /// data.
    metadata_lookup_map: HashMap<(QualifiedContractIdentifier, String), Vec<String>>,
    /// Keeps track of the most recent [RollbackContext], which tells us which edits 
    /// were performed by which context. At the moment, each context's edit history
    /// is a separate [Vec] which must be drained into the parent on commits, meaning that
    /// the amortized cost of committing a value isn't O(1), but actually O(k) where 
    /// k is stack depth.
    ///
    /// TODO: The solution to this is to just have a _single_ edit stack, and merely store indexes
    /// to indicate a given contexts "start depth".
    stack: Vec<RollbackContext>,
    /// Indicates whether or not "get"-methods should query the uncommitted state
    /// of this [RollbackWrapper] instance for data prior to searching the underlying
    /// [ClarityBackingStore]. The default value of this field is `true`.
    query_pending_data: bool,
}

/// Used for preserving rollback data longer than a [ClarityBackingStore] 
/// pointer. This is useful to prevent excessive lifetime parameters in the 
/// database/context and eval code.
#[derive(Debug, Default)]
pub struct RollbackWrapperPersistedLog {
    /// Unique id of the [RollbackWrapper] instance.
    id: u32,
    /// Copy of the `lookup_map` field from the source [RollbackWrapper] instance.
    lookup_map: HashMap<String, Vec<String>>,
    /// Copy of the `metadata_lookup_map` field from the source [RollbackWrapper] 
    /// instance.
    metadata_lookup_map: HashMap<(QualifiedContractIdentifier, String), Vec<String>>,
    /// Copy of the `stack` field from the source [RollbackWrapper] instance.
    stack: Vec<RollbackContext>,
}

impl<'a> From<RollbackWrapper<'a>> for RollbackWrapperPersistedLog {
    /// Allow for the conversion of a [RollbackWrapper] into a 
    /// [RollbackWrapperPersistedLog] using `.from()`/`.into()` syntax.
    fn from(o: RollbackWrapper<'a>) -> RollbackWrapperPersistedLog {
        RollbackWrapperPersistedLog {
            id: o.id,
            lookup_map: o.lookup_map,
            metadata_lookup_map: o.metadata_lookup_map,
            stack: o.stack,
        }
    }
}

impl RollbackWrapperPersistedLog {
    /// Create a new, empty [RollbackWrapperPersistedLog] instance. Note that
    /// in its default state, the instance will not have an ongoing stack frame
    /// and will not be able to perform any operations until a new stack frame
    /// ([RollbackContext])is created using the [Self::nest] method.
    pub fn new() -> RollbackWrapperPersistedLog {
        RollbackWrapperPersistedLog {
            id: thread_rng().gen_range(1000000..9999999),
            lookup_map: HashMap::new(),
            metadata_lookup_map: HashMap::new(),
            stack: Vec::new(),
        }
    }

    /// Creates a new [RollbackContext] and pushes it onto the stack. This is
    /// analogous to a "begin transaction" operation in a database.
    pub fn nest(&mut self) {
        self.stack.push(RollbackContext::default());
    }
}

/// TODO: Document this function
fn rollback_lookup_map<T>(
    key: &T,
    value: &RollbackValueCheck,
    lookup_map: &mut HashMap<T, Vec<String>>,
) -> Result<String, InterpreterError>
where
    T: Eq + Hash + Clone,
{
    let popped_value;
    let remove_edit_deque = {
        let key_edit_history = lookup_map.get_mut(key).ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM had edit log entry, but not lookup_map entry".into(),
            )
        })?;
        popped_value = key_edit_history.pop().ok_or_else(|| {
            InterpreterError::Expect("ERROR: expected value in edit history".into())
        })?;
        rollback_value_check(&popped_value, value);
        key_edit_history.is_empty()
    };
    if remove_edit_deque {
        lookup_map.remove(key);
    }
    Ok(popped_value)
}

impl<'a> RollbackWrapper<'a> {
    /// Creates a new [RollbackWrapper] instance with the provided [ClarityBackingStore]
    /// implementation. 
    ///
    /// The new instance will not have an ongoing stack frame and will
    /// not be able to perform any (write) operations until a new stack frame 
    /// ([RollbackContext]) is created using the [Self::nest] method.
    ///
    /// The instance, by default, will query the uncommitted state of the wrapper for
    /// data prior to searching the underlying [ClarityBackingStore]. This can be
    /// overridden by setting the `query_pending_data` field to `false`.
    pub fn new(store: &'a mut dyn ClarityBackingStore) -> RollbackWrapper {
        RollbackWrapper {
            id: thread_rng().gen_range(1000000..9999999),
            store,
            lookup_map: HashMap::new(),
            metadata_lookup_map: HashMap::new(),
            stack: Vec::new(),
            query_pending_data: true,
        }
    }

    /// Restores a [RollbackWrapper] instance from a [RollbackWrapperPersistedLog]
    /// using the provided [ClarityBackingStore] implementation. The stack and
    /// any uncommitted data will be restored to the state it was in when the
    /// [RollbackWrapperPersistedLog] was created.
    ///
    /// The instance, by default, will query the uncommitted state of the wrapper for
    /// data prior to searching the underlying [ClarityBackingStore], irregardless
    /// of whether or not `query_pending_data` was enabled on the original
    /// [RollbackWrapper]. This can be overridden by setting the `query_pending_data` 
    /// field to `false`.
    pub fn from_persisted_log(
        store: &'a mut dyn ClarityBackingStore,
        log: RollbackWrapperPersistedLog,
    ) -> RollbackWrapper<'a> {
        RollbackWrapper {
            id: log.id,
            store,
            lookup_map: log.lookup_map,
            metadata_lookup_map: log.metadata_lookup_map,
            stack: log.stack,
            query_pending_data: true,
        }
    }

    /// TODO: Document this function
    pub fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        self.store.get_cc_special_cases_handler()
    }

    /// Creates a new [RollbackContext] and pushes it onto the stack. This is
    /// analogous to a "begin transaction" operation in a database.
    pub fn nest(&mut self) {
        self.stack.push(RollbackContext::default());
    }

    /// Rolls-back the current [RollbackContext] and pops it off the stack. any
    /// pending edits in the current "stack frame" will be discarded:
    /// - All pending consensus-critical `edits`.
    /// - All pending non-consensus-critical `metadata_edits`.
    /// - All pending contracts and contract analyses.
    pub fn rollback(&mut self) -> Result<(), InterpreterError> {
        test_debug!(
            "[{}] KV rollback (from depth: {})",
            self.id,
            self.stack.len()
        );
        let mut last_item = self.stack.pop().ok_or_else(|| {
            InterpreterError::Expect("ERROR: Clarity VM attempted to commit past the stack.".into())
        })?;

        last_item.edits.reverse();
        last_item.metadata_edits.reverse();

        for (key, value) in last_item.edits.drain(..) {
            rollback_lookup_map(&key, &value, &mut self.lookup_map)?;
        }

        for (key, value) in last_item.metadata_edits.drain(..) {
            rollback_lookup_map(&key, &value, &mut self.metadata_lookup_map)?;
        }

        for contract in last_item.pending_contracts.drain(..) {
            test_debug!(
                "[{}] ... KV removing pending contract: {}",
                self.id,
                contract.contract.contract_identifier
            );
        }

        for analysis in last_item.contract_analyses.drain(..) {
            test_debug!(
                "[{}] ... KV removing contract analysis: {}",
                self.id,
                analysis.contract_identifier
            );
        }

        Ok(())
    }

    /// Returns the current depth of the rollback stack, i.e. how many [RollbackContext]s
    /// currently exist in the stack.
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Internal convenience method used to walk the rollback stack and find a 
    /// [PendingContract] with the provided contract identifier. This method is
    /// used when querying the uncommitted state of the wrapper for data prior
    /// to searching the underlying [ClarityBackingStore].
    fn find_pending_contract(
        &self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Option<&PendingContract> {
        test_debug!("[{}] KV querying pending data", self.id);
        for ctx in self.stack.iter().rev() {
            for pending_contract in &ctx.pending_contracts {
                test_debug!(
                    "[{}] ... KV checking pending contract: {}",
                    self.id,
                    pending_contract.contract.contract_identifier
                );
                if &pending_contract.contract.contract_identifier == contract_identifier {
                    test_debug!(
                        "[{}] ... KV found pending contract; returning true",
                        self.id
                    );
                    return Some(pending_contract);
                }
            }
        }
        None
    }

    /// Internal convenience method used to walk the rollback stack and find a
    /// [ContractAnalysis] with the provided contract identifier. This method is
    /// used when querying the uncommitted state of the wrapper for data prior
    /// to searching the underlying [ClarityBackingStore].
    fn find_pending_contract_analysis(
        &self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Option<&ContractAnalysis> {
        test_debug!("[{}] KV querying pending data", self.id);
        for ctx in self.stack.iter().rev() {
            for analysis in &ctx.contract_analyses {
                test_debug!(
                    "[{}] ... KV checking pending contract analysis: {}",
                    self.id,
                    analysis.contract_identifier
                );
                if &analysis.contract_identifier == contract_identifier {
                    test_debug!(
                        "[{}] ... KV found pending contract analysis; returning true",
                        self.id
                    );
                    return Some(analysis);
                }
            }
        }
        None
    }

    /// Commits the current [RollbackContext] and pops it off the stack. This
    /// method has two distinct behaviors depending on the current depth of the
    /// rollback stack:
    /// - If the stack is empty, this method will commit all pending edits to the
    ///   underlying [ClarityBackingStore] and clear the rollback stack.
    /// - If the stack is not empty, this method will bubble up all pending edits
    ///   to the next [RollbackContext] in the stack.
    pub fn commit(&mut self) -> Result<(), InterpreterError> {
        let mut last_item = self.stack.pop().ok_or_else(|| {
            InterpreterError::Expect("ERROR: Clarity VM attempted to commit past the stack.".into())
        })?;

        if let Some(next_up) = self.stack.last_mut() {
            //test_debug!("[{}] KV roll-up commit", self.id);
            // bubble up to the next item in the stack
            // last_mut() must exist because of the if-statement
            for (key, value) in last_item.edits.drain(..) {
                next_up.edits.push((key, value));
            }
            for (key, value) in last_item.metadata_edits.drain(..) {
                next_up.metadata_edits.push((key, value));
            }

            next_up
                .pending_contracts
                .append(&mut last_item.pending_contracts);
            next_up
                .contract_analyses
                .append(&mut last_item.contract_analyses);
        } else {
            test_debug!("[{}] KV persist commit", self.id);
            // stack is empty, committing to the backing store
            let all_edits =
                rollback_check_pre_bottom_commit(last_item.edits, &mut self.lookup_map)?;

            if all_edits.len() > 0 {
                test_debug!("[{}] ... KV persisting data: {}", self.id, all_edits.len());
                self.store.put_all_data(all_edits).map_err(|e| {
                    InterpreterError::Expect(format!(
                        "ERROR: Failed to commit data to backing store: {e:?}"
                    ))
                })?;
            }

            let metadata_edits = rollback_check_pre_bottom_commit(
                last_item.metadata_edits,
                &mut self.metadata_lookup_map,
            )?;

            if metadata_edits.len() > 0 {
                test_debug!(
                    "[{}] ... KV persisting metadata: {}",
                    self.id,
                    metadata_edits.len()
                );
                self.store.put_all_metadata(metadata_edits).map_err(|e| {
                    InterpreterError::Expect(format!(
                        "ERROR: Failed to commit data to backing store: {e:?}"
                    ))
                })?;
            }

            for mut contract in last_item.pending_contracts.drain(..) {
                let contract_data = self.store.insert_contract(&mut contract).map_err(|e| {
                    InterpreterError::Expect(format!(
                        "ERROR: failed to insert contract into backing store: {e:?}"
                    ))
                })?;

                test_debug!(
                    "[{}] ... KV persisting contract: {}",
                    self.id,
                    contract.contract.contract_identifier
                );

                with_clarity_cache(|cache| 
                    cache.push_contract_id(
                        contract.contract.contract_identifier, 
                        contract_data.id
                    ));
            }

            for analysis in last_item.contract_analyses.drain(..) {
                test_debug!(
                    "[{}] ... KV persisting analysis: {}",
                    self.id,
                    analysis.contract_identifier
                );

                let id = match with_clarity_cache(|cache| cache.try_get_contract_id(&analysis.contract_identifier)) {
                    Some(id) => id,
                    None => self.store
                                .get_contract_id(ContractId::QualifiedContractIdentifier(&analysis.contract_identifier))
                                    .map_err(|e| InterpreterError::Expect("ERROR: error while attempting to get contract id from backing store".into()))?
                                    .ok_or_else(|| InterpreterError::Expect("ERROR: failed to map contract identifier to contract id when storing analysis".into()))?
                };

                self.store
                    .insert_contract_analysis(ContractId::Id(id), &analysis)
                    .map_err(|e| {
                        InterpreterError::Expect(
                            format!("ERROR: failed to insert contract analysis into backing store: {e:?}"))
                    })?;
            }
        }

        test_debug!("... KV commit complete; stack depth: {}", self.stack.len());

        Ok(())
    }
}

/// Internal convenience method used to push a new consensus-critical key-value
/// pair onto the rollback stack.
fn inner_put<T>(
    lookup_map: &mut HashMap<T, Vec<String>>,
    edits: &mut Vec<(T, RollbackValueCheck)>,
    key: T,
    value: String,
) where
    T: Eq + Hash + Clone,
{
    let key_edit_deque = lookup_map.entry(key.clone()).or_insert_with(|| Vec::new());
    rollback_edits_push(edits, key, &value);
    key_edit_deque.push(value);
}

impl<'a> RollbackWrapper<'a> {
    /// Pushes a [ContractAnalysis] instance onto the uncommitted state of this
    /// [RollbackWrapper] instance, in the current [RollbackContext]. 
    ///
    /// If a [ContractAnalysis] already exists for the provided [QualifiedContractIdentifier],
    /// it will be replaced by the provided [ContractAnalysis] without warning.
    ///
    /// This function with panic if there is no active [RollbackContext]. To begin
    /// a new nested context, the [Self::nest] function must be called.
    /// 
    /// To persist these changes, the [Self::commit] function must be called.
    /// To roll-back these changes, the [Self::rollback] function must be called.
    pub fn put_contract_analysis(&mut self, analysis: &ContractAnalysis) {
        test_debug!("[{}] KV put contract analysis: {}",
            self.id,
            analysis.contract_identifier
        );

        // Iterate over the stack and remove any existing contract analysis 
        // with the same identifier.
        for frame in self.stack.iter_mut() {
            frame
                .contract_analyses
                .iter()
                .position(|x| x.contract_identifier == analysis.contract_identifier)
                .map(|x| {
                    test_debug!(
                        "[{}] KV removing pending contract analysis: {}",
                        self.id,
                        analysis.contract_identifier
                    );
                    frame.pending_contracts.remove(x)
                });
        }

        // Retrieve the current context, panicking if there is none.
        let current = self
            .stack
            .last_mut()
            // TODO: Improve error handling here.
            .expect("ERROR: Clarity VM attempted PUT ANALYSIS on non-nested context.");

        // Push the provided contract analysis onto the current context.
        current.contract_analyses.push(analysis.clone());
    }

    /// Adds the provided contract to the uncommitted state of this [RollbackWrapper]
    /// instance, in the current [RollbackContext]. If there is no current context 
    /// this function will panic.
    ///
    /// To begin a new stack frame, the [Self::nest] function must be called.
    /// To persist these changes, the [Self::commit] function must be called.
    /// To roll-back these changes, the [Self::rollback] function must be called.
    pub fn put_contract(
        &mut self,
        src: &str,
        contract: ContractContext,
    ) -> InterpreterResult<()> {
        let content_hash = Sha512Trunc256Sum::from_data(src.as_bytes());
        let key = make_contract_hash_key(&contract.contract_identifier);
        let value = self.store.make_contract_commitment(content_hash);
        self.put_data(&key, &value)?;

        test_debug!("[{}] KV put contract: {}",
            self.id,
            contract.contract_identifier
        );
        test_debug!("[{}] ... with k/v: {} / {}", self.id, key, value);

        // Iterate over the stack and remove any existing contract with the same
        // identifier.
        for frame in self.stack.iter_mut() {
            frame
                .pending_contracts
                .iter()
                .position(|x| x.contract.contract_identifier == contract.contract_identifier)
                .map(|x| {
                    test_debug!(
                        "[{}] KV removing pending contract: {}",
                        self.id,
                        contract.contract_identifier
                    );
                    frame.pending_contracts.remove(x)
                });
        }

        // Retrieve the current context, panicking if there is none.
        let current = self
            .stack
            .last_mut()
            // TODO: Improve error handling here.
            .expect("ERROR: Clarity VM attempted PUT CONTRACT on non-nested context.");

        // Push the provided contract onto the current context.
        current.pending_contracts.push(PendingContract {
            source: src.into(),
            contract,
        });

        Ok(())
    }

    /// Retrieves the contract context for a given contract identifier. If
    /// `query_pending_data` is true on this [RollbackWrapper] instance,
    /// it will first check the uncommitted state of this instance for the
    /// contract. If it is not found, it will query the underlying store.
    ///
    /// NOTE: Removed the requirement for a nested context for this function,
    /// which was previously enforced by the `get_data` and `get_metadata`
    /// functions.
    pub fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> InterpreterResult<GetContractResult> {
        test_debug!("[{}] KV get contract for {}", self.id, contract_identifier);
        if self.query_pending_data {
            if let Some(pending_contract) = self.find_pending_contract(contract_identifier) {
                test_debug!(
                    "[{}] ... KV found pending contract; returning true",
                    self.id
                );
                return Ok(GetContractResult::Pending(pending_contract.clone()));
            }
        }

        match self.store.get_contract(contract_identifier)? {
            Some(stored) => Ok(GetContractResult::Stored(stored)),
            None => Ok(GetContractResult::NotFound),
        }
    }

    /// Retrieves the contract analysis for the given contract identifier. If
    /// `query_pending_data` is true on this [RollbackWrapper] instance, it will
    /// first check the uncommitted state of this instance for the analysis. If
    /// it is not found, it will then query the underlying store.
    ///
    /// Returns [InterpreterError::Expect] if the contract analysis is not found.
    pub(crate) fn get_contract_analysis(
        &mut self, 
        contract_identifier: &QualifiedContractIdentifier
    ) -> InterpreterResult<Option<ContractAnalysis>> {
        test_debug!("[{}] KV get contract analysis for {}", self.id, contract_identifier);
        if self.query_pending_data {
            if let Some(analysis) = self.find_pending_contract_analysis(contract_identifier) {
                test_debug!(
                    "[{}] ... KV found pending contract analysis; returning true",
                    self.id
                );
                return Ok(Some(analysis.clone()));
            }
        }

        self.store.get_contract_analysis(
            ContractId::QualifiedContractIdentifier(contract_identifier)
        )
    }

    /// Checks if a contract exists. If `query_pending_data` is true on this
    /// [RollbackWrapper] instance, it will first check the uncommitted state
    /// of this instance for the contract. If it is not found, it will query the
    /// underlying store.
    ///
    /// NOTE: Removed the requirement for a nested context for this function,
    /// which was previously enforced by the `get_data` and `get_metadata` functions.
    pub fn has_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> InterpreterResult<bool> {
        test_debug!("[{}] KV  has contract for {}", self.id, contract_identifier);
        if self.query_pending_data {
            if self.find_pending_contract(contract_identifier).is_some() {
                trace!("... KV found pending contract; returning true");
                return Ok(true);
            }
        }

        test_debug!("[{}] ... KV querying store", self.id);
        Ok(self.store.contract_exists(contract_identifier)?)
    }

    /// Retrieves and calculates the contract size (size of the contract's source code
    /// in bytes + the contract's data size) for a given contract identifier. If
    /// `query_pending_data` is true on this [RollbackWrapper] instance, it will first
    /// check the uncommitted state of this instance for the contract. If it is not found,
    /// it will query the underlying store.
    ///
    /// NOTE: Removed the requirement for a nested context for this function, which
    /// was previously enforced by the `get_data` and `get_metadata` functions.
    pub fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> InterpreterResult<u32> {
        test_debug!(
            "[{}] KV get contract size for {}",
            self.id,
            contract_identifier
        );
        if self.query_pending_data {
            if let Some(pending_contract) = self.find_pending_contract(contract_identifier) {
                trace!("... KV found pending contract; returning true");
                return Ok(pending_contract.source.len() as u32
                    + pending_contract.contract.data_size as u32);
            }
        }

        test_debug!("[{}] ... KV querying store", self.id);
        Ok(self.store.get_contract_size(contract_identifier)?)
    }

    /// Appends the provided key and value to the uncommitted state of this
    /// [RollbackWrapper] instance, in the current stack frame. If there is
    /// no current stack frame, this function will panic.
    ///
    /// To begin a new stack frame, the `nest` function must be called.
    /// To persist these changes, the `commit` function must be called.
    pub fn put_data(&mut self, key: &str, value: &str) -> InterpreterResult<()> {
        // Retrieve the current context, panicking if there is none.
        let current = self.stack.last_mut().ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM attempted PUT on non-nested context.".into(),
            )
        })?;

        // Push the provided key and value onto the current context.
        Ok(inner_put(
            &mut self.lookup_map,
            &mut current.edits,
            key.to_string(),
            value.to_string(),
        ))
    }

    ///
    /// `query_pending_data` indicates whether the rollback wrapper should query the rollback
    ///    wrapper's pending data on reads. This is set to `false` during (at-block ...) closures,
    ///    and `true` otherwise.
    ///
    pub fn set_block_hash(
        &mut self,
        bhh: StacksBlockId,
        query_pending_data: bool,
    ) -> InterpreterResult<StacksBlockId> {
        // Use and_then so that query_pending_data is only set once set_block_hash succeeds
        // this doesn't matter in practice, because a set_block_hash failure always aborts
        // the transaction with a runtime error (destroying its environment), but it's much
        // better practice to do this, especially if the abort behavior changes in the future.
        let block_id = self.store.set_block_hash(bhh)?;
        self.query_pending_data = query_pending_data;
        Ok(block_id)
    }

    /// This function will only return commitment proofs for values _already_ materialized
    /// in the underlying [ClarityBackingStore], otherwise it returns [None].
    pub fn get_with_proof<T>(&mut self, key: &str) -> InterpreterResult<Option<(T, Vec<u8>)>>
    where
        T: ClarityDeserializable<T>,
    {
        self.store
            .get_data_with_proof(key)?
            .map(|(value, proof)| Ok((T::deserialize(&value)?, proof)))
            .transpose()
    }

    /// Retrieves a consensus-critical value with the provided key. If `query_pending_data`
    /// is true on this [RollbackWrapper] instance, it will first check the uncommitted state
    /// of this instance for the value. If it is not found, it will query the underlying store.
    pub fn get_data<T>(&mut self, key: &str) -> InterpreterResult<Option<T>>
    where
        T: ClarityDeserializable<T>,
    {
        // Retrieve the current context, returning an error if there is none.
        self.stack.last().ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM attempted GET on non-nested context.".into(),
            )
        })?;

        // If `query_pending_data` is true, check the uncommitted state of this instance for the value.
        if self.query_pending_data {
            if let Some(pending_value) = self.lookup_map.get(key).and_then(|x| x.last()) {
                // if there's pending data and we're querying pending data, return here
                return Some(T::deserialize(pending_value)).transpose();
            }
        }

        // Otherwise, lookup from the underlying store.
        self.store
            .get_data(key)?
            .map(|x| T::deserialize(&x))
            .transpose()
    }

    /// Attempts to deserialize a [Value] from a hex string.
    pub fn deserialize_value(
        value_hex: &str,
        expected: &TypeSignature,
        epoch: &StacksEpochId,
    ) -> std::result::Result<ValueResult, SerializationError> {
        let serialized_byte_len = value_hex.len() as u64 / 2;
        let sanitize = epoch.value_sanitizing();
        let value = Value::try_deserialize_hex(value_hex, expected, sanitize)?;

        Ok(ValueResult {
            value,
            serialized_byte_len,
        })
    }

    /// Get a Clarity value from the underlying Clarity KV store.
    /// Returns Some if found, with the Clarity Value and the serialized byte 
    /// length of the value.
    pub fn get_value(
        &mut self,
        key: &str,
        expected: &TypeSignature,
        epoch: &StacksEpochId,
    ) -> Result<Option<ValueResult>, SerializationError> {
        // Retrieve the current context, returning an error if there is none.
        self.stack.last().ok_or_else(|| {
            SerializationError::DeserializationError(
                "ERROR: Clarity VM attempted GET on non-nested context.".into(),
            )
        })?;

        // If `query_pending_data` is true, check the uncommitted state of this instance for the value.
        if self.query_pending_data {
            if let Some(x) = self.lookup_map.get(key).and_then(|x| x.last()) {
                return Ok(Some(Self::deserialize_value(x, expected, epoch)?));
            }
        }

        // Otherwise, lookup from the underlying store.
        let stored_data = self.store.get_data(key).map_err(|_| {
            SerializationError::DeserializationError("ERROR: Clarity backing store failure".into())
        })?;

        // If a value was found, deserialize it and return it, otherwise
        // return `None`.
        match stored_data {
            Some(x) => Ok(Some(Self::deserialize_value(&x, expected, epoch)?)),
            None => Ok(None),
        }
    }

    /// This is the height we are currently constructing. It comes from the MARF.
    pub fn get_current_block_height(&mut self) -> u32 {
        self.store.get_current_block_height()
    }

    /// Is None if `block_height` >= the "currently" under construction Stacks block height.
    pub fn get_block_header_hash(&mut self, block_height: u32) -> Option<StacksBlockId> {
        self.store.get_block_at_height(block_height)
    }

    /// Creates the initial contract commitment for a new contract. This creates
    /// a key in the form of "clarity-contract::{contract.display()}"
    pub fn prepare_for_contract_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        content_hash: Sha512Trunc256Sum,
    ) -> InterpreterResult<()> {
        let key = make_contract_hash_key(contract);
        let value = self.store.make_contract_commitment(content_hash);
        self.put_data(&key, &value)
    }

    /// Inserts a metadata key-value pair into the uncommitted state of this
    /// [RollbackWrapper] instance, in the current [RollbackContext]. If there is no
    /// current context, this function will return an error.
    pub fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<(), InterpreterError> {
        // Retrieve the current context, returning an error if there is none.
        let current = self.stack.last_mut().ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM attempted PUT on non-nested context.".into(),
            )
        })?;

        let metadata_key = (contract.clone(), key.to_string());

        Ok(inner_put(
            &mut self.metadata_lookup_map,
            &mut current.metadata_edits,
            metadata_key,
            value.to_string(),
        ))
    }

    /// Retrieves a non-consensus-critical metadata value with the provided key.
    /// Throws a NoSuchContract error if contract doesn't exist, returns [None] 
    /// if there is no such metadata field.
    pub fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        // Retrieve the current context, returning an error if there is none.
        self.stack.last().ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM attempted GET on non-nested context.".into(),
            )
        })?;

        // This is THEORETICALLY a spurious clone, but it's hard to turn something like
        //  (&A, &B) into &(A, B).
        let metadata_key = (contract.clone(), key.to_string());

        let lookup_result = if self.query_pending_data {
            self.metadata_lookup_map
                .get(&metadata_key)
                .and_then(|x| x.last().cloned())
        } else {
            None
        };

        match lookup_result {
            Some(x) => Ok(Some(x)),
            None => Ok(self.store.get_metadata(contract, key)?),
        }
    }

    /// Retrieves a non-consensus-critical metadata value with the provided key
    /// and at the specified Stacks block-height. Throws a NoSuchContract error
    /// if contract doesn't exist, returns [None] if there is no such metadata field.
    pub fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> InterpreterResult<Option<String>> {
        self.stack.last().ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM attempted GET on non-nested context.".into(),
            )
        })?;

        // This is THEORETICALLY a spurious clone, but it's hard to turn something like
        //  (&A, &B) into &(A, B).
        let metadata_key = (contract.clone(), key.to_string());
        let lookup_result = if self.query_pending_data {
            self.metadata_lookup_map
                .get(&metadata_key)
                .and_then(|x| x.last().cloned())
        } else {
            None
        };

        match lookup_result {
            Some(x) => Ok(Some(x)),
            None => self.store.get_metadata_manual(at_height, contract, key),
        }
    }

    /// Checks for the existence of a consensus-critical key-value entry with the
    /// provided key. If `query_pending_data` is true on this [RollbackWrapper]
    /// instance, it will first check its uncommitted state for the value. If it
    /// is not found, it will query the underlying store.
    ///
    /// Returns [true] if the key exists, [false] otherwise.
    pub fn has_data_entry(&mut self, key: &str) -> InterpreterResult<bool> {
        self.stack.last().ok_or_else(|| {
            InterpreterError::Expect(
                "ERROR: Clarity VM attempted GET on non-nested context.".into(),
            )
        })?;
        if self.query_pending_data && self.lookup_map.contains_key(key) {
            Ok(true)
        } else {
            Ok(self.store.has_data_entry(key)?)
        }
    }

    /// Checks for the existence of a non-consensus-critical metadata entry with
    /// the provided key. If `query_pending_data` is true on this [RollbackWrapper]
    /// instance, it will first check its uncommitted state for the value. If it
    /// is not found, it will query the underlying store.
    ///
    /// Returns [true] if the key exists, [false] otherwise.
    pub fn has_metadata_entry(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> bool {
        matches!(self.get_metadata(contract, key), Ok(Some(_)))
    }
}
