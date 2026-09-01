// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use std::{cmp, fmt};

use costs_1::Costs1;
use costs_2::Costs2;
use costs_2_testnet::Costs2Testnet;
use costs_3::Costs3;
use costs_4::Costs4;
use costs_5::Costs5;
use serde::{Deserialize, Serialize};
use stacks_common::types::StacksEpochId;

use super::errors::{RuntimeCheckErrorKind, RuntimeError};
use crate::boot_util::boot_code_id;
use crate::vm::contexts::{ExecutionState, GlobalContext, InvocationContext};
use crate::vm::contracts::Contract;
use crate::vm::costs::cost_functions::ClarityCostFunction;
pub use crate::vm::costs::errors::CostErrors;
pub use crate::vm::costs::execution_cost::{CostOverflowingMath, ExecutionCost};
use crate::vm::database::ClarityDatabase;
use crate::vm::database::clarity_store::NullBackingStore;
use crate::vm::errors::VmExecutionError;
use crate::vm::types::Value::UInt;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, TypeSignature};
use crate::vm::{CallStack, LocalContext, SymbolicExpression, Value};
pub mod constants;
pub mod cost_functions;
#[allow(unused_variables)]
pub mod costs_1;
#[allow(unused_variables)]
pub mod costs_2;
#[allow(unused_variables)]
pub mod costs_2_testnet;
#[allow(unused_variables)]
pub mod costs_3;
#[allow(unused_variables)]
pub mod costs_4;
pub mod costs_5;
pub mod errors;
pub mod execution_cost;

pub const CLARITY_MEMORY_LIMIT: u64 = 100 * 1000 * 1000;

// TODO: factor out into a boot lib?
pub const COSTS_1_NAME: &str = "costs";
pub const COSTS_2_NAME: &str = "costs-2";
pub const COSTS_3_NAME: &str = "costs-3";
pub const COSTS_4_NAME: &str = "costs-4";
pub const COSTS_5_NAME: &str = "costs-5";

pub fn runtime_cost<T: TryInto<u64>, C: CostTracker>(
    cost_function: ClarityCostFunction,
    tracker: &mut C,
    input: T,
) -> Result<(), CostErrors> {
    let size: u64 = input.try_into().map_err(|_| CostErrors::CostOverflow)?;
    let cost = tracker.compute_cost(cost_function, &[size])?;

    tracker.add_cost(cost)
}

macro_rules! finally_drop_memory {
    ( $gc: expr, $used_mem:expr; $exec:expr ) => {{
        let result = (|| $exec)();
        $gc.drop_memory($used_mem)?;
        result
    }};
}

pub fn analysis_typecheck_cost<T: CostTracker>(
    track: &mut T,
    t1: &TypeSignature,
    t2: &TypeSignature,
) -> Result<(), CostErrors> {
    let t1_size = t1.type_size().map_err(|_| CostErrors::CostOverflow)?;
    let t2_size = t2.type_size().map_err(|_| CostErrors::CostOverflow)?;
    let cost = track.compute_cost(
        ClarityCostFunction::AnalysisTypeCheck,
        &[cmp::max(t1_size, t2_size) as u64],
    )?;
    track.add_cost(cost)
}

pub trait MemoryConsumer {
    fn get_memory_use(&self) -> Result<u64, CostErrors>;
}

impl MemoryConsumer for Value {
    fn get_memory_use(&self) -> Result<u64, CostErrors> {
        Ok(self
            .size()
            .map_err(|_| CostErrors::InterpreterFailure)?
            .into())
    }
}

pub trait CostTracker {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors>;
    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors>;
    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors>;
    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors>;
    fn reset_memory(&mut self);
}

// Don't track!
impl CostTracker for () {
    fn compute_cost(
        &mut self,
        _cost_function: ClarityCostFunction,
        _input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        Ok(ExecutionCost::ZERO)
    }
    fn add_cost(&mut self, _cost: ExecutionCost) -> Result<(), CostErrors> {
        Ok(())
    }
    fn add_memory(&mut self, _memory: u64) -> Result<(), CostErrors> {
        Ok(())
    }
    fn drop_memory(&mut self, _memory: u64) -> Result<(), CostErrors> {
        Ok(())
    }
    fn reset_memory(&mut self) {}
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ClarityCostFunctionReference {
    pub contract_id: QualifiedContractIdentifier,
    pub function_name: String,
}

impl ::std::fmt::Display for ClarityCostFunctionReference {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}.{}", self.contract_id, self.function_name)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Copy)]
pub enum DefaultVersion {
    Costs1,
    Costs2,
    Costs2Testnet,
    Costs3,
    Costs4,
    Costs5,
}

impl DefaultVersion {
    pub fn evaluate(
        &self,
        cost_function_ref: &ClarityCostFunctionReference,
        f: &ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        let n = input.first().ok_or_else(|| {
            CostErrors::Expect("Default cost function supplied with 0 args".into())
        })?;
        let r = match self {
            DefaultVersion::Costs1 => f.eval::<Costs1>(*n),
            DefaultVersion::Costs2 => f.eval::<Costs2>(*n),
            DefaultVersion::Costs2Testnet => f.eval::<Costs2Testnet>(*n),
            DefaultVersion::Costs3 => f.eval::<Costs3>(*n),
            DefaultVersion::Costs4 => f.eval::<Costs4>(*n),
            DefaultVersion::Costs5 => f.eval::<Costs5>(*n),
        };
        r.map_err(|e| {
            let e = match e {
                VmExecutionError::Runtime(RuntimeError::NotImplemented, _) => {
                    RuntimeCheckErrorKind::UndefinedFunction(
                        cost_function_ref.function_name.clone(),
                    )
                    .into()
                }
                other => other,
            };

            CostErrors::CostComputationFailed(format!(
                "Error evaluating result of cost function {cost_function_ref}: {e}",
            ))
        })
    }
}

impl DefaultVersion {
    pub fn try_from(mainnet: bool, value: &QualifiedContractIdentifier) -> Result<Self, String> {
        if !value.is_boot() {
            return Err("Not a boot contract".into());
        }
        if value.name.as_str() == COSTS_1_NAME {
            Ok(Self::Costs1)
        } else if value.name.as_str() == COSTS_2_NAME {
            if mainnet {
                Ok(Self::Costs2)
            } else {
                Ok(Self::Costs2Testnet)
            }
        } else if value.name.as_str() == COSTS_3_NAME {
            Ok(Self::Costs3)
        } else if value.name.as_str() == COSTS_4_NAME {
            Ok(Self::Costs4)
        } else if value.name.as_str() == COSTS_5_NAME {
            Ok(Self::Costs5)
        } else {
            Err(format!("Unknown default contract {}", value.name))
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum ClarityCostFunctionEvaluator {
    Default(
        ClarityCostFunctionReference,
        ClarityCostFunction,
        DefaultVersion,
    ),
    Clarity(ClarityCostFunctionReference),
}

impl ClarityCostFunctionReference {
    fn new(id: QualifiedContractIdentifier, name: String) -> ClarityCostFunctionReference {
        ClarityCostFunctionReference {
            contract_id: id,
            function_name: name,
        }
    }
}

#[derive(Clone)]
/// This struct holds all of the data required for non-free LimitedCostTracker instances
pub struct TrackerData {
    cost_function_references: HashMap<&'static ClarityCostFunction, ClarityCostFunctionEvaluator>,
    cost_contracts: HashMap<QualifiedContractIdentifier, Contract>,
    total: ExecutionCost,
    limit: ExecutionCost,
    memory: u64,
    memory_limit: u64,
    /// if the cost tracker is non-free, this holds the StacksEpochId that should be used to evaluate
    ///  the Clarity cost functions. If the tracker *is* free, then those functions do not need to be
    ///  evaluated, so no epoch identifier is necessary.
    pub epoch: StacksEpochId,
    mainnet: bool,
    chain_id: u32,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum LimitedCostTracker {
    Limited(TrackerData),
    Free,
}

#[cfg(any(test, feature = "testing"))]
impl LimitedCostTracker {
    pub fn cost_function_references(
        &self,
    ) -> HashMap<&'static ClarityCostFunction, ClarityCostFunctionEvaluator> {
        match self {
            Self::Free => panic!("Cannot get cost function references on free tracker"),
            Self::Limited(TrackerData {
                cost_function_references,
                ..
            }) => cost_function_references.clone(),
        }
    }
}

impl fmt::Debug for LimitedCostTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free => f.debug_struct("LimitedCostTracker::Free").finish(),
            Self::Limited(TrackerData {
                total,
                limit,
                memory,
                memory_limit,
                ..
            }) => f
                .debug_struct("LimitedCostTracker")
                .field("total", total)
                .field("limit", limit)
                .field("memory", memory)
                .field("memory_limit", memory_limit)
                .finish(),
        }
    }
}

impl PartialEq for LimitedCostTracker {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Free, Self::Free) => true,
            (Self::Limited(self_data), Self::Limited(other_data)) => {
                self_data.total == other_data.total
                    && other_data.limit == self_data.limit
                    && self_data.memory == other_data.memory
                    && self_data.memory_limit == other_data.memory_limit
            }
            (_, _) => false,
        }
    }
}

impl LimitedCostTracker {
    pub fn new(
        mainnet: bool,
        chain_id: u32,
        limit: ExecutionCost,
        clarity_db: &mut ClarityDatabase,
        epoch: StacksEpochId,
    ) -> Result<LimitedCostTracker, CostErrors> {
        let mut cost_tracker = TrackerData {
            cost_function_references: HashMap::new(),
            cost_contracts: HashMap::new(),
            limit,
            memory_limit: CLARITY_MEMORY_LIMIT,
            total: ExecutionCost::ZERO,
            memory: 0,
            epoch,
            mainnet,
            chain_id,
        };
        assert!(clarity_db.is_stack_empty());
        cost_tracker.load_costs(clarity_db)?;
        Ok(Self::Limited(cost_tracker))
    }

    pub fn new_mid_block(
        mainnet: bool,
        chain_id: u32,
        limit: ExecutionCost,
        clarity_db: &mut ClarityDatabase,
        epoch: StacksEpochId,
    ) -> Result<LimitedCostTracker, CostErrors> {
        let mut cost_tracker = TrackerData {
            cost_function_references: HashMap::new(),
            cost_contracts: HashMap::new(),
            limit,
            memory_limit: CLARITY_MEMORY_LIMIT,
            total: ExecutionCost::ZERO,
            memory: 0,
            epoch,
            mainnet,
            chain_id,
        };
        cost_tracker.load_costs(clarity_db)?;
        Ok(Self::Limited(cost_tracker))
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_max_limit(
        clarity_db: &mut ClarityDatabase,
        epoch: StacksEpochId,
        use_mainnet: bool,
    ) -> Result<LimitedCostTracker, CostErrors> {
        use crate::vm::tests::test_only_mainnet_to_chain_id;
        let chain_id = test_only_mainnet_to_chain_id(use_mainnet);
        assert!(clarity_db.is_stack_empty());
        LimitedCostTracker::new(
            use_mainnet,
            chain_id,
            ExecutionCost::max_value(),
            clarity_db,
            epoch,
        )
    }

    pub fn new_free() -> LimitedCostTracker {
        Self::Free
    }

    /// Return the default cost contract name for the provided epoch.
    pub fn default_cost_contract_for_epoch(epoch_id: StacksEpochId) -> Result<String, CostErrors> {
        let result = match epoch_id {
            StacksEpochId::Epoch10 => {
                return Err(CostErrors::Expect("Attempted to get default cost functions for Epoch 1.0 where Clarity does not exist".into()));
            }
            StacksEpochId::Epoch20 => COSTS_1_NAME.to_string(),
            StacksEpochId::Epoch2_05 => COSTS_2_NAME.to_string(),
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31
            | StacksEpochId::Epoch32 => COSTS_3_NAME.to_string(),
            StacksEpochId::Epoch33 | StacksEpochId::Epoch34 => COSTS_4_NAME.to_string(),
            StacksEpochId::Epoch40 | StacksEpochId::Epoch41 => COSTS_5_NAME.to_string(),
        };
        Ok(result)
    }

    /// Create a [`LimitedCostTracker`] given an epoch id and an execution cost limit for testing purpose
    ///
    /// Autoconfigure itself loading all clarity const functions without the need of passing a clarity database
    #[cfg(any(test, feature = "testing"))]
    pub fn new_with_limit(epoch_id: StacksEpochId, limit: ExecutionCost) -> LimitedCostTracker {
        use stacks_common::consts::CHAIN_ID_TESTNET;

        let contract_name = LimitedCostTracker::default_cost_contract_for_epoch(epoch_id)
            .expect("Failed retrieving cost contract!");
        let boot_costs_id = boot_code_id(&contract_name, false);

        let version = DefaultVersion::try_from(false, &boot_costs_id)
            .expect("Failed defining default version!");

        let mut cost_functions = HashMap::new();
        for each in ClarityCostFunction::ALL {
            let evaluator = ClarityCostFunctionEvaluator::Default(
                ClarityCostFunctionReference {
                    contract_id: boot_costs_id.clone(),
                    function_name: each.get_name(),
                },
                each.clone(),
                version,
            );
            cost_functions.insert(each, evaluator);
        }

        let cost_tracker = TrackerData {
            cost_function_references: cost_functions,
            cost_contracts: HashMap::new(),
            limit,
            memory_limit: CLARITY_MEMORY_LIMIT,
            total: ExecutionCost::ZERO,
            memory: 0,
            epoch: epoch_id,
            mainnet: false,
            chain_id: CHAIN_ID_TESTNET,
        };

        LimitedCostTracker::Limited(cost_tracker)
    }
}

impl TrackerData {
    /// Load the default cost functions for this tracker's epoch.
    ///
    /// Before Epoch 4.0, this also loads the corresponding boot cost contract.
    /// Epoch 4.0 and later use the native Rust cost implementation.
    fn load_costs(&mut self, clarity_db: &mut ClarityDatabase) -> Result<(), CostErrors> {
        clarity_db.begin();
        let epoch_id = clarity_db
            .get_clarity_epoch_version()
            .map_err(|e| CostErrors::CostComputationFailed(e.to_string()))?;
        let boot_costs_id = boot_code_id(
            &LimitedCostTracker::default_cost_contract_for_epoch(epoch_id)?,
            self.mainnet,
        );

        let v = DefaultVersion::try_from(self.mainnet, &boot_costs_id).map_err(|e| {
            CostErrors::Expect(format!(
                "Failed to get version of default costs contract {e}"
            ))
        })?;

        let mut m = HashMap::with_capacity(ClarityCostFunction::ALL.len());
        for f in ClarityCostFunction::ALL.iter() {
            let cost_function_ref =
                ClarityCostFunctionReference::new(boot_costs_id.clone(), f.get_name());
            m.insert(
                f,
                ClarityCostFunctionEvaluator::Default(cost_function_ref, f.clone(), v),
            );
        }

        let mut cost_contracts = HashMap::with_capacity(1);
        if epoch_id < StacksEpochId::Epoch40 {
            let boot_cost_contract = match clarity_db.get_contract(&boot_costs_id) {
                Ok(contract) => contract,
                Err(e) => {
                    error!("Failed to load intended Clarity cost contract";
                           "contract" => %boot_costs_id,
                           "error" => ?e);
                    clarity_db
                        .roll_back()
                        .map_err(|e| CostErrors::Expect(e.to_string()))?;
                    return Err(CostErrors::CostContractLoadFailure);
                }
            };
            cost_contracts.insert(boot_costs_id, boot_cost_contract);
        }

        self.cost_function_references = m;
        self.cost_contracts = cost_contracts;

        clarity_db
            .commit()
            .map_err(|e| CostErrors::Expect(e.to_string()))?;

        Ok(())
    }
}

impl LimitedCostTracker {
    pub fn get_total(&self) -> ExecutionCost {
        match self {
            Self::Limited(TrackerData { total, .. }) => total.clone(),
            Self::Free => ExecutionCost::ZERO,
        }
    }
    #[allow(clippy::panic)]
    pub fn set_total(&mut self, total: ExecutionCost) {
        // used by the miner to "undo" the cost of a transaction when trying to pack a block.
        match self {
            Self::Limited(data) => data.total = total,
            Self::Free => panic!("Cannot set total on free tracker"),
        }
    }
    pub fn get_limit(&self) -> ExecutionCost {
        match self {
            Self::Limited(TrackerData { limit, .. }) => limit.clone(),
            Self::Free => ExecutionCost::max_value(),
        }
    }

    pub fn get_memory(&self) -> u64 {
        match self {
            Self::Limited(TrackerData { memory, .. }) => *memory,
            Self::Free => 0,
        }
    }
    pub fn get_memory_limit(&self) -> u64 {
        match self {
            Self::Limited(TrackerData { memory_limit, .. }) => *memory_limit,
            Self::Free => u64::MAX,
        }
    }
}

pub fn parse_cost(
    cost_function_name: &str,
    eval_result: Result<Value, VmExecutionError>,
) -> Result<ExecutionCost, CostErrors> {
    match eval_result {
        Ok(Value::Tuple(data)) => {
            let results = (
                data.data_map.get("write_length"),
                data.data_map.get("write_count"),
                data.data_map.get("runtime"),
                data.data_map.get("read_length"),
                data.data_map.get("read_count"),
            );

            match results {
                (
                    Some(UInt(write_length)),
                    Some(UInt(write_count)),
                    Some(UInt(runtime)),
                    Some(UInt(read_length)),
                    Some(UInt(read_count)),
                ) => Ok(ExecutionCost {
                    write_length: (*write_length).try_into().unwrap_or(u64::MAX),
                    write_count: (*write_count).try_into().unwrap_or(u64::MAX),
                    runtime: (*runtime).try_into().unwrap_or(u64::MAX),
                    read_length: (*read_length).try_into().unwrap_or(u64::MAX),
                    read_count: (*read_count).try_into().unwrap_or(u64::MAX),
                }),
                _ => Err(CostErrors::CostComputationFailed(
                    "Execution Cost tuple does not contain only UInts".to_string(),
                )),
            }
        }
        Ok(_) => Err(CostErrors::CostComputationFailed(
            "Clarity cost function returned something other than a Cost tuple".to_string(),
        )),
        Err(e) => Err(CostErrors::CostComputationFailed(format!(
            "Error evaluating result of cost function {cost_function_name}: {e}"
        ))),
    }
}

// TODO: add tests from mutation testing results #4832
#[cfg_attr(test, mutants::skip)]
pub fn compute_cost(
    cost_tracker: &TrackerData,
    cost_function_reference: ClarityCostFunctionReference,
    input_sizes: &[u64],
    eval_in_epoch: StacksEpochId,
) -> Result<ExecutionCost, CostErrors> {
    let mainnet = cost_tracker.mainnet;
    let chain_id = cost_tracker.chain_id;
    let mut null_store = NullBackingStore::new();
    let conn = null_store.as_clarity_db();
    let mut global_context = GlobalContext::new(
        mainnet,
        chain_id,
        conn,
        LimitedCostTracker::new_free(),
        eval_in_epoch,
    );

    let cost_contract = cost_tracker
        .cost_contracts
        .get(&cost_function_reference.contract_id)
        .ok_or(CostErrors::CostComputationFailed(format!(
            "CostFunction not found: {cost_function_reference}"
        )))?;

    let mut program = vec![SymbolicExpression::atom(
        cost_function_reference.function_name[..]
            .to_string()
            .try_into()
            .map_err(|_| {
                CostErrors::Expect("Cost function should be a valid Clarity name".to_string())
            })?,
    )];

    for input_size in input_sizes.iter() {
        program.push(SymbolicExpression::atom_value(Value::UInt(
            *input_size as u128,
        )));
    }

    let function_invocation = SymbolicExpression::list(program);
    let eval_result = global_context.execute(|global_context| {
        let context = LocalContext::new();
        let mut call_stack = CallStack::new();
        let publisher: PrincipalData = cost_contract.contract_identifier.issuer.clone().into();
        let mut env = ExecutionState {
            global_context,
            call_stack: &mut call_stack,
        };
        let invoke_ctx = InvocationContext {
            contract_context: cost_contract,
            sender: Some(publisher.clone()),
            caller: Some(publisher.clone()),
            sponsor: None,
        };
        super::eval(&function_invocation, &mut env, &invoke_ctx, &context)
            .and_then(|v| v.clone_with_cost(&mut env))
    });
    parse_cost(&cost_function_reference.to_string(), eval_result)
}

fn add_cost(s: &mut TrackerData, cost: ExecutionCost) -> Result<(), CostErrors> {
    s.total.add(&cost)?;
    if cfg!(feature = "disable-costs") {
        // Disable check for exceeding the cost limit to allow mining large blocks for profiling purposes.
        return Ok(());
    }
    if s.total.exceeds(&s.limit) {
        Err(CostErrors::CostBalanceExceeded(
            s.total.clone(),
            s.limit.clone(),
        ))
    } else {
        Ok(())
    }
}

fn add_memory(s: &mut TrackerData, memory: u64) -> Result<(), CostErrors> {
    s.memory = s.memory.cost_overflow_add(memory)?;
    if s.memory > s.memory_limit {
        Err(CostErrors::MemoryBalanceExceeded(s.memory, s.memory_limit))
    } else {
        Ok(())
    }
}

fn drop_memory(s: &mut TrackerData, memory: u64) -> Result<(), CostErrors> {
    s.memory = s
        .memory
        .checked_sub(memory)
        .ok_or_else(|| CostErrors::Expect("Underflowed dropped memory".into()))?;
    Ok(())
}

impl CostTracker for LimitedCostTracker {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        match self {
            Self::Free => {
                // tracker is free, return zero!
                Ok(ExecutionCost::ZERO)
            }
            Self::Limited(data) => {
                if cost_function == ClarityCostFunction::Unimplemented {
                    return Err(CostErrors::Expect(
                        "Used unimplemented cost function".into(),
                    ));
                }
                let cost_function_ref = data.cost_function_references.get(&cost_function).ok_or(
                    CostErrors::CostComputationFailed(format!(
                        "CostFunction not defined: {cost_function}"
                    )),
                )?;

                match cost_function_ref {
                    ClarityCostFunctionEvaluator::Default(
                        cost_function_ref,
                        clarity_cost_function,
                        default_version,
                    ) => default_version.evaluate(cost_function_ref, clarity_cost_function, input),
                    ClarityCostFunctionEvaluator::Clarity(cost_function_ref) => {
                        compute_cost(data, cost_function_ref.clone(), input, data.epoch)
                    }
                }
            }
        }
    }
    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors> {
        match self {
            Self::Free => Ok(()),
            Self::Limited(data) => add_cost(data, cost),
        }
    }
    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        match self {
            Self::Free => Ok(()),
            Self::Limited(data) => add_memory(data, memory),
        }
    }
    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        match self {
            Self::Free => Ok(()),
            Self::Limited(data) => drop_memory(data, memory),
        }
    }
    fn reset_memory(&mut self) {
        match self {
            Self::Free => {}
            Self::Limited(data) => {
                data.memory = 0;
            }
        }
    }
}

impl CostTracker for &mut LimitedCostTracker {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        LimitedCostTracker::compute_cost(self, cost_function, input)
    }
    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors> {
        LimitedCostTracker::add_cost(self, cost)
    }
    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        LimitedCostTracker::add_memory(self, memory)
    }
    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        LimitedCostTracker::drop_memory(self, memory)
    }
    fn reset_memory(&mut self) {
        LimitedCostTracker::reset_memory(self)
    }
}

// ONLY WORKS IF INPUT IS u64
fn int_log2(input: u64) -> Option<u64> {
    63_u32.checked_sub(input.leading_zeros()).map(|floor_log| {
        if input.trailing_zeros() == floor_log {
            u64::from(floor_log)
        } else {
            u64::from(floor_log + 1)
        }
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_simple_overflows() {
        assert_eq!(u64::MAX.cost_overflow_add(1), Err(CostErrors::CostOverflow));
        assert_eq!(u64::MAX.cost_overflow_mul(2), Err(CostErrors::CostOverflow));
    }

    #[test]
    fn test_simple_sub() {
        assert_eq!(0u64.cost_overflow_sub(1), Err(CostErrors::CostOverflow));
    }

    #[test]
    fn test_simple_log2s() {
        let inputs = [
            1,
            2,
            4,
            8,
            16,
            31,
            32,
            33,
            39,
            64,
            128,
            2_u64.pow(63),
            u64::MAX,
        ];
        let expected = [0, 1, 2, 3, 4, 5, 5, 6, 6, 6, 7, 63, 64];
        for (input, expected) in inputs.iter().zip(expected.iter()) {
            assert_eq!(int_log2(*input).unwrap(), *expected);
        }
    }
}
