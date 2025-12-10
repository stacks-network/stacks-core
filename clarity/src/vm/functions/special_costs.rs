use clarity_types::execution_cost::ExecutionCost;
use clarity_types::representations::SymbolicExpression;
use stacks_common::types::StacksEpochId;
use crate::vm::{costs::cost_functions::ClarityCostFunction, functions::NativeFunctions};

pub fn get_cost_for_special_function(native_function: NativeFunctions, args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    match native_function {
        NativeFunctions::Let => cost_binding_list_len(args, epoch),
        NativeFunctions::If => cost_binding_list_len(args, epoch),
        NativeFunctions::TupleCons => cost_binding_list_len(args, epoch),
        _ => ExecutionCost::ZERO,
    }
}

pub fn cost_binding_list_len(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let binding_len = args.get(1).and_then(|e| e.match_list()).map(|binding_list| binding_list.len() as u64).unwrap_or(0);
    ClarityCostFunction::Let.eval_for_epoch(binding_len, epoch).unwrap_or_else(|_| {
        ExecutionCost::ZERO
    })
}

pub fn noop(_args: &[SymbolicExpression], _epoch: StacksEpochId) -> ExecutionCost {
    ExecutionCost::ZERO
}

