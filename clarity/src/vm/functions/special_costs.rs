use clarity_types::execution_cost::ExecutionCost;
use clarity_types::representations::SymbolicExpression;
use stacks_common::types::StacksEpochId;

use crate::vm::costs::analysis::UserArgumentsContext;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::functions::NativeFunctions;
use crate::vm::types::Value;
use crate::vm::version::ClarityVersion;

pub fn get_cost_for_special_function(
    native_function: NativeFunctions,
    args: &[SymbolicExpression],
    epoch: StacksEpochId,
    user_args: Option<&UserArgumentsContext>,
) -> ExecutionCost {
    match native_function {
        NativeFunctions::Let => cost_binding_list_len(args, epoch),
        NativeFunctions::If => ClarityCostFunction::If
            .eval_for_epoch(0, epoch)
            .unwrap_or_else(|_| ExecutionCost::ZERO),
        NativeFunctions::TupleCons => cost_binding_list_len(args, epoch),
        NativeFunctions::ContractCall => contract_call_cost(args, epoch),
        NativeFunctions::ListCons => cost_list_cons(args, epoch),
        NativeFunctions::TupleGet => cost_tuple_get(args, epoch),
        NativeFunctions::Append => cost_append(args, epoch),
        NativeFunctions::Concat => cost_concat(args, epoch),
        NativeFunctions::Slice => cost_slice(args, epoch),
        NativeFunctions::ReplaceAt => cost_replace_at(args, epoch),
        NativeFunctions::FetchVar => cost_fetch_var(args, epoch),
        NativeFunctions::SetVar => cost_set_var(args, epoch),
        NativeFunctions::FetchEntry => cost_fetch_entry(args, epoch),
        NativeFunctions::SetEntry => cost_set_entry(args, epoch),
        NativeFunctions::InsertEntry => cost_insert_entry(args, epoch),
        NativeFunctions::DeleteEntry => cost_delete_entry(args, epoch),
        NativeFunctions::Print => cost_print(args, epoch),
        NativeFunctions::ToAscii => cost_to_ascii(args, epoch),
        NativeFunctions::CmpGeq
        | NativeFunctions::CmpLeq
        | NativeFunctions::CmpGreater
        | NativeFunctions::CmpLess => cost_comparison(native_function, args, epoch, user_args),
        NativeFunctions::MintAsset => cost_mint_asset(args, epoch),
        native_function => ClarityCostFunction::from_native_function(native_function)
            .eval_for_epoch(args.len() as u64, epoch)
            .unwrap_or_else(|_| ExecutionCost::ZERO),
    }
}

// contract-call cost is static (134 in epoch 3+), the second part (load
// contract) is from `execute_contract` and the function application is in
// `execute_apply`
pub fn contract_call_cost(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    // if epoch is less than 3.3, the argument type is used, but after 3.3 the argument size is used
    // For static analysis, we extract literal values from the arguments and calculate their sizes
    // args structure: [contract-identifier-or-trait-ref, function-name, arg1, arg2, ...]
    //   - args[0]: contract identifier (principal) for static dispatch, or trait reference (atom) for dynamic dispatch
    //   - args[1]: function name
    //   - args[2..]: actual function arguments to the called contract function
    // We need to process args[2..] (the actual function arguments)

    if epoch < StacksEpochId::Epoch33 {
        // Before epoch 3.3, the function application cost (in execute_apply) was based on
        // parameter types, not argument sizes. However, the base contract-call cost itself
        // is static and doesn't depend on arguments - the cost function ignores the parameter.
        // The runtime also passes 0 here (see special_contract_call in database.rs:70).
        ClarityCostFunction::ContractCall
            .eval_for_epoch(0, epoch)
            .unwrap_or_else(|_| ExecutionCost::ZERO)
    } else {
        // After epoch 3.3, use actual argument sizes
        // Extract literal values from args[2..] and sum their sizes
        let rest_args = args.get(2..).unwrap_or(&[]);
        let mut total_size = 0 as u64;

        for arg in rest_args {
            // Try to extract literal value from the symbolic expression
            if let Some(value) = arg.match_atom_value().or_else(|| arg.match_literal_value()) {
                // Calculate the size of the value
                // Value::size() returns u32, so we convert to u64
                if let Ok(size) = value.size() {
                    total_size = total_size.saturating_add(size as u64);
                }
            }
        }

        ClarityCostFunction::ContractCall
            .eval_for_epoch(total_size, epoch)
            .unwrap_or_else(|_| ExecutionCost::ZERO)
    }
}

pub fn cost_binding_list_len(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let binding_len = args
        .get(0)
        .and_then(|e| e.match_list())
        .map(|binding_list| binding_list.len() as u64)
        .unwrap_or(0);
    ClarityCostFunction::Let
        .eval_for_epoch(binding_len, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// ListCons cost is based on sum of argument sizes
pub fn cost_list_cons(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let mut total_size = 0u64;
    for arg in args {
        if let Some(value) = arg.match_atom_value().or_else(|| arg.match_literal_value()) {
            if let Ok(size) = value.size() {
                total_size = total_size.saturating_add(size as u64);
            }
        }
    }
    ClarityCostFunction::ListCons
        .eval_for_epoch(total_size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// TupleGet cost is based on tuple length
// For static analysis, we try to extract the tuple from args[1] if it's a literal
pub fn cost_tuple_get(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let tuple_len = args
        .get(1)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|value| {
            if let Value::Tuple(tuple_data) = value {
                Some(tuple_data.len() as u64)
            } else {
                None
            }
        })
        .unwrap_or(0);
    ClarityCostFunction::TupleGet
        .eval_for_epoch(tuple_len, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// Append cost is based on max of entry type size and element type size
// For static analysis, we try to extract sizes from literal values
pub fn cost_append(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let size = args
        .get(0)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|seq_value| {
            args.get(1)
                .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
                .and_then(|elem_value| {
                    // Try to get sizes from values
                    let seq_size = seq_value.size().ok()? as u64;
                    let elem_size = elem_value.size().ok()? as u64;
                    Some(std::cmp::max(seq_size, elem_size))
                })
        })
        .unwrap_or(0);
    ClarityCostFunction::Append
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// Concat cost is based on sum of sequence sizes
// Epoch-dependent: v200 uses value sizes, v205 uses sequence lengths
pub fn cost_concat(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let clarity_version = ClarityVersion::default_for_epoch(epoch);
    let size = if clarity_version >= ClarityVersion::Clarity2 {
        // v205: use sequence lengths
        args.get(0)
            .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
            .and_then(|seq1| {
                args.get(1)
                    .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
                    .and_then(|seq2| {
                        if let (Value::Sequence(s1), Value::Sequence(s2)) = (seq1, seq2) {
                            Some((s1.len() as u64).saturating_add(s2.len() as u64))
                        } else {
                            None
                        }
                    })
            })
            .unwrap_or(1) // fallback to 1 on error (matches runtime behavior)
    } else {
        // v200: use value sizes
        args.get(0)
            .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
            .and_then(|seq1| {
                args.get(1)
                    .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
                    .and_then(|seq2| {
                        let size1 = seq1.size().ok()? as u64;
                        let size2 = seq2.size().ok()? as u64;
                        size1.checked_add(size2)
                    })
            })
            .unwrap_or(0)
    };
    ClarityCostFunction::Concat
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// Slice cost is based on (right_position - left_position) * element_size
// For static analysis, we try to extract positions from args
pub fn cost_slice(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let size = args
        .get(1)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|left_val| {
            args.get(2)
                .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
                .and_then(|right_val| {
                    args.get(0)
                        .and_then(|arg| {
                            arg.match_atom_value().or_else(|| arg.match_literal_value())
                        })
                        .and_then(|seq_val| {
                            if let (Value::UInt(left), Value::UInt(right), Value::Sequence(seq)) =
                                (left_val, right_val, seq_val)
                            {
                                if right >= left {
                                    let slice_len = (right - left) as u64;
                                    let elem_size = seq.element_size().ok()? as u64;
                                    Some(slice_len * elem_size)
                                } else {
                                    Some(0)
                                }
                            } else {
                                None
                            }
                        })
                })
        })
        .unwrap_or(0);
    ClarityCostFunction::Slice
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// ReplaceAt cost is based on sequence type size
pub fn cost_replace_at(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let size = args
        .get(0)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|seq_val| {
            if let Value::Sequence(seq) = seq_val {
                // Try to get element size from sequence
                seq.element_size().ok().map(|s| s as u64)
            } else {
                None
            }
        })
        .unwrap_or(0);
    ClarityCostFunction::ReplaceAt
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// FetchVar cost is epoch-dependent: v200 uses type size, v205 uses actual result size
// TODO
pub fn cost_fetch_var(_args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    ClarityCostFunction::FetchVar
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// SetVar cost is epoch-dependent and uses result size
// TODO
pub fn cost_set_var(_args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    ClarityCostFunction::SetVar
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// FetchEntry cost is epoch-dependent and uses result size
// TODO
pub fn cost_fetch_entry(_args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    // Static analysis can't determine actual stored size, so we use 0 as fallback
    ClarityCostFunction::FetchEntry
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// SetEntry cost is epoch-dependent and uses result size
// TODO
pub fn cost_set_entry(_args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    ClarityCostFunction::SetEntry
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// InsertEntry cost is epoch-dependent and uses result size
// Note: InsertEntry uses SetEntry cost function
pub fn cost_insert_entry(_args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    ClarityCostFunction::SetEntry
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// DeleteEntry cost is epoch-dependent and uses result size
// Note: DeleteEntry uses SetEntry cost function
pub fn cost_delete_entry(_args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    ClarityCostFunction::SetEntry
        .eval_for_epoch(0, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// Print cost is based on input size
pub fn cost_print(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let size = args
        .get(0)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|value| value.size().ok().map(|s| s as u64))
        .unwrap_or(0);
    ClarityCostFunction::Print
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// ToAscii cost is based on value size
pub fn cost_to_ascii(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let size = args
        .get(0)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|value| value.size().ok().map(|s| s as u64))
        .unwrap_or(0);
    ClarityCostFunction::ToAscii
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// Comparison functions (Geq, Leq, Ge, Le) are epoch-dependent:
// v1 uses args.len(), v2 uses min(a.size(), b.size())
pub fn cost_comparison(
    native_function: NativeFunctions,
    args: &[SymbolicExpression],
    epoch: StacksEpochId,
    user_args: Option<&UserArgumentsContext>,
) -> ExecutionCost {
    let clarity_version = ClarityVersion::default_for_epoch(epoch);
    let cost_fn = match native_function {
        NativeFunctions::CmpGeq => ClarityCostFunction::Geq,
        NativeFunctions::CmpLeq => ClarityCostFunction::Leq,
        NativeFunctions::CmpGreater => ClarityCostFunction::Ge,
        NativeFunctions::CmpLess => ClarityCostFunction::Le,
        _ => return ExecutionCost::ZERO,
    };

    let size = if clarity_version >= ClarityVersion::Clarity2 {
        // v2 min(a.size(), b.size())
        // Helper function to get size from an argument (literal value or variable type)
        let get_arg_size = |arg: &SymbolicExpression| -> Option<u64> {
            // Try literal value first
            if let Some(value) = arg.match_atom_value().or_else(|| arg.match_literal_value()) {
                value.size().ok().map(|s| s as u64)
            } else if let Some(var_name) = arg.match_atom() {
                // Try to get type from user_args
                user_args
                    .and_then(|ua| ua.get_argument_type(var_name))
                    .and_then(|type_sig| type_sig.size().ok().map(|s| s as u64))
            } else {
                None
            }
        };

        // Try to get sizes from literal values first, then from variable types
        let size_a = args.get(0).and_then(get_arg_size);
        let size_b = args.get(1).and_then(get_arg_size);

        match (size_a, size_b) {
            (Some(a), Some(b)) => std::cmp::min(a, b),
            _ => args.len() as u64, // fallback to args.len()
        }
    } else {
        // v1
        args.len() as u64
    };

    cost_fn
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}

// MintAsset cost is based on asset_size
pub fn cost_mint_asset(args: &[SymbolicExpression], epoch: StacksEpochId) -> ExecutionCost {
    let size = args
        .get(2)
        .and_then(|arg| arg.match_atom_value().or_else(|| arg.match_literal_value()))
        .and_then(|asset_value| asset_value.size().ok().map(|s| s as u64))
        .unwrap_or(0);
    ClarityCostFunction::NftMint
        .eval_for_epoch(size, epoch)
        .unwrap_or_else(|_| ExecutionCost::ZERO)
}
