use vm::functions::{handle_binding_list};
use vm::representations::{SymbolicExpression, SymbolicExpressionType, depth_traverse, ClarityName};

use super::{constants, CheckResult, CostOverflowingMath, CostFunctions, ExecutionCost,
            SimpleCostSpecification };

pub fn get_hash_cost(name_size: u64, type_size: u64) -> CheckResult<ExecutionCost> {
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::DB_HASH_COST_A, constants::DB_HASH_COST_B))
        .compute_cost(type_size.cost_overflow_add(name_size)?)
}

pub fn get_binding_cost(name: &str) -> CheckResult<ExecutionCost> {
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::BINDING_COST_A, constants::BINDING_COST_B))
        .compute_cost(name.len() as u64)
}

pub fn get_function_lookup_cost(name: &str) -> CheckResult<ExecutionCost> {
    // hashing function name => linear.
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::FUNC_LOOKUP_COST_A, constants::FUNC_LOOKUP_COST_B))
        .compute_cost(name.len() as u64)
}

pub fn get_variable_lookup_cost(name: &str, context_depth: u64) -> CheckResult<ExecutionCost> {
    let mut lookup_cost = SimpleCostSpecification::new_diskless(
        CostFunctions::Linear(constants::VAR_LOOKUP_COST_A, constants::VAR_LOOKUP_COST_B))
        .compute_cost(name.len() as u64)?;
    lookup_cost.multiply(context_depth)?;
    Ok(lookup_cost)
}

pub fn get_expression_size(expr: &SymbolicExpression) -> CheckResult<u64> {
    let mut tot_size: u64 = 0;

    let traversal_result: CheckResult<()> = depth_traverse(
        expr,
        |e| {
            let expr_size = match &e.expr {
                SymbolicExpressionType::AtomValue(v) | SymbolicExpressionType::LiteralValue(v) => u64::from(v.size()),
                SymbolicExpressionType::Atom(name) => name.len() as u64,
                SymbolicExpressionType::List(_) => 1,
            };
            tot_size = tot_size.cost_overflow_add(expr_size)?;
            Ok(())
        });

    traversal_result?;
    Ok(tot_size)
}

pub fn contract_storage_cost(contract_size: u64) -> CheckResult<ExecutionCost> {
    let storage_cost_func = SimpleCostSpecification {
        write_count: CostFunctions::Constant(1),
        write_length: CostFunctions::Linear(constants::STORE_CONTRACT_LENGTH_A, constants::STORE_CONTRACT_LENGTH_B),
        read_count: CostFunctions::Constant(1),
        read_length: CostFunctions::Constant(constants::STORE_CONTRACT_READ_LENGTH),
        runtime: CostFunctions::Linear(constants::STORE_CONTRACT_RUNTIME_A, constants::STORE_CONTRACT_RUNTIME_B)
    };

    storage_cost_func.compute_cost(contract_size)
}

pub fn parse_type_cost(type_description: &SymbolicExpression) -> CheckResult<ExecutionCost> {
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::PARSE_TYPE_A, constants::PARSE_TYPE_B))
        .compute_cost(get_expression_size(type_description)?)
}

// this is the cost of parsing a function signature into the type <-> argument mapping and binding the function name
//   to its type signature
pub fn parse_signature_cost(signature: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
    let (func_name, arg_bindings) = signature.split_first().expect("Function signature should be legal");
    // 1) binding cost of the function name.
    let mut total_costs = get_binding_cost(func_name.match_atom().expect("Function signature should be name"))?;
    // 2) binding and parsing costs of the function arguments
    handle_binding_list(arg_bindings, |var_name, type_description| {
        // the cost of binding the name.
        total_costs.add(&get_binding_cost(var_name)?)?;

        // the cost of calculating the bound value
        total_costs.add(
            &parse_type_cost(type_description)?)
    })?;

    Ok(total_costs)
}
