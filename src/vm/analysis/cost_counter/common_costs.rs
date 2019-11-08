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
