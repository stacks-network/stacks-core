use vm::ast::parse;
use vm::representations::SymbolicExpression;
use vm::analysis::type_checker::{TypeResult, TypeChecker};
use vm::analysis::{AnalysisDatabase};
use vm::analysis::errors::{CheckErrors, CheckResult};
use vm::analysis::mem_type_check;
use vm::analysis::cost_counter::{ContractCostAnalysis, ExecutionCost};

use vm::analysis::types::ContractAnalysis;
use vm::contexts::{OwnedEnvironment};
use vm::types::{Value, PrincipalData, TypeSignature, FunctionType, FixedFunction, BUFF_32, BUFF_64,
                QualifiedContractIdentifier};

use vm::types::TypeSignature::{IntType, BoolType, BufferType, UIntType};
use std::convert::TryInto;

fn cost_check_contract(exp: &str) -> CheckResult<(ContractCostAnalysis, ExecutionCost)> {
    mem_type_check(exp)
        .map(|(_, analysis)| {
            (analysis.cost_analysis.unwrap(), analysis.instantiation_cost.unwrap())
        })
}

// these simple tests *DO NOT* test for expected cost values.
// the reason for this is that the current cost values do not correspond to anything --
//   all the constants are set to "1", meaning that these values are pretty arbitrary.
// once these constants are _tuned_ they'll need a separate testing structure which
//   instruments the actual cost of execution and compares against the returned cost
//   from the analysis.

#[test]
fn test_simple_maps() {
    let mapped_func = "(define-private (increment-x (x int)) (+ x 1))";
    let tests = [ format!("{} (map increment-x (list 1 2 3 4 5 6 7 8 9 0))", mapped_func),
                  format!("{} (map increment-x (list 1 2 3))", mapped_func) ];

    let expected = [
        ExecutionCost { write_length: 232, write_count: 1, read_length: 1, read_count: 1, runtime: 582 },
        ExecutionCost { write_length: 120, write_count: 1, read_length: 1, read_count: 1, runtime: 246 },
    ];

    for (test, expected_cost) in tests.iter().zip(expected.iter()) {
        let (_, exec_cost) = cost_check_contract(test).unwrap();
        assert_eq!(exec_cost, *expected_cost);
    }
}
