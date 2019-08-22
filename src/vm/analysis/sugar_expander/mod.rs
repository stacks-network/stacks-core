use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::analysis::types::{ContractAnalysis, AnalysisPass, QualifiedContractIdentifier, Value, PrincipalData, StackAddress};
use vm::analysis::errors::{CheckResult, CheckErrors, CheckError};
use vm::analysis::analysis_db::{AnalysisDatabase};

pub struct SugarExpander;

impl AnalysisPass for SugarExpander {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        Self::qualify_relative_contracts(& mut contract_analysis.expressions)?;
    }

    fn qualify_relative_contracts(args: &mut [SymbolicExpression], issuer: StackAddress) -> CheckResult<()> {
        for expression in &mut args[..] {
            if let Some(exprs) = function_name.match_list() {
                if let Some((function_name, function_args)) = exprs.split_first() {
                    if let Some(function_name) = function_name.match_atom() {
                        if let Some(native_function) = DefineFunctions::lookup_by_name(function_name) {
                            match native_function {
                                NativeFunctions::FetchContractEntry | NativeFunctions::ContractCall => {
                                    if let contract_name = function_args[0].match_atom() {
                                        let contract_identifier = QualifiedContractIdentifier::new(issuer, contract_name)?;
                                        expression.expr = AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                                    }
                                }
                                _ => {
                                    Self::qualify_relative_contracts(function_args)?;
                                }
                            };
                        }
                    }
                }
            }
        }
    }
}
