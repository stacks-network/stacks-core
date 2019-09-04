use vm::representations::{SymbolicExpression};
use vm::{SymbolicExpressionType};
use vm::types::{QualifiedContractIdentifier, Value, PrincipalData, StackAddress};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::functions::NativeFunctions;
use vm::analysis::errors::{CheckResult, CheckErrors, CheckError};
use vm::analysis::analysis_db::{AnalysisDatabase};

pub struct SugarExpander {
    issuer: StackAddress   
}

impl AnalysisPass for SugarExpander {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut pass = SugarExpander::new(contract_analysis.contract_identifier.issuer.clone());
        pass.run(&mut contract_analysis.expressions)
    }
}

impl SugarExpander {

    fn new(issuer: StackAddress) -> Self {
        Self { issuer }
    }

    pub fn run(&mut self, expressions: &mut [SymbolicExpression]) -> CheckResult<()> {
        for expression in &mut expressions[..] {
            self.qualify_relative_contracts(expression)?;
        }
        Ok(())
    }

    fn qualify_relative_contracts(&mut self, expression: &mut SymbolicExpression) -> CheckResult<()> {
        let (function_name, function_args) = {
            if let SymbolicExpressionType::List(ref mut exprs) = expression.expr {
                if let Some((inner_expr, mut function_args)) = exprs.split_first_mut() {
                    match inner_expr.expr {
                        SymbolicExpressionType::Atom(ref mut function_name) => (function_name, function_args),
                        SymbolicExpressionType::AtomValue(_) => return Ok(()),
                        SymbolicExpressionType::List(_) => return self.qualify_relative_contracts(inner_expr)
                    }
                } else { return Ok(()) }
            } else { return Ok(()) }
        };
        if let Some(native_function) = NativeFunctions::lookup_by_name(&function_name) {
            match native_function {
                NativeFunctions::FetchContractEntry | NativeFunctions::ContractCall => {
                    if let Some(contract_name) = function_args[0].clone().match_atom() {
                        let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name.to_string()).unwrap();
                        function_args[0].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                    }
                }
                _ => {}
            }
        }

        for expr in function_args.into_iter() {
            self.qualify_relative_contracts(expr)?;
        }

        Ok(())
    }
}

