use std::collections::HashMap;

use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::analysis::AnalysisDatabase;
use vm::analysis::errors::{CheckResult, CheckError, CheckErrors};
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::types::{Value, TraitIdentifier, TypeSignature, FunctionType};
use vm::functions::NativeFunctions;
use vm::functions::define::{DefineFunctions, DefineFunctionsParsed};

pub struct TraitChecker {
}

impl AnalysisPass for TraitChecker {

    fn run_pass(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut command = TraitChecker::new();
        command.run(contract_analysis, analysis_db)?;
        Ok(())
    }
}

impl TraitChecker {

    fn new() -> Self {
        Self {
        }
    }

    pub fn run(&mut self, contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
    
        for trait_identifier in &contract_analysis.implemented_traits {

            let trait_name = trait_identifier.name.to_string();
            let contract_defining_trait = analysis_db.load_contract(&trait_identifier.contract_identifier)
                .ok_or(CheckErrors::TraitReferenceUnknown(trait_identifier.name.to_string()))?;
            let trait_sig = contract_defining_trait.get_defined_trait(&trait_name)
                .ok_or(CheckErrors::TraitReferenceUnknown(trait_identifier.name.to_string()))?;

            for (func_name, expected_sig) in trait_sig.iter() {
                match contract_analysis.get_public_function_type(func_name) {
                    Some(FunctionType::Fixed(func)) => {
                        if func.args.len() != expected_sig.args.len() {
                            return Err(CheckErrors::BadTraitImplementation(trait_name.clone(), func_name.to_string()).into())
                        }
                        let args = expected_sig.args.iter().zip(func.args.iter());
                        for (expected_arg, arg) in args {
                            match (expected_arg, &arg.signature) {
                                (TypeSignature::TraitReferenceType(expected), TypeSignature::TraitReferenceType(actual)) => {
                                    if actual != expected {
                                        return Err(CheckErrors::BadTraitImplementation(trait_name.clone(), func_name.to_string()).into())
                                    }
                                }
                                _ => {
                                    if !expected_arg.admits_type(&arg.signature) {
                                        return Err(CheckErrors::BadTraitImplementation(trait_name.clone(), func_name.to_string()).into())
                                    }        
                                }
                            }
                        }

                        if !expected_sig.returns.admits_type(&func.returns) {
                            return Err(CheckErrors::BadTraitImplementation(trait_name, func_name.to_string()).into())
                        }
                    }
                    _ => {
                        return Err(CheckErrors::BadTraitImplementation(trait_name, func_name.to_string()).into())
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
