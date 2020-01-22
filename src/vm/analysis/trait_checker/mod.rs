use std::collections::HashMap;

use super::types::{ContractAnalysis, AnalysisPass, TraitUsages};
use super::AnalysisDatabase;
use super::errors::{CheckResult, CheckError, CheckErrors};
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::types::{Value};
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
        let exprs = contract_analysis.expressions[..].to_vec();
        let trait_usages = self.find_trait_usages(&exprs)?;
        
        // Presence of orphaned traits should throw
        if let Some(t) = trait_usages.orphan_traits.first() {
            return Err(CheckErrors::UnknownTrait(t.to_string()).into());
        }

        // if !error.has_expression() {
        //     error.set_expression(&exp);
        // }

        // Ensure that used / imported traits are resolving
        // Look at the code for contract-call
        println!("{:?}", trait_usages);

        contract_analysis.trait_usages = Some(trait_usages);

        Ok(())
    }

    fn find_trait_usages(&mut self, exprs: &[SymbolicExpression]) -> CheckResult<TraitUsages> {
        let mut defined_traits = HashMap::new();
        let mut imported_traits = HashMap::new();
        let mut referenced_traits = HashMap::new();

        for exp in exprs.iter() {
            let (define_type, args) = match DefineFunctions::try_parse(exp) {
                Some(x) => x,
                None => continue 
            };
            match (define_type, &args[0].expr) {
                (DefineFunctions::Trait, Atom(trait_name)) => {
                    defined_traits.insert(trait_name.clone(), exp.clone());
                    // Traverse and probe for generics nested in the trait definition
                    if let Some(trait_definition) = &args[1].match_list() {
                        self.probe_for_generics(trait_definition, &mut referenced_traits);
                    }
                },
                (DefineFunctions::UseTrait, Atom(trait_name)) => {
                    imported_traits.insert(trait_name.clone(), exp.clone());
                },
                (DefineFunctions::PublicFunction, List(function_definition)) | 
                (DefineFunctions::PrivateFunction, List(function_definition)) => {
                    // Traverse and probe for generics in functions type definitions
                    self.probe_for_generics(function_definition, &mut referenced_traits);
                },
                _ => { /* no-op */ }
            };
        }

        let mut orphan_traits = vec![];
        for (trait_name, _) in &referenced_traits {
            if !imported_traits.contains_key(trait_name) && !defined_traits.contains_key(trait_name) {
                orphan_traits.push(trait_name.clone());
            }
        }

        Ok(TraitUsages {
            defined_traits,
            imported_traits,
            referenced_traits,
            orphan_traits,        
        })
    }

    fn probe_for_generics(&mut self, exprs: &[SymbolicExpression], referenced_traits: &mut HashMap<ClarityName, SymbolicExpression>) {
        for expression in exprs.iter() {

            match &expression.expr {
                List(list) => self.probe_for_generics(&list, referenced_traits),
                LiteralValue(Value::TraitReference(trait_name)) => { 
                    referenced_traits.insert(trait_name.clone(), expression.clone()); 
                },
                _ => { /* no-op */ }
            }
        }
    }
}
