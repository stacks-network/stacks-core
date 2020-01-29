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

    // todo(ludo): we should also probably run some code, pre-evaluation.

    pub fn run(&mut self, contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let exprs = contract_analysis.expressions[..].to_vec();
        let trait_usages = self.find_trait_usages(&exprs)?;
        
        // Presence of orphaned traits should throw
        if trait_usages.orphan_trait_references.len() > 0 {
            let orphan = trait_usages.orphan_trait_references.keys().next().unwrap();
            let expr = trait_usages.orphan_trait_references.get(orphan).unwrap();
            let mut err = CheckError::new(CheckErrors::TraitReferenceUnknown(orphan.to_string()));
            err.set_expression(&expr);
            return Err(err.into());
        }

        // Ensure that imported traits exists
        for (trait_name, expr) in trait_usages.imported_traits.iter() {
            // todo(ludo): in progress
            // analysis_db.get_defined_trait(contract_identifier, &trait_name)
            //     .ok_or(CheckErrors::TraitReferenceUnknown(orphan.to_string()).into())?;
        }
        // todo(ludo): Ensure that used / imported traits are resolving
        // Look at the code for contract-call

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

        let mut orphan_trait_references = HashMap::new();
        for (trait_name, expr) in &referenced_traits {
            if !imported_traits.contains_key(trait_name) && !defined_traits.contains_key(trait_name) {
                orphan_trait_references.insert(trait_name.clone(), expr.clone());
            }
        }

        Ok(TraitUsages {
            defined_traits,
            imported_traits,
            referenced_traits,
            orphan_trait_references,        
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
