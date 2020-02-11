use std::collections::{HashMap, HashSet};

use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::analysis::AnalysisDatabase;
use vm::analysis::errors::{CheckResult, CheckError, CheckErrors};
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue, TraitReference, Field};
use vm::types::{Value, TraitIdentifier};
use vm::functions::NativeFunctions;
use vm::functions::define::{DefineFunctions, DefineFunctionsParsed};

pub struct PreTypeCheckingTraitChecker {
}

impl AnalysisPass for PreTypeCheckingTraitChecker {

    fn run_pass(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut command = PreTypeCheckingTraitChecker::new();
        command.run(contract_analysis, analysis_db)?;
        Ok(())
    }
}

impl PreTypeCheckingTraitChecker {

    fn new() -> Self {
        Self {
        }
    }

    pub fn run(&mut self, contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let exprs = contract_analysis.expressions[..].to_vec();
        let mut trait_usages = self.find_trait_usages(&exprs)?;
        
        // Presence of orphaned traits should throw
        for (orphan, expr) in trait_usages.orphan_trait_references {
            let mut err = CheckError::new(CheckErrors::TraitReferenceUnknown(orphan.to_string()));
            err.set_expression(&expr);
            return Err(err.into());
        }

        // Ensure that imported traits exists
        for (trait_name, trait_expr) in trait_usages.imported_traits.drain() {
            let imported_trait_args = trait_expr.match_list().ok_or(CheckErrors::ImportTraitBadSignature)?;
            if imported_trait_args.len() != 3 {
                return Err(CheckErrors::ImportTraitBadSignature.into())
            }
            let trait_identifier = match &imported_trait_args[2].expr {
                Field(field) => field,
                _ => return Err(CheckErrors::ImportTraitBadSignature.into()),
            };

            let existing_trait = analysis_db.get_defined_trait(
                &trait_identifier.contract_identifier, 
                &trait_identifier.name)?;
            existing_trait.ok_or(CheckError::new(CheckErrors::TraitReferenceUnknown(trait_name.to_string())))?;
            
            contract_analysis.referenced_traits.insert(trait_name, trait_identifier.clone());
        }

        // Reference the defined traits
        for (name, _) in trait_usages.defined_traits.drain() {
            let trait_id = TraitIdentifier {
                name: name.clone(),
                contract_identifier: contract_analysis.contract_identifier.clone()      
            };

            // Check for collisions between defined traits and imported traits
            if contract_analysis.referenced_traits.contains_key(&name) {
                return Err(CheckErrors::NameAlreadyUsed(name.to_string()).into())
            }
            contract_analysis.referenced_traits.insert(name, trait_id);
        }

        // Ensure that implemented traits exists
        for trait_identifier in trait_usages.implemented_traits.drain() {
            let existing_trait = analysis_db.get_defined_trait(
                &trait_identifier.contract_identifier, 
                &trait_identifier.name)?;
            existing_trait.ok_or(CheckError::new(CheckErrors::TraitReferenceUnknown(trait_identifier.name.to_string())))?;
            contract_analysis.add_implemented_trait(trait_identifier);
        }
        Ok(())
    }

    fn find_trait_usages(&mut self, exprs: &[SymbolicExpression]) -> CheckResult<TraitUsages> {
        let mut defined_traits = HashMap::new();
        let mut imported_traits = HashMap::new();
        let mut referenced_traits = HashMap::new();
        let mut implemented_traits = HashSet::new();

        for exp in exprs.iter() {
            let (define_type, args) = match DefineFunctions::try_parse(exp) {
                Some(x) => x,
                None => continue 
            };
            match define_type {
                DefineFunctions::Trait => {
                    if let Some(trait_name) = args[0].match_atom() {
                        // Check for collisions between defined traits
                        if defined_traits.contains_key(trait_name) {
                            return Err(CheckErrors::NameAlreadyUsed(trait_name.to_string()).into())
                        }

                        defined_traits.insert(trait_name.clone(), exp.clone());
                        // Traverse and probe for generics nested in the trait definition
                        if let Some(trait_definition) = &args[1].match_list() {
                            self.probe_for_generics(trait_definition, &mut referenced_traits, true)?;
                        }    
                    }
                },
                DefineFunctions::UseTrait => {
                    if let Some(trait_name) = args[0].match_atom() {
                        // Check for collisions between imported traits
                        if imported_traits.contains_key(trait_name) {
                            return Err(CheckErrors::NameAlreadyUsed(trait_name.to_string()).into())
                        }

                        imported_traits.insert(trait_name.clone(), exp.clone());
                    }
                },
                DefineFunctions::ImplTrait => {
                    if let Some(trait_identifier) = args[0].match_field() {
                        // Check for multiple impl-trait statements targeting the same trait
                        if implemented_traits.contains(trait_identifier) {
                            return Err(CheckErrors::NameAlreadyUsed(trait_identifier.name.to_string()).into())
                        }
                        
                        implemented_traits.insert(trait_identifier.clone());
                    }
                },
                DefineFunctions::PublicFunction | DefineFunctions::PrivateFunction | DefineFunctions::ReadOnlyFunction => {
                    // Traverse and probe for generics in functions type definitions
                    self.probe_for_generics(&args, &mut referenced_traits, true)?;
                },
                DefineFunctions::Constant | DefineFunctions::Map | DefineFunctions::PersistedVariable | 
                DefineFunctions::FungibleToken | DefineFunctions::NonFungibleToken => {
                    self.probe_for_generics(&args[1..], &mut referenced_traits, false)?;
                }
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
            implemented_traits,
            orphan_trait_references,        
        })
    }

    fn probe_for_generics(&mut self, exprs: &[SymbolicExpression], 
                          referenced_traits: &mut HashMap<ClarityName, SymbolicExpression>, 
                          should_reference: bool) -> CheckResult<()>  {
        for expression in exprs.iter() {

            match &expression.expr {
                List(list) => { self.probe_for_generics(&list, referenced_traits, should_reference)?; },
                TraitReference(trait_name) => {
                    if should_reference {
                        referenced_traits.insert(trait_name.clone(), expression.clone());
                    } else {
                        return Err(CheckErrors::TraitReferenceNotAllowed.into())
                    }
                },
                _ => { /* no-op */ }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TraitUsages {
    pub defined_traits: HashMap<ClarityName, SymbolicExpression>,
    pub imported_traits: HashMap<ClarityName, SymbolicExpression>,
    pub referenced_traits: HashMap<ClarityName, SymbolicExpression>,
    pub implemented_traits: HashSet<TraitIdentifier>,
    pub orphan_trait_references: HashMap<ClarityName, SymbolicExpression>,
}