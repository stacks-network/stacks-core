use std::collections::{HashMap, HashSet};

use vm::analysis::AnalysisDatabase;
use vm::representations::{SymbolicExpression, PreSymbolicExpression, ClarityName};
use vm::types::{Value, TraitIdentifier, QualifiedContractIdentifier};
use vm::functions::NativeFunctions;
use vm::functions::define::{DefineFunctions, DefineFunctionsParsed};
use vm::ast::types::{ContractAST, BuildASTPass, PreExpressionsDrain};
use vm::ast::errors::{ParseResult, ParseError, ParseErrors};
use vm::representations::PreSymbolicExpressionType::{AtomValue, Atom, List, TraitReference, SugaredFieldIdentifier, FieldIdentifier};            

pub struct TraitsResolver {
}

impl BuildASTPass for TraitsResolver {

    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        let mut command = TraitsResolver::new();
        command.run(contract_ast)?;
        Ok(())
    }
}

impl TraitsResolver {

    fn new() -> Self {
        Self {
        }
    }

    pub fn run(&mut self, contract_ast: &mut ContractAST) -> ParseResult<()> {
        let exprs = contract_ast.pre_expressions[..].to_vec();
        let mut trait_usages = self.find_trait_usages(&exprs)?;
        
        // Presence of orphaned traits should throw
        for (orphan, expr) in trait_usages.orphan_trait_references {
            let mut err = ParseError::new(ParseErrors::TraitReferenceUnknown(orphan.to_string()));
            err.set_pre_expression(&expr);
            return Err(err.into());
        }

        // Ensure that imported traits exists
        for (trait_name, trait_expr) in trait_usages.imported_traits.drain() {
            let imported_trait_args = trait_expr.match_list().ok_or(ParseErrors::ImportTraitBadSignature)?;
            if imported_trait_args.len() != 3 {
                return Err(ParseErrors::ImportTraitBadSignature.into())
            }
            let trait_identifier = match &imported_trait_args[2].pre_expr {
                SugaredFieldIdentifier(contract_name, name) => {
                    let contract_identifier = QualifiedContractIdentifier::new(
                        contract_ast.contract_identifier.issuer.clone(), 
                        contract_name.clone());
                    TraitIdentifier { name: name.clone(), contract_identifier}
                },
                FieldIdentifier(trait_identifier) => trait_identifier.clone(),
                _ => return Err(ParseErrors::ImportTraitBadSignature.into()),
            };
            contract_ast.referenced_traits.insert(trait_name, trait_identifier);
        }

        // Reference the defined traits
        for (name, _) in trait_usages.defined_traits.drain() {
            let trait_id = TraitIdentifier {
                name: name.clone(),
                contract_identifier: contract_ast.contract_identifier.clone()      
            };

            // Check for collisions between defined traits and imported traits
            if contract_ast.referenced_traits.contains_key(&name) {
                return Err(ParseErrors::NameAlreadyUsed(name.to_string()).into())
            }
            contract_ast.referenced_traits.insert(name, trait_id);
        }

        // Ensure that implemented traits exists
        for trait_identifier in trait_usages.implemented_traits.drain() {
            // let existing_trait = analysis_db.get_defined_trait(
            //     &trait_identifier.contract_identifier, 
            //     &trait_identifier.name)?;
            // existing_trait.ok_or(CheckError::new(CheckErrors::TraitReferenceUnknown(trait_identifier.name.to_string())))?;
            contract_ast.add_implemented_trait(trait_identifier);
        }
        Ok(())
    }

    fn find_trait_usages(&mut self, exprs: &[PreSymbolicExpression]) -> ParseResult<TraitUsages> {
        let mut defined_traits = HashMap::new();
        let mut imported_traits = HashMap::new();
        let mut referenced_traits = HashMap::new();
        let mut implemented_traits = HashSet::new();

        for exp in exprs.iter() {
            
            let (define_type, args) = match self.try_parse_pre_expr(exp) {
                Some(x) => x,
                None => continue 
            };

            match define_type {
                DefineFunctions::Trait => {
                    if let Some(trait_name) = args[0].match_atom() {
                        // Check for collisions between defined traits
                        if defined_traits.contains_key(trait_name) {
                            return Err(ParseErrors::NameAlreadyUsed(trait_name.to_string()).into())
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
                            return Err(ParseErrors::NameAlreadyUsed(trait_name.to_string()).into())
                        }

                        imported_traits.insert(trait_name.clone(), exp.clone());
                    }
                },
                DefineFunctions::ImplTrait => {
                    if let Some(trait_identifier) = args[0].match_field_identifier() {
                        // Check for multiple impl-trait statements targeting the same trait
                        if implemented_traits.contains(trait_identifier) {
                            return Err(ParseErrors::NameAlreadyUsed(trait_identifier.name.to_string()).into())
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

    fn try_parse_pre_expr<'a>(&self, expression: &'a PreSymbolicExpression) -> Option<(DefineFunctions, &'a [PreSymbolicExpression])> {
        let expression = expression.match_list()?;
        let (function_name, args) = expression.split_first()?;
        let function_name = function_name.match_atom()?;
        let define_type = DefineFunctions::lookup_by_name(function_name)?;
        Some((define_type, args))
    }

    fn probe_for_generics(&mut self, exprs: &[PreSymbolicExpression], 
                          referenced_traits: &mut HashMap<ClarityName, PreSymbolicExpression>, 
                          should_reference: bool) -> ParseResult<()>  {
        for expression in exprs.iter() {

            match &expression.pre_expr {
                List(list) => { self.probe_for_generics(&list, referenced_traits, should_reference)?; },
                TraitReference(trait_name) => {
                    if should_reference {
                        referenced_traits.insert(trait_name.clone(), expression.clone());
                    } else {
                        return Err(ParseErrors::TraitReferenceNotAllowed.into())
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
    pub defined_traits: HashMap<ClarityName, PreSymbolicExpression>,
    pub imported_traits: HashMap<ClarityName, PreSymbolicExpression>,
    pub referenced_traits: HashMap<ClarityName, PreSymbolicExpression>,
    pub implemented_traits: HashSet<TraitIdentifier>,
    pub orphan_trait_references: HashMap<ClarityName, PreSymbolicExpression>,
}