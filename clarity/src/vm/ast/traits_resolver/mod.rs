// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::{HashMap, HashSet};

use crate::vm::analysis::AnalysisDatabase;
use crate::vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use crate::vm::ast::types::{BuildASTPass, ContractAST, PreExpressionsDrain};
use crate::vm::functions::define::{DefineFunctions, DefineFunctionsParsed};
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::PreSymbolicExpressionType::{
    Atom, AtomValue, FieldIdentifier, List, SugaredFieldIdentifier, TraitReference, Tuple,
};
use crate::vm::representations::{
    ClarityName, PreSymbolicExpression, SymbolicExpression, TraitDefinition,
};
use crate::vm::types::{QualifiedContractIdentifier, TraitIdentifier, Value};

pub struct TraitsResolver {}

impl BuildASTPass for TraitsResolver {
    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        let mut command = TraitsResolver::new();
        command.run(contract_ast)?;
        Ok(())
    }
}

impl TraitsResolver {
    fn new() -> TraitsResolver {
        TraitsResolver {}
    }

    pub fn run(&mut self, contract_ast: &mut ContractAST) -> ParseResult<()> {
        let exprs = contract_ast.pre_expressions[..].to_vec();
        let mut referenced_traits = HashMap::new();

        for exp in exprs.iter() {
            let (define_type, args) = match self.try_parse_pre_expr(exp) {
                Some(x) => x,
                None => continue,
            };

            match define_type {
                DefineFunctions::Trait => {
                    if args.len() != 2 {
                        return Err(ParseErrors::DefineTraitBadSignature.into());
                    }

                    match (&args[0].pre_expr, &args[1].pre_expr) {
                        (Atom(trait_name), List(trait_definition)) => {
                            // Check for collisions
                            if contract_ast.referenced_traits.contains_key(trait_name) {
                                return Err(
                                    ParseErrors::NameAlreadyUsed(trait_name.to_string()).into()
                                );
                            }

                            // Traverse and probe for generics nested in the trait definition
                            self.probe_for_generics(
                                trait_definition,
                                &mut referenced_traits,
                                true,
                            )?;

                            let trait_id = TraitIdentifier {
                                name: trait_name.clone(),
                                contract_identifier: contract_ast.contract_identifier.clone(),
                            };
                            contract_ast
                                .referenced_traits
                                .insert(trait_name.clone(), TraitDefinition::Defined(trait_id));
                        }
                        _ => return Err(ParseErrors::DefineTraitBadSignature.into()),
                    }
                }
                DefineFunctions::UseTrait => {
                    if args.len() != 2 {
                        return Err(ParseErrors::ImportTraitBadSignature.into());
                    }

                    if let Some(trait_name) = args[0].match_atom() {
                        // Check for collisions
                        if contract_ast.referenced_traits.contains_key(trait_name) {
                            return Err(ParseErrors::NameAlreadyUsed(trait_name.to_string()).into());
                        }

                        let trait_id = match &args[1].pre_expr {
                            SugaredFieldIdentifier(contract_name, name) => {
                                let contract_identifier = QualifiedContractIdentifier::new(
                                    contract_ast.contract_identifier.issuer.clone(),
                                    contract_name.clone(),
                                );
                                TraitIdentifier {
                                    name: name.clone(),
                                    contract_identifier,
                                }
                            }
                            FieldIdentifier(trait_identifier) => trait_identifier.clone(),
                            _ => return Err(ParseErrors::ImportTraitBadSignature.into()),
                        };
                        contract_ast
                            .referenced_traits
                            .insert(trait_name.clone(), TraitDefinition::Imported(trait_id));
                    } else {
                        return Err(ParseErrors::ImportTraitBadSignature.into());
                    }
                }
                DefineFunctions::ImplTrait => {
                    if args.len() != 1 {
                        return Err(ParseErrors::ImplTraitBadSignature.into());
                    }

                    let trait_id = match &args[0].pre_expr {
                        SugaredFieldIdentifier(contract_name, name) => {
                            let contract_identifier = QualifiedContractIdentifier::new(
                                contract_ast.contract_identifier.issuer.clone(),
                                contract_name.clone(),
                            );
                            TraitIdentifier {
                                name: name.clone(),
                                contract_identifier,
                            }
                        }
                        FieldIdentifier(trait_identifier) => trait_identifier.clone(),
                        _ => return Err(ParseErrors::ImplTraitBadSignature.into()),
                    };
                    contract_ast.implemented_traits.insert(trait_id);
                }
                DefineFunctions::PublicFunction
                | DefineFunctions::PrivateFunction
                | DefineFunctions::ReadOnlyFunction => {
                    // Traverse and probe for generics in functions type definitions
                    self.probe_for_generics(&args, &mut referenced_traits, true)?;
                }
                DefineFunctions::Constant
                | DefineFunctions::Map
                | DefineFunctions::PersistedVariable
                | DefineFunctions::FungibleToken
                | DefineFunctions::NonFungibleToken => {
                    self.probe_for_generics(&args[1..], &mut referenced_traits, false)?;
                }
            };
        }

        for (trait_reference, expr) in referenced_traits {
            if !contract_ast
                .referenced_traits
                .contains_key(&trait_reference)
            {
                let mut err = ParseError::new(ParseErrors::TraitReferenceUnknown(
                    trait_reference.to_string(),
                ));
                err.set_pre_expression(&expr);
                return Err(err.into());
            }
        }

        Ok(())
    }

    fn try_parse_pre_expr<'a>(
        &self,
        expression: &'a PreSymbolicExpression,
    ) -> Option<(DefineFunctions, &'a [PreSymbolicExpression])> {
        let expression = expression.match_list()?;
        let (function_name, args) = expression.split_first()?;
        let function_name = function_name.match_atom()?;
        let define_type = DefineFunctions::lookup_by_name(function_name)?;
        Some((define_type, args))
    }

    fn probe_for_generics(
        &mut self,
        exprs: &[PreSymbolicExpression],
        referenced_traits: &mut HashMap<ClarityName, PreSymbolicExpression>,
        should_reference: bool,
    ) -> ParseResult<()> {
        for expression in exprs.iter() {
            match &expression.pre_expr {
                List(list) => {
                    self.probe_for_generics(&list, referenced_traits, should_reference)?;
                }
                TraitReference(trait_name) => {
                    if should_reference {
                        referenced_traits.insert(trait_name.clone(), expression.clone());
                    } else {
                        return Err(ParseErrors::TraitReferenceNotAllowed.into());
                    }
                }
                Tuple(atoms) => {
                    self.probe_for_generics(&atoms, referenced_traits, should_reference)?;
                }
                _ => { /* no-op */ }
            }
        }
        Ok(())
    }
}
