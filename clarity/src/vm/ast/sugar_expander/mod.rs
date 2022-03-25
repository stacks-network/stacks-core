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
use std::convert::TryInto;
use vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use vm::ast::types::{BuildASTPass, ContractAST, PreExpressionsDrain};
use vm::functions::define::{DefineFunctions, DefineFunctionsParsed};
use vm::functions::NativeFunctions;
use vm::representations::{
    ClarityName, PreSymbolicExpression, PreSymbolicExpressionType, SymbolicExpression,
    SymbolicExpressionType,
};
use vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TraitIdentifier, Value,
};
use vm::ClarityVersion;

pub struct SugarExpander {
    issuer: StandardPrincipalData,
    defined_traits: HashSet<ClarityName>,
    imported_traits: HashMap<ClarityName, TraitIdentifier>,
}

impl BuildASTPass for SugarExpander {
    fn run_pass(contract_ast: &mut ContractAST, _version: ClarityVersion) -> ParseResult<()> {
        let pass = SugarExpander::new(contract_ast.contract_identifier.issuer.clone());
        pass.run(contract_ast)?;
        Ok(())
    }
}

impl SugarExpander {
    fn new(issuer: StandardPrincipalData) -> Self {
        Self {
            issuer,
            defined_traits: HashSet::new(),
            imported_traits: HashMap::new(),
        }
    }

    pub fn run(&self, contract_ast: &mut ContractAST) -> ParseResult<()> {
        let expressions = self.transform(contract_ast.pre_expressions_drain(), contract_ast)?;
        contract_ast.expressions = expressions;
        Ok(())
    }

    pub fn transform(
        &self,
        pre_exprs_iter: PreExpressionsDrain,
        contract_ast: &mut ContractAST,
    ) -> ParseResult<Vec<SymbolicExpression>> {
        let mut expressions = Vec::new();

        for pre_expr in pre_exprs_iter {
            let mut expr = match pre_expr.pre_expr {
                PreSymbolicExpressionType::AtomValue(content) => {
                    SymbolicExpression::literal_value(content)
                }
                PreSymbolicExpressionType::Atom(content) => SymbolicExpression::atom(content),
                PreSymbolicExpressionType::List(pre_exprs) => {
                    let drain = PreExpressionsDrain::new(pre_exprs.to_vec().drain(..), None);
                    let expression = self.transform(drain, contract_ast)?;
                    SymbolicExpression::list(expression.into_boxed_slice())
                }
                PreSymbolicExpressionType::Tuple(pre_exprs) => {
                    let drain = PreExpressionsDrain::new(pre_exprs.to_vec().drain(..), None);
                    let expression = self.transform(drain, contract_ast)?;
                    let mut pairs = expression
                        .chunks(2)
                        .map(|pair| pair.to_vec().into_boxed_slice())
                        .map(SymbolicExpression::list)
                        .collect::<Vec<_>>();
                    pairs.insert(
                        0,
                        SymbolicExpression::atom("tuple".to_string().try_into().unwrap()),
                    );
                    SymbolicExpression::list(pairs.into_boxed_slice())
                }
                PreSymbolicExpressionType::SugaredContractIdentifier(contract_name) => {
                    let contract_identifier =
                        QualifiedContractIdentifier::new(self.issuer.clone(), contract_name);
                    SymbolicExpression::literal_value(Value::Principal(PrincipalData::Contract(
                        contract_identifier,
                    )))
                }
                PreSymbolicExpressionType::SugaredFieldIdentifier(contract_name, name) => {
                    let contract_identifier =
                        QualifiedContractIdentifier::new(self.issuer.clone(), contract_name);
                    SymbolicExpression::field(TraitIdentifier {
                        name,
                        contract_identifier,
                    })
                }
                PreSymbolicExpressionType::FieldIdentifier(trait_identifier) => {
                    SymbolicExpression::field(trait_identifier)
                }
                PreSymbolicExpressionType::TraitReference(name) => {
                    if let Some(trait_reference) = contract_ast.get_referenced_trait(&name) {
                        SymbolicExpression::trait_reference(name, trait_reference.clone())
                    } else {
                        return Err(ParseErrors::TraitReferenceUnknown(name.to_string()).into());
                    }
                }
            };
            // expr.id will be set by the subsequent expression identifier pass.
            expr.span = pre_expr.span.clone();
            expressions.push(expr);
        }
        Ok(expressions)
    }
}

#[cfg(test)]
mod test {
    use vm::ast::errors::{ParseError, ParseErrors};
    use vm::ast::sugar_expander::SugarExpander;
    use vm::ast::types::ContractAST;
    use vm::representations::{ContractName, PreSymbolicExpression, SymbolicExpression};
    use vm::types::{PrincipalData, QualifiedContractIdentifier};
    use vm::{ast, Value};

    fn make_pre_atom(
        x: &str,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::atom(x.into());
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_pre_atom_value(
        x: Value,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::atom_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_pre_list(
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        x: Box<[PreSymbolicExpression]>,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::list(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_pre_tuple(
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        x: Box<[PreSymbolicExpression]>,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::tuple(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_sugared_contract_identifier(
        x: ContractName,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::sugared_contract_identifier(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_atom(
        x: &str,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> SymbolicExpression {
        let mut e = SymbolicExpression::atom(x.into());
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_atom_value(
        x: Value,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> SymbolicExpression {
        let mut e = SymbolicExpression::atom_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_list(
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        x: Box<[SymbolicExpression]>,
    ) -> SymbolicExpression {
        let mut e = SymbolicExpression::list(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_literal_value(
        x: Value,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> SymbolicExpression {
        let mut e = SymbolicExpression::literal_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    #[test]
    fn test_transform_pre_ast() {
        let pre_ast = vec![
            make_pre_atom("z", 1, 1, 1, 1),
            make_pre_list(
                1,
                3,
                6,
                11,
                Box::new([
                    make_pre_atom("let", 1, 4, 1, 6),
                    make_pre_list(
                        1,
                        8,
                        1,
                        20,
                        Box::new([
                            make_pre_list(
                                1,
                                9,
                                1,
                                13,
                                Box::new([
                                    make_pre_atom("x", 1, 10, 1, 10),
                                    make_pre_atom_value(Value::Int(1), 1, 12, 1, 12),
                                ]),
                            ),
                            make_pre_list(
                                1,
                                15,
                                1,
                                19,
                                Box::new([
                                    make_pre_atom("y", 1, 16, 1, 16),
                                    make_pre_atom_value(Value::Int(2), 1, 18, 1, 18),
                                ]),
                            ),
                        ]),
                    ),
                    make_pre_list(
                        2,
                        5,
                        6,
                        10,
                        Box::new([
                            make_pre_atom("+", 2, 6, 2, 6),
                            make_pre_atom("x", 2, 8, 2, 8),
                            make_pre_list(
                                4,
                                9,
                                5,
                                16,
                                Box::new([
                                    make_pre_atom("let", 4, 10, 4, 12),
                                    make_pre_list(
                                        4,
                                        14,
                                        4,
                                        20,
                                        Box::new([make_pre_list(
                                            4,
                                            15,
                                            4,
                                            19,
                                            Box::new([
                                                make_pre_atom("x", 4, 16, 4, 16),
                                                make_pre_atom_value(Value::Int(3), 4, 18, 4, 18),
                                            ]),
                                        )]),
                                    ),
                                    make_pre_list(
                                        5,
                                        9,
                                        5,
                                        15,
                                        Box::new([
                                            make_pre_atom("+", 5, 10, 5, 10),
                                            make_pre_atom("x", 5, 12, 5, 12),
                                            make_pre_atom("y", 5, 14, 5, 14),
                                        ]),
                                    ),
                                ]),
                            ),
                            make_pre_atom("x", 6, 9, 6, 9),
                        ]),
                    ),
                ]),
            ),
            make_pre_atom("x", 6, 13, 6, 13),
            make_pre_atom("y", 6, 15, 6, 15),
        ];

        let ast = vec![
            make_atom("z", 1, 1, 1, 1),
            make_list(
                1,
                3,
                6,
                11,
                Box::new([
                    make_atom("let", 1, 4, 1, 6),
                    make_list(
                        1,
                        8,
                        1,
                        20,
                        Box::new([
                            make_list(
                                1,
                                9,
                                1,
                                13,
                                Box::new([
                                    make_atom("x", 1, 10, 1, 10),
                                    make_literal_value(Value::Int(1), 1, 12, 1, 12),
                                ]),
                            ),
                            make_list(
                                1,
                                15,
                                1,
                                19,
                                Box::new([
                                    make_atom("y", 1, 16, 1, 16),
                                    make_literal_value(Value::Int(2), 1, 18, 1, 18),
                                ]),
                            ),
                        ]),
                    ),
                    make_list(
                        2,
                        5,
                        6,
                        10,
                        Box::new([
                            make_atom("+", 2, 6, 2, 6),
                            make_atom("x", 2, 8, 2, 8),
                            make_list(
                                4,
                                9,
                                5,
                                16,
                                Box::new([
                                    make_atom("let", 4, 10, 4, 12),
                                    make_list(
                                        4,
                                        14,
                                        4,
                                        20,
                                        Box::new([make_list(
                                            4,
                                            15,
                                            4,
                                            19,
                                            Box::new([
                                                make_atom("x", 4, 16, 4, 16),
                                                make_literal_value(Value::Int(3), 4, 18, 4, 18),
                                            ]),
                                        )]),
                                    ),
                                    make_list(
                                        5,
                                        9,
                                        5,
                                        15,
                                        Box::new([
                                            make_atom("+", 5, 10, 5, 10),
                                            make_atom("x", 5, 12, 5, 12),
                                            make_atom("y", 5, 14, 5, 14),
                                        ]),
                                    ),
                                ]),
                            ),
                            make_atom("x", 6, 9, 6, 9),
                        ]),
                    ),
                ]),
            ),
            make_atom("x", 6, 13, 6, 13),
            make_atom("y", 6, 15, 6, 15),
        ];

        let contract_id = QualifiedContractIdentifier::parse(
            "S1G2081040G2081040G2081040G208105NK8PE5.contract-a",
        )
        .unwrap();
        let mut contract_ast = ContractAST::new(contract_id.clone(), pre_ast);
        let expander = SugarExpander::new(contract_id.issuer);
        expander.run(&mut contract_ast).unwrap();
        assert_eq!(
            contract_ast.expressions, ast,
            "Should match expected symbolic expression"
        );
    }

    #[test]
    fn test_transform_tuple_literal() {
        let pre_ast = vec![make_pre_tuple(
            1,
            1,
            1,
            9,
            Box::new([
                make_pre_atom("id", 1, 2, 1, 3),
                make_pre_atom_value(Value::Int(1337), 1, 5, 1, 8),
            ]),
        )];
        let ast = vec![make_list(
            1,
            1,
            1,
            9,
            Box::new([
                make_atom("tuple", 0, 0, 0, 0),
                make_list(
                    0,
                    0,
                    0,
                    0,
                    Box::new([
                        make_atom("id", 1, 2, 1, 3),
                        make_literal_value(Value::Int(1337), 1, 5, 1, 8),
                    ]),
                ),
            ]),
        )];
        let contract_id = QualifiedContractIdentifier::parse(
            "S1G2081040G2081040G2081040G208105NK8PE5.contract-a",
        )
        .unwrap();
        let mut contract_ast = ContractAST::new(contract_id.clone(), pre_ast);
        let expander = SugarExpander::new(contract_id.issuer);
        expander.run(&mut contract_ast).unwrap();
        assert_eq!(
            contract_ast.expressions, ast,
            "Should match expected tuple symbolic expression"
        );
    }
    #[test]
    fn test_transform_sugared_contract_identifier() {
        let contract_name = "tokens".into();
        let pre_ast = vec![make_sugared_contract_identifier(contract_name, 1, 1, 1, 1)];
        let unsugared_contract_id =
            QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens")
                .unwrap();
        let ast = vec![make_literal_value(
            Value::Principal(PrincipalData::Contract(unsugared_contract_id)),
            1,
            1,
            1,
            1,
        )];

        let contract_id = QualifiedContractIdentifier::parse(
            "S1G2081040G2081040G2081040G208105NK8PE5.contract-a",
        )
        .unwrap();
        let mut contract_ast = ContractAST::new(contract_id.clone(), pre_ast);
        let expander = SugarExpander::new(contract_id.issuer);
        expander.run(&mut contract_ast).unwrap();
        assert_eq!(
            contract_ast.expressions, ast,
            "Should match expected symbolic expression"
        );
    }
}
