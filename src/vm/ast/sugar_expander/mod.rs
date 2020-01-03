use std::convert::TryInto;
use vm::representations::{PreSymbolicExpression, PreSymbolicExpressionType, SymbolicExpression, SymbolicExpressionType};
use vm::types::{QualifiedContractIdentifier, Value, PrincipalData, StandardPrincipalData};
use vm::ast::types::{ContractAST, BuildASTPass};
use vm::ast::errors::{ParseResult, ParseError, ParseErrors};
use vm::functions::NativeFunctions;

pub struct SugarExpander {
    issuer: StandardPrincipalData   
}

impl BuildASTPass for SugarExpander {

    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        let pass = SugarExpander::new(contract_ast.contract_identifier.issuer.clone());
        let expressions = pass.run(&mut contract_ast.pre_expressions);
        contract_ast.expressions = expressions;
        Ok(())
    }
}

impl SugarExpander {

    fn new(issuer: StandardPrincipalData) -> Self {
        Self { issuer }
    }

    pub fn run(&self, pre_expressions: &mut Vec<PreSymbolicExpression>) -> Vec<SymbolicExpression> {
        self.transform(pre_expressions)
    }

    pub fn transform(&self, pre_expressions: &mut Vec<PreSymbolicExpression>) -> Vec<SymbolicExpression> {
        let mut expressions = Vec::new();
        for pre_expr in pre_expressions.drain(..) {

            let mut expr = match pre_expr.pre_expr {
                PreSymbolicExpressionType::AtomValue(content) => {
                    SymbolicExpression::literal_value(content)
                },
                PreSymbolicExpressionType::Atom(content) => {
                    SymbolicExpression::atom(content)
                },
                PreSymbolicExpressionType::UnexpandedContractName(contract_name) => {
                    let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name);
                    SymbolicExpression::literal_value(Value::Principal(PrincipalData::Contract(contract_identifier)))
                },
                PreSymbolicExpressionType::List(pre_exprs) => {
                    let exprs = self.transform(&mut pre_exprs.to_vec());
                    SymbolicExpression::list(exprs.into_boxed_slice())
                }
            };
            expr.span = pre_expr.span.clone();
            expressions.push(expr);
        }
        expressions
    }
}



#[cfg(test)]
mod test {
    use vm::representations::{PreSymbolicExpression, SymbolicExpression, ContractName};
    use vm::{Value, ast};
    use vm::types::{QualifiedContractIdentifier, PrincipalData};
    use vm::ast::errors::{ParseErrors, ParseError};
    use vm::ast::sugar_expander::SugarExpander;

    fn make_pre_atom(x: &str, start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::atom(x.into());
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_pre_atom_value(x: Value, start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::atom_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_pre_list(start_line: u32, start_column: u32, end_line: u32, end_column: u32, x: Box<[PreSymbolicExpression]>) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::list(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_unexpanded_contract_name(x: ContractName, start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::unexpanded_contract_name(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_atom(x: &str, start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> SymbolicExpression {
        let mut e = SymbolicExpression::atom(x.into());
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_atom_value(x: Value, start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> SymbolicExpression {
        let mut e = SymbolicExpression::atom_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_list(start_line: u32, start_column: u32, end_line: u32, end_column: u32, x: Box<[SymbolicExpression]>) -> SymbolicExpression {
        let mut e = SymbolicExpression::list(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_literal_value(x: Value, start_line: u32, start_column: u32, end_line: u32, end_column: u32) -> SymbolicExpression {
        let mut e = SymbolicExpression::literal_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    #[test]
    fn test_transform_pre_ast() {
        let mut pre_ast = vec![
            make_pre_atom("z", 1, 1, 1, 1),
            make_pre_list(1, 3, 6, 11, Box::new([
                make_pre_atom("let", 1, 4, 1, 6),
                make_pre_list(1, 8, 1, 20, Box::new([
                    make_pre_list(1, 9, 1, 13, Box::new([
                        make_pre_atom("x", 1, 10, 1, 10),
                        make_pre_atom_value(Value::Int(1), 1, 12, 1, 12)])),
                    make_pre_list(1, 15, 1, 19, Box::new([
                        make_pre_atom("y", 1, 16, 1, 16),
                        make_pre_atom_value(Value::Int(2), 1, 18, 1, 18)]))])),
                make_pre_list(2, 5, 6, 10, Box::new([
                    make_pre_atom("+", 2, 6, 2, 6),
                    make_pre_atom("x", 2, 8, 2, 8),
                    make_pre_list(4, 9, 5, 16, Box::new([
                        make_pre_atom("let", 4, 10, 4, 12),
                        make_pre_list(4, 14, 4, 20, Box::new([
                            make_pre_list(4, 15, 4, 19, Box::new([
                                make_pre_atom("x", 4, 16, 4, 16),
                                make_pre_atom_value(Value::Int(3), 4, 18, 4, 18)]))])),
                        make_pre_list(5, 9, 5, 15, Box::new([
                            make_pre_atom("+", 5, 10, 5, 10),
                            make_pre_atom("x", 5, 12, 5, 12),
                            make_pre_atom("y", 5, 14, 5, 14)]))])),
                    make_pre_atom("x", 6, 9, 6, 9)]))])),
            make_pre_atom("x", 6, 13, 6, 13),
            make_pre_atom("y", 6, 15, 6, 15),
        ];

        let ast = vec![
            make_atom("z", 1, 1, 1, 1),
            make_list(1, 3, 6, 11, Box::new([
                make_atom("let", 1, 4, 1, 6),
                make_list(1, 8, 1, 20, Box::new([
                    make_list(1, 9, 1, 13, Box::new([
                        make_atom("x", 1, 10, 1, 10),
                        make_literal_value(Value::Int(1), 1, 12, 1, 12)])),
                    make_list(1, 15, 1, 19, Box::new([
                        make_atom("y", 1, 16, 1, 16),
                        make_literal_value(Value::Int(2), 1, 18, 1, 18)]))])),
                make_list(2, 5, 6, 10, Box::new([
                    make_atom("+", 2, 6, 2, 6),
                    make_atom("x", 2, 8, 2, 8),
                    make_list(4, 9, 5, 16, Box::new([
                        make_atom("let", 4, 10, 4, 12),
                        make_list(4, 14, 4, 20, Box::new([
                            make_list(4, 15, 4, 19, Box::new([
                                make_atom("x", 4, 16, 4, 16),
                                make_literal_value(Value::Int(3), 4, 18, 4, 18)]))])),
                        make_list(5, 9, 5, 15, Box::new([
                            make_atom("+", 5, 10, 5, 10),
                            make_atom("x", 5, 12, 5, 12),
                            make_atom("y", 5, 14, 5, 14)]))])),
                    make_atom("x", 6, 9, 6, 9)]))])),
            make_atom("x", 6, 13, 6, 13),
            make_atom("y", 6, 15, 6, 15),
        ];

        let contract_id = QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.contract-a").unwrap();
        let expander = SugarExpander::new(contract_id.issuer);
        assert_eq!(expander.run(&mut pre_ast), ast, "Should match expected symbolic expression");
    }

    #[test]
    fn test_transform_unexpanded_contract_name() {
        let contract_name = "tokens".into();
        let mut pre_ast = vec![make_unexpanded_contract_name(contract_name, 1, 1, 1, 1)];
        let unsugared_contract_id = QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.tokens").unwrap();
        let ast = vec![make_literal_value(Value::Principal(PrincipalData::Contract(unsugared_contract_id)), 1, 1, 1, 1)];

        let contract_id = QualifiedContractIdentifier::parse("S1G2081040G2081040G2081040G208105NK8PE5.contract-a").unwrap();
        let expander = SugarExpander::new(contract_id.issuer);
        assert_eq!(expander.run(&mut pre_ast), ast, "Should match expected symbolic expression");
    }
}
