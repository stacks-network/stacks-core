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

    pub fn run(&self, pre_expressions: &[PreSymbolicExpression]) -> Vec<SymbolicExpression> {
        self.transform(pre_expressions)
    }

    pub fn transform(&self, pre_expressions: &[PreSymbolicExpression]) -> Vec<SymbolicExpression> {
        let mut expressions = Vec::new();
        for pre_expr in pre_expressions.iter() {

            let mut expr = match pre_expr.pre_expr {
                PreSymbolicExpressionType::AtomValue(ref content) => {
                    SymbolicExpression::atom_value(content.clone())
                },
                PreSymbolicExpressionType::Atom(ref content) => {
                    SymbolicExpression::atom(content.clone())
                },
                PreSymbolicExpressionType::UnexpandedContractName(ref contract_name) => {
                    let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name.clone());
                    SymbolicExpression::literal_value(Value::Principal(PrincipalData::Contract(contract_identifier)))
                },
                PreSymbolicExpressionType::List(ref pre_exprs) => {
                    let exprs = self.transform(&pre_exprs);
                    SymbolicExpression::list(exprs.into_boxed_slice())
                }
            };
            expr.span = pre_expr.span.clone();
            expressions.push(expr);
        }
        expressions
    }
}

