use std::convert::TryInto;
use vm::representations::{SymbolicExpression};
use vm::{SymbolicExpressionType};
use vm::types::{QualifiedContractIdentifier, Value, PrincipalData, StandardPrincipalData};
use vm::ast::types::{ContractAST, BuildASTPass};
use vm::ast::errors::{ParseResult, ParseError, ParseErrors};
use vm::functions::NativeFunctions;

pub struct SugarExpander {
    issuer: StandardPrincipalData   
}

impl BuildASTPass for SugarExpander {

    fn run_pass(contract_ast: &mut ContractAST) -> ParseResult<()> {
        let mut pass = SugarExpander::new(contract_ast.contract_identifier.issuer.clone());
        pass.run(&mut contract_ast.expressions)
    }
}

impl SugarExpander {

    fn new(issuer: StandardPrincipalData) -> Self {
        Self { issuer }
    }

    pub fn run(&mut self, expressions: &mut [SymbolicExpression]) -> ParseResult<()> {
        for expression in &mut expressions[..] {
            self.qualify_relative_contracts(expression)?;
        }
        Ok(())
    }

    fn qualify_relative_contracts(&mut self, expression: &mut SymbolicExpression) -> ParseResult<()> {
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
            // todo(ludo): revisit this implementation
            match native_function {
                NativeFunctions::FetchContractEntry | NativeFunctions::ContractCall => {
                    if let Some(arg) = function_args[0].clone().match_atom() {
                        let contract_name = arg.to_string().try_into()
                            .map_err(|x| { ParseError::new(ParseErrors::IllegalContractName(arg.to_string())) })?;
                        let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name);
                        function_args[0].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                    }
                }
                // NativeFunctions::MintAsset | NativeFunctions::MintToken => {
                //     if let Some(contract_name) = function_args[2].clone().match_atom() {
                //         let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name.into());
                //         function_args[2].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                //     }
                // } 
                // NativeFunctions::TransferAsset | NativeFunctions::TransferToken => {
                //     if let Some(contract_name) = function_args[1].clone().match_atom() {
                //         let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name.into());
                //         function_args[1].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                //     }
                //     if let Some(contract_name) = function_args[2].clone().match_atom() {
                //         let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name.into());
                //         function_args[2].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                //     }
                // }
                // NativeFunctions::GetTokenBalance => {
                //     if let Some(contract_name) = function_args[1].clone().match_atom() {
                //         let contract_identifier = QualifiedContractIdentifier::new(self.issuer.clone(), contract_name.into());
                //         function_args[1].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                //     }
                // }
                _ => {}
            }
        }
        for expr in function_args.into_iter() {
            self.qualify_relative_contracts(expr)?;
        }

        Ok(())
    }
}

