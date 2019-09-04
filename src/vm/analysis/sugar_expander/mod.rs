use vm::representations::{SymbolicExpression};
use vm::{SymbolicExpressionType};
use vm::types::{QualifiedContractIdentifier, Value, PrincipalData, StackAddress};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::functions::NativeFunctions;
use vm::analysis::errors::{CheckResult, CheckErrors, CheckError};
use vm::analysis::analysis_db::{AnalysisDatabase};

pub struct SugarExpander;

impl AnalysisPass for SugarExpander {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        println!("SugarExpander in progress");
        Self::qualify_relative_contracts(& mut contract_analysis.expressions, &contract_analysis.contract_identifier.issuer)
    }
}

impl SugarExpander {

    fn qualify_relative_contracts(args: &mut [SymbolicExpression], issuer: &StackAddress) -> CheckResult<()> {
        for expression in &mut args[..] {
            let (function_name, mut function_args) = {
                if let SymbolicExpressionType::List(ref mut exprs) = expression.expr {
                    if let Some((function_name, mut function_args)) = exprs.split_first_mut() {
                        if let Some(function_name) = function_name.match_atom() {
                            (function_name.to_string(), function_args)
                        } else { continue }
                    } else { continue }
                } else { continue }
            };

            if let Some(native_function) = NativeFunctions::lookup_by_name(&function_name) {
                match native_function {
                    NativeFunctions::FetchContractEntry | NativeFunctions::ContractCall => {
                            if let Some(contract_name) = function_args[0].clone().match_atom() {
                                let contract_identifier = QualifiedContractIdentifier::new(issuer.clone(), contract_name.to_string()).unwrap();
                                println!("Before: {:?} ", function_args[0].expr);
                                function_args[0].expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
                                println!("After: {:?} ", function_args[0].expr);
                            }
                    }
                    _ => {
                        Self::qualify_relative_contracts(&mut function_args, issuer)?
                    }
                }
            } else { 
                Self::qualify_relative_contracts(&mut function_args, issuer)?
            }
        }
        Ok(())
    }
}





    // fn qualify_relative_contracts(args: &mut [SymbolicExpression], issuer: &StackAddress) -> CheckResult<()> {
    //     for expression in &mut args[..] {
    //         let (function_name, mut function_args) = {
    //             match expression.expr {
    //                 SymbolicExpressionType::List(ref mut exprs) => {
    //                     if let Some((function_name, function_args)) = exprs.split_first_mut() {
    //                         (function_name, function_args)
    //                     } else {
    //                         continue;
    //                     }
    //                 },
    //                 _ => { continue }

    //             }
    //         };
    //         if let Some(function_name) = function_name.match_atom() {
    //             if let Some(native_function) = NativeFunctions::lookup_by_name(function_name) {
    //                 match native_function {
    //                     NativeFunctions::FetchContractEntry | NativeFunctions::ContractCall => {
    //                         if let Some(contract_name) = function_args[0].match_atom() {
    //                             let contract_identifier = QualifiedContractIdentifier::new(issuer.clone(), contract_name.to_string()).unwrap();
    //                             expression.expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
    //                         }
    //                     }
    //                     _ => {
    //                         Self::qualify_relative_contracts(function_args, issuer)?
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     Ok(())
    // }

    //     fn qualify_relative_contracts(args: &mut [SymbolicExpression], issuer: &StackAddress) -> CheckResult<()> {
    //     for expression in &mut args[..] {
    //         let (function_name, mut function_args) = {
    //             if let SymbolicExpressionType::List(ref mut exprs) = expression.expr {
    //                 if let Some((function_name, mut function_args)) = exprs.split_first_mut() {
    //                     if let Some(function_name) = function_name.match_atom() {
    //                         (function_name.to_string(), function_args[..].to_vec())
    //                     } else { continue }
    //                 } else { continue }
    //             } else { continue }
    //         };

    //         if let Some(native_function) = NativeFunctions::lookup_by_name(&function_name) {
    //             match native_function {
    //                 NativeFunctions::FetchContractEntry | NativeFunctions::ContractCall => {
    //                     if let Some(ref mut expr_to_unsugar) = function_args.get_mut(0) {
    //                         if let Some(contract_name) = expr_to_unsugar.clone().match_atom() {
    //                             let contract_identifier = QualifiedContractIdentifier::new(issuer.clone(), contract_name.to_string()).unwrap();
    //                             println!("Before: {:?} ", expr_to_unsugar.expr);
    //                             expr_to_unsugar.expr = SymbolicExpressionType::AtomValue(Value::Principal(PrincipalData::Contract(contract_identifier)));
    //                             println!("After: {:?} ", expr_to_unsugar.expr);
    //                         }
    //                     }
    //                 }
    //                 _ => {
    //                     Self::qualify_relative_contracts(&mut function_args, issuer)?
    //                 }
    //             }
    //         } else { 
    //             Self::qualify_relative_contracts(&mut function_args, issuer)?
    //         }
    //     }
    //     Ok(())
    // }
