use vm::representations::{SymbolicExpression};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::types::{AtomTypeIdentifier, TypeSignature, TupleTypeSignature, parse_name_type_pairs};
use vm::functions::NativeFunctions;
use vm::functions::tuples;
use vm::functions::tuples::TupleDefinitionType::{Implicit, Explicit};

use vm::variables::NativeVariables;
use std::collections::HashMap;

use super::AnalysisDatabase;
pub use super::errors::{CheckResult, CheckError, CheckErrors};

#[cfg(test)]
mod tests;

pub struct ReadOnlyChecker <'a, 'b> {
    db: &'a AnalysisDatabase<'b>,
    defined_functions: HashMap<String, bool>
}


impl <'a, 'b> ReadOnlyChecker <'a, 'b> {
    

    fn new(db: &'a AnalysisDatabase<'b>) -> ReadOnlyChecker<'a, 'b> {
        ReadOnlyChecker { db, defined_functions: HashMap::new() }
    }

    pub fn check_contract(contract: &mut [SymbolicExpression], analysis_db: &AnalysisDatabase) -> CheckResult<()> {
        let mut checker = ReadOnlyChecker::new(analysis_db);

        for exp in contract {
            checker.check_reads_only_valid(exp)?;
        }


        Ok(())
    }

    fn check_define_function(&self, expr: &[SymbolicExpression]) -> CheckResult<(String, bool)> {
        if expr.len() != 3 {
            return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, expr.len() - 1)))
        }

        let signature = expr[1].match_list()
            .ok_or(CheckError::new(CheckErrors::DefineFunctionBadSignature))?;
        let body = &expr[2];

        let (function_name, _) = signature.split_first()
            .ok_or(CheckError::new(CheckErrors::DefineFunctionBadSignature))?;

        let is_read_only = self.is_read_only(body)?;

        Ok((function_name.to_string(), is_read_only))
    }

    fn check_reads_only_valid(&mut self, expr: &SymbolicExpression) -> CheckResult<()> {
        if let Some(ref expression) = expr.match_list() {
            if let Some((function_name, function_args)) = expression.split_first() {
                if let Some(function_name) = function_name.match_atom() {
                    match function_name.as_str() {
                        "define" => {
                            if function_args.len() < 1 {
                                return Err(CheckError::new(CheckErrors::DefineFunctionBadSignature))
                            } else {
                                if function_args[0].match_list().is_some() {
                                    let (f_name, is_read_only) = self.check_define_function(expression)?;
                                    self.defined_functions.insert(f_name, is_read_only);
                                    Ok(())
                                } else {
                                    // this is trying to define a variable -- doesn't need to be checked.
                                    Ok(())
                                }
                            }
                        },
                        "define-public" => {
                            let (f_name, is_read_only) = self.check_define_function(expression)?;
                            self.defined_functions.insert(f_name, is_read_only);
                            Ok(())
                        },
                        "define-read-only" => {
                            let (f_name, is_read_only) = self.check_define_function(expression)?;
                            if !is_read_only {
                                Err(CheckError::new(CheckErrors::WriteAttemptedInReadOnly))
                            } else {
                                self.defined_functions.insert(f_name, is_read_only);
                                Ok(())
                            }
                        },
                        "define-map" => {
                            Ok(()) // define-map never needs to be checked.
                        },
                        "define-data-var" => {
                            Ok(()) // define-data-var never needs to be checked.
                        },
                        _ => {
                            Ok(())
                        }
                    }
                } else {
                    Ok(()) // not a define
                }
            } else {
                Ok(()) // not a define
            }
        } else {
            Ok(()) // not a define.
        }
    }

    fn are_all_read_only(&self, initial: bool, expressions: &[SymbolicExpression]) -> CheckResult<bool> {
        expressions.iter()
            .fold(Ok(initial),
                  |acc, argument| {
                      Ok(acc? && self.is_read_only(&argument)?) })
    }

    fn is_implicit_tuple_definition_read_only(&self, tuples: &[SymbolicExpression]) -> CheckResult<bool> {
        for tuple_expr in tuples.iter() {
            let pair = tuple_expr.match_list()
                .ok_or(CheckError::new(CheckErrors::TupleExpectsPairs))?;
            if pair.len() != 2 {
                return Err(CheckError::new(CheckErrors::TupleExpectsPairs))
            }

            if !self.is_read_only(&pair[1])? {
                return Ok(false)
            }
        }
        Ok(true)
    }

    fn try_native_function_check(&self, function: &str, args: &[SymbolicExpression]) -> Option<CheckResult<bool>> {
        if let Some(ref function) = NativeFunctions::lookup_by_name(function) {
            Some(self.handle_native_function(function, args))
        } else {
            None
        }
    }

    fn handle_native_function(&self, function: &NativeFunctions, args: &[SymbolicExpression]) -> CheckResult<bool> {
        use vm::functions::NativeFunctions::*;

        match function {
            Add | Subtract | Divide | Multiply | CmpGeq | CmpLeq | CmpLess | CmpGreater |
            Modulo | Power | BitwiseXOR | And | Or | Not | Hash160 | Sha256 | Keccak256 | Equals | If |
            ConsSome | ConsOkay | ConsError | DefaultTo | Expects | ExpectsErr | IsOkay | IsNone |
            ListCons | GetBlockInfo | TupleGet | Print | AsContract | Begin | FetchVar => {
                self.are_all_read_only(true, args)
            },
            FetchEntry => {                
                let res = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
                    Implicit(ref tuple_expr) => {
                        self.is_implicit_tuple_definition_read_only(tuple_expr)
                    },
                    Explicit => {
                        self.are_all_read_only(true, args)
                    }
                };
                res
            },
            FetchContractEntry => {                
                let res = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
                    Implicit(ref tuple_expr) => {
                        self.is_implicit_tuple_definition_read_only(tuple_expr)
                    },
                    Explicit => {
                        self.are_all_read_only(true, args)
                    }
                };
                res
            },
            SetEntry | DeleteEntry | InsertEntry | SetVar => {
                Ok(false)
            },
            Let => {
                if args.len() != 2 {
                    return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
                }
    
                let binding_list = args[0].match_list()
                    .ok_or(CheckError::new(CheckErrors::BadLetSyntax))?;

                for pair in binding_list.iter() {
                    let pair_expression = pair.match_list()
                        .ok_or(CheckError::new(CheckErrors::BadSyntaxBinding))?;
                    if pair_expression.len() != 2 {
                        return Err(CheckError::new(CheckErrors::BadSyntaxBinding))
                    }

                    if !self.is_read_only(&pair_expression[1])? {
                        return Ok(false)
                    }
                }
    
                self.is_read_only(&args[1])
            },
            Map | Filter => {
                if args.len() != 2 {
                    return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
                }
    
                // note -- we do _not_ check here to make sure we're not mapping on
                //      a special function. that check is performed by the type checker.
                //   we're pretty directly violating type checks in this recursive step:
                //   we're asking the read only checker to check whether a function application
                //     of the _mapping function_ onto the rest of the supplied arguments would be
                //     read-only or not.
                self.is_function_application_read_only(args)
            },
            Fold => {
                if args.len() != 3 {
                    return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, args.len())))
                }
    
                // note -- we do _not_ check here to make sure we're not folding on
                //      a special function. that check is performed by the type checker.
                //   we're pretty directly violating type checks in this recursive step:
                //   we're asking the read only checker to check whether a function application
                //     of the _folding function_ onto the rest of the supplied arguments would be
                //     read-only or not.
                self.is_function_application_read_only(args)
            },
            TupleCons => {
                for pair in args.iter() {
                    let pair_expression = pair.match_list()
                        .ok_or(CheckError::new(CheckErrors::TupleExpectsPairs))?;
                    if pair_expression.len() != 2 {
                        return Err(CheckError::new(CheckErrors::TupleExpectsPairs))
                    }

                    if !self.is_read_only(&pair_expression[1])? {
                        return Ok(false)
                    }
                }
                Ok(true)
            },
            ContractCall => {
                if args.len() < 2 {
                    return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
                }
                let contract_name = args[0].match_atom()
                    .ok_or(CheckError::new(CheckErrors::ContractCallExpectName))?;
                let function_name = args[1].match_atom()
                    .ok_or(CheckError::new(CheckErrors::ContractCallExpectName))?;

                let is_function_read_only = self.db.get_read_only_function_type(contract_name, function_name)?.is_some();
                self.are_all_read_only(is_function_read_only, &args[2..])
            }
        }
    }

    fn is_function_application_read_only(&self, expression: &[SymbolicExpression]) -> CheckResult<bool> {
        let (function_name, args) = expression.split_first()
            .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;

        let function_name = function_name.match_atom()
            .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;

        if let Some(result) = self.try_native_function_check(function_name, args) {
            result
        } else {
            let is_function_read_only = self.defined_functions.get(function_name)
                .ok_or(CheckError::new(CheckErrors::UnknownFunction(function_name.clone())))?;
            self.are_all_read_only(*is_function_read_only, args)
        }
    }


    fn is_read_only(&self, expr: &SymbolicExpression) -> CheckResult<bool> {
        match expr.expr {
            AtomValue(_) => {
                Ok(true)
            },
            Atom(_) => {
                Ok(true)
            },
            List(ref expression) => {
                self.is_function_application_read_only(expression)
            }
        }
    }
}
