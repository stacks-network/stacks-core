pub mod contexts;
//mod maps;
pub mod natives;

use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::types::{AtomTypeIdentifier, TypeSignature, TupleTypeSignature, FunctionArg, FunctionType, parse_name_type_pairs};
use vm::functions::NativeFunctions;
use vm::functions::define::DefineFunctions;
use vm::variables::NativeVariables;

use super::AnalysisDatabase;
pub use super::types::{ContractAnalysis, AnalysisPass};

use self::contexts::{TypeMap, TypingContext, ContractContext};

pub use self::natives::{TypedNativeFunction, SimpleNativeFunction};

pub use super::errors::{CheckResult, CheckError, CheckErrors, check_argument_count,
                        check_arguments_at_least};


#[cfg(test)]
mod tests;

/*

Type-checking in our language is achieved through a single-direction inference.
This leads to efficient type-checking. This form of type-checking is only possible
due to the rules of our language. In particular, functions define their input types,
and any given intermediate in the language has a strict type as well, meaning something
of the form:

(if x
   'true
   -1)

Is illegally typed in our language.

*/

pub struct TypeChecker <'a, 'b> {
    pub type_map: TypeMap,
    contract_context: ContractContext,
    function_return_tracker: Option<Option<TypeSignature>>,
    db: &'a mut AnalysisDatabase<'b>
}

impl <'a, 'b> AnalysisPass for TypeChecker <'a, 'b> {
    fn run_pass(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut command = TypeChecker::new(analysis_db);
        command.run(contract_analysis)?;
        command.into_contract_analysis(contract_analysis);
        Ok(())
    }
}

pub type TypeResult = CheckResult<TypeSignature>;

pub fn check_function_args(function_type: &FunctionType, args: &[TypeSignature]) -> CheckResult<()> {
    match function_type {
        FunctionType::Variadic(expected_type, _) => {
            check_arguments_at_least(1, args)?;
            for found_type in args.iter() {
                if !expected_type.admits_type(found_type) {
                    return Err(CheckError::new(CheckErrors::TypeError(
                        expected_type.clone(), found_type.clone())))
                }                    
            }
            Ok(())
        },
        FunctionType::Fixed(arg_types, _) => {
            check_argument_count(arg_types.len(), args)?;
            for (expected_type, found_type) in arg_types.iter().map(|x| &x.signature).zip(args) {
                if !expected_type.admits_type(found_type) {
                    return Err(CheckError::new(CheckErrors::TypeError(
                        expected_type.clone(), found_type.clone())))
                }
            }
            Ok(())
        },
        FunctionType::UnionArgs(arg_types, _) => {
            check_argument_count(1, args)?;
            let found_type = &args[0];
            for expected_type in arg_types.iter() {
                if expected_type.admits_type(found_type) {
                    return  Ok(())
                }
            }
            Err(CheckError::new(CheckErrors::UnionTypeError(
                arg_types.clone(), found_type.clone())))
        }
    }
}


fn type_reserved_variable(variable_name: &str) -> Option<TypeSignature> {
    if let Some(variable) = NativeVariables::lookup_by_name(variable_name) {
        use vm::variables::NativeVariables::*;
        let var_type = match variable {
            TxSender => AtomTypeIdentifier::PrincipalType.into(),
            ContractCaller => AtomTypeIdentifier::PrincipalType.into(),
            BlockHeight => AtomTypeIdentifier::IntType.into(),
            BurnBlockHeight => AtomTypeIdentifier::IntType.into(),
            NativeNone => AtomTypeIdentifier::OptionalType(Box::new(no_type())).into(),
        };
        Some(var_type)
    } else {
        None
    }
}

pub fn no_type() -> TypeSignature {
    AtomTypeIdentifier::NoType.into()
}

impl <'a, 'b> TypeChecker <'a, 'b> {
    fn new(db: &'a mut AnalysisDatabase<'b>) -> TypeChecker<'a, 'b> {
        Self {
            db,
            contract_context: ContractContext::new(),
            function_return_tracker: None,
            type_map: TypeMap::new()
        }
    }

    fn into_contract_analysis(self, contract_analysis: &mut ContractAnalysis) {
        self.contract_context.into_contract_analysis(contract_analysis);
    }

    pub fn track_return_type(&mut self, return_type: TypeSignature) -> CheckResult<()> {
        match self.function_return_tracker {
            Some(ref mut tracker) => {
                let new_type = match tracker.take() {
                    Some(expected_type) => {
                        TypeSignature::most_admissive(expected_type, return_type)
                            .map_err(|(expected_type, return_type)| CheckErrors::ReturnTypesMustMatch(expected_type, return_type))?
                    },
                    None => return_type
                };

                tracker.replace(new_type);
                Ok(())
            },
            None => {
                // not in a defining function, so it's okay if aborts, etc., are trying
                //   to return random things, as it'll just error in any case.
                Ok(())
            }
        }
    }

    pub fn run(&mut self, contract_analysis: &mut ContractAnalysis) -> CheckResult<()> {
        let mut local_context = TypingContext::new();

        for exp in contract_analysis.expressions_iter() {
            let mut result_res = self.try_type_check_define(&exp, &mut local_context);
            if let Err(ref mut error) = result_res {
                if !error.has_expression() {
                    error.set_expression(&exp);
                }
            }
            let result = result_res?;
            if result.is_none() {
                // was _not_ a define statement, so handle like a normal statement.
                self.type_check(&exp, &local_context)?;
            }
        }

        Ok(())
    }

    // Type check an expression, with an expected_type that should _admit_ the expression.
    pub fn type_check_expects(&mut self, expr: &SymbolicExpression, context: &TypingContext, expected_type: &TypeSignature) -> TypeResult {
        let actual_type = self.type_check(expr, context)?;
        if !expected_type.admits_type(&actual_type) {
            let mut err: CheckError = CheckErrors::TypeError(expected_type.clone(), actual_type).into();
            err.set_expression(expr);
            Err(err)
        } else {
            Ok(actual_type)
        }
    }
    // Type checks an expression, recursively type checking its subexpressions
    pub fn type_check(&mut self, expr: &SymbolicExpression, context: &TypingContext) -> TypeResult {
        let mut result = self.inner_type_check(expr, context);

        if let Err(ref mut error) = result {
            if !error.has_expression() {
                error.set_expression(expr);
            }
        }

        result
    }

    fn type_check_all(&mut self, args: &[SymbolicExpression], context: &TypingContext) -> CheckResult<Vec<TypeSignature>> {
        let mut result = Vec::new();
        for arg in args.iter() {
            // don't use map here, since type_check has side-effects.
            result.push(self.type_check(arg, context)?)
        }
        Ok(result)
    }

    fn type_check_function_type(&mut self, func_type: &FunctionType,
                                args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
        let typed_args = self.type_check_all(args, context)?;
        check_function_args(func_type, &typed_args)?;
        Ok(func_type.return_type().clone())
    }

    fn get_function_type(&self, function_name: &str) -> Option<FunctionType> {
        self.contract_context.get_function_type(function_name)
            .cloned()
    }

    fn type_check_define_function(&mut self, args: &[SymbolicExpression],
                                  context: &TypingContext) -> CheckResult<(ClarityName, FunctionType)> {
        check_argument_count(2, &args)?;

        self.type_map.set_type(&args[0], no_type())?;

        let signature = args[0].match_list()
            .ok_or(CheckErrors::DefineFunctionBadSignature)?;
        let body = &args[1];

        let (function_name, args) = signature.split_first()
            .ok_or(CheckErrors::RequiresAtLeastArguments(1, 0))?;
        let function_name = function_name.match_atom()
            .ok_or(CheckErrors::BadFunctionName)?;
        let mut args = parse_name_type_pairs(args)
            .map_err(|_| { CheckErrors::BadSyntaxBinding })?;

        if self.function_return_tracker.is_some() {
            panic!("Interpreter error: Previous function define left dirty typecheck state.");
        }


        let mut function_context = context.extend()?;
        for (arg_name, arg_type) in args.iter() {
            self.contract_context.check_name_used(arg_name)?;

            function_context.variable_types.insert(arg_name.clone(),
                                                   arg_type.clone());
        }

        self.function_return_tracker = Some(None);

        let return_result = self.type_check(body, &function_context);

        match return_result {
            Err(e) => {
                self.function_return_tracker = None;
                return Err(e)            
            },
            Ok(return_type) => {
                let return_type = {
                    if let Some(Some(ref expected)) = self.function_return_tracker {
                        // check if the computed return type matches the return type
                        //   of any early exits from the call graph (e.g., (expects ...) calls)
                        TypeSignature::most_admissive(expected.clone(), return_type)
                            .map_err(|(expected, return_type)| CheckErrors::ReturnTypesMustMatch(expected, return_type))?
                    } else {
                        return_type
                    }
                };

                self.function_return_tracker = None;

                let func_args: Vec<FunctionArg> = args.drain(..)
                    .map(|(arg_name, arg_type)| FunctionArg::new(arg_type, &arg_name)).collect();

                Ok((function_name.clone(), FunctionType::Fixed(func_args, return_type)))
            }
        }
    }

    fn type_check_define_map(&mut self, args: &[SymbolicExpression],
                                 _context: &TypingContext) -> CheckResult<(ClarityName, (TypeSignature, TypeSignature))> {
        check_argument_count(3, &args)?;

        self.type_map.set_type(&args[0], no_type())?;
        self.type_map.set_type(&args[1], no_type())?;
        self.type_map.set_type(&args[2], no_type())?;
        // should we set the type of the subexpressions of the signature to no-type as well?

        let map_name = args[0].match_atom()
            .ok_or(CheckErrors::BadMapName)?;
        let key_type = &args[1];
        let value_type = &args[2];

        let key_type = TypeSignature::new_tuple(
            TupleTypeSignature::parse_name_type_pair_list(key_type)
                .map_err(|_| { CheckErrors::BadMapTypeDefinition })?)
            .map_err(|_| { CheckErrors::BadMapTypeDefinition })?;
        let value_type = TypeSignature::new_tuple(
            TupleTypeSignature::parse_name_type_pair_list(value_type)
                .map_err(|_| { CheckErrors::BadMapTypeDefinition })?)
            .map_err(|_| { CheckErrors::BadMapTypeDefinition })?;


        Ok((map_name.clone(), (key_type, value_type)))
    }

    // Aaron: note, using lazy statics here would speed things up a bit and reduce clone()s
    fn try_native_function_check(&mut self, function: &str, args: &[SymbolicExpression], context: &TypingContext) -> Option<TypeResult> {
        if let Some(ref native_function) = NativeFunctions::lookup_by_name(function) {
            let typed_function = TypedNativeFunction::type_native_function(native_function);
            Some(typed_function.type_check_appliction(self, args, context))
        } else {
            None
        }
    }

    fn type_check_function_application(&mut self, expression: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
        let (function_name, args) = expression.split_first()
            .ok_or(CheckErrors::NonFunctionApplication)?;

        self.type_map.set_type(function_name, no_type())?;
        let function_name = function_name.match_atom()
            .ok_or(CheckErrors::NonFunctionApplication)?;

        if let Some(type_result) = self.try_native_function_check(function_name, args, context) {
            type_result
        } else {
            let function_type = self.get_function_type(function_name)
                .ok_or(CheckErrors::UnknownFunction(function_name.to_string()))?;
            self.type_check_function_type(&function_type, args, context)
        }
    }

    fn lookup_variable(&self, name: &str, context: &TypingContext) -> TypeResult {
        if let Some(type_result) = type_reserved_variable(name) {
            Ok(type_result)
        } else if let Some(type_result) = self.contract_context.get_variable_type(name) {
            Ok(type_result.clone())
        } else if let Some(type_result) = context.lookup_variable_type(name) {
            Ok(type_result.clone())
        } else {
            Err(CheckError::new(CheckErrors::UnboundVariable(name.to_string())))
        }
    }

    fn inner_type_check(&mut self, expr: &SymbolicExpression, context: &TypingContext) -> TypeResult {
        let type_sig = match expr.expr {
            AtomValue(ref value) => {
                TypeSignature::type_of(value)
            },
            Atom(ref name) => {
                self.lookup_variable(name, context)?
            },
            List(ref expression) => {
                self.type_check_function_application(expression, context)?
            }
        };

        self.type_map.set_type(expr, type_sig.clone())?;
        Ok(type_sig)
    }

    fn type_check_define_variable(&mut self, args: &[SymbolicExpression], context: &mut TypingContext) -> CheckResult<(ClarityName, TypeSignature)> {
        check_argument_count(2, args)?;
        let var_name = args[0].match_atom()
            .ok_or(CheckErrors::DefineVariableBadSignature)?
            .clone();
        let var_type = self.type_check(&args[1], context)?;
        Ok((var_name, var_type))
    }

    fn type_check_define_persisted_variable(&mut self, args: &[SymbolicExpression], context: &mut TypingContext) -> CheckResult<(ClarityName, TypeSignature)> {
        check_argument_count(3, args)?;
        let var_name = args[0].match_atom()
            .ok_or(CheckErrors::DefineVariableBadSignature)?
            .clone();

        let expected_type = TypeSignature::parse_type_repr(&args[1], true)
            .map_err(|e| CheckErrors::DefineVariableBadSignature)?;

        self.type_check_expects(&args[2], context, &expected_type)?;

        Ok((var_name, expected_type))
    }

    fn type_check_define_ft(&mut self, args: &[SymbolicExpression], context: &mut TypingContext) -> CheckResult<ClarityName> {
        if args.len() != 1 && args.len() != 2 {
            return Err(CheckErrors::IncorrectArgumentCount(2, args.len()).into())
        }

        if args.len() == 2 {
            self.type_check_expects(&args[1], context, &AtomTypeIdentifier::IntType.into())?;
        }

        let token_name = args[0].match_atom()
            .ok_or(CheckErrors::DefineFTBadSignature)?
            .clone();

        Ok(token_name)
    }

    fn type_check_define_nft(&mut self, args: &[SymbolicExpression], context: &mut TypingContext) -> CheckResult<(ClarityName, TypeSignature)> {
        check_argument_count(2, args)?;

        let asset_name = args[0].match_atom()
            .ok_or(CheckErrors::DefineNFTBadSignature)?
            .clone();

        let asset_type = TypeSignature::parse_type_repr(&args[1], true)
            .or_else(|_| Err(CheckErrors::DefineNFTBadSignature))?;

        Ok((asset_name, asset_type))
    }

    // Checks if an expression is a _define_ expression, and if so, typechecks it. Otherwise, it returns Ok(None)
    fn try_type_check_define(&mut self, expression: &SymbolicExpression, context: &mut TypingContext) -> CheckResult<Option<()>> {
        use vm::functions::define::DefineFunctions::*;
        if let Some((define_type, args)) = DefineFunctions::try_parse(expression) {
            match define_type {
                Constant => {
                    let (v_name, v_type) = self.type_check_define_variable(args, context)?;
                    self.contract_context.add_variable_type(v_name, v_type)?;
                },
                PrivateFunction => {
                    let (f_name, f_type) = self.type_check_define_function(args, context)?;
                    self.contract_context.add_private_function_type(f_name, f_type)?;
                },
                PublicFunction => {
                    let (f_name, f_type) = self.type_check_define_function(args, context)?;
                    let return_type = f_type.return_type();
                    let return_type = return_type.match_atomic()
                        .ok_or(CheckError::new(CheckErrors::PublicFunctionMustReturnResponse(f_type.return_type())))?;
                    if let AtomTypeIdentifier::ResponseType(_) = return_type {
                        self.contract_context.add_public_function_type(f_name, f_type)?;
                        return Ok(Some(()));
                    } else {
                        return Err(CheckErrors::PublicFunctionMustReturnResponse(f_type.return_type()).into());
                    }
                },
                ReadOnlyFunction => {
                    let (f_name, f_type) = self.type_check_define_function(args, context)?;
                    self.contract_context.add_read_only_function_type(f_name, f_type)?;
                },
                Map => {
                    let (f_name, f_type) = self.type_check_define_map(args, context)?;
                    self.contract_context.add_map_type(f_name, f_type)?;
                },
                PersistedVariable => {
                    let (v_name, v_type) = self.type_check_define_persisted_variable(args, context)?;
                    self.contract_context.add_persisted_variable_type(v_name, v_type)?;
                },
                FungibleToken => {
                    let token_name = self.type_check_define_ft(args, context)?;
                    self.contract_context.add_ft(token_name)?;
                },
                NonFungibleToken => {
                    let (token_name, token_type) = self.type_check_define_nft(args, context)?;
                    self.contract_context.add_nft(token_name, token_type)?;
                }
            };
            Ok(Some(()))
        } else {
        // not a define.
            Ok(None)
        }
    }
}

