pub mod contexts;
//mod maps;
pub mod natives;

use vm::representations::{SymbolicExpression};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::types::{AtomTypeIdentifier, TypeSignature, TupleTypeSignature, parse_name_type_pairs};
use vm::functions::NativeFunctions;
use vm::variables::NativeVariables;

use super::AnalysisDatabase;
use self::contexts::{TypeMap, TypingContext, ContractContext};

pub use self::natives::{TypedNativeFunction, SimpleNativeFunction};

pub use self::contexts::ContractAnalysis;
pub use super::errors::{CheckResult, CheckError, CheckErrors};


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


// Aaron: TODO:
//   we need to treat VOID types differently than we currently are.
//   it should only be admissable for Void slots,
//      _and_ tuple slots. 

pub type TypeResult = CheckResult<TypeSignature>;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(Vec<TypeSignature>, TypeSignature)
}

pub struct TypeChecker <'a, 'b> {
    pub type_map: TypeMap,
    contract_context: ContractContext,
    db: &'a AnalysisDatabase<'b>
}

impl FunctionType {
    pub fn check_args(&self, args: &[TypeSignature]) -> CheckResult<()> {
        match self {
            FunctionType::Variadic(expected_type, _) => {
                if args.len() < 1 {
                    return Err(CheckError::new(CheckErrors::VariadicNeedsOneArgument))
                }
                for found_type in args.iter() {
                    if !expected_type.admits_type(found_type) {
                        return Err(CheckError::new(CheckErrors::TypeError(
                            expected_type.clone(), found_type.clone())))
                    }                    
                }
                Ok(())
            },
            FunctionType::Fixed(arg_types, _) => {
                if arg_types.len() != args.len() {
                    return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(
                        arg_types.len(), args.len())))
                }
                for (expected_type, found_type) in arg_types.iter().zip(args) {
                    if !expected_type.admits_type(found_type) {
                        return Err(CheckError::new(CheckErrors::TypeError(
                            expected_type.clone(), found_type.clone())))
                    }
                }
                Ok(())
            }
        }
    }

    pub fn return_type(&self) -> TypeSignature {
        match self {
            FunctionType::Variadic(_, return_type) => return_type.clone(),
            FunctionType::Fixed(_, return_type) => return_type.clone()
        }
    }
}

fn type_reserved_variable(variable_name: &str) -> Option<TypeSignature> {
    if let Some(variable) = NativeVariables::lookup_by_name(variable_name) {
        use vm::variables::NativeVariables::*;
        let var_type = match variable {
            TxSender => TypeSignature::new_atom(AtomTypeIdentifier::PrincipalType),
            BlockHeight => TypeSignature::new_atom(AtomTypeIdentifier::IntType),
            BurnBlockHeight => TypeSignature::new_atom(AtomTypeIdentifier::IntType),
        };
        Some(var_type)
    } else {
        None
    }
}

fn no_type() -> TypeSignature {
    TypeSignature::new_atom(AtomTypeIdentifier::NoType)
}

fn check_atomic_type(atom: AtomTypeIdentifier, to_check: &TypeSignature) -> CheckResult<()> {
    let expected = TypeSignature::new_atom(atom);
    if !expected.admits_type(to_check) {
        Err(CheckError::new(CheckErrors::TypeError(expected, to_check.clone())))
    } else {
        Ok(())
    }
}

impl <'a, 'b> TypeChecker <'a, 'b> {
    fn new(db: &'a AnalysisDatabase<'b>) -> TypeChecker<'a, 'b> {
        TypeChecker {
            db: db,
            contract_context: ContractContext::new(),
            type_map: TypeMap::new()
        }
    }

    pub fn type_check_contract(contract: &mut [SymbolicExpression], analysis_db: &AnalysisDatabase) -> CheckResult<ContractAnalysis> {
        let mut type_checker = TypeChecker::new(analysis_db);
        let mut local_context = TypingContext::new();

        for exp in contract {
            if type_checker.try_type_check_define(exp, &mut local_context)?
                .is_none() {
                    // was _not_ a define statement, so handle like a normal statement.
                    type_checker.type_check(exp, &local_context)?;
                }
        }


        Ok(type_checker.contract_context.to_contract_analysis())
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
        func_type.check_args(&typed_args)?;
        Ok(func_type.return_type().clone())
    }

    fn type_check_list_pairs<'c> (&mut self, bindings: &[SymbolicExpression],
                                  context: &'c TypingContext) -> CheckResult<TypingContext<'c>> {
        let mut out_context = context.extend()?;
        for binding in bindings.iter() {
            let binding_exps = binding.match_list()
                .ok_or(CheckError::new(CheckErrors::BadSyntaxBinding))?;
            
            if binding_exps.len() != 2 {
                return Err(CheckError::new(CheckErrors::BadSyntaxBinding))
            }

            let var_name = binding_exps[0].match_atom()
                .ok_or(CheckError::new(CheckErrors::BadSyntaxBinding))?;

            self.type_map.set_type(&binding_exps[0], no_type())?;
            let typed_result = self.type_check(&binding_exps[1], context)?;
            out_context.variable_types.insert(var_name.clone(),
                                              typed_result);
        }

        Ok(out_context)
    }

    fn get_function_type(&self, function_name: &str) -> Option<FunctionType> {
        if let Some(function_type) = self.contract_context.get_function_type(function_name) {
            Some(function_type.clone())
        } else {
            None
        }
    }

    fn type_check_define_function(&mut self, function_expression: &[SymbolicExpression],
                                  context: &TypingContext) -> CheckResult<(String, FunctionType)> {
        if function_expression.len() != 3 {
            return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, function_expression.len() - 1)))
        }

        self.type_map.set_type(&function_expression[0], no_type())?;
        self.type_map.set_type(&function_expression[1], no_type())?;
        // should we set the type of the subexpressions of the signature to no-type as well?

        let signature = function_expression[1].match_list()
            .ok_or(CheckError::new(CheckErrors::DefineFunctionBadSignature))?;
        let body = &function_expression[2];

        let (function_name, args) = signature.split_first()
            .ok_or(CheckError::new(CheckErrors::VariadicNeedsOneArgument))?;
        let function_name = function_name.match_atom()
            .ok_or(CheckError::new(CheckErrors::BadFunctionName))?;
        let mut args = parse_name_type_pairs(args)
            .map_err(|_| { CheckError::new(CheckErrors::BadSyntaxBinding) })?;

        let mut function_context = context.extend()?;
        for (arg_name, arg_type) in args.iter() {
            function_context.variable_types.insert(arg_name.clone(),
                                                   arg_type.clone());
        }


        let return_type = self.type_check(body, &function_context)?;
        let arg_types: Vec<TypeSignature> = args.drain(..)
            .map(|(_, arg_type)| arg_type).collect();

        Ok((function_name.to_string(), FunctionType::Fixed(arg_types, return_type)))
    }

    fn type_check_define_map(&mut self, map_expression: &[SymbolicExpression],
                                 _context: &TypingContext) -> CheckResult<(String, (TypeSignature, TypeSignature))> {
        if map_expression.len() != 4 {
            return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, map_expression.len() - 2)))
        }

        self.type_map.set_type(&map_expression[0], no_type())?;
        self.type_map.set_type(&map_expression[1], no_type())?;
        self.type_map.set_type(&map_expression[2], no_type())?;
        self.type_map.set_type(&map_expression[3], no_type())?;
        // should we set the type of the subexpressions of the signature to no-type as well?

        let map_name = map_expression[1].match_atom()
            .ok_or(CheckError::new(CheckErrors::BadMapName))?;
        let key_type = &map_expression[2];
        let value_type = &map_expression[3];

        let key_type = TypeSignature::new_tuple(
            TupleTypeSignature::parse_name_type_pair_list(key_type)
                .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?)
            .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?;
        let value_type = TypeSignature::new_tuple(
            TupleTypeSignature::parse_name_type_pair_list(value_type)
                .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?)
            .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?;


        Ok((map_name.to_string(), (key_type, value_type)))
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
        if let Some((function_name, args)) = expression.split_first() {
            self.type_map.set_type(function_name, no_type())?;
            let function_name = function_name.match_atom()
                .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;

            if let Some(type_result) = self.try_native_function_check(function_name, args, context) {
                type_result
            } else {
                let function_type = self.get_function_type(function_name)
                    .ok_or(CheckError::new(CheckErrors::UnknownFunction(function_name.clone())))?;
                self.type_check_function_type(&function_type, args, context)
            }
        } else {
            Err(CheckError::new(CheckErrors::NonFunctionApplication))
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

    fn type_check_define_variable(&mut self, args: &[SymbolicExpression], context: &mut TypingContext) -> CheckResult<(String, TypeSignature)> {
        if args.len() != 2 {
            return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
        }
        let var_name = args[0].match_atom()
            .ok_or(CheckError::new(CheckErrors::DefineVariableBadSignature))?
            .clone();
        let var_type = self.type_check(&args[1], context)?;
        Ok((var_name, var_type))
    }


    // Checks if an expression is a _define_ expression, and if so, typechecks it. Otherwise, it returns Ok(None)
    fn try_type_check_define(&mut self, expr: &SymbolicExpression, context: &mut TypingContext) -> CheckResult<Option<()>> {
        if let Some(ref expression) = expr.match_list() {
            if let Some((function_name, function_args)) = expression.split_first() {
                if let Some(function_name) = function_name.match_atom() {
                    match function_name.as_str() {
                        "define" => {
                            if function_args.len() < 1 {
                                return Err(CheckError::new(CheckErrors::DefineFunctionBadSignature))
                            } else {
                                if function_args[0].match_list().is_some() {
                                    let (f_name, f_type) = self.type_check_define_function(expression,
                                                                                           context)?;
                                    self.contract_context.add_private_function_type(f_name, f_type)?;
                                    Ok(Some(()))
                                } else {
                                    let (v_name, v_type) = self.type_check_define_variable(function_args,
                                                                                           context)?;
                                    self.contract_context.add_variable_type(v_name, v_type)?;
                                    Ok(Some(()))
                                }
                            }
                        },
                        "define-public" => {
                            let (f_name, f_type) = self.type_check_define_function(expression,
                                                                                   context)?;
                            if !TypeSignature::new_atom(AtomTypeIdentifier::BoolType).admits_type(
                                &f_type.return_type()) {
                                Err(CheckError::new(CheckErrors::PublicFunctionMustReturnBool))
                            } else {
                                self.contract_context.add_public_function_type(f_name, f_type)?;
                                Ok(Some(()))
                            }
                        },
                        "define-map" => {
                            let (f_name, f_type) = self.type_check_define_map(expression,
                                                                              context)?;
                            self.contract_context.add_map_type(f_name, f_type)?;
                            Ok(Some(()))
                        },
                        _ => {
                            Ok(None)
                        }
                    }
                } else {
                    Ok(None)
                }
            } else {
                Ok(None) // not a define
            }
        } else {
            Ok(None) // not a define.
        }
    }
}

