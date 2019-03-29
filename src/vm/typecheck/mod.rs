use std::collections::HashMap;
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::types::{AtomTypeIdentifier, TypeSignature, Value};

mod errors;
mod identity_pass;

pub use self::errors::{CheckResult, CheckError, CheckErrors};

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


pub type TypeResult = CheckResult<TypeSignature>;


// TODO
//  probably want to implement typemap ourselves.
//   it should, e.g., error on overwriting inserts.
pub type TypeMap = HashMap<u64, TypeSignature>;

pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(Vec<TypeSignature>, TypeSignature)
}

pub struct TypingContext <'a> {
    variable_types: HashMap<String, TypeSignature>,
    function_types: HashMap<String, FunctionType>,
    parent: Option<&'a TypingContext<'a>>
}

fn no_type() -> TypeSignature {
    TypeSignature::new_atom(AtomTypeIdentifier::NoType)
}

impl <'a> TypingContext <'a> {
    pub fn new() -> TypingContext<'static> {
        TypingContext {
            variable_types: HashMap::new(),
            function_types: HashMap::new(),
            parent: None
        }
    }
    pub fn lookup_function_type(&self, name: &str) -> Option<FunctionType> {
        None
    }
    pub fn lookup_variable_type(&self, name: &str) -> Option<TypeSignature> {
        None
    }
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
                        return Err(CheckError::new(CheckErrors::TypeError(//format!("Bad type supplied to function. Expected {:?}, Found {:?}.",
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
                        return Err(CheckError::new(CheckErrors::TypeError(//format!("Bad type supplied to function. Expected {:?}, Found {:?}.",
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

fn type_check_all(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> CheckResult<Vec<TypeSignature>> {
    args.iter().map(|arg| type_check(arg, context, type_map)).collect()
}

fn type_check_function_type(func_name: &str, func_type: &FunctionType,
                            args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    let typed_args = type_check_all(args, context, type_map)?;
    func_type.check_args(&typed_args)?;
    Ok(func_type.return_type().clone())
}

fn arithmetic_type(variadic: bool) -> FunctionType {
    if variadic {
        FunctionType::Variadic(TypeSignature::new_atom( AtomTypeIdentifier::IntType ),
                               TypeSignature::new_atom( AtomTypeIdentifier::IntType ))
    } else {
        FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::IntType ),
                                 TypeSignature::new_atom( AtomTypeIdentifier::IntType )],
                            TypeSignature::new_atom( AtomTypeIdentifier::IntType ))
    }
}

fn arithmetic_comparison() -> FunctionType {
    FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::IntType ),
                             TypeSignature::new_atom( AtomTypeIdentifier::IntType )],
                        TypeSignature::new_atom( AtomTypeIdentifier::BoolType ))    
}

fn native_function_type_lookup(function: &str) -> Option<FunctionType> {
    match function {
        "+" => Some(arithmetic_type(true)),
        "-" => Some(arithmetic_type(true)),
        "*" => Some(arithmetic_type(true)),
        "/" => Some(arithmetic_type(true)),
        "mod" => Some(arithmetic_type(false)),
        "pow" => Some(arithmetic_type(false)),
        "xor" => Some(arithmetic_type(false)),
        ">=" => Some(arithmetic_comparison()),
        "<=" => Some(arithmetic_comparison()),
        "<" => Some(arithmetic_comparison()),
        ">" => Some(arithmetic_comparison()),
        "and" => Some(
            FunctionType::Variadic(TypeSignature::new_atom( AtomTypeIdentifier::BoolType ),
                                   TypeSignature::new_atom( AtomTypeIdentifier::BoolType ))),
        "or" => Some(
            FunctionType::Variadic(TypeSignature::new_atom( AtomTypeIdentifier::BoolType ),
                                   TypeSignature::new_atom( AtomTypeIdentifier::BoolType ))),
        "not" => Some(
            FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::BoolType )],
                                TypeSignature::new_atom( AtomTypeIdentifier::BoolType ))),
        "eq?" => Some(
            FunctionType::Variadic(TypeSignature::new_atom( AtomTypeIdentifier::AnyType ),
                                   TypeSignature::new_atom( AtomTypeIdentifier::BoolType ))),
        "hash160" => Some(
            FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::AnyType )],
                                TypeSignature::new_atom( AtomTypeIdentifier::BufferType(20) ))),
        _ => None
    }
}

fn get_type<'a>(expr: &SymbolicExpression, type_map: &'a TypeMap) -> CheckResult<&'a TypeSignature> {
    type_map.get(&expr.id)
        .ok_or(CheckError::new(CheckErrors::TypeNotAnnotatedFailure))
}

fn check_atomic_type(atom: AtomTypeIdentifier, to_check: &TypeSignature) -> CheckResult<()> {
    let expected = TypeSignature::new_atom(atom);
    if !expected.admits_type(to_check) {
        Err(CheckError::new(CheckErrors::TypeError(expected, to_check.clone())))
    } else {
        Ok(())
    }
}

fn check_special_if(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() != 2 && args.len() != 3 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    type_check_all(args, context, type_map)?;

    check_atomic_type(AtomTypeIdentifier::BoolType, get_type(&args[0], type_map)?)?;

    let return_type = {
        if args.len() == 2 {
            get_type(&args[1], type_map)?
                .clone()
        } else {
            let expr1 = get_type(&args[1], type_map)?;
            let expr2 = get_type(&args[2], type_map)?;
            if expr1.admits_type(expr2) {
                expr1.clone()
            } else if expr2.admits_type(expr1) {
                expr2.clone()
            } else {
                return Err(CheckError::new(CheckErrors::IfArmsMustMatch(expr1.clone(), expr2.clone())));
            }
        }
    };

    Ok(return_type)
}

/*fn type_check_list_pairs<'a> (bindings: &[SymbolicExpression],
                              context: &TypingContext) -> Result<(TypingContext<'a>, TypeAnnotatedSymbolicExpression), String> {
    let mut result = Vec::new();
    let mut out_context = TypingContext::new();
    out_context.parent = Some(context);
    for binding in bindings.iter() {
        if let SymbolicExpression::list(ref binding_exps) = *binding {
            if binding_exps.len() != 2 {
                return Err(format!("Passed non 2-length list as a binding. Bindings should be of the form (name value)."))
            }
            if let SymbolicExpression::Atom(ref var_name) = binding_exps[0] {
                let typed_result = type_check(&binding_exps[1], context)?;
                result.push(
                    TypeAnnotatedSymbolicExpression::binding(var_name.clone(),
                                                             typed_result));
                out_context.variable_types.insert(var_name.clone(),
                                                  typed_result.annotation.clone());
            } else {
                return Err(Error::new(ErrType::InvalidArguments("Passed bad variable name as a binding. Bindings should be of the form (name value).".to_string())))
            }
        } else {
            return Err(format!("Passed non-list as bindings."))
        }
    }

    Ok((out_context,
        TypeAnnotatedSymbolicExpression::bindings(result)))
}*/

fn check_special_let(args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    return Err(CheckError::new(CheckErrors::NotImplemented))
}


/*
    "let" => Some(CallableType::SpecialFunction("native_let", &special_let)),
    "map" => Some(CallableType::SpecialFunction("native_map", &lists::list_map)),
    "fold" => Some(CallableType::SpecialFunction("native_fold", &lists::list_fold)),
    "list" => Some(CallableType::NativeFunction("native_cons", &lists::list_cons)),
    "fetch-entry" => Some(CallableType::SpecialFunction("native_fetch-entry", &database::special_fetch_entry)),
    "set-entry!" => Some(CallableType::SpecialFunction("native_set-entry", &database::special_set_entry)),
    "insert-entry!" => Some(CallableType::SpecialFunction("native_insert-entry", &database::special_insert_entry)),
    "delete-entry!" => Some(CallableType::SpecialFunction("native_delete-entry", &database::special_delete_entry)),
    "tuple" => Some(CallableType::SpecialFunction("native_tuple", &tuples::tuple_cons)),
    "get" => Some(CallableType::SpecialFunction("native_get-tuple", &tuples::tuple_get)),
    "begin" => Some(CallableType::NativeFunction("native_begin", &native_begin)),
    "print" => Some(CallableType::NativeFunction("native_print", &native_print)),
    "contract-call!" => Some(CallableType::SpecialFunction("native_contract-call", &database::special_contract_call)), */

fn try_special_function_check(function: &str, args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> Option<TypeResult> {
    match function {
        "if" => Some(check_special_if(args, context, type_map)),
        _ => None
    }
}

fn type_check_function_application(expression: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if let Some((function_name, args)) = expression.split_first() {
        type_map.insert(function_name.id, no_type());
        if let SymbolicExpressionType::Atom(ref function_name) = function_name.expr {
            if let Some(type_result) = try_special_function_check(function_name, args, context, type_map) {
                type_result
            } else {
                if let Some(function_type) = native_function_type_lookup(function_name) {
                    type_check_function_type(function_name, &function_type, args, context, type_map)
                } else if let Some(function_type) = context.lookup_function_type(function_name) {
                    type_check_function_type(function_name, &function_type, args, context, type_map)
                } else {
                    Err(CheckError::new(CheckErrors::UnknownFunction(function_name.clone())))
                }
            }
        } else {
            Err(CheckError::new(CheckErrors::NonFunctionApplication))
        }
    } else {
        Err(CheckError::new(CheckErrors::NonFunctionApplication))
    }
}

pub fn type_check(expr: &SymbolicExpression, context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    let type_sig = match expr.expr {
        AtomValue(ref value) => {
            TypeSignature::type_of(value)
        },
        Atom(ref name) => {
            context.lookup_variable_type(name)
                .ok_or(CheckError::new(CheckErrors::UnboundVariable(name.clone())))?
        },
        List(ref expression) => {
            type_check_function_application(expression, context, type_map)?
        }
    };

    type_map.insert(expr.id, type_sig.clone());
    Ok(type_sig)
}

#[cfg(test)]
mod test {
    use vm::parser::parse;
    use super::*;

    #[test]
    fn test_simple_arithmetic_checks() {
        let good = ["(>= (+ 1 2 3) (- 1 2))",
                    "(eq? (+ 1 2 3) 'true 'false)",
                    "(and (or 'true 'false) 'false)"];
        let bad = ["(+ 1 2 3 (>= 5 7))",
                   "(-)",
                   "(xor 1)",
                   "(+ 1 2 3 (eq? 1 2))",
                   "(and (or 'true 'false) (+ 1 2 3))"];
        for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut good_test).unwrap();
            type_check(&good_test[0], &TypingContext::new(), &mut HashMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut HashMap::new()).is_err())
        }
    }

    #[test]
    fn test_simple_ifs() {
        let good = ["(if (> 1 2) (+ 1 2 3) (- 1 2))",
                    "(if 'true 'true)",
                    "(if 'true \"abcdef\" \"abc\")",
                    "(if 'true \"a\" \"abcdef\")" ];
        let bad = ["(if 'true 'true 1)",
                   "(if 'true \"a\" 'false)",
                   "(if)",
                   "(if 0 1 0)"];
        for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut good_test).unwrap();
            type_check(&good_test[0], &TypingContext::new(), &mut HashMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut HashMap::new()).is_err())
        }
    }
}
