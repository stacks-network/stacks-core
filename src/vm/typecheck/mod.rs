use std::collections::HashMap;
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::types::{AtomTypeIdentifier, TypeSignature, Value, TupleTypeSignature};
use vm::errors::{ErrType as InterpError};

use vm::contexts::MAX_CONTEXT_DEPTH;

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

pub struct TypeMap {
    map: HashMap<u64, TypeSignature>
}

#[derive(Debug, Clone)]
pub enum FunctionType {
    Variadic(TypeSignature, TypeSignature),
    Fixed(Vec<TypeSignature>, TypeSignature)
}

pub struct TypingContext <'a> {
    variable_types: HashMap<String, TypeSignature>,
    function_types: HashMap<String, FunctionType>,
    parent: Option<&'a TypingContext<'a>>,
    depth: u16
}

fn no_type() -> TypeSignature {
    TypeSignature::new_atom(AtomTypeIdentifier::NoType)
}

impl TypeMap {
    fn new() -> TypeMap {
        TypeMap { map: HashMap::new() }
    }

    fn set_type(&mut self, expr: &SymbolicExpression, type_sig: TypeSignature) -> CheckResult<()> {
        if self.map.insert(expr.id, type_sig).is_some() {
            Err(CheckError::new(CheckErrors::TypeAlreadyAnnotatedFailure))
        } else {
            Ok(())
        }
    }

    fn get_type(&self, expr: &SymbolicExpression) -> CheckResult<&TypeSignature> {
        self.map.get(&expr.id)
            .ok_or(CheckError::new(CheckErrors::TypeNotAnnotatedFailure))
    }
}

impl <'a> TypingContext <'a> {
    pub fn new() -> TypingContext<'static> {
        TypingContext {
            variable_types: HashMap::new(),
            function_types: HashMap::new(),
            depth: 0,
            parent: None
        }
    }

    pub fn extend<'b>(&'b self) -> CheckResult<TypingContext<'b>> {
        if self.depth >= MAX_CONTEXT_DEPTH {
            Err(CheckError::new(CheckErrors::MaxContextDepthReached))
        } else {
            Ok(TypingContext {
                variable_types: HashMap::new(),
                function_types: HashMap::new(),
                parent: Some(self),
                depth: self.depth + 1
            })
        }
    }

    pub fn lookup_function_type(&self, name: &str) -> Option<&FunctionType> {
        match self.function_types.get(name) {
            Some(value) => Some(value),
            None => {
                match self.parent {
                    Some(parent) => parent.lookup_function_type(name),
                    None => None
                }
            }
        }
    }

    pub fn lookup_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        match self.variable_types.get(name) {
            Some(value) => Some(value),
            None => {
                match self.parent {
                    Some(parent) => parent.lookup_variable_type(name),
                    None => None
                }
            }
        }
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


fn get_function_type(function_name: &str, context: &TypingContext) -> Option<FunctionType> {
    if let Some(function_type) = native_function_type_lookup(function_name) {
        Some(function_type)
    } else if let Some(function_type) = context.lookup_function_type(function_name) {
        Some(function_type.clone())
    } else {
        None
    }
}

fn type_check_all(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> CheckResult<Vec<TypeSignature>> {
    let mut result = Vec::new();
    for arg in args.iter() {
        // don't use map here, since type_check has side-effects.
        result.push(type_check(arg, context, type_map)?)
    }
    Ok(result)
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

// Aaron: note, using lazy statics here would speed things up a bit and reduce clone()s
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

    check_atomic_type(AtomTypeIdentifier::BoolType, type_map.get_type(&args[0])?)?;

    let return_type = {
        if args.len() == 2 {
            type_map.get_type(&args[1])?
                .clone()
        } else {
            let expr1 = type_map.get_type(&args[1])?;
            let expr2 = type_map.get_type(&args[2])?;
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

fn type_check_list_pairs<'a> (bindings: &[SymbolicExpression],
                              context: &'a TypingContext,
                              type_map: &mut TypeMap) -> CheckResult<TypingContext<'a>> {
    let mut out_context = context.extend()?;
    for binding in bindings.iter() {
        let binding_exps = binding.match_list()
            .ok_or(CheckError::new(CheckErrors::BadSyntaxBinding))?;

        if binding_exps.len() != 2 {
            return Err(CheckError::new(CheckErrors::BadSyntaxBinding))
        }

        let var_name = binding_exps[0].match_atom()
            .ok_or(CheckError::new(CheckErrors::BadSyntaxBinding))?;

        type_map.set_type(&binding_exps[0], no_type())?;
        let typed_result = type_check(&binding_exps[1], context, type_map)?;
        out_context.variable_types.insert(var_name.clone(),
                                          typed_result);
    }

    Ok(out_context)
}

fn check_special_let(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    type_map.set_type(&args[0], no_type())?;
    let binding_list = args[0].match_list()
        .ok_or(CheckError::new(CheckErrors::BadLetSyntax))?;

    let let_context = type_check_list_pairs(binding_list, context, type_map)?;

    let body_return_type = type_check(&args[1], &let_context, type_map)?;

    Ok(body_return_type)
}

fn check_special_map(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    let function_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ map a special function.
    let function_type = get_function_type(function_name, context)
        .ok_or(CheckError::new(CheckErrors::IllegalOrUnknownFunctionApplication(function_name.clone())))?;

    type_map.set_type(&args[0], no_type())?;

    let argument_type = type_check(&args[1], context, type_map)?;

    let argument_length = argument_type.list_max_len()
        .ok_or(CheckError::new(CheckErrors::ExpectedListApplication))?;

    let argument_items_type = argument_type.get_list_item_type()
        .ok_or(CheckError::new(CheckErrors::ExpectedListApplication))?;

    function_type.check_args(&[argument_items_type])?;

    let mapped_type = function_type.return_type();

    TypeSignature::list_of(mapped_type, argument_length)
        .map_err(|_| CheckError::new(CheckErrors::ConstructedListTooLarge))
}

fn check_special_fold(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() != 3 {
        eprintln!("{:?}", args);
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, args.len())))
    }

    let function_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ fold a special function.
    let function_type = get_function_type(function_name, context)
        .ok_or(CheckError::new(CheckErrors::IllegalOrUnknownFunctionApplication(function_name.clone())))?;

    type_map.set_type(&args[0], no_type())?;

    let list_argument_type = type_check(&args[1], context, type_map)?;

    let list_items_type = list_argument_type.get_list_item_type()
        .ok_or(CheckError::new(CheckErrors::ExpectedListApplication))?;

    let initial_value_type = type_check(&args[2], context, type_map)?;
    let return_type = function_type.return_type();

    // fold: f(A, B) -> A
    //     where A = initial_value_type
    //           B = list items type

    // f must accept the initial value and the list items type
    function_type.check_args(&[initial_value_type.clone(), list_items_type.clone()])?;
    // f must _also_ accepts its own return type!
    function_type.check_args(&[return_type.clone(), list_items_type.clone()])?;
    // TODO: those clones _should_ be removed.

    Ok(return_type)
}

fn check_special_list_cons(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    let typed_args = type_check_all(args, context, type_map)?;
    TypeSignature::parent_list_type(&typed_args)
        .map_err(|x| {
            let error_type = match x.err_type {
                InterpError::BadTypeConstruction => CheckErrors::ListTypesMustMatch,
                InterpError::ListTooLarge => CheckErrors::ConstructedListTooLarge,
                InterpError::ListDimensionTooHigh => CheckErrors::ConstructedListTooLarge,
                _ => CheckErrors::UnknownListConstructionFailure
            };
            CheckError::new(error_type)
        })
}

fn check_special_print(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }

    type_check(&args[0], context, type_map)
}

fn check_special_begin(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 1 {
        return Err(CheckError::new(CheckErrors::VariadicNeedsOneArgument))
    }

    let mut typed_args = type_check_all(args, context, type_map)?;

    let last_return = typed_args.pop()
        .ok_or(CheckError::new(CheckErrors::CheckerImplementationFailure))?;

    Ok(last_return)
}

fn check_special_get(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    let field_to_get = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadTupleFieldName))?;

    type_map.set_type(&args[0], no_type())?;

    let argument_type = type_check(&args[1], context, type_map)?;
    let atomic_type = argument_type
        .match_atomic()
        .ok_or(CheckError::new(CheckErrors::ExpectedTuple(argument_type.clone())))?;

    if let AtomTypeIdentifier::TupleType(tuple_type_sig) = atomic_type {
        let return_type = tuple_type_sig.field_type(field_to_get)
            .ok_or(CheckError::new(CheckErrors::NoSuchTupleField(field_to_get.clone())))?
            .clone();
        Ok(return_type)
    } else {
        Err(CheckError::new(CheckErrors::ExpectedTuple(argument_type.clone())))
    }
}

fn check_special_tuple_cons(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 1 {
        return Err(CheckError::new(CheckErrors::VariadicNeedsOneArgument))
    }

    let mut tuple_type_data = Vec::new();
    for pair in args.iter() {
        let pair_expression = pair.match_list()
            .ok_or(CheckError::new(CheckErrors::TupleExpectsPairs))?;
        if pair_expression.len() != 2 {
            return Err(CheckError::new(CheckErrors::TupleExpectsPairs))
        }

        let var_name = pair_expression[0].match_atom()
            .ok_or(CheckError::new(CheckErrors::TupleExpectsPairs))?;
        type_map.set_type(&pair_expression[0], no_type())?;

        let var_type = type_check(&pair_expression[1], context, type_map)?;
        tuple_type_data.push((var_name.clone(), var_type))
    }

    let tuple_signature = TupleTypeSignature::new(tuple_type_data)
        .map_err(|_| CheckError::new(CheckErrors::BadTupleConstruction))?;

    Ok(TypeSignature::new_atom(
        AtomTypeIdentifier::TupleType(tuple_signature)))
}
/*
fn check_special_fetch_entry(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    let map_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadMapName))?;

    type_map.set_type(&args[0], no_type())?;

    let key_type = type_check(&args[1], context, type_map)?;

    let expected_key_type = context.get_map_key_type(map_name)?;

    if !expected_key_type.admits(key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type, key_type)))
    } else {
        return Ok(context.get_map_value_type(map_name)?)
    }
}
*/

/*
    "set-entry!" => Some(CallableType::SpecialFunction("native_set-entry", &database::special_set_entry)),
    "insert-entry!" => Some(CallableType::SpecialFunction("native_insert-entry", &database::special_insert_entry)),
    "delete-entry!" => Some(CallableType::SpecialFunction("native_delete-entry", &database::special_delete_entry)),
    "contract-call!" => Some(CallableType::SpecialFunction("native_contract-call", &database::special_contract_call)), */

fn try_special_function_check(function: &str, args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> Option<TypeResult> {
    match function {
        "if" => Some(check_special_if(args, context, type_map)),
        "let" => Some(check_special_let(args, context, type_map)),
        "get" => Some(check_special_get(args, context, type_map)),
        "tuple" => Some(check_special_tuple_cons(args, context, type_map)),
        "map" => Some(check_special_map(args, context, type_map)),
        "fold" => Some(check_special_fold(args, context, type_map)),
        "list" => Some(check_special_list_cons(args, context, type_map)),
        "print" => Some(check_special_print(args, context, type_map)),
        "begin" => Some(check_special_begin(args, context, type_map)),
        _ => None
    }
}

fn type_check_function_application(expression: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if let Some((function_name, args)) = expression.split_first() {
        type_map.set_type(function_name, no_type())?;
        let function_name = function_name.match_atom()
            .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;

        if let Some(type_result) = try_special_function_check(function_name, args, context, type_map) {
            type_result
        } else {
            let function_type = get_function_type(function_name, context)
                .ok_or(CheckError::new(CheckErrors::UnknownFunction(function_name.clone())))?;
            type_check_function_type(function_name, &function_type, args, context, type_map)
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
                .clone()
        },
        List(ref expression) => {
            type_check_function_application(expression, context, type_map)?
        }
    };

    type_map.set_type(expr, type_sig.clone())?;
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
                   "(+ x y z)", // unbound variables.
                   "(+ 1 2 3 (eq? 1 2))",
                   "(and (or 'true 'false) (+ 1 2 3))"];
        for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut good_test).unwrap();
            type_check(&good_test[0], &TypingContext::new(), &mut TypeMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut TypeMap::new()).is_err())
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
            type_check(&good_test[0], &TypingContext::new(), &mut TypeMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut TypeMap::new()).is_err())
        }
    }

    #[test]
    fn test_simple_lets() {
        let good = ["(let ((x 1) (y 2) (z 3)) (if (> x 2) (+ 1 x y) (- 1 z)))",
                    "(let ((x 'true) (y (+ 1 2)) (z 3)) (if x (+ 1 z y) (- 1 z)))"];
        let bad = ["(let ((1)) (+ 1 2))",
                   "(let ((1 2)) (+ 1 2))"];
        for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut good_test).unwrap();
            type_check(&good_test[0], &TypingContext::new(), &mut TypeMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut TypeMap::new()).is_err())
        }
    }

    #[test]
    fn test_lists() {
        let good = ["(map hash160 (list 1 2 3 4 5))",
                    "(list (list 1 2) (list 3 4) (list 5 1 7))",
                    "(fold and (list 'true 'true 'false 'false) 'true)",
                    "(map - (list (+ 1 2) 3 (+ 4 5) (* (+ 1 2) 3)))"];
        let bad = [
            "(fold and (list 'true 'false) 2)",
            "(fold hash160 (list 1 2 3 4) 2)",
            "(fold >= (list 1 2 3 4) 2)",
            "(list (list 1 2) (list 'true) (list 5 1 7))",
            "(list 1 2 3 'true 'false 4 5 6)",
            "(map mod (list 1 2 3 4 5))",
            "(map - (list 'true 'false 'true 'false))",
            "(map hash160 (+ 1 2))",];
                   
        for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut good_test).unwrap();
            type_check(&good_test[0], &TypingContext::new(), &mut TypeMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut TypeMap::new()).is_err())
        }
    }

    #[test]
    fn test_tuples() {
        let good = ["(+ 1 2     (get abc (tuple (abc 1) (def 'true))))",
                    "(and 'true (get def (tuple (abc 1) (def 'true))))"];
        let bad = ["(+ 1 2      (get def (tuple (abc 1) (def 'true))))",
                   "(and 'true  (get abc (tuple (abc 1) (def 'true))))"];
                   
        for mut good_test in good.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut good_test).unwrap();
            type_check(&good_test[0], &TypingContext::new(), &mut TypeMap::new()).unwrap();
        }

        for mut bad_test in bad.iter().map(|x| parse(x).unwrap()) {
            identity_pass::identity_pass(&mut bad_test).unwrap();
            assert!(type_check(&bad_test[0], &TypingContext::new(), &mut TypeMap::new()).is_err())
        }
    }

}
