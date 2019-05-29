use vm::errors::{ErrType as InterpError};
use vm::functions::NativeFunctions;
use vm::representations::{SymbolicExpression};
use vm::types::{TypeSignature, AtomTypeIdentifier, TupleTypeSignature, BlockInfoProperty};
use super::{TypeChecker, TypingContext, TypeResult, FunctionType, no_type, check_atomic_type}; 
use vm::checker::errors::{CheckError, CheckErrors, CheckResult};

mod maps;

pub enum TypedNativeFunction {
    Special(SpecialNativeFunction),
    Simple(SimpleNativeFunction)
}

pub struct SpecialNativeFunction(&'static Fn(&mut TypeChecker, &[SymbolicExpression], &TypingContext) -> TypeResult);
pub struct SimpleNativeFunction(pub FunctionType);

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

fn check_special_list_cons(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    let typed_args = checker.type_check_all(args, context)?;
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

fn check_special_print(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }
    
    checker.type_check(&args[0], context)
}

fn check_special_okay(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::ResponseType(Box::new((inner_type.clone(), no_type()))));
    Ok(resp_type)
}

fn check_special_error(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::ResponseType(Box::new((no_type(), inner_type.clone()))));
    Ok(resp_type)
}

fn check_special_is_okay(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))
    }
    
    let input = checker.type_check(&args[0], context)?;

    if let Some(AtomTypeIdentifier::ResponseType(_types)) = input.match_atomic() {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    } else {
        return Err(CheckError::new(CheckErrors::ExpectedResponseType))
    }
}

fn check_special_default_to(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))        
    }
    
    let default = checker.type_check(&args[0], context)?;
    let input = checker.type_check(&args[1], context)?;

    if let Some(AtomTypeIdentifier::OptionalType(input_type)) = input.match_atomic() {
        if input_type.admits_type(&default) {
            return Ok((**input_type).clone())
        } else if default.admits_type(&input_type) {
            return Ok(default)
        } else {
            return Err(CheckError::new(CheckErrors::DefaultTypesMustMatch((**input_type).clone(), default)))
        }
    } else {
        return Err(CheckError::new(CheckErrors::ExpectedOptionalType))
    }
}

fn check_special_expects(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))        
    }
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    if let Some(AtomTypeIdentifier::OptionalType(input_type)) = input.match_atomic() {
        return Ok((**input_type).clone())
    } else {
        return Err(CheckError::new(CheckErrors::ExpectedOptionalType))
    }
}

fn check_special_as_contract(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }
    
    checker.type_check(&args[0], context)
}

fn check_special_begin(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() < 1 {
        return Err(CheckError::new(CheckErrors::VariadicNeedsOneArgument))
    }
    
    let mut typed_args = checker.type_check_all(args, context)?;
    
    let last_return = typed_args.pop()
        .ok_or(CheckError::new(CheckErrors::CheckerImplementationFailure))?;
    
    Ok(last_return)
}

fn inner_handle_tuple_get(tuple_type_sig: &TupleTypeSignature, field_to_get: &str) -> TypeResult {
    let return_type = tuple_type_sig.field_type(field_to_get)
        .ok_or(CheckError::new(CheckErrors::NoSuchTupleField(field_to_get.to_string())))?
        .clone();
    Ok(return_type)
}

fn check_special_get(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }
    
    let field_to_get = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadTupleFieldName))?;
    
    checker.type_map.set_type(&args[0], no_type())?;
    
    let argument_type = checker.type_check(&args[1], context)?;
    let atomic_type = argument_type
        .match_atomic()
        .ok_or(CheckError::new(CheckErrors::ExpectedTuple(argument_type.clone())))?;
    
    if let AtomTypeIdentifier::TupleType(tuple_type_sig) = atomic_type {
        inner_handle_tuple_get(tuple_type_sig, field_to_get)
    } else if let AtomTypeIdentifier::OptionalType(value_type_sig) = atomic_type {
        let atomic_value_type = value_type_sig.match_atomic()
            .ok_or(CheckError::new(CheckErrors::ExpectedTuple((**value_type_sig).clone())))?;
        if let AtomTypeIdentifier::TupleType(tuple_type_sig) = atomic_value_type {
            let inner_type = inner_handle_tuple_get(tuple_type_sig, field_to_get)?;
            let option_type = TypeSignature::new_option(inner_type);
            Ok(option_type)
        } else {
            Err(CheckError::new(CheckErrors::ExpectedTuple((**value_type_sig).clone())))
        }
    } else {
        Err(CheckError::new(CheckErrors::ExpectedTuple(argument_type.clone())))
    }
}

fn check_special_tuple_cons(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
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
        checker.type_map.set_type(&pair_expression[0], no_type())?;
        
        let var_type = checker.type_check(&pair_expression[1], context)?;
        tuple_type_data.push((var_name.clone(), var_type))
    }
    
    let tuple_signature = TupleTypeSignature::new(tuple_type_data)
        .map_err(|_| CheckError::new(CheckErrors::BadTupleConstruction))?;
    
    Ok(TypeSignature::new_atom(
        AtomTypeIdentifier::TupleType(tuple_signature)))
}

fn get_simple_native_or_user_define(function_name: &str, checker: &TypeChecker) -> CheckResult<FunctionType> {
    if let Some(ref native_function) = NativeFunctions::lookup_by_name(function_name) {
        if let TypedNativeFunction::Simple(SimpleNativeFunction(function_type)) = TypedNativeFunction::type_native_function(native_function) {
            Ok(function_type)
        } else {
            Err(CheckError::new(CheckErrors::IllegalOrUnknownFunctionApplication(function_name.to_string())))
        }
    } else {
        checker.get_function_type(function_name)
            .ok_or(CheckError::new(CheckErrors::IllegalOrUnknownFunctionApplication(function_name.to_string())))
    }
}

fn check_special_map(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }
    
    let function_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ map a special function.
    let function_type = get_simple_native_or_user_define(function_name, checker)?;
    
    checker.type_map.set_type(&args[0], no_type())?;
    
    let argument_type = checker.type_check(&args[1], context)?;
    
    let argument_length = argument_type.list_max_len()
        .ok_or(CheckError::new(CheckErrors::ExpectedListApplication))?;
    
    let argument_items_type = argument_type.get_list_item_type()
        .ok_or(CheckError::new(CheckErrors::ExpectedListApplication))?;
    
    function_type.check_args(&[argument_items_type])?;
    
    let mapped_type = function_type.return_type();
    
    TypeSignature::list_of(mapped_type, argument_length)
        .map_err(|_| CheckError::new(CheckErrors::ConstructedListTooLarge))
}

fn check_special_fold(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 3 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, args.len())))
    }
    
    let function_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::NonFunctionApplication))?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ fold a special function.
    let function_type = get_simple_native_or_user_define(function_name, checker)?;
    
    checker.type_map.set_type(&args[0], no_type())?;
    
    let list_argument_type = checker.type_check(&args[1], context)?;

    let list_items_type = list_argument_type.get_list_item_type()
        .ok_or(CheckError::new(CheckErrors::ExpectedListApplication))?;
        
    let initial_value_type = checker.type_check(&args[2], context)?;
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

fn check_special_let(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }
    
    checker.type_map.set_type(&args[0], no_type())?;
    let binding_list = args[0].match_list()
        .ok_or(CheckError::new(CheckErrors::BadLetSyntax))?;
    
    let let_context = checker.type_check_list_pairs(binding_list, context)?;
    
    let body_return_type = checker.type_check(&args[1], &let_context)?;
    
    Ok(body_return_type)
}

fn check_special_if(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 && args.len() != 3 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }
    
    checker.type_check_all(args, context)?;

    check_atomic_type(AtomTypeIdentifier::BoolType, checker.type_map.get_type(&args[0])?)?;
    
    let return_type = {
        if args.len() == 2 {
            checker.type_map.get_type(&args[1])?
                .clone()
            } else {
            let expr1 = checker.type_map.get_type(&args[1])?;
            let expr2 = checker.type_map.get_type(&args[2])?;
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

fn check_contract_call(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() < 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }
    let contract_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::ContractCallExpectName))?;
    let function_name = args[1].match_atom()
        .ok_or(CheckError::new(CheckErrors::ContractCallExpectName))?;
    checker.type_map.set_type(&args[0], no_type())?;
    checker.type_map.set_type(&args[1], no_type())?;

    let contract_call_function_type = {
        if let Some(function_type) = checker.db.get_public_function_type(contract_name, function_name)? {
            Ok(function_type)
        } else if let Some(function_type) = checker.db.get_read_only_function_type(contract_name, function_name)? {
            Ok(function_type)
        } else {
            Err(CheckError::new(CheckErrors::NoSuchPublicFunction(contract_name.to_string(),
                                                                  function_name.to_string())))
        }
    }?;

    let contract_call_args = checker.type_check_all(&args[2..], context)?;
    
    contract_call_function_type.check_args(&contract_call_args)?;
    
    Ok(contract_call_function_type.return_type())
}

fn check_get_block_info(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() < 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    checker.type_map.set_type(&args[0], no_type())?;
    let block_info_prop_str = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::GetBlockInfoExpectPropertyName))?;

    let block_info_prop = BlockInfoProperty::from_str(block_info_prop_str)
        .ok_or(CheckError::new(CheckErrors::NoSuchBlockInfoProperty(block_info_prop_str.to_string())))?;

    let block_height_arg = checker.type_check(&args[1], &context)?;
    check_atomic_type(AtomTypeIdentifier::IntType, &block_height_arg)?;
    
    Ok(block_info_prop.type_result())
}

impl TypedNativeFunction {
    pub fn type_check_appliction(&self, checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
        use self::TypedNativeFunction::{Special, Simple};
        match self {
            Special(SpecialNativeFunction(check)) => check(checker, args, context),
            Simple(SimpleNativeFunction(function_type)) => checker.type_check_function_type(function_type, args, context)
        }
    }

    pub fn type_native_function(function: &NativeFunctions) -> TypedNativeFunction {
        use self::TypedNativeFunction::{Special, Simple};
        use vm::functions::NativeFunctions::*;
        match function {
            Add | Subtract | Divide | Multiply =>
                Simple(SimpleNativeFunction(arithmetic_type(true))),
            CmpGeq | CmpLeq | CmpLess | CmpGreater =>
                Simple(SimpleNativeFunction(arithmetic_comparison())),
            Modulo | Power | BitwiseXOR =>
                Simple(SimpleNativeFunction(arithmetic_type(false))),
            And | Or =>
                Simple(SimpleNativeFunction(FunctionType::Variadic(TypeSignature::new_atom( AtomTypeIdentifier::BoolType ),
                                                                   TypeSignature::new_atom( AtomTypeIdentifier::BoolType )))),
            Not =>
                Simple(SimpleNativeFunction(FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::BoolType )],
                                                                TypeSignature::new_atom( AtomTypeIdentifier::BoolType )))),
            Hash160 =>
                Simple(SimpleNativeFunction(FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::AnyType )],
                                                                TypeSignature::new_atom( AtomTypeIdentifier::BufferType(20) )))),
            Sha256 =>
                Simple(SimpleNativeFunction(FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::AnyType )],
                                                                TypeSignature::new_atom( AtomTypeIdentifier::BufferType(32) )))),
            Keccak256 =>
                Simple(SimpleNativeFunction(FunctionType::Fixed(vec![TypeSignature::new_atom( AtomTypeIdentifier::AnyType )],
                                                                TypeSignature::new_atom( AtomTypeIdentifier::BufferType(32) )))),
            Equals =>
                Simple(SimpleNativeFunction(FunctionType::Variadic(TypeSignature::new_atom( AtomTypeIdentifier::AnyType ),
                                                                   TypeSignature::new_atom( AtomTypeIdentifier::BoolType )))),
            If => Special(SpecialNativeFunction(&check_special_if)),
            Let => Special(SpecialNativeFunction(&check_special_let)),
            Map => Special(SpecialNativeFunction(&check_special_map)),
            Fold => Special(SpecialNativeFunction(&check_special_fold)),
            ListCons => Special(SpecialNativeFunction(&check_special_list_cons)),
            FetchEntry => Special(SpecialNativeFunction(&maps::check_special_fetch_entry)),
            FetchContractEntry => Special(SpecialNativeFunction(&maps::check_special_fetch_contract_entry)),
            SetEntry => Special(SpecialNativeFunction(&maps::check_special_set_entry)),
            InsertEntry => Special(SpecialNativeFunction(&maps::check_special_insert_entry)),
            DeleteEntry => Special(SpecialNativeFunction(&maps::check_special_delete_entry)),
            TupleCons => Special(SpecialNativeFunction(&check_special_tuple_cons)),
            TupleGet => Special(SpecialNativeFunction(&check_special_get)),
            Begin => Special(SpecialNativeFunction(&check_special_begin)),
            Print => Special(SpecialNativeFunction(&check_special_print)),
            AsContract => Special(SpecialNativeFunction(&check_special_as_contract)),
            ContractCall => Special(SpecialNativeFunction(&check_contract_call)),
            GetBlockInfo => Special(SpecialNativeFunction(&check_get_block_info)),
            ConsOkay => Special(SpecialNativeFunction(&check_special_okay)),
            ConsError => Special(SpecialNativeFunction(&check_special_error)),
            DefaultTo => Special(SpecialNativeFunction(&check_special_default_to)),
            Expects => Special(SpecialNativeFunction(&check_special_expects)),
            IsOkay => Special(SpecialNativeFunction(&check_special_is_okay))
        }
    }
}
