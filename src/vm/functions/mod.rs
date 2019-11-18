pub mod define;
pub mod tuples;
mod lists;
mod arithmetic;
mod boolean;
mod database;
mod options;
mod assets;

use std::convert::TryInto;
use vm::errors::{CheckErrors, RuntimeErrorType, ShortReturnType, InterpreterResult as Result, check_argument_count, check_arguments_at_least};
use vm::types::{Value, PrincipalData, ResponseData, TypeSignature};
use vm::callables::CallableType;
use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName};
use vm::representations::SymbolicExpressionType::{List, Atom};
use vm::{LocalContext, Environment, eval};
use util::hash;

define_named_enum!(NativeFunctions {
    Add("+"),
    Subtract("-"),
    Multiply("*"),
    Divide("/"),
    CmpGeq(">="),
    CmpLeq("<="),
    CmpLess("<"),
    CmpGreater(">"),
    ToInt("to-int"),
    ToUInt("to-uint"),
    Modulo("mod"),
    Power("pow"),
    BitwiseXOR("xor"),
    And("and"),
    Or("or"),
    Not("not"),
    Equals("eq?"),
    If("if"),
    Let("let"),
    Map("map"),
    Fold("fold"),
    Len("len"),
    ListCons("list"),
    FetchVar("var-get"),
    SetVar("var-set!"),
    FetchEntry("map-get"),
    FetchContractEntry("contract-map-get"),
    SetEntry("map-set!"),
    InsertEntry("map-insert!"),
    DeleteEntry("map-delete!"),
    TupleCons("tuple"),
    TupleGet("get"),
    Begin("begin"),
    Hash160("hash160"),
    Sha256("sha256"),
    Sha512("sha512"),
    Sha512Trunc256("sha512/256"),
    Keccak256("keccak256"),
    Print("print"),
    ContractCall("contract-call!"),
    AsContract("as-contract"),
    AtBlock("at-block"),
    GetBlockInfo("get-block-info"),
    ConsError("err"),
    ConsOkay("ok"),
    ConsSome("some"),
    DefaultTo("default-to"),
    Asserts("asserts!"),
    Expects("expects!"),
    ExpectsErr("expects-err!"),
    Unwrap("unwrap"),
    UnwrapErr("unwrap-err"),
    MatchOpt("match-opt"),
    MatchResp("match-resp"),
    IsOkay("is-ok?"),
    IsNone("is-none?"),
    IsErr("is-err?"),
    IsSome("is-some?"),
    Filter("filter"),
    GetTokenBalance("ft-get-balance"),
    GetAssetOwner("nft-get-owner"),
    TransferToken("ft-transfer!"),
    TransferAsset("nft-transfer!"),
    MintAsset("nft-mint!"),
    MintToken("ft-mint!"),
});

pub fn lookup_reserved_functions(name: &str) -> Option<CallableType> {
    use vm::functions::NativeFunctions::*;
    if let Some(native_function) = NativeFunctions::lookup_by_name(name) {
        let callable = match native_function {
            Add => CallableType::NativeFunction("native_add", &arithmetic::native_add),
            Subtract => CallableType::NativeFunction("native_sub", &arithmetic::native_sub),
            Multiply => CallableType::NativeFunction("native_mul", &arithmetic::native_mul),
            Divide => CallableType::NativeFunction("native_div", &arithmetic::native_div),
            CmpGeq => CallableType::NativeFunction("native_geq", &arithmetic::native_geq),
            CmpLeq => CallableType::NativeFunction("native_leq", &arithmetic::native_leq),
            CmpLess => CallableType::NativeFunction("native_le", &arithmetic::native_le),
            CmpGreater => CallableType::NativeFunction("native_ge", &arithmetic::native_ge),
            ToUInt => CallableType::NativeFunction("native_to_uint", &arithmetic::native_to_uint),
            ToInt => CallableType::NativeFunction("native_to_int", &arithmetic::native_to_int),
            Modulo => CallableType::NativeFunction("native_mod", &arithmetic::native_mod),
            Power => CallableType::NativeFunction("native_pow", &arithmetic::native_pow),
            BitwiseXOR => CallableType::NativeFunction("native_xor", &arithmetic::native_xor),
            And => CallableType::SpecialFunction("native_and", &boolean::special_and),
            Or => CallableType::SpecialFunction("native_or", &boolean::special_or),
            Not => CallableType::NativeFunction("native_not", &boolean::native_not),
            Equals => CallableType::NativeFunction("native_eq", &native_eq),
            If => CallableType::SpecialFunction("native_if", &special_if),
            Let => CallableType::SpecialFunction("native_let", &special_let),
            FetchVar => CallableType::SpecialFunction("native_var-get", &database::special_fetch_variable),
            SetVar => CallableType::SpecialFunction("native_set-var", &database::special_set_variable),
            Map => CallableType::SpecialFunction("native_map", &lists::list_map),
            Filter => CallableType::SpecialFunction("native_filter", &lists::list_filter),
            Fold => CallableType::SpecialFunction("native_fold", &lists::list_fold),
            Len => CallableType::SpecialFunction("native_len", &lists::list_len),
            ListCons => CallableType::NativeFunction("native_cons", &lists::list_cons),
            FetchEntry => CallableType::SpecialFunction("native_map-get", &database::special_fetch_entry),
            FetchContractEntry => CallableType::SpecialFunction("native_contract-map-get", &database::special_fetch_contract_entry),
            SetEntry => CallableType::SpecialFunction("native_set-entry", &database::special_set_entry),
            InsertEntry => CallableType::SpecialFunction("native_insert-entry", &database::special_insert_entry),
            DeleteEntry => CallableType::SpecialFunction("native_delete-entry", &database::special_delete_entry),
            TupleCons => CallableType::SpecialFunction("native_tuple", &tuples::tuple_cons),
            TupleGet => CallableType::SpecialFunction("native_get-tuple", &tuples::tuple_get),
            Begin => CallableType::NativeFunction("native_begin", &native_begin),
            Hash160 => CallableType::NativeFunction("native_hash160", &native_hash160),
            Sha256 => CallableType::NativeFunction("native_sha256", &native_sha256),
            Sha512 => CallableType::NativeFunction("native_sha512", &native_sha512),
            Sha512Trunc256 => CallableType::NativeFunction("native_sha512trunc256", &native_sha512trunc256),
            Keccak256 => CallableType::NativeFunction("native_keccak256", &native_keccak256),
            Print => CallableType::NativeFunction("native_print", &native_print),
            ContractCall => CallableType::SpecialFunction("native_contract-call", &database::special_contract_call),
            AsContract => CallableType::SpecialFunction("native_as-contract", &special_as_contract),
            GetBlockInfo => CallableType::SpecialFunction("native_get_block_info", &database::special_get_block_info),
            ConsSome => CallableType::NativeFunction("native_some", &options::native_some),
            ConsOkay => CallableType::NativeFunction("native_okay", &options::native_okay),
            ConsError => CallableType::NativeFunction("native_error", &options::native_error),
            DefaultTo => CallableType::NativeFunction("native_default_to", &options::native_default_to),
            Asserts => CallableType::SpecialFunction("native_asserts", &special_asserts),
            Expects => CallableType::NativeFunction("native_expects", &options::native_unwrap_or_ret),
            ExpectsErr => CallableType::NativeFunction("native_expects_err", &options::native_unwrap_err_or_ret),
            IsOkay => CallableType::NativeFunction("native_is_okay", &options::native_is_okay),
            IsNone => CallableType::NativeFunction("native_is_none", &options::native_is_none),
            IsErr => CallableType::NativeFunction("native_is_err", &options::native_is_err),
            IsSome => CallableType::NativeFunction("native_is_some", &options::native_is_some),
            Unwrap => CallableType::NativeFunction("native_unwrap", &options::native_unwrap),
            UnwrapErr => CallableType::NativeFunction("native_unwrap_err", &options::native_unwrap_err),
            MatchOpt => CallableType::SpecialFunction("special_match_opt", &options::special_match_opt),
            MatchResp => CallableType::SpecialFunction("special_match_resp", &options::special_match_resp),
            MintAsset => CallableType::SpecialFunction("special_mint_asset", &assets::special_mint_asset),
            MintToken => CallableType::SpecialFunction("special_mint_token", &assets::special_mint_token),
            TransferAsset => CallableType::SpecialFunction("special_transfer_asset", &assets::special_transfer_asset),
            TransferToken => CallableType::SpecialFunction("special_transfer_token", &assets::special_transfer_token),
            GetTokenBalance => CallableType::SpecialFunction("special_get_balance", &assets::special_get_balance),
            GetAssetOwner => CallableType::SpecialFunction("special_get_owner", &assets::special_get_owner),
            AtBlock => CallableType::SpecialFunction("special_at_block", &database::special_at_block),
        };
        Some(callable)
    } else {
        None
    }
}

fn native_eq(args: &[Value]) -> Result<Value> {
    // TODO: this currently uses the derived equality checks of Value,
    //   however, that's probably not how we want to implement equality
    //   checks on the ::ListTypes

    if args.len() < 2 {
        Ok(Value::Bool(true))
    } else {
        let first = &args[0];
        // check types:
        let mut arg_type = TypeSignature::type_of(first);
        for x in args.iter() {
            arg_type = TypeSignature::least_supertype(&TypeSignature::type_of(x), &arg_type)?;
            if x != first {
                return Ok(Value::Bool(false))
            }
        }
        Ok(Value::Bool(true))
    }
}

macro_rules! native_hash_func {
    ($name:ident, $module:ty) => {
        fn $name(args: &[Value]) -> Result<Value> {
            check_argument_count(1, args)?;

            let input = &args[0];
            let bytes = match input {
                Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
                Value::Buffer(value) => Ok(value.data.clone()),
                _ => Err(CheckErrors::UnionTypeValueError(vec![TypeSignature::IntType, TypeSignature::max_buffer()], input.clone()))
            }?;
            let hash = <$module>::from_data(&bytes);
            Value::buff_from(hash.as_bytes().to_vec())
        }
    }
}

native_hash_func!(native_hash160, hash::Hash160);
native_hash_func!(native_sha256, hash::Sha256Sum);
native_hash_func!(native_sha512, hash::Sha512Sum);
native_hash_func!(native_sha512trunc256, hash::Sha512Trunc256Sum);
native_hash_func!(native_keccak256, hash::Keccak256Hash);

fn native_begin(args: &[Value]) -> Result<Value> {
    match args.last() {
        Some(v) => Ok(v.clone()),
        None => Err(CheckErrors::RequiresAtLeastArguments(1,0).into())
    }
}

fn native_print(args: &[Value]) -> Result<Value> {
    check_argument_count(1, args)?;

    if cfg!(feature = "developer-mode") {
        eprintln!("{:?}", args[0]);
    }
    Ok(args[0].clone())
}

fn special_if(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    // handle the conditional clause.
    let conditional = eval(&args[0], env, context)?;
    match conditional {
        Value::Bool(result) => {
            if result {
                eval(&args[1], env, context)
            } else {
                eval(&args[2], env, context)
            }
        },
        _ => Err(CheckErrors::TypeValueError(TypeSignature::BoolType, conditional).into())
    }
}

fn special_asserts(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    // handle the conditional clause.
    let conditional = eval(&args[0], env, context)?;

    match conditional {
        Value::Bool(result) => {
            if result {
                Ok(conditional)
            } else {
                let thrown = eval(&args[1], env, context)?;
                Err(ShortReturnType::AssertionFailed(thrown.clone()).into())
            }
        },
        _ => Err(CheckErrors::TypeValueError(TypeSignature::BoolType, conditional).into())
    }
}

pub fn handle_binding_list <F, E> (bindings: &[SymbolicExpression], mut handler: F) -> std::result::Result<(), E>
where F: FnMut(&ClarityName, &SymbolicExpression) -> std::result::Result<(), E>,
      E: From<CheckErrors>
{
    for binding in bindings.iter() {
        let binding_expression = binding.match_list()
            .ok_or(CheckErrors::BadSyntaxBinding)?;
        if binding_expression.len() != 2 {
            return Err(CheckErrors::BadSyntaxBinding.into());
        }
        let var_name = binding_expression[0].match_atom()
            .ok_or(CheckErrors::BadSyntaxBinding)?;
        let var_sexp = &binding_expression[1];

        handler(var_name, var_sexp)?;
    }
    Ok(())
}

pub fn parse_eval_bindings(bindings: &[SymbolicExpression],
                       env: &mut Environment, context: &LocalContext)-> Result<Vec<(ClarityName, Value)>> {
    let mut result = Vec::new();
    handle_binding_list(bindings, |var_name, var_sexp| {
        eval(var_sexp, env, context)
            .and_then(|value| {
                result.push((var_name.clone(), value));
                Ok(()) })
    })?;

    Ok(result)
}

fn special_let(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (let ((x 1) (y 2)) (+ x y)) -> 3
    // arg0 => binding list
    // arg1..n => body
    check_arguments_at_least(2, args)?;

    // create a new context.
    let mut inner_context = context.extend()?;

    let bindings = args[0].match_list()
        .ok_or(CheckErrors::BadLetSyntax)?;

    // parse and eval the bindings.
    let mut binding_results = parse_eval_bindings(bindings, env, context)?;
    for (binding_name, binding_value) in binding_results.drain(..) {
        if is_reserved(&binding_name) ||
           env.contract_context.lookup_function(&binding_name).is_some() ||
           inner_context.lookup_variable(&binding_name).is_some() {
            return Err(CheckErrors::NameAlreadyUsed(binding_name.into()).into())
        }
        inner_context.variables.insert(binding_name, binding_value);
    }

    // evaluate the let-bodies

    let mut last_result = None;
    for body in args[1..].iter() {
        let body_result = eval(&body, env, &inner_context)?;
        last_result.replace(body_result);
    }

    // last_result should always be Some(...), because of the arg len check above.
    Ok(last_result.unwrap())
}

fn special_as_contract(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    // (as-contract (..))
    // arg0 => body
    check_argument_count(1, args)?;

    // nest an environment.
    let contract_principal = Value::Principal(PrincipalData::Contract(env.contract_context.contract_identifier.clone()));
    let mut nested_env = env.nest_as_principal(contract_principal);

    eval(&args[0], &mut nested_env, context)
}
