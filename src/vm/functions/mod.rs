pub mod define;
pub mod tuples;
mod lists;
mod arithmetic;
mod boolean;
mod database;
mod options;
mod assets;

use vm::errors::{UncheckedError, RuntimeErrorType, InterpreterResult as Result, check_argument_count};
use vm::types::{Value, PrincipalData, ResponseData, TypeSignature};
use vm::callables::CallableType;
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::representations::SymbolicExpressionType::{List, Atom};
use vm::{LocalContext, Environment, eval};


macro_rules! define_enum {
    ($Name:ident { $($Variant:ident),* $(,)* }) =>
    {
        #[derive(Debug)]
        pub enum $Name {
            $($Variant),*,
        }
        impl $Name {
            pub const ALL: &'static [$Name] = &[$($Name::$Variant),*];
        }
    }
}

define_enum!(NativeFunctions {
    Add,
    Subtract,
    Multiply,
    Divide,
    CmpGeq,
    CmpLeq,
    CmpLess,
    CmpGreater,
    Modulo,
    Power,
    BitwiseXOR,
    And,
    Or,
    Not,
    Equals,
    If,
    Let,
    FetchVar,
    SetVar,
    Map,
    Fold,
    ListCons,
    FetchEntry,
    FetchContractEntry,
    SetEntry,
    InsertEntry,
    DeleteEntry,
    TupleCons,
    TupleGet,
    Begin,
    Hash160,
    Sha256,
    Keccak256,
    Print,
    ContractCall,
    AsContract,
    GetBlockInfo,
    ConsOkay,
    ConsError,
    ConsSome,
    DefaultTo,
    Expects,
    ExpectsErr,
    IsOkay,
    IsNone,
    Filter,
    MintAsset,
    MintToken,
    TransferAsset,
    TransferToken,
    GetTokenBalance,
    GetAssetOwner,
});

impl NativeFunctions {
    pub fn lookup_by_name(name: &str) -> Option<NativeFunctions> {
        use vm::functions::NativeFunctions::*;
        match name {
            "+" => Some(Add),
            "-" => Some(Subtract),
            "*" => Some(Multiply),
            "/" => Some(Divide),
            ">=" => Some(CmpGeq),
            "<=" => Some(CmpLeq),
            "<" => Some(CmpLess),
            ">" => Some(CmpGreater),
            "mod" => Some(Modulo),
            "pow" => Some(Power),
            "xor" => Some(BitwiseXOR),
            "and" => Some(And),
            "or" => Some(Or),
            "not" => Some(Not),
            "eq?" => Some(Equals),
            "if" => Some(If),
            "let" => Some(Let),
            "fetch-var" => Some(FetchVar),
            "set-var!" => Some(SetVar),
            "map" => Some(Map),
            "fold" => Some(Fold),
            "list" => Some(ListCons),
            "fetch-entry" => Some(FetchEntry),
            "fetch-contract-entry" => Some(FetchContractEntry),
            "set-entry!" => Some(SetEntry),
            "insert-entry!" => Some(InsertEntry),
            "delete-entry!" => Some(DeleteEntry),
            "tuple" => Some(TupleCons),
            "get" => Some(TupleGet),
            "begin" => Some(Begin),
            "hash160" => Some(Hash160),
            "sha256" => Some(Sha256),
            "keccak256" => Some(Keccak256),
            "print" => Some(Print),
            "contract-call!" => Some(ContractCall),
            "as-contract" => Some(AsContract),
            "get-block-info" => Some(GetBlockInfo),
            "err" => Some(ConsError),
            "ok" => Some(ConsOkay),
            "some" => Some(ConsSome),
            "default-to" => Some(DefaultTo),
            "expects!" => Some(Expects),
            "expects-err!" => Some(ExpectsErr),
            "is-ok?" => Some(IsOkay),
            "is-none?" => Some(IsNone),
            "filter" => Some(Filter),
            "get-token-balance" => Some(GetTokenBalance),
            "get-asset-owner" => Some(GetAssetOwner),
            "transfer-token!" => Some(TransferToken),
            "transfer-asset!" => Some(TransferAsset),
            "mint-asset!" => Some(MintAsset),
            "mint-token!" => Some(MintToken),
            _ => None
        }
    }
}

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
            Modulo => CallableType::NativeFunction("native_mod", &arithmetic::native_mod),
            Power => CallableType::NativeFunction("native_pow", &arithmetic::native_pow),
            BitwiseXOR => CallableType::NativeFunction("native_xor", &arithmetic::native_xor),
            And => CallableType::SpecialFunction("native_and", &boolean::special_and),
            Or => CallableType::SpecialFunction("native_or", &boolean::special_or),
            Not => CallableType::NativeFunction("native_not", &boolean::native_not),
            Equals => CallableType::NativeFunction("native_eq", &native_eq),
            If => CallableType::SpecialFunction("native_if", &special_if),
            Let => CallableType::SpecialFunction("native_let", &special_let),
            FetchVar => CallableType::SpecialFunction("native_fetch-var", &database::special_fetch_variable),
            SetVar => CallableType::SpecialFunction("native_set-var", &database::special_set_variable),
            Map => CallableType::SpecialFunction("native_map", &lists::list_map),
            Filter => CallableType::SpecialFunction("native_filter", &lists::list_filter),
            Fold => CallableType::SpecialFunction("native_fold", &lists::list_fold),
            ListCons => CallableType::NativeFunction("native_cons", &lists::list_cons),
            FetchEntry => CallableType::SpecialFunction("native_fetch-entry", &database::special_fetch_entry),
            FetchContractEntry => CallableType::SpecialFunction("native_fetch-contract-entry", &database::special_fetch_contract_entry),
            SetEntry => CallableType::SpecialFunction("native_set-entry", &database::special_set_entry),
            InsertEntry => CallableType::SpecialFunction("native_insert-entry", &database::special_insert_entry),
            DeleteEntry => CallableType::SpecialFunction("native_delete-entry", &database::special_delete_entry),
            TupleCons => CallableType::SpecialFunction("native_tuple", &tuples::tuple_cons),
            TupleGet => CallableType::SpecialFunction("native_get-tuple", &tuples::tuple_get),
            Begin => CallableType::NativeFunction("native_begin", &native_begin),
            Hash160 => CallableType::NativeFunction("native_hash160", &native_hash160),
            Sha256 => CallableType::NativeFunction("native_sha256", &native_sha256),
            Keccak256 => CallableType::NativeFunction("native_keccak256", &native_keccak256),
            Print => CallableType::NativeFunction("native_print", &native_print),
            ContractCall => CallableType::SpecialFunction("native_contract-call", &database::special_contract_call),
            AsContract => CallableType::SpecialFunction("native_as-contract", &special_as_contract),
            GetBlockInfo => CallableType::SpecialFunction("native_get_block_info", &database::special_get_block_info),
            ConsSome => CallableType::NativeFunction("native_some", &options::native_some),
            ConsOkay => CallableType::NativeFunction("native_okay", &options::native_okay),
            ConsError => CallableType::NativeFunction("native_error", &options::native_error),
            DefaultTo => CallableType::NativeFunction("native_default_to", &options::native_default_to),
            Expects => CallableType::NativeFunction("native_expects", &options::native_expects),
            ExpectsErr => CallableType::NativeFunction("native_expects_err", &options::native_expects_err),
            IsOkay => CallableType::NativeFunction("native_is_okay", &options::native_is_okay),
            IsNone => CallableType::NativeFunction("native_is_none", &options::native_is_none),
            MintAsset => CallableType::SpecialFunction("special_mint_asset", &assets::special_mint_asset),
            MintToken => CallableType::SpecialFunction("special_mint_token", &assets::special_mint_token),
            TransferAsset => CallableType::SpecialFunction("special_transfer_asset", &assets::special_transfer_asset),
            TransferToken => CallableType::SpecialFunction("special_transfer_token", &assets::special_transfer_token),
            GetTokenBalance => CallableType::SpecialFunction("special_get_balance", &assets::special_get_balance),
            GetAssetOwner => CallableType::SpecialFunction("special_get_owner", &assets::special_get_owner),
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
            arg_type = TypeSignature::most_admissive(TypeSignature::type_of(x), arg_type)
                .map_err(|(a,b)| UncheckedError::TypeError(format!("{}", b), x.clone()))?;
            if x != first {
                return Ok(Value::Bool(false))
            }
        }
        Ok(Value::Bool(true))
    }
}

fn native_hash160(args: &[Value]) -> Result<Value> {
    use util::hash::Hash160;
    check_argument_count(1, args)?;

    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(UncheckedError::TypeError("Int|Buffer".to_string(), input.clone()))
    }?;
    let hash160 = Hash160::from_data(&bytes);
    Value::buff_from(hash160.as_bytes().to_vec())
}

fn native_sha256(args: &[Value]) -> Result<Value> {
    use util::hash::Sha256Sum;
    check_argument_count(1, args)?;

    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(UncheckedError::TypeError("Int|Buffer".to_string(), input.clone()))
    }?;
    let sha256 = Sha256Sum::from_data(&bytes);
    Value::buff_from(sha256.as_bytes().to_vec())
}

fn native_keccak256(args: &[Value]) -> Result<Value> {
    use util::hash::Keccak256Hash;
    check_argument_count(1, args)?;

    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(UncheckedError::TypeError("Int|Buffer".to_string(), input.clone()))
    }?;
    let keccak256 = Keccak256Hash::from_data(&bytes);
    Value::buff_from(keccak256.as_bytes().to_vec())
}

fn native_begin(args: &[Value]) -> Result<Value> {
    match args.last() {
        Some(v) => Ok(v.clone()),
        None => Err(UncheckedError::IncorrectArgumentCount(1,0).into())
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
        _ => Err(UncheckedError::TypeError("BoolType".to_string(), conditional).into())
    }
}

fn parse_eval_bindings(bindings: &[SymbolicExpression],
                       env: &mut Environment, context: &LocalContext)-> Result<Vec<(String, Value)>> {
    let mut result = Vec::new();
    for binding in bindings.iter() {
        let binding_expression = binding.match_list()
            .ok_or(UncheckedError::BindingExpectsPair)?;
        if binding_expression.len() != 2 {
            return Err(UncheckedError::BindingExpectsPair.into());
        }
        let var_name = binding_expression[0].match_atom()
            .ok_or(UncheckedError::ExpectedVariableName)?;
        let value = eval(&binding_expression[1], env, context)?;
        result.push((var_name.clone(), value));
    }

    Ok(result)
}

fn special_let(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (let ((x 1) (y 2)) (+ x y)) -> 3
    // arg0 => binding list
    // arg1..n => body
    if args.len() < 2 {
        return Err(UncheckedError::IncorrectArgumentCount(2, 1).into())
    }
    // create a new context.
    let mut inner_context = context.extend()?;

    let bindings = args[0].match_list()
        .ok_or(UncheckedError::ExpectedListPairs)?;

    // parse and eval the bindings.
    let mut binding_results = parse_eval_bindings(bindings, env, context)?;
    for (binding_name, binding_value) in binding_results.drain(..) {
        if is_reserved(&binding_name) {
            return Err(UncheckedError::ReservedName(binding_name).into())
        }
        if env.contract_context.lookup_function(&binding_name).is_some() {
            return Err(UncheckedError::VariableDefinedMultipleTimes(binding_name).into())
        }
        if inner_context.lookup_variable(&binding_name).is_some() {
            return Err(UncheckedError::VariableDefinedMultipleTimes(binding_name).into())
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
    let contract_principal = Value::Principal(PrincipalData::ContractPrincipal(env.contract_context.name.clone()));
    let mut nested_env = env.nest_as_principal(contract_principal);

    eval(&args[0], &mut nested_env, context)
}
