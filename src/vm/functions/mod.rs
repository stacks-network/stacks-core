pub mod define;
pub mod tuples;
mod lists;
mod arithmetic;
mod boolean;
mod database;
mod options;

use vm::errors::{UncheckedError, RuntimeErrorType, InterpreterResult as Result};
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
    Filter
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
                .map_err(|(a,b)| UncheckedError::TypeError(format!("{}", a), x.clone()))?;
            if x != first {
                return Ok(Value::Bool(false))
            }
        }
        Ok(Value::Bool(true))
    }
}

fn native_hash160(args: &[Value]) -> Result<Value> {
    use util::hash::Hash160;

    if !(args.len() == 1) {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to hash160 (expects 1)".to_string()).into())
    }
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

    if !(args.len() == 1) {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to sha256 (expects 1)".to_string()).into())
    }
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

    if !(args.len() == 1) {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to keccak256 (expects 1)".to_string()).into())
    }
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
        None => Err(UncheckedError::InvalidArguments("Must pass at least 1 expression to (begin ...)".to_string()).into())
    }
}

fn native_print(args: &[Value]) -> Result<Value> {
    if !(args.len() == 1) {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to print (expects 1)".to_string()).into())
    }
    if cfg!(feature = "developer-mode") {
        eprintln!("{:?}", args[0]);
    }
    Ok(args[0].clone())
}

fn special_if(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    if args.len() != 3 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to if (expects 3)".to_string()).into())
    }
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
        if let List(ref binding_exps) = binding.expr {
            if binding_exps.len() != 2 {
                return Err(UncheckedError::InvalidArguments("Passed non 2-length list as a binding. Bindings should be of the form (name value).".to_string()).into())
            }
            if let Atom(ref var_name) = binding_exps[0].expr {
                let value = eval(&binding_exps[1], env, context)?;
                result.push((var_name.clone(), value));
            } else {
                return Err(UncheckedError::InvalidArguments("Passed bad variable name as a binding. Bindings should be of the form (name value).".to_string()).into())
            }
        } else {
            return Err(UncheckedError::InvalidArguments("Passed non 2-length list as a binding. Bindings should be of the form (name value).".to_string()).into())
        }
    }

    Ok(result)
}

fn special_let(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (let ((x 1) (y 2)) (+ x y)) -> 3
    // arg0 => binding list
    // arg1 => body
    if args.len() != 2 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to let (expect 2)".to_string()).into())
    }
    // create a new context.
    let mut inner_context = context.extend()?;

    if let List(ref bindings) = args[0].expr {
        // parse and eval the bindings.
        let mut binding_results = parse_eval_bindings(bindings, env, context)?;
        for (binding_name, binding_value) in binding_results.drain(..) {
            if is_reserved(&binding_name) {
                return Err(UncheckedError::ReservedName(binding_name).into())
            }
            if inner_context.variables.contains_key(&binding_name) {
                return Err(UncheckedError::VariableDefinedMultipleTimes(binding_name).into())
            }
            inner_context.variables.insert(binding_name, binding_value);
        }

        // evaluate the let-body
        eval(&args[1], env, &inner_context)
    } else {
        Err(UncheckedError::InvalidArguments("Passed non-list as second argument to let expression.".to_string()).into())
    }
}

fn special_as_contract(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (as-contract (..))
    // arg0 => body
    if args.len() != 1 {
        return Err(UncheckedError::InvalidArguments("Wrong number of arguments to as-contract (expects 1)".to_string()).into())
    }

    // nest an environment.
    let contract_principal = Value::Principal(PrincipalData::ContractPrincipal(env.contract_context.name.clone()));
    let mut nested_env = env.nest_with_sender(contract_principal);

    eval(&args[0], &mut nested_env, context)
}
