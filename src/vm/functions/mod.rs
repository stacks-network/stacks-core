pub mod define;
mod lists;
mod arithmetic;
mod boolean;
mod database;
mod tuples;

use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::types::{Value, PrincipalData};
use vm::callables::CallableType;
use vm::representations::SymbolicExpression;
use vm::representations::SymbolicExpressionType::{List, Atom};
use vm::{LocalContext, Environment, eval};

pub enum NativeFunctions {
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
    IsNull,
    If,
    Let,
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
    AsContract
}

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
            "isnull?" => Some(IsNull),
            "if" => Some(If),
            "let" => Some(Let),
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
            IsNull => CallableType::NativeFunction("native_isnull", &native_isnull),
            If => CallableType::SpecialFunction("native_if", &special_if),
            Let => CallableType::SpecialFunction("native_let", &special_let),
            Map => CallableType::SpecialFunction("native_map", &lists::list_map),
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
        // Using `fold` rather than `all` to prevent short-circuiting. 
        let result = args.iter().fold(true, |acc, x| acc && (*x == *first));
        Ok(Value::Bool(result))
    }
}

fn native_isnull(args: &[Value]) -> Result<Value> {
    // TODO: see note in `native_eq` above ListTypes equality...
    if args.len() == 0 {
        // TODO: Should no input args be allowed, if so should it return true or false?
        Ok(Value::Bool(true))
    } else {
        // Using `fold` rather than `all` to prevent short-circuiting. 
        let result = args.iter().fold(true, |acc, x| acc && match *x {
            Value::Void => true,
            _ => false
        });
        Ok(Value::Bool(result))
    }
}

fn native_hash160(args: &[Value]) -> Result<Value> {
    use util::hash::Hash160;

    if !(args.len() == 1) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to hash160 (expects 1)".to_string())))
    }
    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(Error::new(ErrType::NotImplemented))
    }?;
    let hash160 = Hash160::from_data(&bytes);
    Value::buff_from(hash160.as_bytes().to_vec())
}

fn native_sha256(args: &[Value]) -> Result<Value> {
    use util::hash::Sha256Hash;

    if !(args.len() == 1) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to sha256 (expects 1)".to_string())))
    }
    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(Error::new(ErrType::NotImplemented))
    }?;
    let sha256 = Sha256Hash::from_data(&bytes);
    Value::buff_from(sha256.as_bytes().to_vec())
}

fn native_keccak256(args: &[Value]) -> Result<Value> {
    use util::hash::Keccak256Hash;

    if !(args.len() == 1) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to keccak256 (expects 1)".to_string())))
    }
    let input = &args[0];
    let bytes = match input {
        Value::Int(value) => Ok(value.to_le_bytes().to_vec()),
        Value::Buffer(value) => Ok(value.data.clone()),
        _ => Err(Error::new(ErrType::NotImplemented))
    }?;
    let keccak256 = Keccak256Hash::from_data(&bytes);
    Value::buff_from(keccak256.as_bytes().to_vec())
}

fn native_begin(args: &[Value]) -> Result<Value> {
    match args.last() {
        Some(v) => Ok(v.clone()),
        None => Ok(Value::Void)
    }
}

fn native_print(args: &[Value]) -> Result<Value> {
    if !(args.len() == 1) {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to print (expects 1)".to_string())))
    }
    if cfg!(feature = "developer-mode") {
        eprintln!("{:?}", args[0]);
    }
    Ok(args[0].clone())
}

fn special_if(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    if args.len() != 3 {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to if (expects 3)".to_string())))
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
        _ => Err(Error::new(ErrType::TypeError("BoolType".to_string(), conditional)))
    }
}

fn parse_eval_bindings(bindings: &[SymbolicExpression],
                       env: &mut Environment, context: &LocalContext)-> Result<Vec<(String, Value)>> {
    let mut result = Vec::new();
    for binding in bindings.iter() {
        if let List(ref binding_exps) = binding.expr {
            if binding_exps.len() != 2 {
                return Err(Error::new(ErrType::InvalidArguments("Passed non 2-length list as a binding. Bindings should be of the form (name value).".to_string())))
            }
            if let Atom(ref var_name) = binding_exps[0].expr {
                let value = eval(&binding_exps[1], env, context)?;
                result.push((var_name.clone(), value));
            } else {
                return Err(Error::new(ErrType::InvalidArguments("Passed bad variable name as a binding. Bindings should be of the form (name value).".to_string())))
            }
        } else {
            return Err(Error::new(ErrType::InvalidArguments("Passed non 2-length list as a binding. Bindings should be of the form (name value).".to_string())))
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
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to let (expect 2)".to_string())))
    }
    // create a new context.
    let mut inner_context = context.extend()?;

    if let List(ref bindings) = args[0].expr {
        // parse and eval the bindings.
        let mut binding_results = parse_eval_bindings(bindings, env, context)?;
        for (binding_name, binding_value) in binding_results.drain(..) {
            if is_reserved(&binding_name) {
                return Err(Error::new(ErrType::ReservedName(binding_name)))
            }
            if inner_context.variables.contains_key(&binding_name) {
                return Err(Error::new(ErrType::VariableDefinedMultipleTimes(binding_name)))
            }
            inner_context.variables.insert(binding_name, binding_value);
        }

        // evaluate the let-body
        eval(&args[1], env, &inner_context)
    } else {
        Err(Error::new(ErrType::InvalidArguments("Passed non-list as second argument to let expression.".to_string())))
    }
}

fn special_as_contract(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::is_reserved;

    // (as-contract (..))
    // arg0 => body
    if args.len() != 1 {
        return Err(Error::new(ErrType::InvalidArguments("Wrong number of arguments to as-contract (expects 1)".to_string())))
    }

    // nest an environment.
    let contract_principal = Value::Principal(PrincipalData::ContractPrincipal(env.contract_context.name.clone()));
    let mut nested_env = env.nest_with_sender(contract_principal);

    eval(&args[0], &mut nested_env, context)
}
