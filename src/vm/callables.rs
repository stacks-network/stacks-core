use std::fmt;
use std::convert::TryInto;

use vm::costs::{cost_functions, SimpleCostSpecification};

use vm::errors::{InterpreterResult as Result, Error, check_argument_count};
use vm::analysis::errors::CheckErrors;
use vm::representations::{SymbolicExpression, ClarityName};
use vm::types::TypeSignature;
use vm::{eval, Value, LocalContext, Environment};

pub enum CallableType {
    UserFunction(DefinedFunction),
    NativeFunction(&'static str, NativeHandle, SimpleCostSpecification),
    SpecialFunction(&'static str, &'static dyn Fn(&[SymbolicExpression], &mut Environment, &LocalContext) -> Result<Value>)
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum DefineType {
    ReadOnly,
    Public,
    Private
}

#[derive(Clone,Serialize, Deserialize)]
pub struct DefinedFunction {
    identifier: FunctionIdentifier,
    arg_types: Vec<TypeSignature>,
    define_type: DefineType,
    arguments: Vec<ClarityName>,
    body: SymbolicExpression
}

pub enum NativeHandle {
    SingleArg(&'static dyn Fn(Value) -> Result<Value>),
    DoubleArg(&'static dyn Fn(Value, Value) -> Result<Value>),
    MoreArg(&'static dyn Fn(Vec<Value>) -> Result<Value>)
}

impl NativeHandle {
    pub fn apply(&self, mut args: Vec<Value>) -> Result<Value> {
        match self {
            NativeHandle::SingleArg(function) => {
                check_argument_count(1, &args)?;
                function(args.pop().unwrap())
            },
            NativeHandle::DoubleArg(function) => {
                check_argument_count(2, &args)?;
                let second = args.pop().unwrap();
                let first = args.pop().unwrap();
                function(first, second)
            },
            NativeHandle::MoreArg(function) => {
                function(args)
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct FunctionIdentifier {
    identifier: String
}

impl fmt::Display for FunctionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl DefinedFunction {
    pub fn new(mut arguments: Vec<(ClarityName, TypeSignature)>, body: SymbolicExpression,
               define_type: DefineType, name: &ClarityName, context_name: &str) -> DefinedFunction {
        let (argument_names, types) = arguments.drain(..).unzip();

        DefinedFunction {
            identifier: FunctionIdentifier::new_user_function(name, context_name),
            arguments: argument_names,
            define_type: define_type,
            body: body,
            arg_types: types
        }
    }

    pub fn execute_apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        let mut context = LocalContext::new();
        if args.len() != self.arguments.len() {
            Err(CheckErrors::IncorrectArgumentCount(self.arguments.len(), args.len()))?
        }

        let arg_iterator = self.arguments.iter().zip(self.arg_types.iter()).zip(args.iter());
        for ((arg, type_sig), value) in arg_iterator {
            if !type_sig.admits(value) {
                return Err(CheckErrors::TypeValueError(type_sig.clone(), value.clone()).into())
            }
            if let Some(_) = context.variables.insert(arg.clone(), value.clone()) {
                return Err(CheckErrors::NameAlreadyUsed(arg.to_string()).into())
            }
        }
        let result = eval(&self.body, env, &context);

        // if the error wasn't actually an error, but a function return,
        //    pull that out and return it.
        match result {
            Ok(r) => Ok(r),
            Err(e) => {
                match e {
                    Error::ShortReturn(v) => Ok(v.into()),
                    _ => Err(e)
                }
            }
        }
    }

    pub fn is_read_only(&self) -> bool {
        self.define_type == DefineType::ReadOnly
    }

    pub fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        runtime_cost!(cost_functions::USER_FUNCTION_APPLICATION,
                      env, self.arguments.len())?;
        for arg_type in self.arg_types.iter() {
            runtime_cost!(cost_functions::TYPE_CHECK_COST,
                          env, arg_type)?;
        }

        match self.define_type {
            DefineType::Private => self.execute_apply(args, env),
            DefineType::Public => env.execute_function_as_transaction(self, args, None),
            DefineType::ReadOnly => env.execute_function_as_transaction(self, args, None)
        }
    }

    pub fn is_public(&self) -> bool {
        match self.define_type {
            DefineType::Public => true,
            DefineType::Private => false,
            DefineType::ReadOnly => true
        }
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        self.identifier.clone()
    }
}

impl CallableType {
    pub fn get_identifier(&self) -> FunctionIdentifier {
        match self {
            CallableType::UserFunction(f) => f.get_identifier(),
            CallableType::NativeFunction(s, _, _) => FunctionIdentifier::new_native_function(s),
            CallableType::SpecialFunction(s, _) => FunctionIdentifier::new_native_function(s),
        }
    }
}

impl FunctionIdentifier {
    fn new_native_function(name: &str) -> FunctionIdentifier {
        let identifier = format!("_native_:{}", name);
        FunctionIdentifier { identifier: identifier }
    }

    fn new_user_function(name: &str, context: &str) -> FunctionIdentifier {
        let identifier = format!("{}:{}", context, name);
        FunctionIdentifier { identifier: identifier }
    }
}
