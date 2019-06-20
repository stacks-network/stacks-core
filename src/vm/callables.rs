use std::fmt;

use vm::errors::{InterpreterResult as Result, Error, UncheckedError};
use vm::representations::SymbolicExpression;
use vm::types::TypeSignature;
use vm::{eval, Value, LocalContext, Environment};

pub enum CallableType {
    UserFunction(DefinedFunction),
    NativeFunction(&'static str, &'static Fn(&[Value]) -> Result<Value>),
    SpecialFunction(&'static str, &'static Fn(&[SymbolicExpression], &mut Environment, &LocalContext) -> Result<Value>)
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
    arguments: Vec<String>,
    body: SymbolicExpression
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
    pub fn new(mut arguments: Vec<(String, TypeSignature)>, body: SymbolicExpression,
               define_type: DefineType, name: &str, context_name: &str) -> DefinedFunction {
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
        let arg_iterator = self.arguments.iter().zip(self.arg_types.iter()).zip(args.iter());
        for ((arg, type_sig), value) in arg_iterator {
            if !type_sig.admits(value) {
                return Err(UncheckedError::TypeError(format!("{}", type_sig), value.clone()).into()) 
            }
            if let Some(_) = context.variables.insert(arg.clone(), value.clone()) {
                return Err(UncheckedError::VariableDefinedMultipleTimes(arg.clone()).into())
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
            CallableType::NativeFunction(s, _) => FunctionIdentifier::new_native_function(s),
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
