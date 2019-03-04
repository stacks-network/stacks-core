use std::fmt;

use vm::errors::{InterpreterResult as Result, Error, ErrType};
use vm::representations::SymbolicExpression;
use vm::types::TypeSignature;
use vm::{eval, Value, LocalContext, Environment};

pub enum CallableType <'a> {
    UserFunction(DefinedFunction),
    NativeFunction(&'a Fn(&[Value]) -> Result<Value>),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &mut Environment, &LocalContext) -> Result<Value>)
}

#[derive(Clone,Serialize, Deserialize)]
pub enum DefinedFunction {
    Public(PublicFunction),
    Private(PrivateFunction)
}

#[derive(Clone,Serialize, Deserialize)]
pub struct PublicFunction {
    name: String,
    context: String,
    types: Vec<TypeSignature>,
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}

#[derive(Clone,Serialize, Deserialize)]
pub struct PrivateFunction {
    name: String,
    context: String,
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct FunctionIdentifier {
    identifier: String
}

impl fmt::Display for FunctionIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UserFunction({})", self.identifier)
    }    
}

impl PublicFunction {
    pub fn new(mut arguments: Vec<(String, TypeSignature)>, body: SymbolicExpression,
               name: String, context_name: String) -> DefinedFunction {
        let (argument_names, types) = arguments.drain(..).unzip();

        DefinedFunction::Public(PublicFunction {
            name: name,
            context: context_name,
            arguments: argument_names,
            body: body,
            types: types
        })
    }

    fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        //   since self is a malformed object.
        let mut context = LocalContext::new();
        let arg_iterator = self.arguments.iter().zip(self.types.iter()).zip(args.iter());
        for ((arg, type_sig), value) in arg_iterator {
            if !type_sig.admits(value) {
                return Err(Error::new(ErrType::TypeError(format!("{:?}", type_sig), value.clone()))) 
            }
            if let Some(_) = context.variables.insert(arg.clone(), value.clone()) {
                return Err(Error::new(ErrType::VariableDefinedMultipleTimes(arg.clone())))
            }
        }
        eval(&self.body, env, &context)
    }
}

impl PrivateFunction {
    pub fn new(arguments: Vec<String>, body: SymbolicExpression,
               name: String, context_name: String) -> DefinedFunction {
        DefinedFunction::Private(PrivateFunction {
            name: name,
            context: context_name,
            arguments: arguments,
            body: body,
        })
    }

    fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        let mut context = LocalContext::new();
        let arg_iterator = self.arguments.iter().zip(args.iter());
        for (arg, value) in arg_iterator {
            if let Some(_) = context.variables.insert(arg.clone(), value.clone()) {
                return Err(Error::new(ErrType::VariableDefinedMultipleTimes(arg.clone())))
            }
        }
        eval(&self.body, env, &context)
    }
}

impl DefinedFunction {
    pub fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        match self {
            DefinedFunction::Private(f) => f.apply(args, env),
            DefinedFunction::Public(f) => f.apply(args, env),
        }
    }

    pub fn is_public(&self) -> bool {
        match self {
            DefinedFunction::Public(_) => true,
            DefinedFunction::Private(_) => false
        }
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        let (name, context) = match self {
            DefinedFunction::Private(f) => (&f.name, &f.context),
            DefinedFunction::Public(f) => (&f.name, &f.context)
        };
        let identifier = format!("{}:{}", context, name);

        return FunctionIdentifier {
            identifier: identifier }
    }
}
