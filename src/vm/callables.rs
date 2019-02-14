use vm::errors::{InterpreterResult as Result, Error};
use vm::representations::SymbolicExpression;
use vm::types::TypeSignature;
use vm::{eval, Value, Context, Environment};

pub enum CallableType <'a> {
    UserFunction(DefinedFunction),
    NativeFunction(&'a Fn(&[Value]) -> Result<Value>),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &mut Environment, &Context) -> Result<Value>)
}

#[derive(Clone)]
pub struct DefinedFunction {
    is_public: bool,
    types: Option<Vec<TypeSignature>>,
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}

#[derive(Clone,PartialEq,Eq,Hash)]
pub struct FunctionIdentifier {
    pub arguments: Vec<String>,
    pub body: SymbolicExpression
}


impl DefinedFunction {
    pub fn apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        let mut context = Context::new();

        if !self.is_public {
            let arg_iterator = self.arguments.iter().zip(args.iter());
            for (arg, value) in arg_iterator {
                if let Some(_) = context.variables.insert(arg.clone(), value.clone()) {
                    return Err(Error::MultiplyDefined(arg.clone()))
                }
            }
        } else {
            let types = self.types.as_ref().unwrap(); // if types is None, and is_public = true, we should panic.
                                                      //   since self is a malformed object.
            let arg_iterator = self.arguments.iter().zip(types.iter()).zip(args.iter());
            for ((arg, type_sig), value) in arg_iterator {
                if !type_sig.admits(value) {
                    return Err(Error::TypeError(format!("{:?}", type_sig), value.clone())) 
                }
                if let Some(_) = context.variables.insert(arg.clone(), value.clone()) {
                    return Err(Error::MultiplyDefined(arg.clone()))
                }
            }
        }

        eval(&self.body, env, &context)
    }

    pub fn new_private(arguments: Vec<String>, body: SymbolicExpression) -> DefinedFunction {
        DefinedFunction {
            arguments: arguments,
            body: body,
            is_public: false,
            types: None
        }
    }

    pub fn new_public(mut arguments: Vec<(String, TypeSignature)>, body: SymbolicExpression) -> DefinedFunction {
        let (argument_names, types) = arguments.drain(..).unzip();

        DefinedFunction {
            arguments: argument_names,
            body: body,
            is_public: true,
            types: Some(types)
        }
    }

    pub fn is_public(&self) -> bool {
        self.is_public
    }

    pub fn get_identifier(&self) -> FunctionIdentifier {
        return FunctionIdentifier {
            body: self.body.clone(),
            arguments: self.arguments.clone() }
    }
}
