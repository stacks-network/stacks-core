use vm::errors::{InterpreterResult as Result, Error};
use vm::representations::SymbolicExpression;
use vm::{eval, Value, Context, Environment};

pub enum CallableType <'a> {
    UserFunction(DefinedFunction),
    NativeFunction(&'a Fn(&[Value]) -> Result<Value>),
    SpecialFunction(&'a Fn(&[SymbolicExpression], &mut Environment, &Context) -> Result<Value>)
}

#[derive(Clone)]
pub struct DefinedFunction {
    is_public: bool,
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

        let mut arg_iterator = self.arguments.iter().zip(args.iter());
        let _result = arg_iterator.try_for_each(|(arg, value)| {
            match context.variables.insert((*arg).clone(), (*value).clone()) {
                Some(_val) => Err(Error::InvalidArguments("Multiply defined function argument".to_string())),
                _ => Ok(())
            }
        })?;
        eval(&self.body, env, &context)
    }

    pub fn new(arguments: Vec<String>, body: SymbolicExpression, is_public: bool) -> DefinedFunction {
        DefinedFunction {
            arguments: arguments,
            body: body,
            is_public: is_public
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
