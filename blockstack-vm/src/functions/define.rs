use super::super::types::{ValueType, DefinedFunction};
use super::super::representations::SymbolicExpression;
use super::super::representations::SymbolicExpression::{Atom,AtomValue,List};
use super::super::{Context,CallStack,eval};

pub enum DefineResult {
    Variable(String, ValueType),
    Function(String, DefinedFunction)
}

pub fn handle_define_variable(variable: &String, expression: &SymbolicExpression, context: &Context) -> DefineResult {
    let mut call_stack = CallStack::new();
    let value = eval(expression, context, &mut call_stack, context);
    DefineResult::Variable(variable.clone(), value)
}

pub fn handle_define_function(signature: &[SymbolicExpression], expression: &SymbolicExpression, _context: &Context) -> DefineResult {
    let coerced_atoms: Result<Vec<_>, _> = signature.iter().map(|x| {
        if let Atom(name) = x {
            Ok(name)
        } else {
            Err("Non-atomic argument to method signature in define".to_string())
        }
    }).collect();

    if let Ok(names) = coerced_atoms {
        if let Some((function_name, arg_names)) = names.split_first() {
            let function = DefinedFunction {
                arguments: arg_names.iter().map(|x| (*x).clone()).collect(),
                body: expression.clone()
            };
            DefineResult::Function((*function_name).clone(), function)
        } else {
            panic!("Must supply atleast a name argument to define a function")
        }
    } else {
        panic!("Non-atomic argument to method signature in define")
    }
}

pub fn evaluate_define(expression: &SymbolicExpression, context: &Context) -> Option<DefineResult> {
    if let SymbolicExpression::List(elements) = expression {
        if elements.len() != 3 || elements[0] != Atom("define".to_string()) {
            None
        } else {
            match elements[1] {
                Atom(ref variable) => Some(handle_define_variable(variable, &elements[2], context)),
                AtomValue(ref _value) => panic!("Attempted to define a value type!"),
                List(ref function_signature) => Some(handle_define_function(&function_signature, &elements[2], context))
            }
        }
    } else {
        None
    }
} 
