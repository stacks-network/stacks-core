use std::fmt;
use std::collections::{HashMap, VecDeque};
use std::iter::FromIterator;

use vm::errors::{InterpreterResult as Result, Error};
use vm::analysis::errors::CheckErrors;
use vm::representations::{SymbolicExpression, ClarityName};
use vm::types::{TypeSignature, QualifiedContractIdentifier, PrincipalData};
use vm::{eval, Value, LocalContext, Environment};

pub enum CallableType {
    UserFunction(DefinedFunction),
    NativeFunction(&'static str, &'static dyn Fn(&[Value]) -> Result<Value>),
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
    referenced_traits: HashMap<QualifiedContractIdentifier, ClarityName>,
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
    pub fn new(mut arguments: Vec<(ClarityName, TypeSignature)>, 
               body: SymbolicExpression,
               define_type: DefineType, 
               name: &ClarityName, 
               referenced_traits: HashMap<QualifiedContractIdentifier, ClarityName>,
               context_name: &str) -> DefinedFunction {
        let (argument_names, types) = arguments.drain(..).unzip();

        DefinedFunction {
            identifier: FunctionIdentifier::new_user_function(name, context_name),
            arguments: argument_names,
            define_type,
            body,
            referenced_traits,
            arg_types: types
        }
    }

    pub fn execute_apply(&self, args: &[Value], env: &mut Environment) -> Result<Value> {
        let mut context = LocalContext::new();
        if args.len() != self.arguments.len() {
            Err(CheckErrors::IncorrectArgumentCount(self.arguments.len(), args.len()))?
        }

        let mut arg_iterator: Vec<_> = self.arguments.iter().zip(self.arg_types.iter()).zip(args.iter()).collect();
        let mut flatten_args = VecDeque::new();

        for arg in arg_iterator.drain(..) {
            let ((name, type_sig), value) = arg;
            if !type_sig.admits(value) {
                return Err(CheckErrors::TypeValueError(type_sig.clone(), value.clone()).into())
            }
            if let Some(_) = context.variables.insert(name.clone(), value.clone()) {
                return Err(CheckErrors::NameAlreadyUsed(name.to_string()).into())
            }
            flatten_args.push_back(arg);
        }

        // Recursively traverse the (potential) tree of function arguments
        // in order to catch all the references to traits.
        while let Some(((name, type_sig), value)) = flatten_args.pop_front() {
            match (type_sig, value) {
                (CallablePrincipalType, Value::Principal(PrincipalData::Contract(contract_id))) => {
                    context.callable_contracts.insert(name.clone(), contract_id.clone());
                },
                (TypeSignature::TupleType(tuple_type), Value::Tuple(tuple_data)) => {
                    // todo(ludo): traverse tuple, enqueue components 
                    // flatten_args.push_back((( , ), ))
                    // pub struct TupleData {
                    //     pub type_signature: TupleTypeSignature,
                    //     pub data_map: BTreeMap<ClarityName, Value>
                    // }
                    // tuple_data.
                }
                _ => {}
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
