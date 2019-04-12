use std::collections::{HashMap, HashSet};

use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::types::Value;
use vm::callables::{DefinedFunction, FunctionIdentifier};
use vm::database::{ContractDatabase, ContractDatabaseTransacter};
use vm::{SymbolicExpression};
use vm::contracts::Contract;

pub const MAX_CONTEXT_DEPTH: u16 = 256;


// TODO:
//    hide the environment's instance variables.
//     we don't want many of these changing after instantiation.
pub struct Environment <'a,'b> {
    pub global_context: &'a mut GlobalContext <'b>,
    pub contract_context: &'a ContractContext,
    pub call_stack: &'a mut CallStack,
    pub sender: Option<Value>
}

pub struct GlobalContext <'a> {
    pub database: ContractDatabase<'a>
}

#[derive(Serialize, Deserialize)]
pub struct ContractContext {
    pub name: String,
    pub variables: HashMap<String, Value>,
    pub functions: HashMap<String, DefinedFunction>,
}

pub struct LocalContext <'a> {
    pub parent: Option< &'a LocalContext<'a>>,
    pub variables: HashMap<String, Value>,
    depth: u16
}

pub struct CallStack {
    stack: Vec<FunctionIdentifier>,
    set: HashSet<FunctionIdentifier>
}

pub type StackTrace = Vec<FunctionIdentifier>;

impl <'a, 'b> Environment <'a, 'b> {
    // Environments pack a reference to the global context, a mutable reference to a contract db,
    //   together with a call stack. Generally, the environment structure is intended to be reconstructed
    //   for every transaction.
    pub fn new(global_context: &'a mut GlobalContext<'b>,
               contract_context: &'a ContractContext,
               call_stack: &'a mut CallStack) -> Environment<'a,'b> {
        Environment {
            global_context: global_context,
            contract_context: contract_context,
            call_stack: call_stack,
            sender: None
        }
    }


    pub fn execute_function_as_transaction(&mut self, function: &DefinedFunction, args: &[Value]) -> Result<Value> {
        let function = match function {
            DefinedFunction::Private(_) => Err(Error::new(ErrType::NonPublicFunction(format!("{}", function.get_identifier())))),
            DefinedFunction::Public(f) => Ok(f)
        }?;

        let mut nested_context = GlobalContext::begin_from(&mut self.global_context.database);

        let result = {
            // this is kind of weird. we jump through a lot of hoops here to satisfy the borrow checker.
            //     this could probably be dramatically simplified by moving the "global context" _out_ of the env
            //     struct, which would be a pretty big refactor, but should probably be done.
            let mut nested_env = Environment::new(&mut nested_context, self.contract_context, self.call_stack);
            nested_env.sender = self.sender.clone();

            function.apply(args, &mut nested_env)
        };

        match result {
            Ok(x) => {
                if let Value::Bool(bool_result) = x {
                    if bool_result {
                        nested_context.commit();
                    } else {
                        nested_context.database.roll_back();
                    }
                    Ok(x)
                } else {
                    Err(Error::new(ErrType::ContractMustReturnBoolean))
                }
            },
            Err(_) => {
                nested_context.database.roll_back();
                result
            }
        }
    }

}

impl <'a> GlobalContext <'a> {
    pub fn new(database: ContractDatabase<'a>) -> GlobalContext<'a> {
        GlobalContext {
            database: database
        }
    }

    pub fn begin_from(database: &'a mut ContractDatabaseTransacter) -> GlobalContext<'a> {
        let db = database.begin_save_point();
        GlobalContext::new(db)
    }

    pub fn commit(self) {
        self.database.commit()
    }

    pub fn execute_contract(&mut self, contract_name: &str, 
                            sender: &Value, tx_name: &str,
                            args: &[SymbolicExpression]) -> Result<Value> {
        let mut contract = self.database.get_contract(contract_name)?;
        let contract_result = {
            let mut nested_context = GlobalContext::begin_from(&mut self.database);
            let contract_result = contract.execute_transaction(sender, tx_name, args, 
                                                               &mut nested_context);
            match contract_result {
                Ok(x) => {
                    if let Value::Bool(bool_result) = x {
                        if bool_result {
                            nested_context.commit();
                        } else {
                            nested_context.database.roll_back();
                        }
                        Ok(x)
                    } else {
                        Err(Error::new(ErrType::ContractMustReturnBoolean))
                    }
                },
                Err(_) => {
                    nested_context.database.roll_back();
                    contract_result
                }
            }
        };

        contract_result
    }

    pub fn read_only_eval(&mut self, contract_name: &str, program: &str) -> Result<Value> {
        let mut contract = self.database.get_contract(contract_name)?;
        let mut nested_context = GlobalContext::begin_from(&mut self.database);
        let result = contract.eval(program, &mut nested_context);
        nested_context.database.roll_back();
        result
    }

    pub fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()> {
        let contract = {
            let mut nested_context = GlobalContext::begin_from(&mut self.database);
            let result = Contract::initialize(contract_name, contract_content,
                                              &mut nested_context);
            match result {
                Ok(_) => {
                    nested_context.commit();
                },
                Err(_) => {
                    // not strictly necessary, since the database will roll back when it's reference
                    // is destroyed.
                    nested_context.database.roll_back();
                }
            };

            result
        }?;
        self.database.insert_contract(contract_name, contract)
    }
}

impl ContractContext {
    pub fn new(name: String) -> ContractContext {
        ContractContext {
            name: name,
            variables: HashMap::new(),
            functions: HashMap::new()
        }
    }

    pub fn lookup_variable(&self, name: &str) -> Option<Value> {
        match self.variables.get(name) {
            Some(value) => Option::Some(value.clone()),
            None => Option::None
        }
    }

    pub fn lookup_function(&self, name: &str) -> Option<DefinedFunction> {
        match self.functions.get(name) {
            Some(value) => Option::Some(value.clone()),
            None => Option::None
        }
    }
}

impl <'a> LocalContext <'a> {
    pub fn new() -> LocalContext<'a> {
        LocalContext {
            depth: 0,
            parent: Option::None,
            variables: HashMap::new(),
        }
    }
    
    pub fn extend(&'a self) -> Result<LocalContext<'a>> {
        if self.depth >= MAX_CONTEXT_DEPTH {
            Err(Error::new(ErrType::MaxContextDepthReached))
        } else {
            Ok(LocalContext {
                parent: Some(self),
                variables: HashMap::new(),
                depth: self.depth + 1
            })
        }
    }

    pub fn lookup_variable(&self, name: &str) -> Option<Value> {
        match self.variables.get(name) {
            Some(value) => Option::Some(value.clone()),
            None => {
                match self.parent {
                    Some(parent) => parent.lookup_variable(name),
                    None => Option::None
                }
            }
        }
    }
}

impl CallStack {
    pub fn new() -> CallStack {
        CallStack {
            stack: Vec::new(),
            set: HashSet::new()
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn contains(&self, function: &FunctionIdentifier) -> bool {
        self.set.contains(function)
    }

    pub fn insert(&mut self, function: &FunctionIdentifier, track: bool) {
        self.stack.push(function.clone());
        if track {
            self.set.insert(function.clone());
        }
    }

    pub fn remove(&mut self, function: &FunctionIdentifier, tracked: bool) -> Result<()> {
        if let Some(removed) = self.stack.pop() {
            if removed != *function {
                return Err(Error::new(ErrType::InterpreterError("Tried to remove item from empty call stack.".to_string())))
            }
            if tracked && !self.set.remove(&function) {
                panic!("Tried to remove tracked function from call stack, but could not find in current context.")
            }
            Ok(())
        } else {
            return Err(Error::new(ErrType::InterpreterError("Tried to remove item from empty call stack.".to_string())))
        }
    }

    pub fn make_stack_trace(&self) -> StackTrace {
        self.stack.clone()
    }
}
