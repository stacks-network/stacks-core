use std::collections::{HashMap, HashSet};

use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::types::Value;
use vm::callables::{DefinedFunction, FunctionIdentifier};
use vm::database::{ContractDatabase};
use vm::{SymbolicExpression};
use vm::contracts::Contract;

pub const MAX_CONTEXT_DEPTH: u16 = 256;


// TODO:
//    hide the environment's instance variables.
//     we don't want many of these changing after instantiation.
pub struct Environment <'a> {
    pub global_context: &'a mut GlobalContext,
    pub contract_context: &'a ContractContext,
    pub call_stack: CallStack,
    pub sender: Option<Value>
}

pub struct GlobalContext {
    pub database: Box<ContractDatabase>
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

impl <'a> Environment <'a> {
    // Environments pack a reference to the global context, a mutable reference to a contract db,
    //   together with a call stack. Generally, the environment structure is intended to be reconstructed
    //   for every transaction.
    pub fn new(global_context: &'a mut GlobalContext,
               contract_context: &'a ContractContext) -> Environment<'a> {
        Environment {
            global_context: global_context,
            contract_context: contract_context,
            call_stack: CallStack::new(),
            sender: None
        }
    }
}

impl GlobalContext {
    pub fn new(database: Box<ContractDatabase>) -> GlobalContext {
        GlobalContext {
            database: database
        }
    }

    pub fn execute_contract(&mut self, contract_name: &str, 
                        sender: &Value, tx_name: &str,
                        args: &[SymbolicExpression]) -> Result<Value> {
        let mut contract = self.database.take_contract(contract_name)?;
        self.database.begin_save_point()?;
        let contract_result = contract.execute_transaction(sender, tx_name, args, self);
        // error in replace_contract will supercede any errors in contract's result.
        let replace_result = self.database.replace_contract(contract_name, contract);
        if let Err(error) = replace_result {
            self.database.roll_back()?;
            return Err(error)
        }
        match contract_result {
            Ok(x) => {
                if let Value::Bool(bool_result) = x {
                    if bool_result {
                        self.database.commit()?;
                    } else {
                        self.database.roll_back()?;
                    }
                    return Ok(x)
                } else {
                    self.database.commit()?;
                    return Ok(x)
                }
            },
            Err(_) => {
                self.database.roll_back()?;
                return contract_result
            }
        }
    }

    pub fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()> {
        let contract = Contract::initialize(contract_name, contract_content, self)?;
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
