use std::collections::HashMap;
use std::collections::HashSet;

use vm::errors::{Error, InterpreterResult as Result};
use vm::types::Value;
use vm::callables::{DefinedFunction, FunctionIdentifier};
use vm::database::{ContractDatabase, MemoryContractDatabase};
use vm::{SymbolicExpression};
use vm::contracts::Contract;

const MAX_CONTEXT_DEPTH: u16 = 256;

pub struct Environment <'a> {
    pub global_context: &'a mut GlobalContext,
    pub contract_context: &'a ContractContext,
    pub call_stack: CallStack,
    pub database: &'a mut ContractDatabase
}

pub trait GlobalContext {
    fn execute_contract(&mut self, contract_name: &str, 
                        sender: &Value, tx_name: &str,
                        args: &[SymbolicExpression]) -> Result<Value>;
    fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()>;        
}

#[derive(Serialize, Deserialize)]
pub struct MemoryGlobalContext {
    contracts: HashMap<String, Option<Contract<MemoryContractDatabase>>>
}

#[derive(Serialize, Deserialize)]
pub struct ContractContext {
    pub variables: HashMap<String, Value>,
    pub functions: HashMap<String, DefinedFunction>,
}

pub struct LocalContext <'a> {
    pub parent: Option< &'a LocalContext<'a>>,
    pub variables: HashMap<String, Value>,
    depth: u16
}

pub struct CallStack {
    pub stack: HashSet<FunctionIdentifier>,
}

impl <'a> Environment <'a> {
    // Environments pack a reference to the global context, a mutable reference to a contract db,
    //   together with a call stack. Generally, the environment structure is intended to be reconstructed
    //   for every transaction.
    pub fn new(global_context: &'a mut GlobalContext,
               contract_context: &'a ContractContext,
               database: &'a mut ContractDatabase) -> Environment<'a> {
        Environment {
            global_context: global_context,
            contract_context: contract_context,
            call_stack: CallStack::new(),
            database: database
        }
    }
}

impl MemoryGlobalContext {
    pub fn new() -> MemoryGlobalContext {
        MemoryGlobalContext {
            contracts: HashMap::new()
        }
    }

    fn take_contract(&mut self, contract_name: &str) -> Result<Contract<MemoryContractDatabase>> {
        let contract = self.contracts.get_mut(contract_name)
            .ok_or(Error::Undefined(contract_name.to_string()))?;
        contract.take().ok_or(Error::ContractAlreadyInvoked)
    }

    fn replace_contract(&mut self, contract_name: &str, contract: Contract<MemoryContractDatabase>) -> Result<()> {
        let contract_holder = self.contracts.get_mut(contract_name)
            .ok_or(Error::Undefined(contract_name.to_string()))?;
        match contract_holder.replace(contract) {
            Some(_) => Err(Error::InterpreterError(
                format!("Attempted to close invocation on a non-open contract {}", contract_name))),
            None => Ok(())
        }
    }
}

impl GlobalContext for MemoryGlobalContext {
    fn execute_contract(&mut self, contract_name: &str, 
                        sender: &Value, tx_name: &str,
                        args: &[SymbolicExpression]) -> Result<Value> {
        let mut contract = self.take_contract(contract_name)?;
        let result = contract.execute_transaction(sender, tx_name, args, self);
        // Aaron: TODO: we need to _also_ handle the case of an error in result if
        //  replace_contract errors.
        self.replace_contract(contract_name, contract)?;
        result
    }

    fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()> {
        if self.contracts.contains_key(contract_name) {
            Err(Error::ContractAlreadyExists(contract_name.to_string()))
        } else {
            let contract = Contract::initialize(contract_content)?;
            self.contracts.insert(contract_name.to_string(), Some(contract));
            Ok(())
        }
    }
}

impl ContractContext {
    pub fn new() -> ContractContext {
        ContractContext {
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
            Err(Error::MaxContextDepthReached)
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
            stack: HashSet::new(),
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn contains(&self, user_function: &FunctionIdentifier) -> bool {
        self.stack.contains(user_function)
    }

    pub fn insert(&mut self, user_function: &FunctionIdentifier) {
        self.stack.insert(user_function.clone());
    }

    pub fn remove(&mut self, user_function: &FunctionIdentifier) {
        if !self.stack.remove(&user_function) {
            panic!("Tried to remove function from call stack, but could not find in current context.")
        }
    }
}
