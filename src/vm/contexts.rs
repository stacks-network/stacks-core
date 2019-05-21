use std::collections::{HashMap, HashSet};

use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::types::Value;
use vm::callables::{DefinedFunction, FunctionIdentifier};
use vm::database::{ContractDatabase, ContractDatabaseTransacter};
use vm::{SymbolicExpression};
use vm::contracts::Contract;
use vm::{parser, eval};

use chainstate::burn::VRFSeed;

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

pub struct OwnedEnvironment <'a> {
    context: GlobalContext<'a>,
    default_contract: ContractContext,
    call_stack: CallStack
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

impl <'a> OwnedEnvironment <'a> {
    pub fn new(database: &'a mut ContractDatabaseTransacter) -> OwnedEnvironment<'a> {
        OwnedEnvironment {
            context: GlobalContext::begin_from(database),
            default_contract: ContractContext::new(":transient:".to_string()),
            call_stack: CallStack::new()
        }
    }

    pub fn get_exec_environment <'b> (&'b mut self, sender: Option<Value>) -> Environment<'b,'a> {
        Environment::new(&mut self.context,
                         &self.default_contract,
                         &mut self.call_stack,
                         sender)
    }

    pub fn commit(self) {
        self.context.commit()
    }
}

impl <'a, 'b> Environment <'a, 'b> {
    // Environments pack a reference to the global context (which is basically the db),
    //   the current contract context, a call stack, and the current sender.
    // Essentially, the point of the Environment struct is to prevent all the eval functions
    //   from including all of these items in their method signatures individually. Because
    //   these different contexts can be mixed and matched (i.e., in a contract-call, you change
    //    contract context, or initiating a transaction necessitates a new globalcontext),
    //   a single "invocation" will end up creating multiple environment objects as context changes
    //    occur.
    pub fn new(global_context: &'a mut GlobalContext<'b>,
               contract_context: &'a ContractContext,
               call_stack: &'a mut CallStack,
               sender: Option<Value>) -> Environment<'a,'b> {
        if let Some(ref sender) = sender {
            match sender {
                Value::Principal(_) => {},
                _ => {
                    panic!("Tried to construct environment with bad sender {}", sender);
                }
            }
        }
        Environment {
            global_context: global_context,
            contract_context: contract_context,
            call_stack: call_stack,
            sender: sender
        }
    }

    pub fn nest_with_sender <'c> (&'c mut self, sender: Value) -> Environment<'c, 'b> {
        Environment::new(self.global_context,
                         self.contract_context,
                         self.call_stack,
                         Some(sender))
    }

    pub fn eval_read_only(&mut self, contract_name: &str, program: &str) -> Result<Value> {
        let parsed = parser::parse(program)?;
        if parsed.len() < 1 {
            return Err(Error::new(ErrType::ParseError("Expected a program of at least length 1".to_string())))
        }

        let contract = self.global_context.database.get_contract(contract_name)?;
        let mut nested_context = GlobalContext::begin_from(&mut self.global_context.database);
        let result = {
            let mut nested_env = Environment::new(&mut nested_context, &contract.contract_context, self.call_stack, self.sender.clone());
            let local_context = LocalContext::new();
            eval(&parsed[0], &mut nested_env, &local_context)
        };
        nested_context.database.roll_back();

        result
    }

    pub fn execute_contract(&mut self, contract_name: &str, 
                            tx_name: &str, args: &[SymbolicExpression]) -> Result<Value> {
        let contract = self.global_context.database.get_contract(contract_name)?;
        let mut nested_context = GlobalContext::begin_from(&mut self.global_context.database);
        let result = {
            let mut nested_env = Environment::new(&mut nested_context, &contract.contract_context, self.call_stack, self.sender.clone());
            contract.execute_transaction(tx_name, args, &mut nested_env)
        };

        nested_context.handle_tx_result(result)
    }

    pub fn execute_function_as_transaction(&mut self, function: &DefinedFunction, args: &[Value]) -> Result<Value> {
        let function = match function {
            DefinedFunction::Private(_) => Err(Error::new(ErrType::NonPublicFunction(format!("{}", function.get_identifier())))),
            DefinedFunction::Public(f) => Ok(f)
        }?;

        let mut nested_context = GlobalContext::begin_from(&mut self.global_context.database);

        let result = {
            let mut nested_env = Environment::new(&mut nested_context, self.contract_context, self.call_stack, self.sender.clone());

            function.apply(args, &mut nested_env)
        };

        nested_context.handle_tx_result(result)
    }

    pub fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()> {
        let mut nested_context = GlobalContext::begin_from(&mut self.global_context.database);
        let result = Contract::initialize(contract_name, contract_content,
                                          &mut nested_context);
        match result {
            Ok(contract) => {
                nested_context.database.insert_contract(contract_name, contract);
                nested_context.commit();
                Ok(())
            },
            Err(e) => {
                nested_context.database.roll_back();
                Err(e)
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

    pub fn get_block_height(&self) -> u64 {
        self.database.get_simmed_block_height()
            .expect("Failed to obtain the current block height.")
    }

    pub fn get_block_time(&self, block_height: u64) -> u64 {
        self.database.get_simmed_block_time(block_height)
            .expect("Failed to obtain the block time for the given block height.")
    }

    pub fn get_block_header_hash(&self, block_height: u64) -> Vec<u8> {
        self.database.get_simmed_block_header_hash(block_height)
            .expect("Failed to obtain the block header hash for the given block height.")
    }

    pub fn get_block_vrf_seed(&self, block_height: u64) -> VRFSeed {
        self.database.get_simmed_block_vrf_seed(block_height)
            .expect("Failed to obtain the block vrf seed for the given block height.")
    }

    pub fn begin_from(database: &'a mut ContractDatabaseTransacter) -> GlobalContext<'a> {
        let db = database.begin_save_point();
        GlobalContext::new(db)
    }

    pub fn commit(self) {
        self.database.commit()
    }

    pub fn handle_tx_result(mut self, result: Result<Value>) -> Result<Value> {
        match result {
            Ok(x) => {
                if let Value::Bool(bool_result) = x {
                    if bool_result {
                        self.commit();
                    } else {
                        self.database.roll_back();
                    }
                    Ok(x)
                } else {
                    Err(Error::new(ErrType::ContractMustReturnBoolean))
                }
            },
            Err(_) => {
                self.database.roll_back();
                result
            }
        }
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

    #[cfg(feature = "developer-mode")]
    pub fn make_stack_trace(&self) -> StackTrace {
        self.stack.clone()
    }

    #[cfg(not(feature = "developer-mode"))]
    pub fn make_stack_trace(&self) -> StackTrace {
        Vec::new()
    }
}
