use vm::errors::{Error, InterpreterResult as Result};
use vm::callables::CallableType;
use vm::{Context, SymbolicExpression, Value, Environment, apply, eval_all};
use vm::database::{MemoryContractDatabase, ContractDatabase};
use vm::parser;

pub struct Contract <'a> {
    db: Box<ContractDatabase>,
    global_context: Context<'a>
}

impl <'a> Contract <'a> {
    pub fn make_in_memory_contract(contract: &str) -> Result<Contract<'a>> {
        let parsed: Vec<_> = parser::parse(contract)?;
        let mut global_context = Context::new();
        let mut db_instance = Box::new(MemoryContractDatabase::new());

        let result = eval_all(&parsed, &mut *db_instance, &mut global_context)?;
        match result {
            Value::Void => {},
            _ => return Err(Error::Generic("Contract instantiation should return null.".to_string()))
        }

        Ok(Contract { db: db_instance,
                      global_context: global_context })
    }

    // Todo: add principal value type, check for sender to be one.
    pub fn execute_transaction(&mut self, _sender: &Value, tx_name: &str,
                               args: &[SymbolicExpression]) -> Result<Value> {
        let func = self.global_context.lookup_function(tx_name)
            .ok_or(Error::Undefined(format!("No such function in contract: {}", tx_name)))?;
        if !func.is_public() {
            return Err(Error::Undefined("Attempt to call non-public function".to_string()))
        }

        let mut env = Environment::new(&self.global_context, &mut *self.db);

        for arg in args {
            match arg {
                SymbolicExpression::AtomValue(ref _v) => {},
                _ => return Err(Error::InterpreterError("Passed non-value expression to exec_tx!".to_string()))
            }
        }

        let local_context = Context::new();
        apply(&CallableType::UserFunction(func), args, &mut env, &local_context)
    }
}
