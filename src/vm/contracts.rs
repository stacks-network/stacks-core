use vm::errors::{Error, InterpreterResult as Result};
use vm::callables::CallableType;
use vm::{Context, SymbolicExpression, Value, Environment, apply};
use vm::database::ContractDatabase;

pub struct Contract <'a> {
    db: Box<ContractDatabase>,
    global_context: Context<'a>
}

impl <'a> Contract <'a> {
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
