use vm::{SymbolicExpression, Value, apply, eval_all};
use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::callables::CallableType;
use vm::contexts::{Environment, LocalContext, ContractContext, GlobalContext};
use vm::database::{MemoryContractDatabase, ContractDatabase};
use vm::parser;
use vm::variables;

#[derive(Serialize, Deserialize)]
pub struct Contract {
    contract_context: ContractContext,
}

impl Contract {
    pub fn initialize(name: &str, contract: &str, global_context: &mut GlobalContext) -> Result<Contract> {
        let parsed: Vec<_> = parser::parse(contract)?;
        let mut contract_context = ContractContext::new(name.to_string());

        // TODO: should contract initialization have access to the normal
        //       global context? i.e., should contract initialization be allowed
        //       to call out to other contracts during initialization?
        //         if so, we need to pass in the global_context to this function.
        // let mut global_context = MemoryGlobalContext::new();

        let result = eval_all(&parsed, &mut contract_context, global_context)?;
        match result {
            Value::Void => {},
            _ => return Err(Error::new(ErrType::InvalidArguments("Contract instantiation should return null.".to_string())))
        }

        Ok(Contract { contract_context: contract_context })
    }

    pub fn execute_transaction(&mut self, sender: &Value, tx_name: &str,
                               args: &[SymbolicExpression], global_context: &mut GlobalContext) -> Result<Value> {
        let func = self.contract_context.lookup_function(tx_name)
            .ok_or_else(|| { Error::new(ErrType::UndefinedFunction(tx_name.to_string())) })?;
        if !func.is_public() {
            return Err(Error::new(ErrType::NonPublicFunction(tx_name.to_string())));
        }

        if let Value::Principal(_, _) = sender {
            let mut env = Environment::new(global_context, &self.contract_context);

            for arg in args {
                match arg {
                    SymbolicExpression::AtomValue(ref _v) => {},
                    _ => return Err(Error::new(ErrType::InterpreterError(format!("Passed non-value expression to exec_tx on {}!",
                                                                    tx_name))))
                }
            }

            let mut local_context = LocalContext::new();

            env.sender = Some(sender.clone());

            apply(&CallableType::UserFunction(func), args, &mut env, &local_context)
        } else {
            Err(Error::new(ErrType::BadSender(sender.clone())))
        }
    }
}
