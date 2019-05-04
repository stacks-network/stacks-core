use vm::{Value, apply, eval_all};
use vm::representations::{SymbolicExpression};
use vm::errors::{Error, ErrType, InterpreterResult as Result, IncomparableError};
use vm::callables::CallableType;
use vm::contexts::{Environment, LocalContext, ContractContext, GlobalContext};
use vm::parser;

#[derive(Serialize, Deserialize)]
pub struct Contract {
    pub contract_context: ContractContext,
}

// AARON: this is an increasingly useless wrapper around a ContractContext struct.
//          will probably be removed soon.
impl Contract {
    pub fn initialize <'b> (name: &str, contract: &str, global_context: &mut GlobalContext<'b>) -> Result<Contract> {
        let parsed: Vec<_> = parser::parse(contract)?;
        let mut contract_context = ContractContext::new(name.to_string());

        let result = eval_all(&parsed, &mut contract_context, global_context)?;

        Ok(Contract { contract_context: contract_context })
    }

    pub fn execute_transaction<'b> (&self, tx_name: &str, args: &[SymbolicExpression], env: &mut Environment) -> Result<Value> {
        let func = self.contract_context.lookup_function(tx_name)
            .ok_or_else(|| { Error::new(ErrType::UndefinedFunction(tx_name.to_string())) })?;
        if !func.is_public() {
            return Err(Error::new(ErrType::NonPublicFunction(tx_name.to_string())));
        }
        for arg in args {
            arg.match_atom_value()
                .ok_or_else(|| Error::new(ErrType::InterpreterError(format!("Passed non-value expression to exec_tx on {}!",
                                                                            tx_name))))?;
        }

        let local_context = LocalContext::new();
        apply(&CallableType::UserFunction(func), args, env, &local_context)
        
    }

    pub fn deserialize(json: &str) -> Result<Contract> {
        serde_json::from_str(json)
            .map_err(|x| Error::new(ErrType::DeserializationFailure(
                IncomparableError { err: x } )))
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|x| Error::new(ErrType::SerializationFailure(
                IncomparableError { err: x } )))
    }
}
