use vm::{Value, apply, eval_all};
use vm::representations::{SymbolicExpression};
use vm::errors::{InterpreterResult as Result};
use vm::callables::CallableType;
use vm::contexts::{Environment, LocalContext, ContractContext, GlobalContext};
use vm::parser;
use vm::types::QualifiedContractIdentifier;

#[derive(Serialize, Deserialize)]
pub struct Contract {
    pub contract_context: ContractContext,
}

// AARON: this is an increasingly useless wrapper around a ContractContext struct.
//          will probably be removed soon.
impl Contract {
    pub fn initialize (contract_identifier: QualifiedContractIdentifier, contract: &str, global_context: &mut GlobalContext) -> Result<Contract> {
        let parsed: Vec<_> = parser::parse(contract)?;
        let mut contract_context = ContractContext::new(contract_identifier);

        eval_all(&parsed, &mut contract_context, global_context)?;

        Ok(Contract { contract_context: contract_context })
    }

    pub fn deserialize(json: &str) -> Contract {
        serde_json::from_str(json)
            .expect("Failed to deserialize contract")
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize contract")
    }
}
