use std::collections::HashMap;

use vm::database::{MemoryContractDatabase};
use vm::contexts::GlobalContext;
use vm::{SymbolicExpression};
use vm::contracts::Contract;
use vm::errors::{Error, InterpreterResult as Result};
use vm::types::{Value, TypeSignature, TupleTypeSignature, AtomTypeIdentifier};

pub trait SuperContext {
    fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()>;
    fn execute_contract(&mut self, contract_name: &str, 
                        sender: &Value, tx_name: &str,
                        args: &[SymbolicExpression]) -> Result<Value>;
}

#[derive(Serialize, Deserialize)]
pub struct MemorySuperContext {
    contracts: HashMap<String, Contract<MemoryContractDatabase>>
}

impl MemorySuperContext {
    pub fn new() -> MemorySuperContext {
        MemorySuperContext {
            contracts: HashMap::new()
        }
    }
}

impl SuperContext for MemorySuperContext {
    fn execute_contract(&mut self, contract_name: &str, 
                        sender: &Value, tx_name: &str,
                        args: &[SymbolicExpression]) -> Result<Value> {
        let contract = self.contracts.get_mut(contract_name)
            .ok_or(Error::Undefined(contract_name.to_string()))?;
        contract.execute_transaction(sender, tx_name, args)
    }

    fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()> {
        if self.contracts.contains_key(contract_name) {
            Err(Error::ContractAlreadyExists(contract_name.to_string()))
        } else {
            let contract = Contract::initialize(contract_content)?;
            self.contracts.insert(contract_name.to_string(), contract);
            Ok(())
        }
    }
}
