pub trait SuperContext {
    fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()>;
    fn execute_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()>;
}

pub struct MemorySuperContext {
    contracts: HashMap<String, Option<(GlobalContext, MemoryContractDatabase)>>
}

impl SuperContext for MemoryGlobalDatabase {
    fn execute_contract(&mut self, contract_name: &str, 

    fn take_contract(&mut self, contract_name: &str) -> Result<Contract> {
        let contract_holder: &mut Option<_> = self.contracts.get_mut(contract_name)
            .ok_or(Error::Undefined(contract_name.to_string()))?;
        if let Some((context, db)) = contract_holder.take() {
            Ok(Contract::new(Box::new(db), context))
        } else {
            Err(Error::ContractAlreadyInvoked)            
        }
    }

    fn replace_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()> {
        let contract_holder = self.contracts.get_mut(contract_name)
            .ok_or(Error::Undefined(contract_name.to_string()))?;
        match contract_holder {
            Some(_) => {
                Err(Error::InterpreterError("Attempted to replace contract which hasn't been invoked.".to_string()))
            },
            None => {
                
                contract_holder.replace();
                Ok(())
            }
        }
    }

    fn get_contract(&mut self, contract_name: &str) -> Result<&Contract> {
        self.contracts.get(contract_name)
            .ok_or(Error::Undefined(contract_name.to_string()))?
            .as_ref()
            .ok_or(Error::ContractAlreadyInvoked)
    }

    fn initialize_contract(&mut self, contract_name: &str, contract_content: &str) -> Result<()> {
        if self.contracts.contains_key(contract_name) {
            Err(Error::ContractAlreadyExists(contract_name.to_string()))
        } else {
            let contract = Contract::make_in_memory_contract(contract_content)?;
            self.contracts.insert(contract_name.to_string(), Some(contract));
            Ok(())
        }
    }
}
