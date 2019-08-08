use std::collections::{VecDeque, HashMap};
use std::convert::TryFrom;

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, UncheckedError, InterpreterResult as Result, IncomparableError};
use vm::types::{Value, OptionalData, TypeSignature, TupleTypeSignature, AtomTypeIdentifier, PrincipalData, NONE};

use chainstate::burn::{VRFSeed, BlockHeaderHash};
use burnchains::BurnchainHeaderHash;

use util::hash::Sha256Sum;
use vm::database::structures::{
    FungibleTokenMetadata, NonFungibleTokenMetadata, ContractMetadata,
    DataMapMetadata, DataVariableMetadata, ClaritySerializable, SimmedBlock,
    ClarityDeserializable,
};
use vm::database::{
    KeyValueStorage, RollbackWrapper
};


const SIMMED_BLOCK_TIME: u64 = 10 * 60; // 10 min

pub enum StoreType {
    DataMap, Variable, FungibleToken, CirculatingSupply, NonFungibleToken,
    DataMapMeta, VariableMeta, FungibleTokenMeta, NonFungibleTokenMeta,
    Contract,
    SimmedBlock, SimmedBlockHeight
}

pub struct ClarityDatabase<'a> {
    pub store: RollbackWrapper<'a>
}

impl <'a> ClarityDatabase <'a> {
    pub fn new(store: Box<KeyValueStorage + 'a>) -> ClarityDatabase<'a> {
        ClarityDatabase {
            store: RollbackWrapper::new(store)
        }
    }

    pub fn initialize(&mut self) {
        self.begin();

        use std::time::{SystemTime, UNIX_EPOCH};
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        self.set_simmed_block_height(0);
        for i in 0..20 {
            let block_time = u64::try_from(time_now - ((20 - i) * SIMMED_BLOCK_TIME)).unwrap();
            self.sim_mine_block_with_time(block_time);
        }

        self.commit();
    }

    pub fn begin(&mut self) {
        self.store.nest();
    }

    pub fn commit(&mut self) {
        self.store.commit();
    }

    pub fn roll_back(&mut self) {
        self.store.rollback();
    }

    fn put(&mut self, key: &str, value: &ClaritySerializable) {
        self.store.put(&key, &value.serialize());
    }

    fn get <T> (&mut self, key: &str) -> Option<T> where T: ClarityDeserializable<T> {
        self.store.get(&key)
            .map(|x| T::deserialize(&x))
    }

    pub fn make_key_for_trip(contract_name: &str, data: StoreType, var_name: &str) -> String {
        format!("vm::{}::{}::{}", contract_name, data as u8, var_name)
    }

    pub fn make_key_for_quad(contract_name: &str, data: StoreType, var_name: &str, key_value: String) -> String {
        format!("vm::{}::{}::{}::{}", contract_name, data as u8, var_name, key_value)
    }

    pub fn make_contract_key(contract_name: &str) -> String {
        format!("vm::{}::{}", contract_name, StoreType::Contract as u8)
    }

    pub fn insert_contract(&mut self, contract_name: &str, contract: Contract) {
        let key = ClarityDatabase::make_contract_key(contract_name);
        if self.store.has_entry(&key) {
            panic!("Contract already exists {}", contract_name);
        } else {
            self.put(&key, &contract);
        }
    }

    pub fn get_contract(&mut self, contract_name: &str) -> Result<Contract> {
        let key = ClarityDatabase::make_contract_key(contract_name);
        self.get(&key)
            .ok_or_else(|| { UncheckedError::UndefinedContract(contract_name.to_string()).into() })
    }
}

// Simulating blocks

impl <'a> ClarityDatabase <'a> {
    fn get_simmed_block(&mut self, block_height: u64) -> SimmedBlock {
        let key = ClarityDatabase::make_key_for_trip(
            ":transient:", StoreType::SimmedBlock, &block_height.to_string());
        self.get(&key)
            .expect("Failed to obtain the block for the given block height.")
    }
    
    pub fn get_simmed_block_height(&mut self) -> u64 {
        let key = ClarityDatabase::make_key_for_trip(
            ":transient:", StoreType::SimmedBlockHeight, ":dummy:");
        self.get(&key)
            .expect("Failed to obtain block height.")
    }

    pub fn get_simmed_block_time(&mut self, block_height: u64) -> u64 {
        self.get_simmed_block(block_height)
            .block_time
    }
    pub fn get_simmed_block_header_hash(&mut self, block_height: u64) -> BlockHeaderHash {
        BlockHeaderHash::from_bytes(&self.get_simmed_block(block_height)
                                    .block_header_hash).unwrap()
    }
    pub fn get_simmed_burnchain_block_header_hash(&mut self, block_height: u64) -> BurnchainHeaderHash {
        BurnchainHeaderHash::from_bytes(&self.get_simmed_block(block_height)
                                        .burn_chain_header_hash).unwrap()
    }
    pub fn get_simmed_block_vrf_seed(&mut self, block_height: u64) -> VRFSeed {
        VRFSeed::from_bytes(&self.get_simmed_block(block_height).vrf_seed).unwrap()
    }

    fn set_simmed_block_height(&mut self, block_height: u64) {
        let block_height_key = ClarityDatabase::make_key_for_trip(
            ":transient:", StoreType::SimmedBlockHeight, ":dummy:");
        self.put(&block_height_key, &block_height);
    }

    pub fn sim_mine_block_with_time(&mut self, block_time: u64) {
        let current_height = self.get_simmed_block_height();

        let block_height = current_height + 1;

        let key = ClarityDatabase::make_key_for_trip(
            ":transient:", StoreType::SimmedBlock, &block_height.to_string());

        let mut vrf_seed = [0u8; 32];
        vrf_seed[0] = 1;
        vrf_seed[31] = block_height as u8;

        let mut block_header_hash = [0u8; 32];
        block_header_hash[0] = 2;
        block_header_hash[31] = block_height as u8;

        let mut burn_chain_header_hash = [0u8; 32];
        burn_chain_header_hash[0] = 3;
        burn_chain_header_hash[31] = block_height as u8;

        let block_data = SimmedBlock { block_height, vrf_seed, block_header_hash, burn_chain_header_hash, block_time };

        self.put(&key, &block_data);
        self.set_simmed_block_height(block_height);
    }

    pub fn sim_mine_block(&mut self) {
        let current_height = self.get_simmed_block_height();
        let current_time = self.get_simmed_block_time(current_height);

        let block_time = current_time.checked_add(SIMMED_BLOCK_TIME)
            .expect("Integer overflow while increasing simulated block time");
        self.sim_mine_block_with_time(block_time);
    }

    pub fn sim_mine_blocks(&mut self, count: u32) {
        for i in 0..count {
            self.sim_mine_block();
        }
    }
}

// Variable Functions...
impl <'a> ClarityDatabase <'a> {
    pub fn create_variable(&mut self, contract_name: &str, variable_name: &str, value_type: TypeSignature) {
        let variable_data = DataVariableMetadata { value_type };

        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::VariableMeta, variable_name);

        assert!(!self.store.has_entry(&key), "Clarity VM attempted to initialize existing variable");

        self.put(&key, &variable_data);
    }

    fn load_variable(&mut self, contract_name: &str, variable_name: &str) -> Result<DataVariableMetadata> {
        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::VariableMeta, variable_name);

        let data = self.get(&key)
            .ok_or(UncheckedError::UndefinedVariable(variable_name.to_string()))?;

        Ok(data)
    }

    pub fn set_variable(&mut self, contract_name: &str, variable_name: &str, value: Value) -> Result<Value> {
        let variable_descriptor = self.load_variable(contract_name, variable_name)?;
        if !variable_descriptor.value_type.admits(&value) {
            return Err(UncheckedError::TypeError(format!("{:?}", variable_descriptor.value_type), value).into())
        }

        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::Variable, variable_name);

        self.put(&key, &value);

        return Ok(Value::Bool(true))
    }

    pub fn lookup_variable(&mut self, contract_name: &str, variable_name: &str) -> Result<Value>  {
        let variable_descriptor = self.load_variable(contract_name, variable_name)?;

        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::Variable, variable_name);

        let result = self.get(&key);

        match result {
            None => Ok(Value::none()),
            Some(data) => Ok(data)
        }
    }
}

// Data Map Functions
impl <'a> ClarityDatabase <'a> {
    pub fn create_map(&mut self, contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) {
        let key_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(key_type));
        let value_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(value_type));

        let data = DataMapMetadata { key_type, value_type };

        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::DataMapMeta, map_name);

        assert!(!self.store.has_entry(&key), "Clarity VM attempted to initialize existing data map");

        self.store.put(&key, &data.serialize());
    }

    fn load_map(&mut self, contract_name: &str, map_name: &str) -> Result<DataMapMetadata> {
        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::DataMapMeta, map_name);

        let data = self.get(&key)
            .ok_or(UncheckedError::UndefinedMap(map_name.to_string()))?;

        Ok(data)
    }

    pub fn fetch_entry(&mut self, contract_name: &str, map_name: &str, key_value: &Value) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(key_value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.key_type), (*key_value).clone()).into())
        }

        let key = ClarityDatabase::make_key_for_quad(contract_name, StoreType::DataMap, map_name, key_value.serialize());

        let result = self.get(&key);

        match result {
            None => Ok(Value::none()),
            Some(data) => Ok(data)
        }
    }

    pub fn set_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        self.inner_set_entry(contract_name, map_name, key, value, false)
    }

    pub fn insert_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        self.inner_set_entry(contract_name, map_name, key, value, true)
    }

    fn data_map_entry_exists(&mut self, key: &str) -> Result<bool> {
        match self.store.get(&key) {
            None => Ok(false),
            Some(serialized) =>
                Ok(Value::deserialize(&serialized) != Value::none())
        }
    }
    
    fn inner_set_entry(&mut self, contract_name: &str, map_name: &str, key_value: Value, value: Value, return_if_exists: bool) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(&key_value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.key_type), key_value).into())
        }
        if !map_descriptor.value_type.admits(&value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.value_type), value).into())
        }

        let key = ClarityDatabase::make_key_for_quad(contract_name, StoreType::DataMap, map_name, key_value.serialize());

        if return_if_exists && self.data_map_entry_exists(&key)? {
            return Ok(Value::Bool(false))
        }

        self.put(&key, &Value::some(value));

        return Ok(Value::Bool(true))
    }

    pub fn delete_entry(&mut self, contract_name: &str, map_name: &str, key_value: &Value) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(key_value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.key_type), (*key_value).clone()).into())
        }

        let key = ClarityDatabase::make_key_for_quad(contract_name, StoreType::DataMap, map_name, key_value.serialize());
        if !self.data_map_entry_exists(&key)? {
            return Ok(Value::Bool(false))
        }

        self.put(&key, &(Value::none()));

        return Ok(Value::Bool(true))
    }
}

// Asset Functions

impl <'a> ClarityDatabase <'a> {
    pub fn create_fungible_token(&mut self, contract_name: &str, token_name: &str, total_supply: &Option<i128>) {
        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::FungibleTokenMeta, token_name);
        let data = FungibleTokenMetadata { total_supply: total_supply.clone() };

        assert!(!self.store.has_entry(&key), "Clarity VM attempted to initialize existing token");

        if total_supply.is_some() {
            let supply_key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::CirculatingSupply, token_name);
            self.put(&supply_key, &(0 as i128));
        }

        self.put(&key, &data);
    }

    fn load_ft(&mut self, contract_name: &str, token_name: &str) -> Result<FungibleTokenMetadata> {
        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::FungibleTokenMeta, token_name);

        let data = self.get(&key)
            .ok_or(UncheckedError::UndefinedTokenType(token_name.to_string()))?;

        Ok(data)
    }

    pub fn create_non_fungible_token(&mut self, contract_name: &str, token_name: &str, key_type: &TypeSignature) {
        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::NonFungibleTokenMeta, token_name);
        let data = NonFungibleTokenMetadata { key_type: key_type.clone() };

        assert!(!self.store.has_entry(&key), "Clarity VM attempted to initialize existing token");

        self.put(&key, &data);
    }

    fn load_nft(&mut self, contract_name: &str, token_name: &str) -> Result<NonFungibleTokenMetadata> {
        let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::NonFungibleTokenMeta, token_name);

        let data = self.get(&key)
            .ok_or(UncheckedError::UndefinedTokenType(token_name.to_string()))?;

        Ok(data)
    }

    pub fn checked_increase_token_supply(&mut self, contract_name: &str, token_name: &str, amount: i128) -> Result<()> {
        if amount < 0 {
            panic!("ERROR: Clarity VM attempted to increase token supply by negative balance.");
        }
        let descriptor = self.load_ft(contract_name, token_name)?;

        if let Some(total_supply) = descriptor.total_supply {
            let key = ClarityDatabase::make_key_for_trip(contract_name, StoreType::CirculatingSupply, token_name);
            let current_supply: i128 = self.get(&key)
                .expect("ERROR: Clarity VM failed to track token supply.");
 
            let new_supply = current_supply.checked_add(amount)
                .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

            if new_supply > total_supply {
                Err(RuntimeErrorType::SupplyOverflow(new_supply, total_supply).into())
            } else {
                self.put(&key, &new_supply);
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub fn get_ft_balance(&mut self, contract_name: &str, token_name: &str, principal: &PrincipalData) -> Result<i128> {
        let descriptor = self.load_ft(contract_name, token_name)?;

        let key =  ClarityDatabase::make_key_for_quad(contract_name, StoreType::FungibleToken, token_name, principal.serialize());

        let result = self.get(&key);
        match result {
            None => Ok(0),
            Some(balance) => Ok(balance)
        }
    }

    pub fn set_ft_balance(&mut self, contract_name: &str, token_name: &str, principal: &PrincipalData, balance: i128) -> Result<()> {
        if balance < 0 {
            panic!("ERROR: Clarity VM attempted to set negative token balance.");
        }

        let key =  ClarityDatabase::make_key_for_quad(contract_name, StoreType::FungibleToken, token_name, principal.serialize());
        self.put(&key, &balance);

        Ok(())
    }

    pub fn get_nft_owner(&mut self, contract_name: &str, asset_name: &str, asset: &Value) -> Result<PrincipalData> {
        let descriptor = self.load_nft(contract_name, asset_name)?;
        if !descriptor.key_type.admits(asset) {
            return Err(UncheckedError::TypeError(descriptor.key_type.to_string(), (*asset).clone()).into())
        }

        let key = ClarityDatabase::make_key_for_quad(contract_name, StoreType::NonFungibleToken, asset_name, asset.serialize());

        let result = self.get(&key);
        result.ok_or(RuntimeErrorType::NoSuchToken.into())
    }

    pub fn get_nft_key_type(&mut self, contract_name: &str, asset_name: &str) -> Result<TypeSignature> {
        let descriptor = self.load_nft(contract_name, asset_name)?;
        Ok(descriptor.key_type)
    }

    pub fn set_nft_owner(&mut self, contract_name: &str, asset_name: &str, asset: &Value, principal: &PrincipalData) -> Result<()> {
        let descriptor = self.load_nft(contract_name, asset_name)?;
        if !descriptor.key_type.admits(asset) {
            return Err(UncheckedError::TypeError(descriptor.key_type.to_string(), (*asset).clone()).into())
        }

        let key = ClarityDatabase::make_key_for_quad(contract_name, StoreType::NonFungibleToken, asset_name, asset.serialize());

        self.put(&key, principal);

        Ok(())
    }
}
