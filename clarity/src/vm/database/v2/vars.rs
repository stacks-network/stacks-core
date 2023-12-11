use stacks_common::types::StacksEpochId;
use crate::vm::{types::{QualifiedContractIdentifier, TypeSignature, serialization::NONE_SERIALIZATION_LEN}, analysis::CheckErrors, Value};
use super::{super::{StoreType, key_value_wrapper::ValueResult, DataVariableMetadata}, ClarityDb, Result, utils::*};

pub trait ClarityDbVars: ClarityDb {
    fn create_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value_type: TypeSignature,
    ) -> Result<DataVariableMetadata> 
    where
        Self: Sized
    {
        let variable_data = DataVariableMetadata { value_type };
        let key = make_metadata_key(StoreType::VariableMeta, variable_name);

        self.insert_metadata(contract_identifier, &key, &variable_data)?;
        Ok(variable_data)
    }

    fn load_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
    ) -> Result<DataVariableMetadata> 
    where
        Self: Sized
    {
        let key = make_metadata_key(StoreType::VariableMeta, variable_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchDataVariable(variable_name.to_string()).into())
    }

    fn set_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
        variable_descriptor: &DataVariableMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult> 
    where
        Self: Sized
    {
        if !variable_descriptor
            .value_type
            .admits(&self.get_clarity_epoch_version()?, &value)?
        {
            return Err(
                CheckErrors::TypeValueError(variable_descriptor.value_type.clone(), value).into(),
            );
        }

        let key = make_key_for_trip(
            contract_identifier,
            StoreType::Variable,
            variable_name,
        );

        let size = self.put_value_with_size(&key, value, epoch)?;

        Ok(ValueResult {
            value: Value::Bool(true),
            serialized_byte_len: size,
        })
    }

    #[cfg(any(test, feature = "testing"))]
    fn set_variable_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
    ) -> Result<Value> 
    where
        Self: Sized
    {
        let descriptor = self.load_variable(contract_identifier, variable_name)?;
        self.set_variable(
            contract_identifier,
            variable_name,
            value,
            &descriptor,
            &StacksEpochId::latest(),
        )
        .map(|data| data.value)
    }

    fn lookup_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
        epoch: &StacksEpochId,
    ) -> Result<Value> {
        let key = make_key_for_trip(
            contract_identifier,
            StoreType::Variable,
            variable_name,
        );

        let result = self.get_value(&key, &variable_descriptor.value_type, epoch)?;

        match result {
            None => Ok(Value::none()),
            Some(data) => Ok(data.value),
        }
    }

    fn lookup_variable_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        epoch: &StacksEpochId,
    ) -> Result<Value> 
    where
        Self: Sized
    {
        let descriptor = self.load_variable(contract_identifier, variable_name)?;
        self.lookup_variable(contract_identifier, variable_name, &descriptor, epoch)
    }

    /// Same as lookup_variable, but returns the byte-size of the looked up
    ///  Clarity value as well as the value.
    fn lookup_variable_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult> {
        let key = make_key_for_trip(
            contract_identifier,
            StoreType::Variable,
            variable_name,
        );

        let result = self.get_value(&key, &variable_descriptor.value_type, epoch)?;

        match result {
            None => Ok(ValueResult {
                value: Value::none(),
                serialized_byte_len: *NONE_SERIALIZATION_LEN,
            }),
            Some(data) => Ok(data),
        }
    }
}