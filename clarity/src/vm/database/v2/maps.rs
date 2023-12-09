use stacks_common::types::StacksEpochId;
use crate::vm::{types::{QualifiedContractIdentifier, TypeSignature, byte_len_of_serialization, serialization::NONE_SERIALIZATION_LEN}, analysis::CheckErrors, Value, errors::InterpreterResult as Result};
use super::{super::{StoreType, key_value_wrapper::ValueResult, DataMapMetadata}, ClarityDb, utils::{make_key_for_quad, make_metadata_key, map_no_contract_as_none}};

pub trait ClarityDbMaps: ClarityDb {
    fn create_map(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_type: TypeSignature,
        value_type: TypeSignature,
    ) -> Result<DataMapMetadata> 
    where
        Self: Sized
    {
        let data = DataMapMetadata {
            key_type,
            value_type,
        };

        let key = make_metadata_key(StoreType::DataMapMeta, map_name);
        self.insert_metadata(contract_identifier, &key, &data)?;

        Ok(data)
    }

    fn load_map(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
    ) -> Result<DataMapMetadata> 
    where
        Self: Sized
    {
        let key = make_metadata_key(StoreType::DataMapMeta, map_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchMap(map_name.to_string()).into())
    }

    fn make_key_for_data_map_entry(
        &self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
    ) -> String {
        self.make_key_for_data_map_entry_serialized(
            contract_identifier,
            map_name,
            &key_value.serialize_to_hex(),
        )
    }

    fn make_key_for_data_map_entry_serialized(
        &self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value_serialized: &str,
    ) -> String {
        make_key_for_quad(
            contract_identifier,
            StoreType::DataMap,
            map_name,
            key_value_serialized,
        )
    }

    fn fetch_entry_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        epoch: &StacksEpochId,
    ) -> Result<Value> 
    where
        Self: Sized
    {
        let descriptor = self.load_map(contract_identifier, map_name)?;
        self.fetch_entry(contract_identifier, map_name, key_value, &descriptor, epoch)
    }

    fn fetch_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<Value> 
    where
        Self: Sized
    {
        if !map_descriptor
            .key_type
            .admits(&self.get_clarity_epoch_version()?, key_value)?
        {
            return Err(CheckErrors::TypeValueError(
                map_descriptor.key_type.clone(),
                (*key_value).clone(),
            )
            .into());
        }

        let key =
            self.make_key_for_data_map_entry(contract_identifier, map_name, key_value);

        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;
        let result = self.get_value(&key, &stored_type, epoch)?;

        match result {
            None => Ok(Value::none()),
            Some(data) => Ok(data.value),
        }
    }

    fn fetch_entry_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult> 
    where
        Self: Sized
    {
        if !map_descriptor
            .key_type
            .admits(&self.get_clarity_epoch_version()?, key_value)?
        {
            return Err(CheckErrors::TypeValueError(
                map_descriptor.key_type.clone(),
                (*key_value).clone(),
            )
            .into());
        }

        let key_serialized = key_value.serialize_to_hex();
        let key = self.make_key_for_data_map_entry_serialized(
            contract_identifier,
            map_name,
            &key_serialized,
        );

        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;
        let result = self.get_value(&key, &stored_type, epoch)?;

        match result {
            None => Ok(ValueResult {
                value: Value::none(),
                serialized_byte_len: byte_len_of_serialization(&key_serialized),
            }),
            Some(ValueResult {
                value,
                serialized_byte_len,
            }) => Ok(ValueResult {
                value,
                serialized_byte_len: serialized_byte_len
                    .checked_add(byte_len_of_serialization(&key_serialized))
                    .expect("Overflowed Clarity key/value size"),
            }),
        }
    }

    fn insert_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult> 
    where
        Self: Sized
    {
        self.inner_set_entry(
            contract_identifier,
            map_name,
            key,
            value,
            true,
            map_descriptor,
            epoch,
        )
    }

    fn data_map_entry_exists(
        &mut self,
        key: &str,
        expected_value: &TypeSignature,
        epoch: &StacksEpochId,
    ) -> Result<bool> {
        match self.get_value(key, expected_value, epoch)? {
            None => Ok(false),
            Some(value) => Ok(value.value != Value::none()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn inner_set_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: Value,
        value: Value,
        return_if_exists: bool,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult> 
    where
        Self: Sized
    {
        if !map_descriptor
            .key_type
            .admits(&self.get_clarity_epoch_version()?, &key_value)?
        {
            return Err(
                CheckErrors::TypeValueError(map_descriptor.key_type.clone(), key_value).into(),
            );
        }
        if !map_descriptor
            .value_type
            .admits(&self.get_clarity_epoch_version()?, &value)?
        {
            return Err(
                CheckErrors::TypeValueError(map_descriptor.value_type.clone(), value).into(),
            );
        }

        let key_serialized = key_value.serialize_to_hex();
        let key_serialized_byte_len = byte_len_of_serialization(&key_serialized);
        let key = make_key_for_quad(
            contract_identifier,
            StoreType::DataMap,
            map_name,
            &key_serialized,
        );
        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;

        if return_if_exists && self.data_map_entry_exists(&key, &stored_type, epoch)? {
            return Ok(ValueResult {
                value: Value::Bool(false),
                serialized_byte_len: key_serialized_byte_len,
            });
        }

        let placed_value = Value::some(value)?;
        let placed_size = self.put_value_with_size(&key, placed_value, epoch)?;

        Ok(ValueResult {
            value: Value::Bool(true),
            serialized_byte_len: key_serialized_byte_len
                .checked_add(placed_size)
                .expect("Overflowed Clarity key/value size"),
        })
    }

    fn delete_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult> 
    where
        Self: Sized
    {
        if !map_descriptor
            .key_type
            .admits(&self.get_clarity_epoch_version()?, key_value)?
        {
            return Err(CheckErrors::TypeValueError(
                map_descriptor.key_type.clone(),
                (*key_value).clone(),
            )
            .into());
        }

        let key_serialized = key_value.serialize_to_hex();
        let key_serialized_byte_len = byte_len_of_serialization(&key_serialized);
        let key = make_key_for_quad(
            contract_identifier,
            StoreType::DataMap,
            map_name,
            &key_serialized,
        );
        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;
        if !self.data_map_entry_exists(&key, &stored_type, epoch)? {
            return Ok(ValueResult {
                value: Value::Bool(false),
                serialized_byte_len: key_serialized_byte_len,
            });
        }

        self.put_value(&key, Value::none(), epoch)?;

        Ok(ValueResult {
            value: Value::Bool(true),
            serialized_byte_len: key_serialized_byte_len
                .checked_add(*NONE_SERIALIZATION_LEN)
                .expect("Overflowed Clarity key/value size"),
        })
    }

    fn set_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<ValueResult>;

    fn set_entry_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
        epoch: &StacksEpochId,
    ) -> Result<Value> 
    where
        Self: Sized
    {
        let descriptor = self.load_map(contract_identifier, map_name)?;
        self.set_entry(
            contract_identifier,
            map_name,
            key,
            value,
            &descriptor,
            epoch,
        )
        .map(|data| data.value)
    }
}