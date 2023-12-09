use stacks_common::types::StacksEpochId;
use crate::vm::{types::{QualifiedContractIdentifier, TypeSignature, PrincipalData}, analysis::CheckErrors, Value, errors::{RuntimeErrorType, InterpreterResult as Result}};
use super::{super::{ClaritySerializable, StoreType, key_value_wrapper::ValueResult, FungibleTokenMetadata, NonFungibleTokenMetadata}, ClarityDb, utils::{make_key_for_quad, make_metadata_key, make_key_for_trip, map_no_contract_as_none}};

pub trait ClarityDbAssets: ClarityDb {
    fn create_fungible_token(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        total_supply: &Option<u128>,
    ) -> Result<FungibleTokenMetadata> 
    where
        Self: Sized
    {
        let data = FungibleTokenMetadata {
            total_supply: *total_supply,
        };

        let key = make_metadata_key(StoreType::FungibleTokenMeta, token_name);
        self.insert_metadata(contract_identifier, &key, &data)?;

        // total supply _is_ included in the consensus hash
        let supply_key = make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        self.put(&supply_key, &(0_u128))?;

        Ok(data)
    }

    fn load_ft(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
    ) -> Result<FungibleTokenMetadata> 
    where
        Self: Sized
    {
        let key = make_metadata_key(StoreType::FungibleTokenMeta, token_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchFT(token_name.to_string()).into())
    }

    fn create_non_fungible_token(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        key_type: &TypeSignature,
    ) -> Result<NonFungibleTokenMetadata> 
    where
        Self: Sized
    {
        let data = NonFungibleTokenMetadata {
            key_type: key_type.clone(),
        };
        let key = make_metadata_key(StoreType::NonFungibleTokenMeta, token_name);
        self.insert_metadata(contract_identifier, &key, &data)?;

        Ok(data)
    }

    fn load_nft(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
    ) -> Result<NonFungibleTokenMetadata> 
    where
        Self: Sized
    {
        let key = make_metadata_key(StoreType::NonFungibleTokenMeta, token_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchNFT(token_name.to_string()).into())
    }

    /// TODO: Refactor `expect` calls into actual errors.
    fn checked_increase_token_supply(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        amount: u128,
        descriptor: &FungibleTokenMetadata,
    ) -> Result<()> 
    where
        Self: Sized
    {
        let key = make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        let current_supply: u128 = self
            .get(&key)?
            .expect("ERROR: Clarity VM failed to track token supply.");

        let new_supply = current_supply
            .checked_add(amount)
            .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

        if let Some(total_supply) = descriptor.total_supply {
            if new_supply > total_supply {
                return Err(RuntimeErrorType::SupplyOverflow(new_supply, total_supply).into());
            }
        }

        self.put(&key, &new_supply)?;
        Ok(())
    }

    fn checked_decrease_token_supply(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        amount: u128,
    ) -> Result<()> 
    where
        Self: Sized
    {
        let key = make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        let current_supply: u128 = self
            .get(&key)?
            .expect("ERROR: Clarity VM failed to track token supply.");

        if amount > current_supply {
            return Err(RuntimeErrorType::SupplyUnderflow(current_supply, amount).into());
        }

        let new_supply = current_supply - amount;

        self.put(&key, &new_supply);
        Ok(())
    }

    fn get_ft_balance(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        principal: &PrincipalData,
        descriptor: Option<&FungibleTokenMetadata>,
    ) -> Result<u128> 
    where
        Self: Sized
    {
        if descriptor.is_none() {
            self.load_ft(contract_identifier, token_name)?;
        }

        let key = make_key_for_quad(
            contract_identifier,
            StoreType::FungibleToken,
            token_name,
            &principal.serialize(),
        );

        let result = self.get(&key)?;
        match result {
            None => Ok(0),
            Some(balance) => Ok(balance),
        }
    }

    fn set_ft_balance(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        principal: &PrincipalData,
        balance: u128,
    ) -> Result<()> 
    where
        Self: Sized
    {
        let key = make_key_for_quad(
            contract_identifier,
            StoreType::FungibleToken,
            token_name,
            &principal.serialize(),
        );
        self.put(&key, &balance)?;

        Ok(())
    }

    /// TODO: Refactor `expect` calls into actual errors.
    fn get_ft_supply(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
    ) -> Result<u128> 
    where
        Self: Sized
    {
        let key = make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        let supply = self
            .get(&key)?
            .expect("ERROR: Clarity VM failed to track token supply.");
        Ok(supply)
    }

    fn get_nft_owner(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
        asset: &Value,
        key_type: &TypeSignature,
    ) -> Result<PrincipalData> 
    where
        Self: Sized
    {
        let epoch_version = self.get_clarity_epoch_version()?;
        if !key_type.admits(&epoch_version, asset)? {
            return Err(CheckErrors::TypeValueError(key_type.clone(), (*asset).clone()).into());
        }

        let key = make_key_for_quad(
            contract_identifier,
            StoreType::NonFungibleToken,
            asset_name,
            &asset.serialize_to_hex(),
        );

        let value: Option<ValueResult> = self.get_value(
            &key,
            &TypeSignature::new_option(TypeSignature::PrincipalType).unwrap(),
            &epoch_version,
        )?;
        let owner = match value {
            Some(owner) => owner.value.expect_optional(),
            None => return Err(RuntimeErrorType::NoSuchToken.into()),
        };

        let principal = match owner {
            Some(value) => value.expect_principal(),
            None => return Err(RuntimeErrorType::NoSuchToken.into()),
        };

        Ok(principal)
    }

    fn get_nft_key_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
    ) -> Result<TypeSignature> 
    where
        Self: Sized
    {
        let descriptor = self.load_nft(contract_identifier, asset_name)?;
        Ok(descriptor.key_type)
    }

    fn set_nft_owner(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
        asset: &Value,
        principal: &PrincipalData,
        key_type: &TypeSignature,
        epoch: &StacksEpochId,
    ) -> Result<()> 
    where
        Self: Sized
    {
        if !key_type.admits(&self.get_clarity_epoch_version()?, asset)? {
            return Err(CheckErrors::TypeValueError(key_type.clone(), (*asset).clone()).into());
        }

        let key = make_key_for_quad(
            contract_identifier,
            StoreType::NonFungibleToken,
            asset_name,
            &asset.serialize_to_hex(),
        );

        let value = Value::some(Value::Principal(principal.clone()))?;
        self.put_value(&key, value, epoch)?;

        Ok(())
    }

    fn burn_nft(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
        asset: &Value,
        key_type: &TypeSignature,
        epoch: &StacksEpochId,
    ) -> Result<()> 
    where
        Self: Sized
    {
        if !key_type.admits(&self.get_clarity_epoch_version()?, asset)? {
            return Err(CheckErrors::TypeValueError(key_type.clone(), (*asset).clone()).into());
        }

        let key = make_key_for_quad(
            contract_identifier,
            StoreType::NonFungibleToken,
            asset_name,
            &asset.serialize_to_hex(),
        );

        self.put_value(&key, Value::none(), epoch)?;
        Ok(())
    }
}