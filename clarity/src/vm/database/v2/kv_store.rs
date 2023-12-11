use stacks_common::{types::chainstate::StacksBlockId, util::hash::Sha512Trunc256Sum};

use crate::vm::{database::{clarity_store::ContractCommitment, ClaritySerializable, SpecialCaseHandler}, types::QualifiedContractIdentifier};

use super::{ClarityDb, Result};

// These functions generally _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait ClarityDbKvStore: ClarityDb
{
    /// put K-V data into the committed datastore
    fn kv_put_all(&mut self, items: Vec<(String, String)>) -> Result<()>;
    /// fetch K-V out of the committed datastore
    //fn get(&mut self, key: &str) -> Option<String>;
    /// fetch K-V out of the committed datastore, along with the byte representation
    ///  of the Merkle proof for that key-value pair
    fn kv_get_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>>;
    fn kv_has_entry(&mut self, key: &str) -> Result<bool>;

    /// change the current MARF context to service reads from a different chain_tip
    ///   used to implement time-shifted evaluation.
    /// returns the previous block header hash on success
    fn kv_set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId>;

    /// Is None if `block_height` >= the "currently" under construction Stacks block height.
    fn kv_get_block_at_height(&mut self, height: u32) -> Result<Option<StacksBlockId>>;

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn kv_get_current_block_height(&mut self) -> Result<u32>;

    fn kv_get_open_chain_tip_height(&mut self) -> Result<u32>;
    fn kv_get_open_chain_tip(&mut self) -> Result<StacksBlockId>;

    fn kv_get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler<Self>> 
    where
        Self: Sized
    {
        None
    }

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn kv_make_contract_commitment(&mut self, contract_hash: Sha512Trunc256Sum) -> Result<String> {
        let block_height = self.kv_get_open_chain_tip_height()?;
        let cc = ContractCommitment {
            hash: contract_hash,
            block_height,
        };

        Ok(cc.serialize())
    }

    /// This function is used to obtain a committed contract hash, and the block header hash of the block
    ///   in which the contract was initialized. This data is used to store contract metadata in the side
    ///   store.
    fn kv_get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)> 
    where
        Self: Sized;

    fn kv_insert_metadata(
        &mut self, 
        contract: &QualifiedContractIdentifier, 
        key: &str, 
        value: &str
    ) -> Result<()>;

    fn kv_get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>>;

    fn kv_get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>>;

    fn kv_put_all_metadata(
        &mut self, 
        items: Vec<((QualifiedContractIdentifier, String), String)>
    ) -> Result<()>
    where
        Self: Sized
    {
        for ((contract, key), value) in items.into_iter() {
            self.insert_metadata(&contract, &key, &value)?;
        }

        Ok(())
    }
}