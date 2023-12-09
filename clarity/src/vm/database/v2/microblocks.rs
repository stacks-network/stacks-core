use stacks_common::util::hash::{Hash160, to_hex};
use crate::vm::{types::{StandardPrincipalData, TupleData, PrincipalData}, Value, ClarityName, errors::InterpreterResult as Result};
use super::{super::SpecialCaseHandler, ClarityDb, utils::{make_microblock_pubkey_height_key, make_microblock_poison_key}};

pub trait ClarityDbMicroblocks: ClarityDb {
    fn insert_microblock_pubkey_hash_height(
        &mut self,
        pubkey_hash: &Hash160,
        height: u32,
    ) -> Result<()> 
    where
        Self: Sized
    {
        let key = make_microblock_pubkey_height_key(pubkey_hash);
        let value = format!("{}", &height);
        self.put(&key, &value)
    }

    fn get_cc_special_cases_handler(
        &self
    ) -> Result<Option<SpecialCaseHandler<Self>>>
    where 
        Self: Sized;

    /// TODO: Refactor `expect` calls into actual errors.
    fn insert_microblock_poison(
        &mut self,
        height: u32,
        reporter: &StandardPrincipalData,
        seq: u16,
    ) -> Result<()> 
    where
        Self: Sized
    {
        let key = make_microblock_poison_key(height);
        let value = Value::Tuple(
            TupleData::from_data(vec![
                (
                    ClarityName::try_from("reporter").expect("BUG: valid string representation"),
                    Value::Principal(PrincipalData::Standard(reporter.clone())),
                ),
                (
                    ClarityName::try_from("sequence").expect("BUG: valid string representation"),
                    Value::UInt(seq as u128),
                ),
            ])
            .expect("BUG: valid tuple representation"),
        );
        let mut value_bytes = vec![];
        value
            .serialize_write(&mut value_bytes)
            .expect("BUG: valid tuple representation did not serialize");

        let value_str = to_hex(&value_bytes);
        self.put(&key, &value_str);
        Ok(())
    }

    /// TODO: Refactor `expect` calls into actual errors.
    fn get_microblock_pubkey_hash_height(&mut self, pubkey_hash: &Hash160) -> Result<Option<u32>> 
    where
        Self: Sized
    {
        let key = make_microblock_pubkey_height_key(pubkey_hash);
        let result = self.get(&key)?.map(|height_str: String| {
            height_str
                .parse::<u32>()
                .expect("BUG: inserted non-u32 as height of microblock pubkey hash")
        });

        Ok(result)
    }

    /// Returns (who-reported-the-poison-microblock, sequence-of-microblock-fork)
    /// TODO: Refactor `expect` and `panic!` calls into actual errors.
    fn get_microblock_poison_report(
        &mut self,
        height: u32,
    ) -> Result<Option<(StandardPrincipalData, u16)>> 
    where
        Self: Sized
    {
        let key = make_microblock_poison_key(height);
        let result = self.get(&key)?.map(|reporter_hex_str: String| {
            let reporter_value = Value::try_deserialize_hex_untyped(&reporter_hex_str)
                .expect("BUG: failed to decode serialized poison-microblock reporter");
            let tuple_data = reporter_value.expect_tuple();
            let reporter_value = tuple_data
                .get("reporter")
                .expect("BUG: poison-microblock report has no 'reporter'")
                .to_owned();
            let seq_value = tuple_data
                .get("sequence")
                .expect("BUG: poison-microblock report has no 'sequence'")
                .to_owned();

            let reporter_principal = reporter_value.expect_principal();
            let seq_u128 = seq_value.expect_u128();

            let seq: u16 = seq_u128.try_into().expect("BUG: seq exceeds u16 max");
            if let PrincipalData::Standard(principal_data) = reporter_principal {
                (principal_data, seq)
            } else {
                panic!("BUG: poison-microblock report principal is not a standard principal");
            }
        });

        Ok(result)
    }
}