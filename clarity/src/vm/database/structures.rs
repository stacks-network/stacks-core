// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::vm::analysis::ContractAnalysis;
use crate::vm::contracts::Contract;
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::{
    Error, IncomparableError, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use crate::vm::types::{
    OptionalData, PrincipalData, TupleTypeSignature, TypeSignature, Value, NONE,
};
use serde::Deserialize;
use stacks_common::util::hash::{hex_bytes, to_hex};
use std::convert::TryInto;
use std::io::Write;

pub trait ClaritySerializable {
    fn serialize(&self) -> String;
}

pub trait ClarityDeserializable<T> {
    fn deserialize(json: &str) -> T;
}

impl ClaritySerializable for String {
    fn serialize(&self) -> String {
        self.into()
    }
}

impl ClarityDeserializable<String> for String {
    fn deserialize(serialized: &str) -> String {
        serialized.into()
    }
}

macro_rules! clarity_serializable {
    ($Name:ident) => {
        impl ClaritySerializable for $Name {
            fn serialize(&self) -> String {
                serde_json::to_string(self).expect("Failed to serialize vm.Value")
            }
        }
        impl ClarityDeserializable<$Name> for $Name {
            fn deserialize(json: &str) -> Self {
                let mut deserializer = serde_json::Deserializer::from_str(&json);
                // serde's default 128 depth limit can be exhausted
                //  by a 64-stack-depth AST, so disable the recursion limit
                deserializer.disable_recursion_limit();
                // use stacker to prevent the deserializer from overflowing.
                //  this will instead spill to the heap
                let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
                Deserialize::deserialize(deserializer).expect("Failed to deserialize vm.Value")
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleTokenMetadata {
    pub total_supply: Option<u128>,
}

clarity_serializable!(FungibleTokenMetadata);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonFungibleTokenMetadata {
    pub key_type: TypeSignature,
}

clarity_serializable!(NonFungibleTokenMetadata);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataMapMetadata {
    pub key_type: TypeSignature,
    pub value_type: TypeSignature,
}

clarity_serializable!(DataMapMetadata);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataVariableMetadata {
    pub value_type: TypeSignature,
}

clarity_serializable!(DataVariableMetadata);

#[derive(Serialize, Deserialize)]
pub struct ContractMetadata {
    pub contract: Contract,
}

clarity_serializable!(ContractMetadata);

#[derive(Serialize, Deserialize)]
pub struct SimmedBlock {
    pub block_height: u64,
    pub block_time: u64,
    pub block_header_hash: [u8; 32],
    pub burn_chain_header_hash: [u8; 32],
    pub vrf_seed: [u8; 32],
}

clarity_serializable!(SimmedBlock);

clarity_serializable!(PrincipalData);
clarity_serializable!(i128);
clarity_serializable!(u128);
clarity_serializable!(u64);
clarity_serializable!(Contract);
clarity_serializable!(ContractAnalysis);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct STXBalance {
    pub amount_unlocked: u128,
    pub amount_locked: u128,
    pub unlock_height: u64,
}

/// Lifetime-limited handle to an uncommitted balance structure.
/// All balance mutations (debits, credits, locks, unlocks) must go through this structure.
pub struct STXBalanceSnapshot<'db, 'conn> {
    principal: PrincipalData,
    balance: STXBalance,
    burn_block_height: u64,
    db_ref: &'conn mut ClarityDatabase<'db>,
}

type Result<T> = std::result::Result<T, Error>;

impl ClaritySerializable for STXBalance {
    fn serialize(&self) -> String {
        let mut buffer = Vec::new();
        buffer
            .write_all(&self.amount_unlocked.to_be_bytes())
            .expect("STXBalance serialization: failed writing amount_unlocked.");
        buffer
            .write_all(&self.amount_locked.to_be_bytes())
            .expect("STXBalance serialization: failed writing amount_locked.");
        buffer
            .write_all(&self.unlock_height.to_be_bytes())
            .expect("STXBalance serialization: failed writing unlock_height.");
        to_hex(buffer.as_slice())
    }
}

impl ClarityDeserializable<STXBalance> for STXBalance {
    fn deserialize(input: &str) -> Self {
        let bytes = hex_bytes(&input).expect("STXBalance deserialization: failed decoding bytes.");
        assert_eq!(bytes.len(), STXBalance::size_of);

        let amount_unlocked = u128::from_be_bytes(
            bytes[0..16]
                .try_into()
                .expect("STXBalance deserialization: failed reading amount_unlocked."),
        );
        let amount_locked = u128::from_be_bytes(
            bytes[16..32]
                .try_into()
                .expect("STXBalance deserialization: failed reading amount_locked."),
        );
        let unlock_height = u64::from_be_bytes(
            bytes[32..40]
                .try_into()
                .expect("STXBalance deserialization: failed reading unlock_height."),
        );

        STXBalance {
            amount_unlocked,
            amount_locked,
            unlock_height,
        }
    }
}

impl<'db, 'conn> STXBalanceSnapshot<'db, 'conn> {
    pub fn new(
        principal: &PrincipalData,
        balance: STXBalance,
        burn_height: u64,
        db_ref: &'conn mut ClarityDatabase<'db>,
    ) -> STXBalanceSnapshot<'db, 'conn> {
        STXBalanceSnapshot {
            principal: principal.clone(),
            balance: balance,
            burn_block_height: burn_height,
            db_ref: db_ref,
        }
    }

    pub fn balance(&self) -> &STXBalance {
        &self.balance
    }

    pub fn save(self) -> () {
        let key = ClarityDatabase::make_key_for_account_balance(&self.principal);
        self.db_ref.put(&key, &self.balance)
    }

    pub fn transfer_to(mut self, recipient: &PrincipalData, amount: u128) -> Result<()> {
        if !self.can_transfer(amount) {
            return Err(InterpreterError::InsufficientBalance.into());
        }

        let recipient_key = ClarityDatabase::make_key_for_account_balance(recipient);
        let mut recipient_balance = self
            .db_ref
            .get(&recipient_key)
            .unwrap_or(STXBalance::zero());

        recipient_balance.amount_unlocked =
            recipient_balance
                .amount_unlocked
                .checked_add(amount)
                .ok_or(Error::Runtime(RuntimeErrorType::ArithmeticOverflow, None))?;

        self.debit(amount);
        self.db_ref.put(&recipient_key, &recipient_balance);
        self.save();
        Ok(())
    }

    pub fn get_available_balance(&self) -> u128 {
        if self.has_unlockable_tokens() {
            self.balance.get_total_balance()
        } else {
            self.balance.amount_unlocked
        }
    }

    pub fn has_locked_tokens(&self) -> bool {
        self.balance
            .has_locked_tokens_at_burn_block(self.burn_block_height)
    }

    pub fn has_unlockable_tokens(&self) -> bool {
        self.balance
            .has_unlockable_tokens_at_burn_block(self.burn_block_height)
    }

    pub fn can_transfer(&self, amount: u128) -> bool {
        self.get_available_balance() >= amount
    }

    pub fn debit(&mut self, amount: u128) {
        let unlocked = self.unlock_available_tokens_if_any();
        if unlocked > 0 {
            debug!("Consolidated after account-debit");
        }

        self.balance.amount_unlocked = self
            .balance
            .amount_unlocked
            .checked_sub(amount)
            .expect("BUG: STX underflow");
    }

    pub fn credit(&mut self, amount: u128) {
        let unlocked = self.unlock_available_tokens_if_any();
        if unlocked > 0 {
            debug!("Consolidated after account-credit");
        }

        self.balance.amount_unlocked = self
            .balance
            .amount_unlocked
            .checked_add(amount)
            .expect("BUG: STX overflow");
    }

    pub fn set_balance(&mut self, balance: STXBalance) {
        self.balance = balance;
    }

    pub fn lock_tokens(&mut self, amount_to_lock: u128, unlock_burn_height: u64) {
        let unlocked = self.unlock_available_tokens_if_any();
        if unlocked > 0 {
            debug!("Consolidated after account-token-lock");
        }

        // caller needs to have checked this
        assert!(amount_to_lock > 0, "BUG: cannot lock 0 tokens");

        if unlock_burn_height <= self.burn_block_height {
            // caller needs to have checked this
            panic!("FATAL: cannot set a lock with expired unlock burn height");
        }

        if self.has_locked_tokens() {
            // caller needs to have checked this
            panic!("FATAL: account already has locked tokens");
        }

        self.balance.unlock_height = unlock_burn_height;
        self.balance.amount_unlocked = self
            .balance
            .amount_unlocked
            .checked_sub(amount_to_lock)
            .expect("STX underflow");

        self.balance.amount_locked = amount_to_lock;
    }

    fn unlock_available_tokens_if_any(&mut self) -> u128 {
        if !self
            .balance
            .has_unlockable_tokens_at_burn_block(self.burn_block_height)
        {
            return 0;
        }

        let unlocked = self.balance.amount_locked;
        self.balance.unlock_height = 0;
        self.balance.amount_unlocked = self
            .balance
            .amount_unlocked
            .checked_add(unlocked)
            .expect("STX overflow");
        self.balance.amount_locked = 0;
        unlocked
    }
}

// NOTE: do _not_ add mutation methods to this struct. Put them in STXBalanceSnapshot!
impl STXBalance {
    pub const size_of: usize = 40;

    pub fn zero() -> STXBalance {
        STXBalance {
            amount_unlocked: 0,
            amount_locked: 0,
            unlock_height: 0,
        }
    }

    pub fn initial(amount_unlocked: u128) -> STXBalance {
        STXBalance {
            amount_unlocked,
            amount_locked: 0,
            unlock_height: 0,
        }
    }

    pub fn get_available_balance_at_burn_block(&self, burn_block_height: u64) -> u128 {
        if self.has_unlockable_tokens_at_burn_block(burn_block_height) {
            self.get_total_balance()
        } else {
            self.amount_unlocked
        }
    }

    pub fn get_locked_balance_at_burn_block(&self, burn_block_height: u64) -> (u128, u64) {
        if self.has_unlockable_tokens_at_burn_block(burn_block_height) {
            (0, 0)
        } else {
            (self.amount_locked, self.unlock_height)
        }
    }

    pub fn get_total_balance(&self) -> u128 {
        self.amount_unlocked
            .checked_add(self.amount_locked)
            .expect("STX overflow")
    }

    pub fn has_locked_tokens_at_burn_block(&self, burn_block_height: u64) -> bool {
        self.amount_locked > 0 && self.unlock_height > burn_block_height
    }

    pub fn has_unlockable_tokens_at_burn_block(&self, burn_block_height: u64) -> bool {
        self.amount_locked > 0 && self.unlock_height <= burn_block_height
    }

    pub fn can_transfer_at_burn_block(&self, amount: u128, burn_block_height: u64) -> bool {
        self.get_available_balance_at_burn_block(burn_block_height) >= amount
    }
}
