// Copyright (C) 2024-2026 Stacks Open Internet Foundation
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

use std::collections::HashMap;

use clarity::util::uint::{BitArray as _, Uint256, Uint512};
use clarity::vm::clarity::ClarityError;
use clarity::vm::database::DataVariableMetadata;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::{
    BufferLength, ListTypeData, PrincipalData, QualifiedContractIdentifier, SequenceData,
    SequenceSubtype, StandardPrincipalData, TupleData, TypeSignature,
};
use clarity::vm::{SymbolicExpression, Value};
use sha2::{Digest, Sha256};
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::deps_common::bitcoin::blockdata::script::{Builder, Script};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{to_hex, Hash160};

use crate::burnchains::bitcoin::WitnessScriptHash;
use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::{
    validate_pox_p2wsh_outputs, SortitionDB, WatchedP2WSHOutputMetadata,
};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{
    NakamotoSignerEntry, PoxStartCycleInfo, PoxVersions, RawRewardSetEntry, RewardSet,
    SIGNERS_LAST_RATIO_PERCENTILES, SIGNERS_LAST_UPDATED_BTC_HEIGHT, SIGNERS_MAX_LIST_SIZE,
    SIGNERS_NAME, SIGNERS_PK_LEN, SIGNERS_UPDATE_STATE, SIGNERS_VOTING_FUNCTION_NAME,
    SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState};
use crate::chainstate::stacks::{Error as ChainstateError, StacksTransaction, TransactionPayload};
use crate::clarity::vm::clarity::{ClarityConnection, TransactionConnection};
use crate::clarity_vm::clarity::ClarityTransactionConnection;
use crate::clarity_vm::database::SortitionDBRef;
use crate::util_lib::boot;
use crate::util_lib::boot::boot_code_id;

pub struct NakamotoSigners();

pub struct SignerCalculation {
    pub reward_set: RewardSet,
    pub events: Vec<StacksTransactionEvent>,
}

pub struct AggregateKeyVoteParams {
    pub signer_index: u64,
    pub aggregate_key: Vec<u8>,
    pub voting_round: u64,
    pub reward_cycle: u64,
}

impl RawRewardSetEntry {
    pub fn from_pox_4_tuple(is_mainnet: bool, tuple: TupleData) -> Result<Self, ChainstateError> {
        let mut tuple_data = tuple.data_map;

        let pox_addr_tuple = tuple_data.remove("pox-addr").ok_or_else(|| {
            ChainstateError::Expects(
                "no `pox-addr` in return value from (get-reward-set-pox-address)".into(),
            )
        })?;

        let reward_address = PoxAddress::try_from_pox_tuple(is_mainnet, &pox_addr_tuple)
            .unwrap_or_else(|| {
                warn!("Invalid PoX address supplied, replacing with burn address"; "pox_addr_tuple" => %pox_addr_tuple);
                PoxAddress::standard_burn_address(is_mainnet)
            });

        let total_ustx = tuple_data
            .remove("total-ustx")
            .ok_or_else(|| {
                ChainstateError::Expects(
                    "no 'total-ustx' in return value from (pox-4.get-reward-set-pox-address)"
                        .into(),
                )
            })?
            .expect_u128().map_err(|_| {
                ChainstateError::Expects(
                    "'total-ustx' in return value from (pox-4.get-reward-set-pox-address) is not a u128".into(),
                )
            })?.try_into().map_err(|_| ChainstateError::Expects("'total-ustx' value out of range for u64".into()))?;

        let stacker = tuple_data
            .remove("stacker")
            .ok_or_else(|| {
                ChainstateError::Expects(
                    "no 'stacker' in return value from (pox-4.get-reward-set-pox-address)".into(),
                )
            })?
            .expect_optional().map_err(|_| {
                ChainstateError::Expects(
                    "'stacker' in return value from (pox-4.get-reward-set-pox-address) is not optional".into(),
                )
            })?
            .map(|value| value.expect_principal())
            .transpose().map_err(|_| {
                ChainstateError::Expects(
                    "'stacker' in return value from (pox-4.get-reward-set-pox-address) is not a principal".into(),
                )
            })?;

        let signer = tuple_data
            .remove("signer")
            .ok_or_else(|| {
                ChainstateError::Expects(
                    "no 'signer' in return value from (pox-4.get-reward-set-pox-address)".into(),
                )
            })?
            .expect_buff(SIGNERS_PK_LEN).map_err(|_| {
                ChainstateError::Expects(
                    format!("'signer' in return value from (pox-4.get-reward-set-pox-address) is not a buff of length {SIGNERS_PK_LEN}"),
                )
            })?;

        // (buff 33) only enforces max size, not min size, so we need to do a len check
        let pk_bytes = if signer.len() == SIGNERS_PK_LEN {
            let mut bytes = [0; SIGNERS_PK_LEN];
            bytes.copy_from_slice(signer.as_slice());
            bytes
        } else {
            [0; SIGNERS_PK_LEN]
        };

        debug!(
            "Parsed PoX reward address";
            "stacked_ustx" => total_ustx,
            "reward_address" => %reward_address,
            "stacker" => ?stacker,
            "signer" => to_hex(&signer),
        );

        Ok(Self {
            reward_address,
            amount_stacked: total_ustx,
            stacker,
            signer: Some(pk_bytes),
        })
    }

    pub fn from_pox_5_tuple(is_mainnet: bool, tuple: TupleData) -> Result<Self, ChainstateError> {
        // PLACEHOLDER (rob-stacks)
        let mut tuple_data = tuple.data_map;

        let pox_addr_tuple = tuple_data.remove("pox-addr").ok_or_else(|| {
            ChainstateError::Expects(
                "no `pox-addr` in return value from (get-reward-set-pox-address)".into(),
            )
        })?;

        let reward_address = PoxAddress::try_from_pox_tuple(is_mainnet, &pox_addr_tuple)
            .ok_or_else(|| {
                ChainstateError::Expects(format!("not a valid PoX address: {pox_addr_tuple}"))
            })?;

        let total_ustx = tuple_data
            .remove("total-ustx")
            .ok_or_else(|| {
                ChainstateError::Expects(
                    "no 'total-ustx' in return value from (pox-4.get-reward-set-pox-address)"
                        .into(),
                )
            })?
            .expect_u128().map_err(|_| {
                ChainstateError::Expects(
                    "'total-ustx' in return value from (pox-4.get-reward-set-pox-address) is not a u128".into(),
                )
            })?.try_into().map_err(|_| ChainstateError::Expects("'total-ustx' value out of range for u64".into()))?;

        let stacker = tuple_data
            .remove("stacker")
            .ok_or_else(|| {
                ChainstateError::Expects(
                    "no 'stacker' in return value from (pox-4.get-reward-set-pox-address)".into(),
                )
            })?
            .expect_optional().map_err(|_| {
                ChainstateError::Expects(
                    "'stacker' in return value from (pox-4.get-reward-set-pox-address) is not optional".into(),
                )
            })?
            .map(|value| value.expect_principal())
            .transpose().map_err(|_| {
                ChainstateError::Expects(
                    "'stacker' in return value from (pox-4.get-reward-set-pox-address) is not a principal".into(),
                )
            })?;

        let signer = tuple_data
            .remove("signer")
            .ok_or_else(|| {
                ChainstateError::Expects(
                    "no 'signer' in return value from (pox-4.get-reward-set-pox-address)".into(),
                )
            })?
            .expect_buff(SIGNERS_PK_LEN).map_err(|_| {
                ChainstateError::Expects(
                    format!("'signer' in return value from (pox-4.get-reward-set-pox-address) is not a buff of length {SIGNERS_PK_LEN}"),
                )
            })?;

        // (buff 33) only enforces max size, not min size, so we need to do a len check
        let pk_bytes = if signer.len() == SIGNERS_PK_LEN {
            let mut bytes = [0; SIGNERS_PK_LEN];
            bytes.copy_from_slice(signer.as_slice());
            bytes
        } else {
            [0; SIGNERS_PK_LEN]
        };

        debug!(
            "Parsed PoX reward address";
            "stacked_ustx" => total_ustx,
            "reward_address" => %reward_address,
            "stacker" => ?stacker,
            "signer" => to_hex(&signer),
        );

        Ok(Self {
            reward_address,
            amount_stacked: total_ustx,
            stacker,
            signer: Some(pk_bytes),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum RawPox5EntryInfo {
    Pool(PrincipalData),
    Solo {
        pox_addr: PoxAddress,
        signer_key: [u8; 33],
    },
}

/// Provides pool information (PoX address and signer key) for PoX-5 pool principals.
pub trait Pox5PoolInfoProvider {
    /// Query pool information for a given pool principal.
    /// Returns `Ok(Some(...))` if pool exists, `Ok(None)` if pool not found,
    /// or `Err(...)` for query/parsing failures.
    fn get_pool_info(
        &mut self,
        pool_principal: &PrincipalData,
    ) -> Result<Option<([u8; 33], PoxAddress)>, PoxEntryParsingError>;
}

/// Concrete implementation that queries pool info from Clarity contract.
pub struct ClarityPox5PoolInfoProvider<'a, 'b, 'c> {
    clarity: &'a mut ClarityTransactionConnection<'b, 'c>,
    pox_contract: &'a QualifiedContractIdentifier,
    is_mainnet: bool,
}

impl<'a, 'b, 'c> ClarityPox5PoolInfoProvider<'a, 'b, 'c> {
    pub fn new(
        clarity: &'a mut ClarityTransactionConnection<'b, 'c>,
        pox_contract: &'a QualifiedContractIdentifier,
    ) -> Self {
        let is_mainnet = clarity.is_mainnet();
        Self {
            clarity,
            pox_contract,
            is_mainnet,
        }
    }
}

impl<'a, 'b, 'c> Pox5PoolInfoProvider for ClarityPox5PoolInfoProvider<'a, 'b, 'c> {
    fn get_pool_info(
        &mut self,
        pool_principal: &PrincipalData,
    ) -> Result<Option<([u8; 33], PoxAddress)>, PoxEntryParsingError> {
        let pool_entry_opt = self
            .clarity
            .eval_method_read_only(
                self.pox_contract,
                "get-pool-info",
                &[SymbolicExpression::atom_value(Value::from(
                    pool_principal.clone(),
                ))],
            )
            .map_err(|e| {
                PoxEntryParsingError::Abort(format!("Error executing get-pool-info: {e}"))
            })?
            .expect_optional()
            .map_err(|_| {
                PoxEntryParsingError::Abort("get-pool-info did not return optional".into())
            })?;

        match pool_entry_opt {
            Some(entry) => {
                let parsed =
                    RawPox5Entry::parse_pox_entry(entry, self.is_mainnet).map_err(|e| {
                        PoxEntryParsingError::Skip(format!("Failed to parse pool info: {e}"))
                    })?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RawPox5Entry {
    pub(crate) user: StandardPrincipalData,
    pub(crate) num_cycles: u128,
    pub(crate) unlock_bytes: Vec<u8>,
    pub(crate) amount_ustx: u128,
    pub(crate) first_reward_cycle: u128,
    pub(crate) unlock_height: u32,
    pub(crate) pox_info: RawPox5EntryInfo,
}

impl RawPox5Entry {
    /// Test constructor for creating RawPox5Entry instances in tests
    #[cfg(test)]
    pub fn new_for_test(
        stacker_version: u8,
        stacker_hash: [u8; 20],
        unlock_height: u32,
        amount_ustx: u128,
        unlock_bytes: Vec<u8>,
    ) -> Self {
        use stacks_common::types::chainstate::StacksAddress;

        use crate::chainstate::stacks::address::PoxAddress;

        let user = StandardPrincipalData::new(stacker_version, stacker_hash).unwrap();
        let pox_addr = PoxAddress::Standard(
            StacksAddress::new(stacker_version, Hash160(stacker_hash)).unwrap(),
            None,
        );

        Self {
            user,
            num_cycles: 1,
            unlock_bytes,
            amount_ustx,
            first_reward_cycle: 0,
            unlock_height,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr,
                signer_key: [0u8; 33],
            },
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_for_signer_test(
        stacks_addr: StandardPrincipalData,
        unlock_height: u32,
        amount_ustx: u128,
        unlock_bytes: Vec<u8>,
        signer_key: [u8; 33],
    ) -> Self {
        let pox_addr = PoxAddress::Standard(StacksAddress::from(stacks_addr.clone()), None);
        Self {
            user: stacks_addr,
            num_cycles: 1,
            unlock_bytes,
            amount_ustx,
            first_reward_cycle: 0,
            unlock_height,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr,
                signer_key,
            },
        }
    }

    /// Compute the full redeem script for the timelock
    pub fn to_redeem_script(&self) -> Script {
        let mut principal_data = vec![0x05, self.user.version()];
        principal_data.extend_from_slice(&self.user.1);
        let builder = Builder::new()
            .push_slice(&principal_data)
            .push_opcode(opcodes::All::OP_DROP)
            .push_scriptint(self.unlock_height.try_into().unwrap())
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(opcodes::All::OP_DROP);
        let builder = if !self.unlock_bytes.is_empty() {
            builder.push_slice(&self.unlock_bytes)
        } else {
            builder
        };
        builder.into_script()
    }

    /// Compute the sha256 hash of the timelock output script
    pub fn script_hash(&self) -> WitnessScriptHash {
        let output = self.to_redeem_script();
        let mut hasher = Sha256::new();
        hasher.update(output.as_bytes());
        WitnessScriptHash::from(hasher)
    }

    /// Compute the P2WSH output corresponding to this witnessScript (aka the "witness redeem
    /// script")
    pub fn to_p2wsh(&self) -> Script {
        self.to_redeem_script().to_v0_p2wsh()
    }

    /// Parse a Clarity value from `get-pool-info` or the self-staked entry
    /// into signer key and PoX address.
    fn parse_pox_entry(entry: Value, is_mainnet: bool) -> Result<([u8; 33], PoxAddress), String> {
        let entry_map = entry
            .expect_tuple()
            .map_err(|_| "Staking entry info should be tuple")?;

        let pox_addr_tuple = entry_map
            .get("pox-addr")
            .map_err(|_| "Staking entry info should have pox-addr")?;

        let pox_addr = PoxAddress::try_from_pox_tuple(is_mainnet, &pox_addr_tuple)
            .ok_or_else(|| format!("not a valid PoX address: {pox_addr_tuple}"))?;

        let Value::Sequence(SequenceData::Buffer(signer)) = entry_map
            .get("signer-key")
            .map_err(|_| "Staking entry info should have signer-key")?
        else {
            return Err("signer-key should be a buff".into());
        };

        let signer_key: [u8; SIGNERS_PK_LEN] = signer
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| [0; SIGNERS_PK_LEN]);

        Ok((signer_key, pox_addr))
    }

    /// Try parsing a value from PoX-5 into a `RawPox5Entry`, if any step of the parsing
    /// (or validation) fails, return a string error.
    fn try_parse(
        user: PrincipalData,
        value: Value,
        is_mainnet: bool,
        first_block_ht: u64,
        pox_constants: &PoxConstants,
    ) -> Result<Self, String> {
        let PrincipalData::Standard(user) = user else {
            return Err("Expected a standard principal, not a contract".into());
        };
        if is_mainnet != user.is_mainnet() {
            return Err("Expected in-network principal version".into());
        }
        let mut value = value
            .expect_tuple()
            .map_err(|_| "Staking entry should be a tuple")?;
        let num_cycles = value
            .data_map
            .get("num-cycles")
            .ok_or_else(|| "Staking entry should have num-cycles")?
            .clone()
            .expect_u128()
            .map_err(|_| "Staking entry should be uint")?;
        let first_reward_cycle = value
            .data_map
            .get("first-reward-cycle")
            .ok_or_else(|| "Staking entry should have first-reward-cycle")?
            .clone()
            .expect_u128()
            .map_err(|_| "Staking entry should be uint")?;
        let amount_ustx = value
            .data_map
            .get("amount-ustx")
            .ok_or_else(|| "Staking entry should have amount-ustx")?
            .clone()
            .expect_u128()
            .map_err(|_| "Staking entry should be uint")?;
        let unlock_bytes = value
            .data_map
            .remove("unlock-bytes")
            .ok_or_else(|| "Staking entry should have unlock-bytes")?
            .expect_buff(683)
            .map_err(|_| "Staking entry should be buff")?;
        let pool_or_solo_info = value
            .data_map
            .remove("pool-or-solo-info")
            .ok_or_else(|| "Staking entry should have pool-or-solo-info")?
            .expect_result()
            .map_err(|_| "Staking entry should be response")?;
        let pox_info = match pool_or_solo_info {
            Ok(pool_info) => RawPox5EntryInfo::Pool(
                pool_info
                    .expect_principal()
                    .map_err(|_| "Staking entry should be principal")?,
            ),
            Err(solo_info) => {
                let (signer_key, pox_addr) = Self::parse_pox_entry(solo_info, is_mainnet)?;
                RawPox5EntryInfo::Solo {
                    signer_key,
                    pox_addr,
                }
            }
        };

        let last_cycle: u64 = first_reward_cycle
            .saturating_add(num_cycles)
            .try_into()
            .map_err(|_| "Staking entry must have a u64 cycle number")?;
        let cycle_length = pox_constants.reward_cycle_length;
        let unlock_height: u32 = pox_constants
            .reward_cycle_to_block_height(first_block_ht, last_cycle)
            .try_into()
            .map_err(|_| "Staking entry must have a u32 unlock height")?;

        let unlock_height = unlock_height.saturating_add(cycle_length / 2);
        if unlock_height > u32::from_le_bytes([0xff, 0xff, 0xff, 0x00]) {
            return Err("Unlock height must be <= 0x00ffffff".into());
        }

        Ok(Self {
            user,
            num_cycles,
            first_reward_cycle,
            amount_ustx,
            unlock_bytes,
            pox_info,
            unlock_height,
        })
    }
}

pub struct StakeEntryIteratorPox5<'a, 'b, 'c> {
    current_staker: Option<PrincipalData>,
    pox_contract: QualifiedContractIdentifier,
    is_mainnet: bool,
    clarity: &'a mut ClarityTransactionConnection<'b, 'c>,
    reward_cycle_clar: SymbolicExpression,
    pox_constants: PoxConstants,
    first_block_ht: u64,
}

#[derive(Debug)]
pub enum PoxEntryParsingError {
    /// Errors for which PoX set calculation should continue, but skip
    ///  the offending entry.
    Skip(String),
    /// Errors for which PoX set calculation should abort.
    Abort(String),
}

impl<'a, 'b, 'c> StakeEntryIteratorPox5<'a, 'b, 'c> {
    fn fallible_next(&mut self) -> Result<Option<RawPox5Entry>, PoxEntryParsingError> {
        let Some(cur_staker) = self.current_staker.take() else {
            return Ok(None);
        };

        let lookup_staker = SymbolicExpression::atom_value(Value::Principal(cur_staker.clone()));
        // update the iterator using the linked list
        let next_staker = self
            .clarity
            .eval_method_read_only(
                &self.pox_contract,
                "get-staker-set-next-item-for-cycle",
                &[lookup_staker.clone(), self.reward_cycle_clar.clone()],
            )
            .map_err(|e| PoxEntryParsingError::Abort(e.to_string()))?
            .expect_optional()
            .map_err(|_| {
                PoxEntryParsingError::Abort(
                    "get-staker-set-next-item-for-cycle did not return optional".into(),
                )
            })?
            .map(|entry| entry.expect_principal())
            .transpose()
            .map_err(|_| {
                PoxEntryParsingError::Abort(
                    "get-staker-set-next-item-for-cycle did not return principal".into(),
                )
            })?;
        self.current_staker = next_staker;

        // errors below this point just continue the iterator, while errors above should
        //  cancel the calculation.
        let staker_entry_clar = self
            .clarity
            .eval_method_read_only(&self.pox_contract, "get-staker-info", &[lookup_staker])
            .map_err(|e| PoxEntryParsingError::Skip(e.to_string()))?
            .expect_optional()
            .map_err(|_| {
                PoxEntryParsingError::Skip("get-staker-info did not return optional".into())
            })?
            .ok_or_else(|| {
                PoxEntryParsingError::Skip(format!(
                    "get-staker-info did not return Some: {cur_staker}"
                ))
            })?;

        let staker_entry = RawPox5Entry::try_parse(
            cur_staker,
            staker_entry_clar,
            self.is_mainnet,
            self.first_block_ht,
            &self.pox_constants,
        )
        .map_err(PoxEntryParsingError::Skip)?;

        Ok(Some(staker_entry))
    }
}

impl<'a, 'b, 'c> Iterator for StakeEntryIteratorPox5<'a, 'b, 'c> {
    type Item = Result<RawPox5Entry, PoxEntryParsingError>;

    fn next(&mut self) -> Option<Self::Item> {
        StakeEntryIteratorPox5::fallible_next(self).transpose()
    }
}

impl NakamotoSigners {
    fn pox_5_stake_entries<'a, 'b, 'c>(
        clarity: &'a mut ClarityTransactionConnection<'b, 'c>,
        reward_cycle: u64,
        pox_contract: &str,
        pox_constants: PoxConstants,
        first_block_height: u64,
    ) -> Result<StakeEntryIteratorPox5<'a, 'b, 'c>, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let _pox_version = if let Some(pox_version) = PoxVersions::lookup_by_name(pox_contract) {
            if pox_version < PoxVersions::Pox5 {
                error!("Invoked PoX-5 reward-set fetch on lower than pox-5 contract");
                return Err(ChainstateError::DefunctPoxContract);
            }
            pox_version
        } else {
            error!("Invalid pox contract");
            return Err(ChainstateError::DefunctPoxContract);
        };

        let pox_contract = boot_code_id(pox_contract, is_mainnet);
        let reward_cycle_clar = SymbolicExpression::atom_value(Value::UInt(reward_cycle.into()));
        let current_staker = clarity
            .eval_method_read_only(
                &pox_contract,
                "get-staker-set-first-item-for-cycle",
                &[reward_cycle_clar.clone()],
            )?
            .expect_optional()
            .map_err(|_| {
                ChainstateError::Expects(
                    "get-staker-set-first-item-for-cycle did not return optional".into(),
                )
            })?
            .map(|value| value.expect_principal())
            .transpose()
            .map_err(|_| {
                ChainstateError::Expects(
                    "get-staker-set-first-item-for-cycle did not return optional principal".into(),
                )
            })?;

        Ok(StakeEntryIteratorPox5 {
            current_staker,
            pox_contract,
            is_mainnet,
            clarity,
            reward_cycle_clar,
            pox_constants,
            first_block_ht: first_block_height,
        })
    }

    fn get_reward_slots(
        clarity: &mut ClarityTransactionConnection,
        reward_cycle: u64,
        pox_contract: &str,
    ) -> Result<Vec<RawRewardSetEntry>, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let pox_version = if let Some(pox_version) = PoxVersions::lookup_by_name(pox_contract) {
            if pox_version < PoxVersions::Pox4 {
                error!("Invoked Nakamoto reward-set fetch on lower than pox-4 contract");
                return Err(ChainstateError::DefunctPoxContract);
            }
            pox_version
        } else {
            error!("Invalid pox contract");
            return Err(ChainstateError::DefunctPoxContract);
        };

        let pox_contract = &boot_code_id(pox_contract, is_mainnet);

        let list_length = clarity
            .eval_method_read_only(
                pox_contract,
                "get-reward-set-size",
                &[SymbolicExpression::atom_value(Value::UInt(
                    reward_cycle.into(),
                ))],
            )?
            .expect_u128()
            .map_err(|_| {
                ChainstateError::Expects("get-reward-set-size did not return u128".into())
            })?;

        let mut slots = vec![];
        for index in 0..list_length {
            let tuple = clarity
                .eval_method_read_only(
                    pox_contract,
                    "get-reward-set-pox-address",
                    &[
                        SymbolicExpression::atom_value(Value::UInt(reward_cycle.into())),
                        SymbolicExpression::atom_value(Value::UInt(index)),
                    ],
                )?
                .expect_optional().map_err(|_| {
                    ChainstateError::Expects("get-reward-set-pox-address did not return optional".into())
                })?
                .ok_or_else(|| {
                    ChainstateError::Expects(format!("Missing PoX address in slot {index} out of {list_length} in reward cycle {reward_cycle}"))
                })?
                .expect_tuple().map_err(|_| {
                    ChainstateError::Expects(format!("PoX address in slot {index} out of {list_length} in reward cycle {reward_cycle} is not a tuple"))
                })?;

            let entry = match pox_version {
                PoxVersions::Pox4 => RawRewardSetEntry::from_pox_4_tuple(is_mainnet, tuple)?,
                PoxVersions::Pox5 => RawRewardSetEntry::from_pox_5_tuple(is_mainnet, tuple)?,
                _ => return Err(ChainstateError::DefunctPoxContract),
            };
            slots.push(entry)
        }

        Ok(slots)
    }

    fn update_signers(
        clarity: &mut ClarityTransactionConnection,
        reward_cycle: u64,
        reward_set: &RewardSet,
        signers_contract: &QualifiedContractIdentifier,
        has_participation: bool,
        coinbase_height: u64,
        is_mainnet: bool,
    ) -> Result<Vec<StacksTransactionEvent>, ChainstateError> {
        let sender_addr = PrincipalData::from(boot::boot_code_addr(is_mainnet));
        let stackerdb_list = if !has_participation {
            vec![]
        } else {
            reward_set
                .signers
                .as_ref()
                .ok_or(ChainstateError::PoxNoRewardCycle)?
                .iter()
                .map(|signer| {
                    let signer_hash = Hash160::from_data(&signer.signing_key);
                    let signing_address = StacksAddress::p2pkh_from_hash(is_mainnet, signer_hash);
                    let tuple_data = TupleData::from_data(vec![
                        (
                            "signer".into(),
                            Value::Principal(PrincipalData::from(signing_address)),
                        ),
                        ("num-slots".into(), Value::UInt(1)),
                    ])
                    .map_err(|e| {
                        ChainstateError::Expects(format!(
                            "Failed to create tuple for stackerdb entry: {e}"
                        ))
                    })?;
                    Ok::<Value, ChainstateError>(Value::Tuple(tuple_data))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let signers_list = if !has_participation {
            vec![]
        } else {
            reward_set
                .signers
                .as_ref()
                .ok_or(ChainstateError::PoxNoRewardCycle)?
                .iter()
                .map(|signer| {
                    let signer_hash = Hash160::from_data(&signer.signing_key);
                    let signing_address = StacksAddress::p2pkh_from_hash(is_mainnet, signer_hash);
                    let tuple = TupleData::from_data(vec![
                        (
                            "signer".into(),
                            Value::Principal(PrincipalData::from(signing_address)),
                        ),
                        ("weight".into(), Value::UInt(signer.weight.into())),
                    ])
                    .map_err(|e| {
                        ChainstateError::Expects(format!(
                            "Failed to create tuple for signers entry: {e}"
                        ))
                    })?;
                    Ok::<Value, ChainstateError>(Value::Tuple(tuple))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        if signers_list.len() > SIGNERS_MAX_LIST_SIZE {
            return Err(ChainstateError::Expects(format!(
                "signers list returned by reward set calculations longer than maximum ({} > {SIGNERS_MAX_LIST_SIZE})",
                signers_list.len()
            )));
        }

        let set_stackerdb_args = [
            SymbolicExpression::atom_value(Value::cons_list_unsanitized(stackerdb_list).map_err(
                |e| {
                    ChainstateError::Expects(format!(
                        "Failed to create cons list for stackerdb arg: {e}"
                    ))
                },
            )?),
            SymbolicExpression::atom_value(Value::UInt(reward_cycle.into())),
            SymbolicExpression::atom_value(Value::UInt(coinbase_height.into())),
        ];

        let set_signers_args = [
            SymbolicExpression::atom_value(Value::UInt(reward_cycle.into())),
            SymbolicExpression::atom_value(Value::cons_list_unsanitized(signers_list).map_err(
                |e| {
                    ChainstateError::Expects(format!(
                        "Failed to create cons list for signers arg: {e}"
                    ))
                },
            )?),
        ];

        let (value, _, events, _) = clarity.with_abort_callback(
            |vm_env| {
                vm_env.execute_in_env(sender_addr.clone(), None, None, |exec_state, invoke_ctx| {
                    exec_state.execute_contract_allow_private(
                        invoke_ctx,
                        signers_contract,
                        "stackerdb-set-signer-slots",
                        &set_stackerdb_args,
                        false,
                    )?;
                    exec_state.execute_contract_allow_private(
                        invoke_ctx,
                        signers_contract,
                        "set-signers",
                        &set_signers_args,
                        false,
                    )
                })
            },
            |_, _| None,
        )?;

        if let Value::Response(ref data) = value {
            if !data.committed {
                error!(
                    "Error while updating .signers contract";
                    "reward_cycle" => reward_cycle,
                    "cc_response" => %value,
                );
                return Err(ChainstateError::Expects(
                    "Failed to update .signers contract".into(),
                ));
            }
        }

        Ok(events)
    }

    /// For PoX-4, compute the reward set for the next reward cycle,
    /// store it, and write it to the .signers contract.
    ///
    /// * `reward_cycle` is the reward cycle for the calculation (i.e., the next cycle).
    fn pox_4_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        let liquid_ustx = clarity.with_clarity_db_readonly(|db| db.get_total_liquid_ustx())?;
        let reward_slots = Self::get_reward_slots(clarity, reward_cycle, pox_contract)?;
        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            pox_constants,
            &reward_slots[..],
            liquid_ustx,
        );

        let reward_set =
            StacksChainState::make_reward_set(threshold, reward_slots, StacksEpochId::Epoch30);

        test_debug!("Reward set for cycle {}: {:?}", &reward_cycle, &reward_set);

        let events = Self::update_signers(
            clarity,
            reward_cycle,
            &reward_set,
            signers_contract,
            participation > 0,
            coinbase_height,
            is_mainnet,
        )?;

        Ok(SignerCalculation { events, reward_set })
    }

    /// For PoX-5, compute the reward set for the next reward cycle,
    /// store it, and write it to the .signers contract.
    ///
    /// * `reward_cycle` is the reward cycle for the calculation (i.e., the next cycle).
    /// * `last_computed_btc_height` is the btc height when the last reward cycle was calculated
    fn pox_5_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
        current_calculation_btc_height: u32,
        last_computed_btc_height: u32,
        sortition_dbconn: &dyn SortitionDBRef,
        current_epoch: &StacksEpochId,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        let first_burn_ht = sortition_dbconn.get_burn_start_height();
        let mut entries = Self::pox_5_stake_entries(
            clarity,
            reward_cycle,
            pox_contract,
            pox_constants.clone(),
            first_burn_ht.into(),
        )?;

        // do the p2wsh validation...
        let new_sortition_db = sortition_dbconn.reopen_handle();
        let mut sortition_handle = new_sortition_db.as_ref();
        let entries = validate_pox_p2wsh_outputs(
            &mut sortition_handle,
            &mut entries,
            last_computed_btc_height,
        )?;

        let ratio_percentiles_type = ListTypeData::new_list(
            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                BufferLength::try_from(512u32).map_err(|_| {
                    ChainstateError::Expects(
                        "FATAL: failed to setup ratio percentile clarity type".into(),
                    )
                })?,
            )),
            4,
        )
        .map_err(|_| {
            ChainstateError::Expects("FATAL: failed to setup ratio percentile clarity type".into())
        })?;
        let ratio_percentiles_type = DataVariableMetadata {
            value_type: ratio_percentiles_type.into(),
        };
        // store the last_computed_btc_height and fetch the prior percentile ranked ratios
        let prior_ratios_clar = clarity
            .with_clarity_db(|db| {
                db.set_variable(
                    signers_contract,
                    SIGNERS_LAST_UPDATED_BTC_HEIGHT,
                    Value::UInt(current_calculation_btc_height.into()),
                    &DataVariableMetadata {
                        value_type: TypeSignature::UIntType,
                    },
                    &current_epoch,
                )
                .map_err(|_| {
                    ClarityError::BadTransaction(
                        "FATAL: failed to set variable during reward set calculation".into(),
                    )
                })?;
                // load the prior 4 reward set's percentile ranked ratio
                let value = db
                    .lookup_variable(
                        signers_contract,
                        SIGNERS_LAST_RATIO_PERCENTILES,
                        &ratio_percentiles_type,
                        current_epoch,
                    )
                    .map_err(|_| {
                        ClarityError::BadTransaction(
                            "FATAL: failed to setup ratio percentile clarity type".into(),
                        )
                    })?;
                Ok(value)
            })
            .map_err(|e| {
                ChainstateError::Expects(format!(
                    "Failure setting SIGNERS_LAST_UPDATED_BTC_HEIGHT: {e}"
                ))
            })?;

        let ratios_result: Result<Vec<_>, String> = prior_ratios_clar
            .expect_list()
            .unwrap_or_else(|_| vec![])
            .into_iter()
            .map(|ratio_entry| {
                let ratio_buff = ratio_entry
                    .expect_buff(512)
                    .map_err(|e| format!("Expected buff for ratio entry: {e}"))?;
                Uint512::from_bytes_le(ratio_buff)
                    .ok_or_else(|| "Failed to parse ratio entry buffer to U512".into())
            })
            .collect();
        let prior_ratios = ratios_result.map_err(|e| {
            ChainstateError::Expects(format!(
                "Failure parsing stored prior reward cycle staking ratios: {e}"
            ))
        })?;

        // compute the reward set, and then update the signers db
        let pox_contract_id = boot_code_id(pox_contract, is_mainnet);
        let mut pool_provider = ClarityPox5PoolInfoProvider::new(clarity, &pox_contract_id);
        let (reward_set, new_ratios) =
            Self::pox_5_make_reward_set(entries, pox_constants, &mut pool_provider, prior_ratios)?;

        let new_ratios_clar: Result<Vec<_>, _> = new_ratios
            .into_iter()
            .map(|big_int| Value::buff_from(big_int.to_bytes_le().to_vec()))
            .collect();
        let new_ratios_clar = Value::cons_list_unsanitized(new_ratios_clar.map_err(|e| {
            ChainstateError::Expects(format!(
                "FATAL: failure storing reward cycle staking ratios as clarity values: {e}"
            ))
        })?)
        .map_err(|e| {
            ChainstateError::Expects(format!(
                "FATAL: failure storing reward cycle staking ratios as clarity values: {e}"
            ))
        })?;

        // store the now 4 most recent percentile ranked ratios
        clarity
            .with_clarity_db(|db| {
                db.set_variable(
                    signers_contract,
                    SIGNERS_LAST_RATIO_PERCENTILES,
                    new_ratios_clar,
                    &ratio_percentiles_type,
                    &current_epoch,
                )
                .map_err(|e| ClarityError::BadTransaction(e.to_string()))
            })
            .map_err(|e| {
                ChainstateError::Expects(format!(
                    "Failed to set SIGNERS_LAST_RATIO_PERCENTILES: {e}"
                ))
            })?;

        let events = Self::update_signers(
            clarity,
            reward_cycle,
            &reward_set,
            signers_contract,
            reward_set.rewarded_addresses.len() > 0,
            coinbase_height,
            is_mainnet,
        )?;

        // if we want to "write-back" any state to PoX-5 (e.g., computed weights)
        //  we should do it here

        Ok(SignerCalculation { reward_set, events })
    }

    pub fn pow_scaled(base: &Uint512, exp: u32, scaling: &Uint512) -> Uint512 {
        if exp == 0 {
            return Uint512::from_u64(1);
        }
        let mut output = *base;
        for _ in 1..exp {
            output = output * *base / *scaling;
        }
        output
    }

    pub fn find_root_floor(base: Uint512, root: u32, scaling: &Uint512) -> Option<Uint512> {
        if root == 1 {
            return Some(base);
        }
        if root == 0 {
            return None;
        }

        let mut low = Uint512::from_u64(1);
        let mut high = base;
        loop {
            if high <= low {
                return Some(high.min(low));
            }
            let guess = (high + low) / Uint512::from_u64(2);
            let value = Self::pow_scaled(&guess, root, scaling);
            if value == base {
                return Some(guess);
            } else if value > base {
                high = guess - Uint512::from_u64(1);
            } else if value < base {
                low = guess + Uint512::from_u64(1);
            }
        }
    }

    pub(crate) fn pox_5_make_reward_set<P: Pox5PoolInfoProvider>(
        entries: Vec<(RawPox5Entry, Vec<WatchedP2WSHOutputMetadata>)>,
        pox_constants: &PoxConstants,
        pool_info_provider: &mut P,
        prior_ratio_percentiles: Vec<Uint512>,
        // will probably need other arguments here to get the windowed averages for
        //  STX/BTC price ratio, STX/BTC 95th percentile ratios
    ) -> Result<(RewardSet, Vec<Uint512>), ChainstateError> {
        let SCALING_FACTOR = Uint512::from_u128(u128::MAX) + Uint512::one();

        // f_min := minimum amount of STX which can be staked for a given BTC stake
        let max_supported_lock_cycles = 12;
        let f_min_denominator = 100;
        let price_ratio = Uint512::from_u64(1);
        // d_min_t := minimum allowed stx / btc ratio scaled by SCALING_FACTOR
        let d_min_t = (price_ratio * SCALING_FACTOR) / Uint512::from_u64(f_min_denominator);
        // p := BTC-weighted Percentile to Define D
        let p = 95;
        // Maximum Ratio Multiplier
        let M_ratio_max = 10;
        // (Maximum Time - 1) numerator
        let M_time_max = 1;
        // (Maximum Time - 1) denominator
        let M_time_max_denominator = 2;

        info!("Entries: {}", entries.len());

        struct SummedPox5Entry {
            entry: RawPox5Entry,
            sats_locked: u64,
        }

        // transform our vec into one with summed entries
        let entries: Vec<_> = entries
            .into_iter()
            .map(|(entry, output)| {
                let sats_locked = output
                    .iter()
                    .fold(0, |acc, output| output.output.amount.saturating_add(acc));
                SummedPox5Entry { entry, sats_locked }
            })
            .collect();

        // Step 1: calculate d_i
        //
        // d_i_vec: d_i is a big int with fixed scaling of SCALING_FACTOR (128 bits)
        //  for ratio of stx/btc.
        // the vec is initially in the same order as entries
        let mut d_i_vec = Vec::new();
        let mut total_btc_locked = 0;
        let mut total_ustx_locked = 0;
        for entry in entries.iter() {
            total_btc_locked = entry.sats_locked.saturating_add(total_btc_locked);
            total_ustx_locked = entry.entry.amount_ustx.saturating_add(total_ustx_locked);
            let ustx_locked = Uint512::from_u128(entry.entry.amount_ustx) * SCALING_FACTOR;
            if entry.sats_locked < 1 {
                // should be unreachable, but better safe
                continue;
            }
            let sats_locked = Uint512::from_u64(entry.sats_locked);
            let d_i = ustx_locked / sats_locked;
            if d_i < d_min_t {
                warn!(
                    "PoX entry had STX/BTC ratio less than the minimum";
                    "d_i_scaled" => %d_i,
                    "d_min" => %d_min_t
                );
                continue;
            }
            // Overflow sanity check:
            // d_i is at most u128::MAX, scaled by 128 bits,
            // so d_i must have 256 empty high bits
            assert_eq!(d_i.0[7], 0);
            assert_eq!(d_i.0[6], 0);
            assert_eq!(d_i.0[5], 0);
            assert_eq!(d_i.0[4], 0);
            d_i_vec.push((d_i, entry));
        }

        // make copy for use in computing w_i later
        let mut w_i_vec = d_i_vec.clone();
        // Step 2: compute D_t -- the BTC weighted pth-percentile of d in this cycle
        // D_t is scaled by SCALING FACTOR
        d_i_vec.sort_by_key(|(d_i, _)| *d_i);
        let total_target_btc_locked = (total_btc_locked / 100) * p;
        let mut total_locked_so_far = 0;
        let mut D_t = Uint512::from_u64(0);
        for (d_i, entry) in d_i_vec {
            total_locked_so_far = entry.sats_locked.saturating_add(total_locked_so_far);
            D_t = d_i;
            if total_locked_so_far >= total_target_btc_locked {
                break;
            }
        }

        // Compute the GeoWeightedAvg for D
        if prior_ratio_percentiles.len() > 4 {
            return Err(ChainstateError::Expects(
                "Prior ratio percentiles length must be less than 4".into(),
            ));
        }
        let weighting = 5;
        let lowest_weight = weighting - prior_ratio_percentiles.len() as u32;
        let total_weight = (lowest_weight..=weighting).sum();
        let D_t_contrib = Self::find_root_floor(
            Self::pow_scaled(&D_t, weighting, &SCALING_FACTOR),
            total_weight,
            &SCALING_FACTOR,
        );
        let D_avg = prior_ratio_percentiles
            .iter()
            .enumerate()
            .fold(D_t_contrib, |acc, (index, prior_ratio)| {
                // will not underflow because of the check for len() > 4 above
                let exponent = weighting - 1 - (index as u32);
                let contribution = Self::find_root_floor(
                    Self::pow_scaled(prior_ratio, exponent, &SCALING_FACTOR),
                    total_weight,
                    &SCALING_FACTOR,
                )?;
                Some(acc? * contribution / SCALING_FACTOR)
            })
            .ok_or_else(|| {
                ChainstateError::Expects("Failed to find w-th root for D calculations".into())
            })?;

        // Overflow sanity check:
        // D_avg is at most u128::MAX, scaled by 128 bits,
        // so D_avg must have 256 empty high bits
        assert_eq!(D_avg.0[7], 0);
        assert_eq!(D_avg.0[6], 0);
        assert_eq!(D_avg.0[5], 0);
        assert_eq!(D_avg.0[4], 0);

        let mut ratios_to_store = Vec::with_capacity(4);
        ratios_to_store.push(D_t);
        ratios_to_store.extend(prior_ratio_percentiles.into_iter().take(3));

        // Step 3: Compute w_i scaled by SCALING_FACTOR
        let mut W = Uint512::zero();
        for (d_i, entry) in w_i_vec.iter_mut() {
            let r_i = if *d_i >= D_avg {
                SCALING_FACTOR // 1
            } else {
                // Overflow sanity check: d_i has 256 empty high bits,
                //  so scaling 128 bits cannot overflow
                // D_avg > d_i, so the following calculation
                // leads to a number between 0 and 1, scaled by SCALING_FACTOR
                *d_i * SCALING_FACTOR / D_avg
            };
            // Overflow sanity check:
            // r_i is at most 1, scaled by 128 bits,
            // so r_i must have 256 + 127 empty high bits
            assert_eq!(r_i.0[7], 0);
            assert_eq!(r_i.0[6], 0);
            assert_eq!(r_i.0[5], 0);
            assert_eq!(r_i.0[4], 0);
            assert_eq!(r_i.0[3], 0);
            assert!(r_i.0[2] <= 1);

            // s_i_numer has scaling factor of 256
            let s_i_numer = r_i * r_i;
            // s_i_denom has a scaling factor of 256
            let s_i_denom = (r_i * r_i) + ((SCALING_FACTOR - r_i) * (SCALING_FACTOR - r_i));
            // drop scaling factor of s_i_denom by 128
            // s_i is the sigmoid output, scaled by SCALING_FACTOR
            let s_i = s_i_numer / (s_i_denom / SCALING_FACTOR);

            // s_i should be <= 1
            // Overflow sanity check:
            // s_i is at most 1, scaled by 128 bits,
            // so s_i must have 256 + 127 empty high bits
            assert_eq!(s_i.0[7], 0);
            assert_eq!(s_i.0[6], 0);
            assert_eq!(s_i.0[5], 0);
            assert_eq!(s_i.0[4], 0);
            assert_eq!(s_i.0[3], 0);
            assert!(s_i.0[2] <= 1);

            // ratio_multiplier is M_ratio_i scaled by SCALING_FACTOR
            // this is at most u32::max (but in constants used, 10)
            // so ratio multiplier has 256 + 96 empty high bits
            let ratio_multiplier = SCALING_FACTOR + s_i.mul_u32(M_ratio_max - 1);
            let time_multiplier_user = SCALING_FACTOR
                * Uint512::from_u128(
                    entry
                        .entry
                        .num_cycles
                        .min(max_supported_lock_cycles)
                        .saturating_sub(1),
                )
                / Uint512::from_u128(max_supported_lock_cycles.saturating_sub(1));
            // time_multiplier is scaled by SCALING_FACTOR
            // this is at most u32::max (but in constants used, 1.5)
            // so time multiplier has 256 + 96 empty high bits
            let time_multiplier = SCALING_FACTOR
                + (time_multiplier_user.mul_u32(M_time_max)
                    / Uint512::from_u64(M_time_max_denominator));

            // overflow sanity check: multiplying ratio_multiplier by
            // time_multiplier occupies at most 160 bits of the 352 available
            let user_multiplier = time_multiplier * ratio_multiplier / SCALING_FACTOR;
            // user_multiplier has scaling factor of SCALING_FACTOR

            // w_i has scaling factor of SCALING_FACTOR
            let w_i = user_multiplier * Uint512::from_u64(entry.sats_locked);
            W = W + w_i;
            *d_i = w_i;
        }

        // Step 4: accumulate pools
        let mut totaled_entries = vec![];
        let mut pooled_entries = HashMap::new();
        for (w_i, entry) in w_i_vec.into_iter() {
            match &entry.entry.pox_info {
                RawPox5EntryInfo::Pool(principal_data) => {
                    let (cur_w, cur_stx_amt) = pooled_entries
                        .entry(principal_data)
                        .or_insert((Uint512::zero(), 0u128));
                    *cur_w = *cur_w + w_i;
                    *cur_stx_amt += entry.entry.amount_ustx;
                }
                RawPox5EntryInfo::Solo {
                    pox_addr,
                    signer_key,
                } => {
                    totaled_entries.push((
                        pox_addr.clone(),
                        *signer_key,
                        w_i,
                        entry.entry.amount_ustx,
                    ));
                }
            }
        }
        // translate pooled_entries into totaled_entries
        for (pool_principal, (w_i, stx_locked)) in pooled_entries.into_iter() {
            match pool_info_provider.get_pool_info(pool_principal) {
                Ok(Some((signer_key, pox_addr))) => {
                    totaled_entries.push((pox_addr, signer_key, w_i, stx_locked));
                }
                Ok(None) => {
                    warn!("No pool entry found, dropping from reward set"; "pool" => %pool_principal);
                }
                Err(PoxEntryParsingError::Skip(e)) => {
                    warn!("Failed to parse pool entry, dropping from reward set"; "pool" => %pool_principal, "err" => %e);
                }
                Err(PoxEntryParsingError::Abort(e)) => {
                    error!("Unexpected error while fetching pool entry, aborting calculation"; "err" => %e);
                    return Err(ChainstateError::Expects(e));
                }
            }
        }

        // Step 5: assign slots
        let reward_slots = pox_constants.reward_slots();
        let mut rewarded_addresses = Vec::with_capacity(reward_slots as usize);
        // same scaling as W and w_i
        let reward_slot_threshold = W / Uint512::from_u64(reward_slots.into());
        for (pox_addr, _, w_i, _) in totaled_entries.iter() {
            // reward_slot_threshold has same scaling as w_i,
            //  so, this result is unscaled
            let slots_assigned = *w_i / reward_slot_threshold;
            let slots_assigned = slots_assigned.low_u32();
            for _ in 0..slots_assigned {
                rewarded_addresses.push((*pox_addr).clone());
            }
        }

        // Step 6: assign signer weights
        //
        // We need to set a threshold amount for signing participation,
        //  so we set a threshold based on total_ustx_locked / reward_slots
        let signer_weight_scaling = Uint256::from_u64(reward_slots.into());
        let signer_threshold_ustx = total_ustx_locked / u128::from(reward_slots);
        let total_ustx_locked_256 = Uint256::from_u128(total_ustx_locked);
        let mut signers = vec![];
        for (_, signer, _, amount_ustx) in totaled_entries.iter() {
            if *amount_ustx < signer_threshold_ustx {
                warn!("Dropping signer who did not have enough ustx locked";
                      "signer_pk" => to_hex(signer),
                      "amount_ustx" => amount_ustx,
                      "threshold" => signer_threshold_ustx,
                      "total_ustx_locked" => total_ustx_locked,
                );
                continue;
            }
            let amount_ustx_scaled = Uint256::from_u128(*amount_ustx) * signer_weight_scaling;
            let signer_weight = amount_ustx_scaled / total_ustx_locked_256;
            signers.push(NakamotoSignerEntry {
                signing_key: *signer,
                stacked_amt: *amount_ustx,
                weight: signer_weight.low_u32(),
            });
        }

        Ok((
            RewardSet {
                rewarded_addresses,
                start_cycle_state: PoxStartCycleInfo {
                    missed_reward_slots: vec![],
                },
                signers: Some(signers),
                pox_ustx_threshold: Some(signer_threshold_ustx),
            },
            ratios_to_store,
        ))
    }

    /// If this block is mined in the prepare phase, based on its tenure's `burn_tip_height`.  If
    /// so, and if we haven't done so yet, then compute the PoX reward set, store it, and update
    /// the .signers contract.  The stored PoX reward set is the reward set for the next reward
    /// cycle, and will be used by the Nakamoto chains coordinator to validate its block-commits
    /// and block signatures.
    pub fn check_and_handle_prepare_phase_start(
        clarity_tx: &mut ClarityTx,
        sortition_dbconn: &dyn SortitionDBRef,
        first_block_height: u64,
        pox_constants: &PoxConstants,
        burn_tip_height: u32,
        coinbase_height: u64,
    ) -> Result<Option<SignerCalculation>, ChainstateError> {
        let current_epoch = clarity_tx.get_epoch();
        if current_epoch < StacksEpochId::Epoch25 {
            // before Epoch-2.5, no need for special handling
            return Ok(None);
        }

        // now, determine if we are in a prepare phase, and we are the first
        //  block in this prepare phase in our fork
        if !pox_constants.is_in_prepare_phase(first_block_height, burn_tip_height.into()) {
            // if we're not in a prepare phase, don't need to do anything
            return Ok(None);
        }

        let Some(cycle_of_prepare_phase) =
            pox_constants.reward_cycle_of_prepare_phase(first_block_height, burn_tip_height.into())
        else {
            // if we're not in a prepare phase, don't need to do anything
            return Ok(None);
        };

        let active_pox_contract = pox_constants.active_pox_contract(burn_tip_height.into());

        let Some(current_pox_version) = PoxVersions::lookup_by_name(active_pox_contract) else {
            debug!("Active PoX contract is not a recognized version, skipping .signers updates");
            return Ok(None);
        };

        if current_pox_version < PoxVersions::Pox4 {
            debug!(
                "Active PoX contract is lower than PoX-4, skipping .signers updates until PoX-4 is active"
            );
            return Ok(None);
        }

        let signers_contract = &boot_code_id(SIGNERS_NAME, clarity_tx.config.mainnet);

        // are we the first block in the prepare phase in our fork?
        let needs_update_result: Result<_, ChainstateError> = clarity_tx
            .connection()
            .with_clarity_db_readonly(|clarity_db| {
                if !clarity_db.has_contract(signers_contract) {
                    // if there's no signers contract, no need to update anything.
                    return Ok((false, 0));
                }
                let value = clarity_db.lookup_variable_unknown_descriptor(
                    signers_contract,
                    SIGNERS_UPDATE_STATE,
                    &current_epoch,
                )?;
                let cycle_number = value.expect_u128().map_err(|_| {
                    ChainstateError::Expects(format!(
                        "Expected u128 for .signers {SIGNERS_UPDATE_STATE} variable"
                    ))
                })?;
                let needs_update = cycle_number < u128::from(cycle_of_prepare_phase);

                let last_update_btc_height: u32 = if needs_update && current_pox_version.performs_btc_lookback() {
                    let value = clarity_db.lookup_variable(
                        signers_contract,
                        SIGNERS_LAST_UPDATED_BTC_HEIGHT,
                        &DataVariableMetadata {
                            value_type: TypeSignature::UIntType,
                        },
                        &current_epoch,
                    )?;
                    value
                        .expect_u128()
                        // if its not a u128, then it means the value has not been stored yet, so default to 0
                        .unwrap_or(0)
                        .try_into()
                        .map_err(|_|
                            ChainstateError::Expects(format!(
                                "Expected u32 for .signers {SIGNERS_LAST_UPDATED_BTC_HEIGHT} variable"
                            ))
                        )?
                } else {
                    0
                };
                // if the cycle_number is less than `cycle_of_prepare_phase`, we need to update
                //  the .signers state.
                Ok((needs_update, last_update_btc_height))
            });

        let (needs_update, last_update_btc_height) = needs_update_result?;

        if !needs_update {
            debug!("Current cycle has already been setup in .signers or .signers is not initialized yet");
            return Ok(None);
        }

        info!(
            "Performing .signers state update";
            "burn_height" => burn_tip_height,
            "for_cycle" => cycle_of_prepare_phase,
            "coinbase_height" => coinbase_height,
            "signers_contract" => %signers_contract,
            "last_update_btc_height" => last_update_btc_height
        );

        clarity_tx
            .connection()
            .as_free_transaction(|clarity| match current_pox_version {
                PoxVersions::Pox1 | PoxVersions::Pox2 | PoxVersions::Pox3 => {
                    Err(ChainstateError::Expects(
                        "Unexpected Pre-Nakamoto PoX version when computing signer set".into(),
                    ))
                }
                PoxVersions::Pox4 => Self::pox_4_compute_and_update_signers(
                    clarity,
                    pox_constants,
                    cycle_of_prepare_phase,
                    active_pox_contract,
                    coinbase_height,
                ),
                PoxVersions::Pox5 => Self::pox_5_compute_and_update_signers(
                    clarity,
                    pox_constants,
                    cycle_of_prepare_phase,
                    active_pox_contract,
                    coinbase_height,
                    burn_tip_height,
                    last_update_btc_height,
                    sortition_dbconn,
                    &current_epoch,
                ),
            })
            .map(Some)
    }

    /// Make the contract name for a signers DB contract
    pub fn make_signers_db_name(reward_cycle: u64, message_id: u32) -> String {
        format!("{}-{}-{}", &SIGNERS_NAME, reward_cycle % 2, message_id)
    }

    /// Make the contract ID for a signers DB contract
    pub fn make_signers_db_contract_id(
        reward_cycle: u64,
        message_id: u32,
        mainnet: bool,
    ) -> QualifiedContractIdentifier {
        let name = Self::make_signers_db_name(reward_cycle, message_id);
        boot_code_id(&name, mainnet)
    }

    /// Get the signer addresses and corresponding weights for a given reward cycle
    pub fn get_signers_weights(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, u64>, ChainstateError> {
        let signers_opt = chainstate
            .eval_boot_code_read_only(
                sortdb,
                block_id,
                SIGNERS_NAME,
                &format!("(get-signers u{reward_cycle})"),
            )?
            .expect_optional()
            .map_err(|_| ChainstateError::Expects("get-signers did not return optional".into()))?;
        let mut signers = HashMap::new();
        if let Some(signers_list) = signers_opt {
            for signer in signers_list
                .expect_list()
                .map_err(|_| ChainstateError::Expects("get-signers did not return a list".into()))?
            {
                let signer_tuple = signer.expect_tuple().map_err(|_| {
                    ChainstateError::Expects(
                        "Signer returned from get-signers is not a tuple".into(),
                    )
                })?;
                let principal_data = signer_tuple
                    .get("signer")
                    .map_err(|_| {
                        ChainstateError::Expects("Failed to get 'signer' from tuple".into())
                    })?
                    .clone()
                    .expect_principal()
                    .map_err(|_| {
                        ChainstateError::Expects("'signer' in tuple is not a principal".into())
                    })?;
                let signer_address = if let PrincipalData::Standard(signer) = principal_data {
                    signer.into()
                } else {
                    return Err(ChainstateError::Expects(
                        "Signer returned from get-signers is not a standard principal".into(),
                    ));
                };
                let weight = u64::try_from(
                    signer_tuple
                        .get("weight")
                        .map_err(|_| {
                            ChainstateError::Expects("Failed to get 'weight' from tuple".into())
                        })?
                        .to_owned()
                        .expect_u128()
                        .map_err(|_| {
                            ChainstateError::Expects("'weight' in tuple is not a u128".into())
                        })?,
                )
                .map_err(|_| {
                    ChainstateError::Expects("Signer weight greater than a u64::MAX".into())
                })?;
                signers.insert(signer_address, weight);
            }
        }
        if signers.is_empty() {
            error!(
                "No signers found for reward cycle";
                "reward_cycle" => reward_cycle,
            );
            return Err(ChainstateError::NoRegisteredSigners(reward_cycle));
        }
        Ok(signers)
    }

    /// Verify that the transaction is a valid vote for the aggregate public key
    /// Note: it does not verify the function arguments, only that the transaction is validly formed
    /// and has a valid nonce from an expected address
    pub fn valid_vote_transaction(
        account_nonces: &HashMap<StacksAddress, u64>,
        transaction: &StacksTransaction,
        is_mainnet: bool,
    ) -> bool {
        let origin_address = transaction.origin_address();
        let origin_nonce = transaction.get_origin_nonce();
        let Some(account_nonce) = account_nonces.get(&origin_address) else {
            debug!("valid_vote_transaction: Unrecognized origin address ({origin_address}).",);
            return false;
        };
        if transaction.is_mainnet() != is_mainnet {
            debug!("valid_vote_transaction: Received a transaction for an unexpected network.",);
            return false;
        }
        if origin_nonce < *account_nonce {
            debug!("valid_vote_transaction: Received a transaction with an outdated nonce ({origin_nonce} < {account_nonce}).");
            return false;
        }
        Self::parse_vote_for_aggregate_public_key(transaction).is_some()
    }

    pub fn parse_vote_for_aggregate_public_key(
        transaction: &StacksTransaction,
    ) -> Option<AggregateKeyVoteParams> {
        let TransactionPayload::ContractCall(payload) = &transaction.payload else {
            // Not a contract call so not a special cased vote for aggregate public key transaction
            return None;
        };
        if payload.contract_identifier()
            != boot_code_id(SIGNERS_VOTING_NAME, transaction.is_mainnet())
            || payload.function_name != SIGNERS_VOTING_FUNCTION_NAME.into()
        {
            // This is not a special cased transaction.
            return None;
        }
        if payload.function_args.len() != 4 {
            return None;
        }
        let signer_index_value = payload.function_args.first()?;
        let signer_index = u64::try_from(signer_index_value.clone().expect_u128().ok()?).ok()?;
        let aggregate_key_value = payload.function_args.get(1)?;
        let aggregate_key = aggregate_key_value.clone().expect_buff(33).ok()?;
        let round_value = payload.function_args.get(2)?;
        let voting_round = u64::try_from(round_value.clone().expect_u128().ok()?).ok()?;
        let reward_cycle =
            u64::try_from(payload.function_args.get(3)?.clone().expect_u128().ok()?).ok()?;
        Some(AggregateKeyVoteParams {
            signer_index,
            aggregate_key,
            voting_round,
            reward_cycle,
        })
    }

    /// Update the map of filtered valid transactions, selecting one per address based first on lowest nonce, then txid
    pub fn update_filtered_transactions(
        filtered_transactions: &mut HashMap<StacksAddress, StacksTransaction>,
        account_nonces: &HashMap<StacksAddress, u64>,
        mainnet: bool,
        transactions: Vec<StacksTransaction>,
    ) {
        for transaction in transactions {
            if NakamotoSigners::valid_vote_transaction(account_nonces, &transaction, mainnet) {
                let origin_address = transaction.origin_address();
                let origin_nonce = transaction.get_origin_nonce();
                if let Some(entry) = filtered_transactions.get_mut(&origin_address) {
                    let entry_nonce = entry.get_origin_nonce();
                    if entry_nonce > origin_nonce
                        || (entry_nonce == origin_nonce && entry.txid() > transaction.txid())
                    {
                        *entry = transaction;
                    }
                } else {
                    filtered_transactions.insert(origin_address, transaction);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use clarity::vm::types::{PrincipalData, StandardPrincipalData};
    use stacks_common::types::chainstate::StacksAddress;
    use stacks_common::util::hash::Hash160;

    use super::*;
    use crate::burnchains::bitcoin::WatchedP2WSHOutput;
    use crate::burnchains::PoxConstants;
    use crate::chainstate::burn::db::sortdb::WatchedP2WSHOutputMetadata;
    use crate::chainstate::burn::ConsensusHash;
    use crate::chainstate::stacks::address::PoxAddress;

    /// Mock implementation of Pox5PoolInfoProvider for testing
    struct MockPox5PoolInfoProvider {
        pools: HashMap<PrincipalData, ([u8; 33], PoxAddress)>,
    }

    impl MockPox5PoolInfoProvider {
        fn new() -> Self {
            Self {
                pools: HashMap::new(),
            }
        }

        fn add_pool(&mut self, principal: PrincipalData, key: [u8; 33], addr: PoxAddress) {
            self.pools.insert(principal, (key, addr));
        }
    }

    impl Pox5PoolInfoProvider for MockPox5PoolInfoProvider {
        fn get_pool_info(
            &mut self,
            pool_principal: &PrincipalData,
        ) -> Result<Option<([u8; 33], PoxAddress)>, PoxEntryParsingError> {
            Ok(self.pools.get(pool_principal).cloned())
        }
    }

    fn make_test_watched_output(sats: u64) -> WatchedP2WSHOutputMetadata {
        use crate::burnchains::Txid;

        // Create a minimal watched output for testing
        WatchedP2WSHOutputMetadata {
            output: WatchedP2WSHOutput {
                witness_script_hash: WitnessScriptHash([0u8; 32]),
                amount: sats,
                txid: Txid([0u8; 32]),
                vout: 0,
            },
            at_block_ch: ConsensusHash([0u8; 20]),
            at_block_ht: 100,
        }
    }

    fn make_test_pox_constants() -> PoxConstants {
        PoxConstants::new(
            5,    // reward_cycle_length
            3,    // prepare_length
            3,    // anchor_threshold
            10,   // pox_rejection_fraction
            10,   // pox_participation_threshold_pct
            5000, // sunset_start
            5100, // sunset_end
            1000, // v1_unlock_height
            2000, // v2_unlock_height
            3000, // v3_unlock_height
            2000, // pox_3_activation_height
            4000, // v4_unlock_height
        )
    }

    #[test]
    fn test_pox_5_make_reward_set_solo_only() {
        let mut provider = MockPox5PoolInfoProvider::new();
        let pox_constants = make_test_pox_constants();

        // Create solo staker entries
        let pox_addr1 =
            PoxAddress::Standard(StacksAddress::new(0, Hash160([1u8; 20])).unwrap(), None);
        let signer_key1 = [11u8; 33];

        let pox_addr2 =
            PoxAddress::Standard(StacksAddress::new(0, Hash160([2u8; 20])).unwrap(), None);
        let signer_key2 = [22u8; 33];

        let entry1 = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 1000000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: pox_addr1.clone(),
                signer_key: signer_key1,
            },
        };

        let entry2 = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 2000000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: pox_addr2.clone(),
                signer_key: signer_key2,
            },
        };

        let entries = vec![
            (entry1, vec![make_test_watched_output(1000000)]),
            (entry2, vec![make_test_watched_output(1000000)]),
        ];

        let result =
            NakamotoSigners::pox_5_make_reward_set(entries, &pox_constants, &mut provider, vec![]);

        assert!(result.is_ok());
        let (reward_set, _new_ratios) = result.unwrap();

        // Verify signers were created
        assert!(reward_set.signers.is_some());
        let signers = reward_set.signers.unwrap();
        assert_eq!(signers.len(), 2);

        // Verify both signers are present
        assert!(signers.iter().any(|s| s.signing_key == signer_key1));
        assert!(signers.iter().any(|s| s.signing_key == signer_key2));

        // Verify stacked amounts
        let signer1 = signers
            .iter()
            .find(|s| s.signing_key == signer_key1)
            .unwrap();
        let signer2 = signers
            .iter()
            .find(|s| s.signing_key == signer_key2)
            .unwrap();
        assert_eq!(signer1.stacked_amt, 1000000);
        assert_eq!(signer2.stacked_amt, 2000000);
    }

    #[test]
    fn test_pox_5_make_reward_set_pool_only() {
        let mut provider = MockPox5PoolInfoProvider::new();
        let pox_constants = make_test_pox_constants();

        // Set up pool info
        let pool_principal = PrincipalData::from(StandardPrincipalData::transient());
        let pool_signer_key = [99u8; 33];
        let pool_pox_addr =
            PoxAddress::Standard(StacksAddress::new(0, Hash160([99u8; 20])).unwrap(), None);
        provider.add_pool(
            pool_principal.clone(),
            pool_signer_key,
            pool_pox_addr.clone(),
        );

        // Create pool staker entries
        let entry1 = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 1500000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Pool(pool_principal.clone()),
        };

        let entry2 = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 2500000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Pool(pool_principal),
        };

        let entries = vec![
            (entry1, vec![make_test_watched_output(1000000)]),
            (entry2, vec![make_test_watched_output(1000000)]),
        ];

        let result =
            NakamotoSigners::pox_5_make_reward_set(entries, &pox_constants, &mut provider, vec![]);

        assert!(result.is_ok());
        let (reward_set, _new_ratios) = result.unwrap();

        // Verify signers - pool entries should be aggregated into one signer
        assert!(reward_set.signers.is_some());
        let signers = reward_set.signers.unwrap();
        assert_eq!(
            signers.len(),
            1,
            "Pool entries should be aggregated into one signer"
        );

        let pool_signer = &signers[0];
        assert_eq!(pool_signer.signing_key, pool_signer_key);
        assert_eq!(
            pool_signer.stacked_amt, 4000000,
            "Pool amounts should be summed"
        );
    }

    #[test]
    fn test_pox_5_make_reward_set_mixed_solo_and_pool() {
        let mut provider = MockPox5PoolInfoProvider::new();
        let pox_constants = make_test_pox_constants();

        // Set up pool info
        let pool_principal = PrincipalData::from(StandardPrincipalData::transient());
        let pool_signer_key = [88u8; 33];
        let pool_pox_addr =
            PoxAddress::Standard(StacksAddress::new(0, Hash160([88u8; 20])).unwrap(), None);
        provider.add_pool(
            pool_principal.clone(),
            pool_signer_key,
            pool_pox_addr.clone(),
        );

        // Create mixed entries
        let solo_pox_addr =
            PoxAddress::Standard(StacksAddress::new(0, Hash160([10u8; 20])).unwrap(), None);
        let solo_signer_key = [10u8; 33];

        let solo_entry = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 3000000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Solo {
                pox_addr: solo_pox_addr.clone(),
                signer_key: solo_signer_key,
            },
        };

        let pool_entry = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 7000000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Pool(pool_principal),
        };

        let entries = vec![
            (solo_entry, vec![make_test_watched_output(1000000)]),
            (pool_entry, vec![make_test_watched_output(1000000)]),
        ];

        let result =
            NakamotoSigners::pox_5_make_reward_set(entries, &pox_constants, &mut provider, vec![]);

        assert!(result.is_ok());
        let (reward_set, _new_ratios) = result.unwrap();

        // Verify both solo and pool signers are present
        assert!(reward_set.signers.is_some());
        let signers = reward_set.signers.unwrap();
        assert_eq!(signers.len(), 2);

        assert!(signers
            .iter()
            .any(|s| s.signing_key == solo_signer_key && s.stacked_amt == 3000000));
        assert!(signers
            .iter()
            .any(|s| s.signing_key == pool_signer_key && s.stacked_amt == 7000000));
    }

    #[test]
    fn test_pox_5_make_reward_set_missing_pool_info() {
        let mut provider = MockPox5PoolInfoProvider::new();
        let pox_constants = make_test_pox_constants();

        // Create pool entry but DON'T add pool info to provider
        let missing_pool_principal = PrincipalData::from(StandardPrincipalData::transient());

        let pool_entry = RawPox5Entry {
            user: StandardPrincipalData::transient(),
            num_cycles: 1,
            unlock_bytes: vec![],
            amount_ustx: 5000000,
            first_reward_cycle: 0,
            unlock_height: 1000,
            pox_info: RawPox5EntryInfo::Pool(missing_pool_principal),
        };

        let entries = vec![(pool_entry, vec![make_test_watched_output(1000000)])];

        let result =
            NakamotoSigners::pox_5_make_reward_set(entries, &pox_constants, &mut provider, vec![]);

        // Should succeed but skip the missing pool entry
        assert!(result.is_ok());
        let (reward_set, _new_ratios) = result.unwrap();

        // No signers should be created since the only entry was skipped
        assert!(reward_set.signers.is_some());
        let signers = reward_set.signers.unwrap();
        assert_eq!(signers.len(), 0, "Missing pool entries should be skipped");
    }
}
