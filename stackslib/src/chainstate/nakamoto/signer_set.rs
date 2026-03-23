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

use clarity::vm::clarity::ClarityError;
use clarity::vm::database::DataVariableMetadata;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData, TupleData, TypeSignature};
use clarity::vm::{SymbolicExpression, Value};
use sha2::{Digest, Sha256};
use stacks_common::deps_common::bitcoin::blockdata::opcodes;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{to_hex, Hash160};

use crate::burnchains::PoxConstants;
use crate::burnchains::bitcoin::WitnessScriptHash;
use crate::chainstate::burn::db::sortdb::{validate_pox_p2wsh_outputs, SortitionDB};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{
    PoxVersions, RawRewardSetEntry, RewardSet, SIGNERS_LAST_UPDATED_BTC_HEIGHT,
    SIGNERS_MAX_LIST_SIZE, SIGNERS_NAME, SIGNERS_PK_LEN, SIGNERS_UPDATE_STATE,
    SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum RawPox5EntryInfo {
    Pool(PrincipalData),
    Solo {
        pox_addr: PoxAddress,
        signer_key: [u8; 33],
    },
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct RawPox5Entry {
    user: StandardPrincipalData,
    num_cycles: u128,
    unlock_bytes: Vec<u8>,
    amount_ustx: u128,
    first_reward_cycle: u128,
    unlock_height: u32,
    pox_info: RawPox5EntryInfo,
}

impl RawPox5Entry {
    pub fn script_hash(&self) -> WitnessScriptHash {
        let mut hasher = Sha256::new();
        hasher.update(&[opcodes::All::OP_PUSHBYTES_22 as u8, self.user.version()]);
        // todo: must validate `self.user.version == 0x05`
        hasher.update(&self.user.1);
        hasher.update(&[opcodes::All::OP_DROP as u8, opcodes::All::OP_PUSHBYTES_3 as u8]);
        hasher.update(&self.unlock_height.to_le_bytes()[0..3]);
        hasher.update(&[opcodes::OP_CLTV as u8, opcodes::All::OP_DROP as u8]);
        hasher.update(&self.unlock_bytes);
        WitnessScriptHash::from(hasher)
    }

    // Note: All of these errors *exit* reward set processing. Should they just skip the given entry?
    fn try_parse(user: PrincipalData, value: Value, is_mainnet: bool, first_block_ht: u64, pox_constants: &PoxConstants) -> Result<Self, String> {
        let PrincipalData::Standard(user) = user else {
            return Err("Expected a standard principal, not a contract".into());
        };
        let mut value = value.expect_tuple().map_err(|_| "Staking entry should be a tuple")?;
        let num_cycles = value.data_map.get("num-cycles")
            .ok_or_else(|| "Staking entry should have num-cycles")?
            .clone()
            .expect_u128()
            .map_err(|_| "Staking entry should be uint")?;
        let first_reward_cycle = value.data_map.get("first-reward-cycle")
            .ok_or_else(|| "Staking entry should have first-reward-cycle")?
            .clone()
            .expect_u128()
            .map_err(|_| "Staking entry should be uint")?;
        let amount_ustx = value.data_map.get("amount-ustx")
            .ok_or_else(|| "Staking entry should have amount-ustx")?
            .clone()
            .expect_u128()
            .map_err(|_| "Staking entry should be uint")?;
        let unlock_bytes = value.data_map.remove("unlock-bytes")
            .ok_or_else(|| "Staking entry should have unlock-bytes")?
            .expect_buff(683)
            .map_err(|_| "Staking entry should be buff")?;
        let pool_or_solo_info = value.data_map.remove("pool-or-solo-info")
            .ok_or_else(|| "Staking entry should have pool-or-solo-info")?
            .expect_result()
            .map_err(|_| "Staking entry should be response")?;
        let pox_info = match pool_or_solo_info {
            Ok(pool_info) => RawPox5EntryInfo::Pool(
                pool_info
                    .expect_principal()
                    .map_err(|_| "Staking entry should be principal")?
            ),
            Err(solo_info) => {
                let solo_info_map = solo_info.expect_tuple()
                    .map_err(|_| "Staking entry info should be tuple")?;
                let pox_addr_tuple = solo_info_map.get("pox-addr")
                    .map_err(|_| "Staking entry info should have pox-addr")?;
                let pox_addr = PoxAddress::try_from_pox_tuple(is_mainnet, &pox_addr_tuple)
                    .ok_or_else(||
                        format!("not a valid PoX address: {pox_addr_tuple}")
                    )?;
                let Value::Sequence(SequenceData::Buffer(signer)) = solo_info_map.get("signer-key")
                    .map_err(|_| "Staking entry info should have signer-key")? else {
                        return Err("signer-key should be a buff".into());
                };

                let signer_key: [u8; SIGNERS_PK_LEN] = signer.as_slice().try_into().unwrap_or_else(|_| [0; SIGNERS_PK_LEN]); 
                RawPox5EntryInfo::Solo {
                    signer_key,
                    pox_addr
                }
            },
        };

        let last_cycle: u64 = first_reward_cycle.saturating_add(num_cycles).try_into()
            .map_err(|_| "Staking entry must have a u64 cycle number")?;
        let unlock_height: u32 = pox_constants.reward_cycle_to_block_height(
            first_block_ht,
            last_cycle
        )
            .try_into()
            .map_err(|_| "Staking entry must have a u32 unlock height")?;
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

impl <'a, 'b, 'c> StakeEntryIteratorPox5<'a, 'b, 'c> {
    fn fallible_next(&mut self) -> Result<Option<RawPox5Entry>, ChainstateError> {
        let Some(cur_staker) = self.current_staker.take() else {
            return Ok(None);
        };

        let lookup_staker = SymbolicExpression::atom_value(Value::Principal(cur_staker.clone()));
        // update the iterator using the linked list
        let next_staker = self.clarity
            .eval_method_read_only(
                &self.pox_contract,
                "get-staker-set-next-item-for-cycle",
                &[lookup_staker.clone(), self.reward_cycle_clar.clone()]
            )?
            .expect_optional()
            .map_err(|_| {
                ChainstateError::Expects("get-staker-set-next-item-for-cycle did not return optional".into())
            })?
            .map(|entry| entry.expect_principal())
            .transpose()
            .map_err(|_| {
                ChainstateError::Expects("get-staker-set-next-item-for-cycle did not return optional".into())
            })?;
        self.current_staker = next_staker;

        // TODO: errors below this point should just continue the iterator, while errors above should
        //  cancel the calculation. So make the error kind matchable
        let staker_entry_clar = self.clarity
            .eval_method_read_only(
                &self.pox_contract,
                "get-staker-set-item-for-cycle",
                &[lookup_staker, self.reward_cycle_clar.clone()]
            )?
            .expect_optional()
            .map_err(|_| {
                ChainstateError::Expects("get-staker-set-item-for-cycle did not return optional".into())
            })?
            .ok_or_else(|| {
                ChainstateError::Expects(format!(
                    "get-staker-set-item-for-cycle did not return Some for a link-list entry: {cur_staker}"))
            })?;
        let staker_entry = RawPox5Entry::try_parse(cur_staker, staker_entry_clar, self.is_mainnet, self.first_block_ht, &self.pox_constants)
            .map_err(ChainstateError::Expects)?;

        Ok(Some(staker_entry))
    }
}

impl <'a, 'b, 'c> Iterator for StakeEntryIteratorPox5<'a, 'b, 'c> {
    type Item = Result<RawPox5Entry, ChainstateError>;

    fn next(&mut self) -> Option<Self::Item> {
        StakeEntryIteratorPox5::fallible_next(self).transpose()
    }
}

impl NakamotoSigners {
    fn pox_5_stake_entries<'a, 'b, 'c> (
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
                &[reward_cycle_clar.clone()]
            )?
            .expect_optional()
            .map_err(|_| {
                ChainstateError::Expects("get-staker-set-first-item-for-cycle did not return optional".into())
            })?
            .map(|value| value.expect_principal())
            .transpose()
            .map_err(|_| {
                ChainstateError::Expects("get-staker-set-first-item-for-cycle did not return optional principal".into())
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
        let sender_addr = PrincipalData::from(boot::boot_code_addr(is_mainnet));
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        let liquid_ustx = clarity.with_clarity_db_readonly(|db| db.get_total_liquid_ustx())?;
        let reward_slots = Self::get_reward_slots(clarity, reward_cycle, pox_contract)?;
        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            pox_constants,
            &reward_slots[..],
            liquid_ustx,
        );

        let pox_version: PoxVersions =
            PoxVersions::lookup_by_name(pox_contract).ok_or(ChainstateError::DefunctPoxContract)?;
        let reward_set = StacksChainState::make_reward_set(
            threshold,
            reward_slots,
            StacksEpochId::Epoch30,
            pox_version,
        );

        test_debug!("Reward set for cycle {}: {:?}", &reward_cycle, &reward_set);
        let stackerdb_list = if participation == 0 {
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

        let signers_list = if participation == 0 {
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
        let sender_addr = PrincipalData::from(boot::boot_code_addr(is_mainnet));
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        let first_burn_ht = sortition_dbconn.get_burn_start_height();
        let liquid_ustx = clarity.with_clarity_db_readonly(|db| db.get_total_liquid_ustx())?;
        let mut entries = Self::pox_5_stake_entries(clarity, reward_cycle, pox_contract, pox_constants.clone(), first_burn_ht.into())?;

        // let reward_slots = Self::get_reward_slots(clarity, reward_cycle, pox_contract)?;
        // let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
        //     pox_constants,
        //     &reward_slots[..],
        //     liquid_ustx,
        // );

        // let pox_version: PoxVersions =
        //     PoxVersions::lookup_by_name(pox_contract).ok_or(ChainstateError::DefunctPoxContract)?;
        // let reward_set = StacksChainState::make_reward_set(
        //     threshold,
        //     reward_slots,
        //     StacksEpochId::Epoch30,
        //     pox_version,
        // );

        // do the p2wsh validation...
        let new_sortition_db = sortition_dbconn.reopen_handle();
        let mut sortition_handle = new_sortition_db.as_ref();
        let _result =
            validate_pox_p2wsh_outputs(&mut sortition_handle, &mut entries, last_computed_btc_height)?;
        // store the last_computed_btc_height
        clarity.with_clarity_db(|db| {
            db.set_variable(
                signers_contract,
                SIGNERS_LAST_UPDATED_BTC_HEIGHT,
                Value::UInt(current_calculation_btc_height.into()),
                &DataVariableMetadata { value_type: TypeSignature::UIntType },
                &current_epoch
            ).map_err(|_| ClarityError::BadTransaction("FATAL: failed to set variable during reward set calculation".into()))
        }).map_err(|_| {
            error!("FATAL: failed to set SIGNERS_LAST_UPDATED_BTC_HEIGHT during reward set calculation");
            ChainstateError::PoxNoRewardCycle
        })?;
        // todo: apply the validation check changes to the reward set.
        Err(ChainstateError::Expects("Not implemented".into()))
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
