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
use std::sync::{LazyLock, RwLock};

use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TupleData,
};
use clarity::vm::{ClarityName, SymbolicExpression, Value};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{to_hex, Hash160};
#[cfg(any(test, feature = "testing"))]
use stacks_common::util::tests::TestFlag;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use crate::chainstate::stacks::boot::{
    NakamotoSignerEntry, PoxVersions, RawRewardSetEntry, RewardSet, WaterfallCycleSet, POX_5_NAME,
    SIGNERS_MAX_LIST_SIZE, SIGNERS_NAME, SIGNERS_PK_LEN, SIGNERS_UPDATE_STATE,
    SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState};
use crate::chainstate::stacks::sbtc::sbtc_pox5_deposit_taproot_output_key;
use crate::chainstate::stacks::{Error as ChainstateError, StacksTransaction, TransactionPayload};
use crate::clarity::vm::clarity::{ClarityConnection, TransactionConnection};
use crate::clarity_vm::clarity::ClarityTransactionConnection;
use crate::core::POX_5_SBTC_DEPOSIT_MAX_FEE_SATS;
use crate::util_lib::boot;
use crate::util_lib::boot::boot_code_id;

/// The default mainnet sBTC token contract.
pub const SBTC_TOKEN_MAINNET_CONTRACT: &str =
    "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token";

/// The default testnet sBTC token contract.
/// Used as the default on any testnet unless overridden via
/// [`set_pox_5_sbtc_contract`], typically via the `pox_5_sbtc_contract`
/// field in the node config file.
pub const SBTC_TOKEN_TESTNET_CONTRACT: &str = "SN69P7RZRKK8ERQCCABHT2JWKB2S4DHH9H74231T.sbtc-token";

pub static SBTC_TOKEN_MAINNET_CONTRACT_ID: LazyLock<QualifiedContractIdentifier> =
    LazyLock::new(|| {
        QualifiedContractIdentifier::parse(SBTC_TOKEN_MAINNET_CONTRACT)
            .expect("Invalid default mainnet sBTC contract ID")
    });

pub static SBTC_TOKEN_TESTNET_CONTRACT_ID: LazyLock<QualifiedContractIdentifier> =
    LazyLock::new(|| {
        QualifiedContractIdentifier::parse(SBTC_TOKEN_TESTNET_CONTRACT)
            .expect("Invalid default mainnet sBTC contract ID")
    });

/// Epoch 4.0 / PoX-5 scaffolding: the sBTC token contract that pox-5
/// references. Read in two places:
///   * `make_pox_5_body` rewrites the canonical mainnet sBTC literal in the
///     contract source so pox-5's `(contract-call? ... get-balance ...)`
///     hits this contract.
///   * signer-set computation reads `get-current-aggregate-pubkey` from this
///     contract to derive the per-cycle sBTC waterfall recipient.
///
/// Set once at node startup from `NodeConfig::pox_5_sbtc_contract`. Goes away
/// when PoX-5 routing is wired and the aggregate pubkey lives on-chain.
static POX_5_SBTC_CONTRACT: RwLock<Option<QualifiedContractIdentifier>> = RwLock::new(None);

/// Set the configured PoX-5 sBTC contract id. Call once during node startup
/// from the run-loop, with the value parsed out of `NodeConfig`.
pub fn set_pox_5_sbtc_contract(contract_id: Option<QualifiedContractIdentifier>) {
    *POX_5_SBTC_CONTRACT.write().unwrap() = contract_id;
}

pub fn pox_5_sbtc_contract(is_mainnet: bool) -> QualifiedContractIdentifier {
    if is_mainnet {
        return SBTC_TOKEN_MAINNET_CONTRACT_ID.clone();
    }
    let contract_id = POX_5_SBTC_CONTRACT.read().unwrap().clone();
    if let Some(contract_id) = contract_id {
        contract_id
    } else {
        SBTC_TOKEN_TESTNET_CONTRACT_ID.clone()
    }
}

/// The default mainnet PoX-5 bond admin principal.
pub const POX_5_BOND_ADMIN_MAINNET: &str = "SP000000000000000000002Q6VF78";

/// The default non-mainnet PoX-5 bond admin principal — the unsignable
/// testnet boot principal. Used as the substitution target on non-mainnet
/// unless overridden via [`set_pox_5_bond_admin`].
pub const POX_5_BOND_ADMIN_TESTNET: &str = "ST000000000000000000002AMW42H";

/// Epoch 4.0 / PoX-5 scaffolding: the principal that pox-5 initializes the
/// `bond-admin` data var to. The contract source bakes in the mainnet
/// principal ([`POX_5_BOND_ADMIN_MAINNET`]); on non-mainnet,
/// `make_pox_5_body` rewrites it to the configured override (set via
/// `NodeConfig::pox_5_bond_admin`) or the testnet default
/// ([`POX_5_BOND_ADMIN_TESTNET`]). Forbidden on mainnet.
static POX_5_BOND_ADMIN: RwLock<Option<PrincipalData>> = RwLock::new(None);

/// Set the configured PoX-5 bond admin principal. Call once during node
/// startup from the run-loop, with the value parsed out of `NodeConfig`.
pub fn set_pox_5_bond_admin(principal: Option<PrincipalData>) {
    *POX_5_BOND_ADMIN.write().unwrap() = principal;
}

/// Resolve the PoX-5 bond admin principal: the configured override if any,
/// otherwise the network-specific default.
pub fn pox_5_bond_admin(is_mainnet: bool) -> PrincipalData {
    let principal = POX_5_BOND_ADMIN.read().unwrap().clone();
    if let Some(principal) = principal {
        principal
    } else if is_mainnet {
        PrincipalData::parse(POX_5_BOND_ADMIN_MAINNET)
            .expect("Invalid default mainnet bond admin principal")
    } else {
        PrincipalData::parse(POX_5_BOND_ADMIN_TESTNET)
            .expect("Invalid default testnet bond admin principal")
    }
}

/// Test-only override: when set, `pox_5_compute_and_update_signers` substitutes
/// these `(signer_key, amount_ustx)` pairs in place of what the (placeholder)
/// PoX-5 contract body would produce for the given reward cycle. The pairs are
/// fed through `pox_5_make_signer_set` so threshold/weight/sort all match the
/// production code path.
#[cfg(any(test, feature = "testing"))]
pub static TEST_WATERFALL_SIGNER_SET_OVERRIDE: LazyLock<
    TestFlag<HashMap<u64, Vec<([u8; SIGNERS_PK_LEN], u128)>>>,
> = LazyLock::new(TestFlag::default);

/// Test-only override: when set to `Some(true)`, force the PoX-5 dispatch arm
/// in `check_and_handle_prepare_phase_start` to run as soon as
/// `epoch >= Epoch40`. Without this, `PoxConstants::active_pox_contract` never
/// returns `pox-5` (production routing for PoX-5 is not yet wired), so the
/// PoX-5 code path is unreachable.
///
/// DELETE once PoX-5 activation height is set in PoxConstants
#[cfg(any(test, feature = "testing"))]
pub static TEST_FORCE_POX_5_ACTIVE: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

#[cfg(any(test, feature = "testing"))]
fn waterfall_signer_set_override(reward_cycle: u64) -> Option<Vec<([u8; SIGNERS_PK_LEN], u128)>> {
    TEST_WATERFALL_SIGNER_SET_OVERRIDE
        .get_opt()
        .and_then(|map| map.get(&reward_cycle).cloned())
}
#[cfg(not(any(test, feature = "testing")))]
fn waterfall_signer_set_override(_reward_cycle: u64) -> Option<Vec<([u8; SIGNERS_PK_LEN], u128)>> {
    None
}

#[cfg(any(test, feature = "testing"))]
fn force_pox_5_active() -> bool {
    TEST_FORCE_POX_5_ACTIVE.get_opt().unwrap_or(false)
}
#[cfg(not(any(test, feature = "testing")))]
fn force_pox_5_active() -> bool {
    false
}

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
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum RawPox5EntryInfo {
    Pool(PrincipalData),
    Solo {
        pox_addr: PoxAddress,
        signer_key: [u8; 33],
    },
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RawPox5Entry {
    pub(crate) user: StandardPrincipalData,
    pub(crate) num_cycles: u128,
    pub(crate) amount_ustx: u128,
    pub(crate) first_reward_cycle: u128,
    pub(crate) signer_key: [u8; SIGNERS_PK_LEN],
}

impl RawPox5Entry {
    /// Try parsing a value from PoX-5 into a `RawPox5Entry`, if any step of the parsing
    /// (or validation) fails, return a string error.
    fn try_parse(user: PrincipalData, value: Value, is_mainnet: bool) -> Result<Self, String> {
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
        let signer_key_buff = value
            .data_map
            .remove("signer-key")
            .ok_or_else(|| "Staking entry should have signer-key")?
            .expect_buff(SIGNERS_PK_LEN)
            .map_err(|_| format!("Staking signer-key should be (buff {SIGNERS_PK_LEN})"))?;
        let signer_key = signer_key_buff
            .try_into()
            .unwrap_or_else(|_| [0; SIGNERS_PK_LEN]);

        Ok(Self {
            user,
            num_cycles,
            first_reward_cycle,
            amount_ustx,
            signer_key,
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

        let staker_entry = RawPox5Entry::try_parse(cur_staker, staker_entry_clar, self.is_mainnet)
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
        })
    }

    fn get_pox_4_reward_slots(
        clarity: &mut ClarityTransactionConnection,
        reward_cycle: u64,
        pox_contract: &str,
    ) -> Result<Vec<RawRewardSetEntry>, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        if !matches!(
            PoxVersions::lookup_by_name(pox_contract),
            Some(PoxVersions::Pox4)
        ) {
            error!("Invoked Nakamoto PoX-4 reward-set fetch on non-pox-4 contract");
            return Err(ChainstateError::DefunctPoxContract);
        }

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

            let entry = RawRewardSetEntry::from_pox_4_tuple(is_mainnet, tuple)?;
            slots.push(entry)
        }

        Ok(slots)
    }

    fn update_signers(
        clarity: &mut ClarityTransactionConnection,
        reward_cycle: u64,
        signers: &Vec<NakamotoSignerEntry>,
        signers_contract: &QualifiedContractIdentifier,
        has_participation: bool,
        coinbase_height: u64,
        is_mainnet: bool,
    ) -> Result<Vec<StacksTransactionEvent>, ChainstateError> {
        let sender_addr = PrincipalData::from(boot::boot_code_addr(is_mainnet));
        let stackerdb_list = if !has_participation {
            vec![]
        } else {
            signers
                .iter()
                .map(|signer| {
                    let signer_hash = Hash160::from_data(&signer.signing_key);
                    let signing_address = StacksAddress::p2pkh_from_hash(is_mainnet, signer_hash);
                    let tuple_data = TupleData::from_data(vec![
                        (
                            ClarityName::from_literal("signer"),
                            Value::Principal(PrincipalData::from(signing_address)),
                        ),
                        (ClarityName::from_literal("num-slots"), Value::UInt(1)),
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
            signers
                .iter()
                .map(|signer| {
                    let signer_hash = Hash160::from_data(&signer.signing_key);
                    let signing_address = StacksAddress::p2pkh_from_hash(is_mainnet, signer_hash);
                    let tuple = TupleData::from_data(vec![
                        (
                            ClarityName::from_literal("signer"),
                            Value::Principal(PrincipalData::from(signing_address)),
                        ),
                        (
                            ClarityName::from_literal("weight"),
                            Value::UInt(signer.weight.into()),
                        ),
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
        let reward_slots = Self::get_pox_4_reward_slots(clarity, reward_cycle, pox_contract)?;
        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            pox_constants,
            &reward_slots[..],
            liquid_ustx,
        );

        let reward_set =
            StacksChainState::make_reward_set(threshold, reward_slots, StacksEpochId::Epoch30);

        test_debug!("Reward set for cycle {}: {:?}", &reward_cycle, &reward_set);

        let empty_signers = vec![];
        let events = Self::update_signers(
            clarity,
            reward_cycle,
            reward_set.signers().unwrap_or(&empty_signers),
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
    fn pox_5_compute_and_update_signers(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
        _current_calculation_btc_height: u32,
        _current_epoch: &StacksEpochId,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        // Build the `(signer_key, amount_ustx)` pair stream: either from a test
        // override (while the PoX-5 contract is unimplemented)
        let signer_set = if let Some(override_pairs) = waterfall_signer_set_override(reward_cycle) {
            let stub_user = StandardPrincipalData::transient();
            let stub_first_reward_cycle = u128::from(reward_cycle);
            let mut entries = override_pairs
                .into_iter()
                .map(move |(signer_key, amount_ustx)| {
                    Ok(RawPox5Entry {
                        user: stub_user.clone(),
                        num_cycles: 1,
                        amount_ustx,
                        first_reward_cycle: stub_first_reward_cycle,
                        signer_key,
                    })
                });
            Self::pox_5_make_signer_set(&mut entries, pox_constants)?
        } else {
            let mut entries = Self::pox_5_stake_entries(
                clarity,
                reward_cycle,
                pox_contract,
                pox_constants.clone(),
            )?;
            let _pox_contract_id = boot_code_id(pox_contract, is_mainnet);
            Self::pox_5_make_signer_set(&mut entries, pox_constants)?
        };

        let events = Self::update_signers(
            clarity,
            reward_cycle,
            &signer_set,
            signers_contract,
            signer_set.len() > 0,
            coinbase_height,
            is_mainnet,
        )?;

        let sbtc_contract_id = pox_5_sbtc_contract(is_mainnet);

        let pubkey_buff = clarity
            .eval_method_read_only(&sbtc_contract_id, "get-current-aggregate-pubkey", &[])?
            .expect_buff(33)
            .map_err(|_| {
                ChainstateError::Expects(
                    "get-current-aggregate-pubkey did not return a buffer of <= 33 bytes".into(),
                )
            })?;
        if pubkey_buff.len() != 33 {
            return Err(ChainstateError::Expects(format!(
                    "get-current-aggregate-pubkey returned {} bytes; expected exactly 33 (compressed secp256k1)",
                    pubkey_buff.len()
                )));
        }
        let pubkey_array: [u8; 33] = pubkey_buff.try_into().expect("length checked above");

        let sbtc_recipient = PrincipalData::Contract(boot_code_id(POX_5_NAME, is_mainnet));
        let output_key = sbtc_pox5_deposit_taproot_output_key(
            &pubkey_array,
            &sbtc_recipient,
            POX_5_SBTC_DEPOSIT_MAX_FEE_SATS,
        )?;

        let sbtc_address = PoxAddress::Addr32(is_mainnet, PoxAddressType32::P2TR, output_key);

        // if we want to "write-back" any state to PoX-5 (e.g., computed weights)
        //  we should do it here

        Ok(SignerCalculation {
            reward_set: RewardSet::Waterfall(WaterfallCycleSet {
                sbtc_address,
                signers: signer_set,
            }),
            events,
        })
    }

    pub(crate) fn pox_5_make_signer_set<I>(
        entries: &mut I,
        pox_constants: &PoxConstants,
    ) -> Result<Vec<NakamotoSignerEntry>, ChainstateError>
    where
        I: Iterator<Item = Result<RawPox5Entry, PoxEntryParsingError>>,
    {
        let mut signer_set = HashMap::new();
        let mut total_ustx_locked = 0u128;
        for entry_res in entries {
            let entry = match entry_res {
                Ok(x) => x,
                Err(PoxEntryParsingError::Skip(err_str)) => {
                    warn!(
                        "Error while iterating PoX-5 entries, impacting a single entry. Dropping entry from signer set";
                        "error" => err_str
                    );
                    continue;
                }
                Err(PoxEntryParsingError::Abort(err_str)) => {
                    error!(
                        "Abort-triggering error while iterating PoX-5 entries";
                        "error" => err_str
                    );
                    return Err(ChainstateError::PoxNoRewardCycle);
                }
            };

            total_ustx_locked += entry.amount_ustx;

            signer_set
                .entry(entry.signer_key)
                .and_modify(|existing_entry| *existing_entry += entry.amount_ustx)
                .or_insert_with(|| entry.amount_ustx);
        }

        // set threshold to the ceil of (total/reward_slots) to guarantee that we don't assign
        //  more total weight than reward_slots, and set the minimum return to 1 to avoid a div by zero
        //  in the unlikely event of a 0 stacked amount.
        let threshold = std::cmp::max(
            1,
            total_ustx_locked.div_ceil(u128::from(pox_constants.reward_slots())),
        );

        let mut signer_set: Vec<_> = signer_set
            .into_iter()
            .filter_map(|(signing_key, stacked_amt)| {
                let weight = u32::try_from(stacked_amt / threshold)
                    .expect("CORRUPTION: Stacker claimed > u32::max() reward slots");
                if weight == 0 {
                    return None;
                }
                Some(NakamotoSignerEntry {
                    signing_key,
                    stacked_amt,
                    weight,
                })
            })
            .collect();

        // finally, we must sort the signer set: the signer participation bit vector depends
        //  on a consensus-critical ordering of the signer set.
        signer_set.sort_by_key(|entry| entry.signing_key);

        Ok(signer_set)
    }

    /// If this block is mined in the prepare phase, based on its tenure's `burn_tip_height`.  If
    /// so, and if we haven't done so yet, then compute the PoX reward set, store it, and update
    /// the .signers contract.  The stored PoX reward set is the reward set for the next reward
    /// cycle, and will be used by the Nakamoto chains coordinator to validate its block-commits
    /// and block signatures.
    pub fn check_and_handle_prepare_phase_start(
        clarity_tx: &mut ClarityTx,
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

        let active_pox_contract = if force_pox_5_active() && current_epoch >= StacksEpochId::Epoch40
        {
            POX_5_NAME
        } else {
            pox_constants.active_pox_contract(burn_tip_height.into())
        };

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
                    return Ok(false);
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
                // if the cycle_number is less than `cycle_of_prepare_phase`, we need to update
                //  the .signers state.
                let needs_update = cycle_number < u128::from(cycle_of_prepare_phase);
                Ok(needs_update)
            });

        let needs_update = needs_update_result?;

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
            || payload.function_name != ClarityName::from_literal(SIGNERS_VOTING_FUNCTION_NAME)
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
