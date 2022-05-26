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

use std::boxed::Box;
use std::cmp;
use std::convert::TryFrom;
use std::convert::TryInto;

use crate::burnchains::Burnchain;
use crate::burnchains::{Address, PoxConstants};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::Error;
use crate::clarity_vm::clarity::ClarityConnection;
use crate::core::{POX_MAXIMAL_SCALING, POX_THRESHOLD_STEPS_USTX};
use clarity::vm::contexts::ContractContext;
use clarity::vm::costs::{
    cost_functions::ClarityCostFunction, ClarityCostFunctionReference, CostStateSummary,
};
use clarity::vm::database::ClarityDatabase;
use clarity::vm::database::{NULL_BURN_STATE_DB, NULL_HEADER_DB};
use clarity::vm::representations::ClarityName;
use clarity::vm::representations::ContractName;
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData, TupleData,
    TypeSignature, Value,
};
use stacks_common::address::AddressHashMode;
use stacks_common::util::hash::Hash160;

use crate::chainstate::stacks::address::StacksAddressExtensions;
use crate::clarity_vm::database::HeadersDBConn;
use crate::types;
use crate::types::chainstate::StacksAddress;
use crate::types::chainstate::StacksBlockId;
use crate::util_lib::boot;
use crate::vm::{costs::LimitedCostTracker, SymbolicExpression};

const BOOT_CODE_POX_BODY: &'static str = std::include_str!("pox.clar");
const BOOT_CODE_POX_TESTNET_CONSTS: &'static str = std::include_str!("pox-testnet.clar");
const BOOT_CODE_POX_MAINNET_CONSTS: &'static str = std::include_str!("pox-mainnet.clar");
const BOOT_CODE_LOCKUP: &'static str = std::include_str!("lockup.clar");
pub const BOOT_CODE_COSTS: &'static str = std::include_str!("costs.clar");
pub const BOOT_CODE_COSTS_2: &'static str = std::include_str!("costs-2.clar");
pub const BOOT_CODE_COSTS_2_TESTNET: &'static str = std::include_str!("costs-2-testnet.clar");
const BOOT_CODE_COST_VOTING_MAINNET: &'static str = std::include_str!("cost-voting.clar");
const BOOT_CODE_BNS: &'static str = std::include_str!("bns.clar");
const BOOT_CODE_GENESIS: &'static str = std::include_str!("genesis.clar");
pub const COSTS_1_NAME: &'static str = "costs";
pub const COSTS_2_NAME: &'static str = "costs-2";

pub mod docs;

lazy_static! {
    static ref BOOT_CODE_POX_MAINNET: String =
        format!("{}\n{}", BOOT_CODE_POX_MAINNET_CONSTS, BOOT_CODE_POX_BODY);
    pub static ref BOOT_CODE_POX_TESTNET: String =
        format!("{}\n{}", BOOT_CODE_POX_TESTNET_CONSTS, BOOT_CODE_POX_BODY);
    pub static ref BOOT_CODE_COST_VOTING_TESTNET: String = make_testnet_cost_voting();
    pub static ref STACKS_BOOT_CODE_MAINNET: [(&'static str, &'static str); 6] = [
        ("pox", &BOOT_CODE_POX_MAINNET),
        ("lockup", BOOT_CODE_LOCKUP),
        ("costs", BOOT_CODE_COSTS),
        ("cost-voting", BOOT_CODE_COST_VOTING_MAINNET),
        ("bns", &BOOT_CODE_BNS),
        ("genesis", &BOOT_CODE_GENESIS),
    ];
    pub static ref STACKS_BOOT_CODE_TESTNET: [(&'static str, &'static str); 6] = [
        ("pox", &BOOT_CODE_POX_TESTNET),
        ("lockup", BOOT_CODE_LOCKUP),
        ("costs", BOOT_CODE_COSTS),
        ("cost-voting", &BOOT_CODE_COST_VOTING_TESTNET),
        ("bns", &BOOT_CODE_BNS),
        ("genesis", &BOOT_CODE_GENESIS),
    ];
}

fn make_testnet_cost_voting() -> String {
    BOOT_CODE_COST_VOTING_MAINNET
        .replacen(
            "(define-constant VETO_LENGTH u1008)",
            "(define-constant VETO_LENGTH u50)",
            1,
        )
        .replacen(
            "(define-constant REQUIRED_VETOES u500)",
            "(define-constant REQUIRED_VETOES u25)",
            1,
        )
}

pub fn make_contract_id(addr: &StacksAddress, name: &str) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(
        StandardPrincipalData::from(addr.clone()),
        ContractName::try_from(name.to_string()).unwrap(),
    )
}

/// Extract a PoX address from its tuple representation
fn tuple_to_pox_addr(tuple_data: TupleData) -> (AddressHashMode, Hash160) {
    let version_value = tuple_data
        .get("version")
        .expect("FATAL: no 'version' field in pox-addr")
        .to_owned();
    let hashbytes_value = tuple_data
        .get("hashbytes")
        .expect("FATAL: no 'hashbytes' field in pox-addr")
        .to_owned();

    let version_u8 = version_value.expect_buff_padded(1, 0)[0];
    let version: AddressHashMode = version_u8
        .try_into()
        .expect("FATAL: PoX version is not a supported version byte");

    let hashbytes_vec = hashbytes_value.expect_buff_padded(20, 0);

    let mut hashbytes_20 = [0u8; 20];
    hashbytes_20.copy_from_slice(&hashbytes_vec[0..20]);
    let hashbytes = Hash160(hashbytes_20);

    (version, hashbytes)
}

impl StacksChainState {
    fn eval_boot_code_read_only(
        &mut self,
        sortdb: &SortitionDB,
        stacks_block_id: &StacksBlockId,
        boot_contract_name: &str,
        code: &str,
    ) -> Result<Value, Error> {
        let iconn = sortdb.index_conn();
        let dbconn = self.state_index.sqlite_conn();
        self.clarity_state
            .eval_read_only(
                &stacks_block_id,
                &HeadersDBConn(dbconn),
                &iconn,
                &boot::boot_code_id(boot_contract_name, self.mainnet),
                code,
            )
            .map_err(Error::ClarityError)
    }

    pub fn get_liquid_ustx(&mut self, stacks_block_id: &StacksBlockId) -> u128 {
        let mut connection = self.clarity_state.read_only_connection(
            stacks_block_id,
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        );
        connection.with_clarity_db_readonly_owned(|mut clarity_db| {
            (clarity_db.get_total_liquid_ustx(), clarity_db)
        })
    }

    /// Determine the minimum amount of STX per reward address required to stack in the _next_
    /// reward cycle
    #[cfg(test)]
    pub fn get_stacking_minimum(
        &mut self,
        sortdb: &SortitionDB,
        stacks_block_id: &StacksBlockId,
    ) -> Result<u128, Error> {
        self.eval_boot_code_read_only(
            sortdb,
            stacks_block_id,
            "pox",
            &format!("(get-stacking-minimum)"),
        )
        .map(|value| value.expect_u128())
    }

    pub fn get_total_ustx_stacked(
        &mut self,
        sortdb: &SortitionDB,
        tip: &StacksBlockId,
        reward_cycle: u128,
    ) -> Result<u128, Error> {
        let function = "get-total-ustx-stacked";
        let mainnet = self.mainnet;
        let contract_identifier = boot::boot_code_id("pox", mainnet);
        let cost_track = LimitedCostTracker::new_free();
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());
        let result = self
            .maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
                clarity_tx.with_readonly_clarity_env(mainnet, sender, cost_track, |env| {
                    env.execute_contract(
                        &contract_identifier,
                        function,
                        &vec![SymbolicExpression::atom_value(Value::UInt(reward_cycle))],
                        true,
                    )
                })
            })?
            .ok_or_else(|| Error::NoSuchBlockError)??
            .expect_u128();
        Ok(result)
    }

    /// Determine how many uSTX are stacked in a given reward cycle
    #[cfg(test)]
    pub fn test_get_total_ustx_stacked(
        &mut self,
        sortdb: &SortitionDB,
        stacks_block_id: &StacksBlockId,
        reward_cycle: u128,
    ) -> Result<u128, Error> {
        self.eval_boot_code_read_only(
            sortdb,
            stacks_block_id,
            "pox",
            &format!("(get-total-ustx-stacked u{})", reward_cycle),
        )
        .map(|value| value.expect_u128())
    }

    /// Is PoX active in the given reward cycle?
    pub fn is_pox_active(
        &mut self,
        sortdb: &SortitionDB,
        stacks_block_id: &StacksBlockId,
        reward_cycle: u128,
    ) -> Result<bool, Error> {
        self.eval_boot_code_read_only(
            sortdb,
            stacks_block_id,
            "pox",
            &format!("(is-pox-active u{})", reward_cycle),
        )
        .map(|value| value.expect_bool())
    }

    /// Given a threshold and set of registered addresses, return a reward set where
    ///   every entry address has stacked more than the threshold, and addresses
    ///   are repeated floor(stacked_amt / threshold) times.
    /// If an address appears in `addresses` multiple times, then the address's associated amounts
    ///   are summed.
    pub fn make_reward_set(
        _threshold: u128,
        _addresses: Vec<(StacksAddress, u128)>,
    ) -> Vec<StacksAddress> {
        vec![]
    }

    pub fn get_threshold_from_participation(
        liquid_ustx: u128,
        participation: u128,
        reward_slots: u128,
    ) -> u128 {
        // set the lower limit on reward scaling at 25% of liquid_ustx
        //   (i.e., liquid_ustx / POX_MAXIMAL_SCALING)
        let scale_by = cmp::max(participation, liquid_ustx / POX_MAXIMAL_SCALING as u128);
        let threshold_precise = scale_by / reward_slots;
        // compute the threshold as nearest 10k > threshold_precise
        let ceil_amount = match threshold_precise % POX_THRESHOLD_STEPS_USTX {
            0 => 0,
            remainder => POX_THRESHOLD_STEPS_USTX - remainder,
        };
        let threshold = threshold_precise + ceil_amount;
        return threshold;
    }

    /// Each address will have at least (get-stacking-minimum) tokens.
    pub fn get_reward_addresses(
        &mut self,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        current_burn_height: u64,
        block_id: &StacksBlockId,
    ) -> Result<Vec<(StacksAddress, u128)>, Error> {
        let reward_cycle = burnchain
            .block_height_to_reward_cycle(current_burn_height)
            .ok_or(Error::PoxNoRewardCycle)?;

        if !self.is_pox_active(sortdb, block_id, reward_cycle as u128)? {
            debug!(
                "PoX was voted disabled in block {} (reward cycle {})",
                block_id, reward_cycle
            );
            return Ok(vec![]);
        }

        // how many in this cycle?
        let num_addrs = self
            .eval_boot_code_read_only(
                sortdb,
                block_id,
                "pox",
                &format!("(get-reward-set-size u{})", reward_cycle),
            )?
            .expect_u128();

        debug!(
            "At block {:?} (reward cycle {}): {} PoX reward addresses",
            block_id, reward_cycle, num_addrs
        );

        let mut ret = vec![];
        for i in 0..num_addrs {
            // value should be (optional (tuple (pox-addr (tuple (...))) (total-ustx uint))).
            // Get the tuple.
            let tuple_data = self
                .eval_boot_code_read_only(
                    sortdb,
                    block_id,
                    "pox",
                    &format!("(get-reward-set-pox-address u{} u{})", reward_cycle, i),
                )?
                .expect_optional()
                .expect(&format!(
                    "FATAL: missing PoX address in slot {} out of {} in reward cycle {}",
                    i, num_addrs, reward_cycle
                ))
                .expect_tuple();

            let pox_addr_tuple = tuple_data
                .get("pox-addr")
                .expect(&format!("FATAL: no 'pox-addr' in return value from (get-reward-set-pox-address u{} u{})", reward_cycle, i))
                .to_owned()
                .expect_tuple();

            let (hash_mode, hash) = tuple_to_pox_addr(pox_addr_tuple);

            let total_ustx = tuple_data
                .get("total-ustx")
                .expect(&format!("FATAL: no 'total-ustx' in return value from (get-reward-set-pox-address u{} u{})", reward_cycle, i))
                .to_owned()
                .expect_u128();

            let version = match self.mainnet {
                true => hash_mode.to_version_mainnet(),
                false => hash_mode.to_version_testnet(),
            };

            test_debug!(
                "PoX reward address (for {} ustx): {:?}",
                total_ustx,
                &StacksAddress::new(version, hash)
            );
            ret.push((StacksAddress::new(version, hash), total_ustx));
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod contract_tests;

#[cfg(test)]
pub mod test {
    use std::collections::{HashMap, HashSet};
    use std::convert::From;
    use std::fs;

    use crate::burnchains::Address;
    use crate::burnchains::PublicKey;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::db::*;
    use crate::chainstate::burn::operations::BlockstackOperationType;
    use crate::chainstate::burn::*;
    use crate::chainstate::stacks::db::test::*;
    use crate::chainstate::stacks::db::*;
    use crate::chainstate::stacks::miner::test::*;
    use crate::chainstate::stacks::miner::*;
    use crate::chainstate::stacks::Error as chainstate_error;
    use crate::chainstate::stacks::*;
    use crate::core::*;
    use crate::net::test::*;
    use clarity::vm::contracts::Contract;
    use clarity::vm::types::*;
    use stacks_common::util::hash::to_hex;
    use stacks_common::util::*;

    use crate::chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    use crate::util_lib::boot::{boot_code_id, boot_code_test_addr};

    use super::*;

    pub const TESTNET_STACKING_THRESHOLD_25: u128 = 8000;

    fn rand_addr() -> StacksAddress {
        key_to_stacks_addr(&StacksPrivateKey::new())
    }

    fn key_to_stacks_addr(key: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(key)],
        )
        .unwrap()
    }

    pub fn instantiate_pox_peer<'a>(
        burnchain: &Burnchain,
        test_name: &str,
        port: u16,
    ) -> (TestPeer<'a>, Vec<StacksPrivateKey>) {
        instantiate_pox_peer_with_epoch(burnchain, test_name, port, None, None)
    }

    pub fn instantiate_pox_peer_with_epoch<'a>(
        burnchain: &Burnchain,
        test_name: &str,
        port: u16,
        epochs: Option<Vec<StacksEpoch>>,
        observer: Option<&'a TestEventObserver>,
    ) -> (TestPeer<'a>, Vec<StacksPrivateKey>) {
        let mut peer_config = TestPeerConfig::new(test_name, port, port + 1);
        peer_config.burnchain = burnchain.clone();
        peer_config.epochs = epochs;
        peer_config.setup_code = format!(
            "(contract-call? .pox set-burnchain-parameters u{} u{} u{} u{})",
            burnchain.first_block_height, 0, 0, 0
        );

        test_debug!("Setup code: '{}'", &peer_config.setup_code);

        let keys = [
            StacksPrivateKey::from_hex(
                "7e3ee1f2a0ae11b785a1f0e725a9b3ab0a5fd6cc057d43763b0a85f256fdec5d01",
            )
            .unwrap(),
            StacksPrivateKey::from_hex(
                "11d055ac8b0ab4f04c5eb5ea4b4def9c60ae338355d81c9411b27b4f49da2a8301",
            )
            .unwrap(),
            StacksPrivateKey::from_hex(
                "00eed368626b96e482944e02cc136979973367491ea923efb57c482933dd7c0b01",
            )
            .unwrap(),
            StacksPrivateKey::from_hex(
                "00380ff3c05350ee313f60f30313acb4b5fc21e50db4151bf0de4cd565eb823101",
            )
            .unwrap(),
        ];

        let addrs: Vec<StacksAddress> = keys.iter().map(|ref pk| key_to_stacks_addr(pk)).collect();

        let balances: Vec<(PrincipalData, u64)> = addrs
            .clone()
            .into_iter()
            .map(|addr| (addr.into(), (1024 * POX_THRESHOLD_STEPS_USTX) as u64))
            .collect();

        peer_config.initial_balances = balances;
        let peer = TestPeer::new_with_observer(peer_config, observer);

        (peer, keys.to_vec())
    }

    fn eval_at_tip(peer: &mut TestPeer, boot_contract: &str, expr: &str) -> Value {
        let sortdb = peer.sortdb.take().unwrap();
        let (consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
        let stacks_block_id = StacksBlockId::new(&consensus_hash, &block_bhh);
        let iconn = sortdb.index_conn();
        let value = peer.chainstate().clarity_eval_read_only(
            &iconn,
            &stacks_block_id,
            &boot_code_id(boot_contract, false),
            expr,
        );
        peer.sortdb = Some(sortdb);
        value
    }

    fn contract_id(addr: &StacksAddress, name: &str) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            StandardPrincipalData::from(addr.clone()),
            ContractName::try_from(name.to_string()).unwrap(),
        )
    }

    fn eval_contract_at_tip(
        peer: &mut TestPeer,
        addr: &StacksAddress,
        name: &str,
        expr: &str,
    ) -> Value {
        let sortdb = peer.sortdb.take().unwrap();
        let (consensus_hash, block_bhh) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
        let stacks_block_id = StacksBlockId::new(&consensus_hash, &block_bhh);
        let iconn = sortdb.index_conn();
        let value = peer.chainstate().clarity_eval_read_only(
            &iconn,
            &stacks_block_id,
            &contract_id(addr, name),
            expr,
        );
        peer.sortdb = Some(sortdb);
        value
    }

    fn get_liquid_ustx(peer: &mut TestPeer) -> u128 {
        let value = eval_at_tip(peer, "pox", "stx-liquid-supply");
        if let Value::UInt(inner_uint) = value {
            return inner_uint;
        } else {
            panic!("stx-liquid-supply isn't a uint");
        }
    }

    fn get_balance(peer: &mut TestPeer, addr: &PrincipalData) -> u128 {
        let value = eval_at_tip(
            peer,
            "pox",
            &format!("(stx-get-balance '{})", addr.to_string()),
        );
        if let Value::UInt(balance) = value {
            return balance;
        } else {
            panic!("stx-get-balance isn't a uint");
        }
    }

    fn get_stacker_info(
        peer: &mut TestPeer,
        addr: &PrincipalData,
    ) -> Option<(u128, (AddressHashMode, Hash160), u128, u128)> {
        let value_opt = eval_at_tip(
            peer,
            "pox",
            &format!("(get-stacker-info '{})", addr.to_string()),
        );
        let data = if let Some(d) = value_opt.expect_optional() {
            d
        } else {
            return None;
        };

        let data = data.expect_tuple();

        let amount_ustx = data.get("amount-ustx").unwrap().to_owned().expect_u128();
        let pox_addr = tuple_to_pox_addr(data.get("pox-addr").unwrap().to_owned().expect_tuple());
        let lock_period = data.get("lock-period").unwrap().to_owned().expect_u128();
        let first_reward_cycle = data
            .get("first-reward-cycle")
            .unwrap()
            .to_owned()
            .expect_u128();
        Some((amount_ustx, pox_addr, lock_period, first_reward_cycle))
    }

    fn with_sortdb<F, R>(peer: &mut TestPeer, todo: F) -> R
    where
        F: FnOnce(&mut StacksChainState, &SortitionDB) -> R,
    {
        let sortdb = peer.sortdb.take().unwrap();
        let r = todo(peer.chainstate(), &sortdb);
        peer.sortdb = Some(sortdb);
        r
    }

    fn get_account(peer: &mut TestPeer, addr: &PrincipalData) -> StacksAccount {
        let account = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
            let (consensus_hash, block_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
            let stacks_block_id = StacksBlockId::new(&consensus_hash, &block_bhh);
            chainstate
                .with_read_only_clarity_tx(&sortdb.index_conn(), &stacks_block_id, |clarity_tx| {
                    StacksChainState::get_account(clarity_tx, addr)
                })
                .unwrap()
        });
        account
    }

    fn get_contract(peer: &mut TestPeer, addr: &QualifiedContractIdentifier) -> Option<Contract> {
        let contract_opt = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
            let (consensus_hash, block_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
            let stacks_block_id = StacksBlockId::new(&consensus_hash, &block_bhh);
            chainstate
                .with_read_only_clarity_tx(&sortdb.index_conn(), &stacks_block_id, |clarity_tx| {
                    StacksChainState::get_contract(clarity_tx, addr).unwrap()
                })
                .unwrap()
        });
        contract_opt
    }

    fn make_pox_addr(addr_version: AddressHashMode, addr_bytes: Hash160) -> Value {
        Value::Tuple(
            TupleData::from_data(vec![
                (
                    ClarityName::try_from("version".to_owned()).unwrap(),
                    Value::buff_from_byte(addr_version as u8),
                ),
                (
                    ClarityName::try_from("hashbytes".to_owned()).unwrap(),
                    Value::Sequence(SequenceData::Buffer(BuffData {
                        data: addr_bytes.as_bytes().to_vec(),
                    })),
                ),
            ])
            .unwrap(),
        )
    }

    fn make_pox_lockup(
        key: &StacksPrivateKey,
        nonce: u64,
        amount: u128,
        addr_version: AddressHashMode,
        addr_bytes: Hash160,
        lock_period: u128,
        burn_ht: u64,
    ) -> StacksTransaction {
        // (define-public (stack-stx (amount-ustx uint)
        //                           (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
        //                           (lock-period uint))
        make_pox_contract_call(
            key,
            nonce,
            "stack-stx",
            vec![
                Value::UInt(amount),
                make_pox_addr(addr_version, addr_bytes),
                Value::UInt(burn_ht as u128),
                Value::UInt(lock_period),
            ],
        )
    }

    fn make_tx(
        key: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
        tx.chain_id = 0x80000000;
        tx.auth.set_origin_nonce(nonce);
        tx.set_post_condition_mode(TransactionPostConditionMode::Allow);
        tx.set_tx_fee(tx_fee);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }

    fn make_pox_contract_call(
        key: &StacksPrivateKey,
        nonce: u64,
        function_name: &str,
        args: Vec<Value>,
    ) -> StacksTransaction {
        let payload = TransactionPayload::new_contract_call(
            boot_code_test_addr(),
            "pox",
            function_name,
            args,
        )
        .unwrap();

        make_tx(key, nonce, 0, payload)
    }

    // make a stream of invalid pox-lockup transactions
    fn make_invalid_pox_lockups(key: &StacksPrivateKey, mut nonce: u64) -> Vec<StacksTransaction> {
        let mut ret = vec![];

        let amount = 1;
        let lock_period = 1;
        let addr_bytes = Hash160([0u8; 20]);

        let bad_pox_addr_version = Value::Tuple(
            TupleData::from_data(vec![
                (
                    ClarityName::try_from("version".to_owned()).unwrap(),
                    Value::UInt(100),
                ),
                (
                    ClarityName::try_from("hashbytes".to_owned()).unwrap(),
                    Value::Sequence(SequenceData::Buffer(BuffData {
                        data: addr_bytes.as_bytes().to_vec(),
                    })),
                ),
            ])
            .unwrap(),
        );

        let generator = |amount, pox_addr, lock_period, nonce| {
            make_pox_contract_call(
                key,
                nonce,
                "stack-stx",
                vec![Value::UInt(amount), pox_addr, Value::UInt(lock_period)],
            )
        };

        let bad_pox_addr_tx = generator(amount, bad_pox_addr_version, lock_period, nonce);
        ret.push(bad_pox_addr_tx);
        nonce += 1;

        let bad_lock_period_short = generator(
            amount,
            make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone()),
            0,
            nonce,
        );
        ret.push(bad_lock_period_short);
        nonce += 1;

        let bad_lock_period_long = generator(
            amount,
            make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone()),
            13,
            nonce,
        );
        ret.push(bad_lock_period_long);
        nonce += 1;

        let bad_amount = generator(
            0,
            make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone()),
            1,
            nonce,
        );
        ret.push(bad_amount);

        ret
    }

    fn make_bare_contract(
        key: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
        name: &str,
        code: &str,
    ) -> StacksTransaction {
        let payload = TransactionPayload::new_smart_contract(name, code).unwrap();
        make_tx(key, nonce, tx_fee, payload)
    }

    fn make_token_transfer(
        key: &StacksPrivateKey,
        nonce: u64,
        tx_fee: u64,
        dest: PrincipalData,
        amount: u64,
    ) -> StacksTransaction {
        let payload = TransactionPayload::TokenTransfer(dest, amount, TokenTransferMemo([0u8; 34]));
        make_tx(key, nonce, tx_fee, payload)
    }

    fn make_pox_lockup_contract(
        key: &StacksPrivateKey,
        nonce: u64,
        name: &str,
    ) -> StacksTransaction {
        let contract = format!("
        (define-public (do-contract-lockup (amount-ustx uint) (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20)))) (lock-period uint))
            (let (
                (this-contract (as-contract tx-sender))
            )
            (begin
                ;; take the stx from the tx-sender
                
                (unwrap-panic (stx-transfer? amount-ustx tx-sender this-contract))

                ;; this contract stacks the stx given to it
                (as-contract
                    (contract-call? '{}.pox stack-stx amount-ustx pox-addr burn-block-height lock-period))
            ))
        )

        ;; get back STX from this contract
        (define-public (withdraw-stx (amount-ustx uint))
            (let (
                (recipient tx-sender)
            )
            (begin
                (unwrap-panic
                    (as-contract
                        (stx-transfer? amount-ustx tx-sender recipient)))
                (ok true)
            ))
        )
        ", boot_code_test_addr());
        let contract_tx = make_bare_contract(key, nonce, 0, name, &contract);
        contract_tx
    }

    // call after make_pox_lockup_contract gets mined
    fn make_pox_lockup_contract_call(
        key: &StacksPrivateKey,
        nonce: u64,
        contract_addr: &StacksAddress,
        name: &str,
        amount: u128,
        addr_version: AddressHashMode,
        addr_bytes: Hash160,
        lock_period: u128,
    ) -> StacksTransaction {
        let payload = TransactionPayload::new_contract_call(
            contract_addr.clone(),
            name,
            "do-contract-lockup",
            vec![
                Value::UInt(amount),
                make_pox_addr(addr_version, addr_bytes),
                Value::UInt(lock_period),
            ],
        )
        .unwrap();
        make_tx(key, nonce, 0, payload)
    }

    // call after make_pox_lockup_contract gets mined
    fn make_pox_withdraw_stx_contract_call(
        key: &StacksPrivateKey,
        nonce: u64,
        contract_addr: &StacksAddress,
        name: &str,
        amount: u128,
    ) -> StacksTransaction {
        let payload = TransactionPayload::new_contract_call(
            contract_addr.clone(),
            name,
            "withdraw-stx",
            vec![Value::UInt(amount)],
        )
        .unwrap();
        make_tx(key, nonce, 0, payload)
    }

    fn make_pox_reject(key: &StacksPrivateKey, nonce: u64) -> StacksTransaction {
        // (define-public (reject-pox))
        make_pox_contract_call(key, nonce, "reject-pox", vec![])
    }

    fn get_reward_addresses_with_par_tip(
        state: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<Vec<(StacksAddress, u128)>, Error> {
        let burn_block_height = get_par_burn_block_height(state, block_id);
        state
            .get_reward_addresses(burnchain, sortdb, burn_block_height, block_id)
            .and_then(|mut addrs| {
                addrs.sort_by_key(|k| k.0.bytes.0);
                Ok(addrs)
            })
    }

    pub fn get_parent_tip(
        parent_opt: &Option<&StacksBlock>,
        chainstate: &StacksChainState,
        sortdb: &SortitionDB,
    ) -> StacksHeaderInfo {
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let parent_tip = match parent_opt {
            None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
            Some(block) => {
                let ic = sortdb.index_conn();
                let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                    &ic,
                    &tip.sortition_id,
                    &block.block_hash(),
                )
                .unwrap()
                .unwrap(); // succeeds because we don't fork
                StacksChainState::get_anchored_block_header_info(
                    chainstate.db(),
                    &snapshot.consensus_hash,
                    &snapshot.winning_stacks_block_hash,
                )
                .unwrap()
                .unwrap()
            }
        };
        parent_tip
    }

    #[test]
    fn test_liquid_ustx() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash::zero());
        burnchain.pox_constants.reward_cycle_length = 5;

        let (mut peer, keys) = instantiate_pox_peer(&burnchain, "test-liquid-ustx", 6000);

        let num_blocks = 10;
        let mut expected_liquid_ustx = 1024 * POX_THRESHOLD_STEPS_USTX * (keys.len() as u128);
        let mut missed_initial_blocks = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash =
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);

                    if tip.total_burn > 0 && missed_initial_blocks == 0 {
                        eprintln!("Missed initial blocks: {}", missed_initial_blocks);
                        missed_initial_blocks = tip.block_height;
                    }

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let block_txs = vec![coinbase_tx];

                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &parent_tip,
                        vrf_proof,
                        tip.total_burn,
                        microblock_pubkeyhash,
                    )
                    .unwrap();
                    let (anchored_block, _size, _cost) =
                        StacksBlockBuilder::make_anchored_block_from_txs(
                            block_builder,
                            chainstate,
                            &sortdb.index_conn(),
                            block_txs,
                        )
                        .unwrap();
                    (anchored_block, vec![])
                },
            );

            let (burn_ht, _, _) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let liquid_ustx = get_liquid_ustx(&mut peer);
            assert_eq!(liquid_ustx, expected_liquid_ustx);

            if tenure_id >= MINER_REWARD_MATURITY as usize {
                let block_reward = 1_000 * MICROSTACKS_PER_STACKS as u128;
                let expected_bonus = (missed_initial_blocks as u128 * block_reward)
                    / (INITIAL_MINING_BONUS_WINDOW as u128);
                // add mature coinbases
                expected_liquid_ustx += block_reward + expected_bonus;
            }
        }
    }

    #[test]
    fn test_lockups() {
        let mut peer_config = TestPeerConfig::new("test_lockups", 2000, 2001);
        let alice = StacksAddress::from_string("STVK1K405H6SK9NKJAP32GHYHDJ98MMNP8Y6Z9N0").unwrap();
        let bob = StacksAddress::from_string("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940").unwrap();
        peer_config.initial_lockups = vec![
            ChainstateAccountLockup::new(alice.into(), 1000, 1),
            ChainstateAccountLockup::new(bob, 1000, 1),
            ChainstateAccountLockup::new(alice, 1000, 2),
            ChainstateAccountLockup::new(bob, 1000, 3),
            ChainstateAccountLockup::new(alice, 1000, 4),
            ChainstateAccountLockup::new(bob, 1000, 4),
            ChainstateAccountLockup::new(bob, 1000, 5),
            ChainstateAccountLockup::new(alice, 1000, 6),
            ChainstateAccountLockup::new(alice, 1000, 7),
        ];
        let mut peer = TestPeer::new(peer_config);

        let num_blocks = 8;
        let mut missed_initial_blocks = 0;

        for tenure_id in 0..num_blocks {
            let alice_balance = get_balance(&mut peer, &alice.to_account_principal());
            let bob_balance = get_balance(&mut peer, &bob.to_account_principal());
            match tenure_id {
                0 => {
                    assert_eq!(alice_balance, 0);
                    assert_eq!(bob_balance, 0);
                }
                1 => {
                    assert_eq!(alice_balance, 1000);
                    assert_eq!(bob_balance, 1000);
                }
                2 => {
                    assert_eq!(alice_balance, 2000);
                    assert_eq!(bob_balance, 1000);
                }
                3 => {
                    assert_eq!(alice_balance, 2000);
                    assert_eq!(bob_balance, 2000);
                }
                4 => {
                    assert_eq!(alice_balance, 3000);
                    assert_eq!(bob_balance, 3000);
                }
                5 => {
                    assert_eq!(alice_balance, 3000);
                    assert_eq!(bob_balance, 4000);
                }
                6 => {
                    assert_eq!(alice_balance, 4000);
                    assert_eq!(bob_balance, 4000);
                }
                7 => {
                    assert_eq!(alice_balance, 5000);
                    assert_eq!(bob_balance, 4000);
                }
                _ => {
                    assert_eq!(alice_balance, 5000);
                    assert_eq!(bob_balance, 4000);
                }
            }
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash =
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);

                    if tip.total_burn > 0 && missed_initial_blocks == 0 {
                        eprintln!("Missed initial blocks: {}", missed_initial_blocks);
                        missed_initial_blocks = tip.block_height;
                    }

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let block_txs = vec![coinbase_tx];

                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &parent_tip,
                        vrf_proof,
                        tip.total_burn,
                        microblock_pubkeyhash,
                    )
                    .unwrap();
                    let (anchored_block, _size, _cost) =
                        StacksBlockBuilder::make_anchored_block_from_txs(
                            block_builder,
                            chainstate,
                            &sortdb.index_conn(),
                            block_txs,
                        )
                        .unwrap();
                    (anchored_block, vec![])
                },
            );

            let (burn_ht, _, _) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        }
    }

    #[test]
    fn test_liquid_ustx_burns() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash::zero());
        burnchain.pox_constants.reward_cycle_length = 5;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-liquid-ustx", 6026);

        let num_blocks = 10;
        let mut expected_liquid_ustx = 1024 * POX_THRESHOLD_STEPS_USTX * (keys.len() as u128);
        let mut missed_initial_blocks = 0;

        let alice = keys.pop().unwrap();

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash =
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
                    .unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);

                    if tip.total_burn > 0 && missed_initial_blocks == 0 {
                        eprintln!("Missed initial blocks: {}", missed_initial_blocks);
                        missed_initial_blocks = tip.block_height;
                    }

                    let coinbase_tx = make_coinbase(miner, tenure_id);

                    let burn_tx = make_bare_contract(
                        &alice,
                        tenure_id as u64,
                        0,
                        &format!("alice-burns-{}", &tenure_id),
                        "(stx-burn? u1 tx-sender)",
                    );

                    let block_txs = vec![coinbase_tx, burn_tx];

                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &parent_tip,
                        vrf_proof,
                        tip.total_burn,
                        microblock_pubkeyhash,
                    )
                    .unwrap();
                    let (anchored_block, _size, _cost) =
                        StacksBlockBuilder::make_anchored_block_from_txs(
                            block_builder,
                            chainstate,
                            &sortdb.index_conn(),
                            block_txs,
                        )
                        .unwrap();
                    (anchored_block, vec![])
                },
            );

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let liquid_ustx = get_liquid_ustx(&mut peer);

            expected_liquid_ustx -= 1;
            assert_eq!(liquid_ustx, expected_liquid_ustx);

            if tenure_id >= MINER_REWARD_MATURITY as usize {
                let block_reward = 1_000 * MICROSTACKS_PER_STACKS as u128;
                let expected_bonus = (missed_initial_blocks as u128) * block_reward
                    / (INITIAL_MINING_BONUS_WINDOW as u128);
                // add mature coinbases
                expected_liquid_ustx += block_reward + expected_bonus;
            }
        }
    }

    fn get_par_burn_block_height(state: &mut StacksChainState, block_id: &StacksBlockId) -> u64 {
        let parent_block_id = StacksChainState::get_parent_block_id(state.db(), block_id)
            .unwrap()
            .unwrap();

        let parent_header_info =
            StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                state.db(),
                &parent_block_id,
            )
            .unwrap()
            .unwrap();

        parent_header_info.burn_header_height as u64
    }
}
